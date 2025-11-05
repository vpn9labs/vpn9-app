use std::{convert::TryFrom, io, time::Duration};

use log::{error, info, warn};
use serde::Serialize;
use tauri::{AppHandle, Emitter};
use tokio::{net::UnixStream, time::sleep};
use tokio_stream::StreamExt;
use tonic::{
    transport::{Channel, Endpoint},
    Request,
};
use tower::service_fn;
use uuid::Uuid;
use vpn9_proto::daemon::{
    wireguard_control_client::WireguardControlClient, ConnectRequest, DisconnectRequest, Empty,
    Event as DaemonEvent, EventType, InterfaceState, OperationStatus, StatusSnapshot,
};

use super::{WireguardConnectInfo, WireguardConnection};

const DAEMON_SOCKET_PATH: &str = "/var/run/vpn9/vpn9d.sock";
const DAEMON_ENDPOINT_URI: &str = "http://[::]:50051";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const WATCH_RETRY_DELAY: Duration = Duration::from_secs(3);
const WATCH_EVENT_NAME: &str = "wireguard-daemon-event";

async fn connect_daemon() -> Result<WireguardControlClient<Channel>, String> {
    let endpoint = Endpoint::try_from(DAEMON_ENDPOINT_URI)
        .map_err(|err| format!("Failed to build daemon endpoint: {err}"))?
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT);

    let path = DAEMON_SOCKET_PATH.to_string();
    let channel = endpoint
        .connect_with_connector(service_fn(move |_| {
            let path = path.clone();
            async move {
                UnixStream::connect(path.clone()).await.map_err(|err| {
                    if err.kind() == io::ErrorKind::PermissionDenied {
                        io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            format!(
                                "Permission denied connecting to vpn9-daemon socket at {}",
                                DAEMON_SOCKET_PATH
                            ),
                        )
                    } else {
                        err
                    }
                })
            }
        }))
        .await
        .map_err(|err| format!("Failed to connect to vpn9-daemon: {err}"))?;

    Ok(WireguardControlClient::new(channel))
}

fn map_operation_status(status: i32, message: &str) -> Result<(), String> {
    match OperationStatus::try_from(status).ok() {
        Some(OperationStatus::StatusOk) | Some(OperationStatus::StatusInProgress) => Ok(()),
        Some(OperationStatus::StatusFailed) => Err(if message.is_empty() {
            "vpn9-daemon reported failure".to_string()
        } else {
            message.to_string()
        }),
        None => Err(format!("vpn9-daemon returned unknown status {status}")),
    }
}

pub async fn connect(config: WireguardConnectInfo) -> Result<WireguardConnection, String> {
    info!(
        "event=wireguard.connect.request interface={} server_id={} server_name={}",
        config.interface_name, config.server_id, config.server_name
    );

    let mut client = connect_daemon().await?;
    let request_id = Uuid::new_v4().to_string();

    let request = ConnectRequest {
        request_id: request_id.clone(),
        interface_name: config.interface_name.clone(),
        server_id: config.server_id.clone(),
        server_name: config.server_name.clone(),
        endpoint: config.endpoint.clone(),
        peer_public_key: config.peer_public_key.clone(),
        private_key: config.private_key.clone(),
        allowed_ips: config.allowed_ips.clone(),
        mtu: config.mtu.map(|value| value as u32),
        keepalive_seconds: config.persistent_keepalive.map(u32::from),
        device_ipv4: config.device.ipv4.clone(),
        device_ipv6: config.device.ipv6.clone(),
    };

    let response = client
        .start_session(Request::new(request))
        .await
        .map_err(|err| format!("vpn9-daemon connect RPC failed: {err}"))?
        .into_inner();

    if let Err(err) = map_operation_status(response.status, &response.message) {
        error!(
            "event=wireguard.connect.failed interface={} server_id={} err={}",
            config.interface_name, config.server_id, err
        );
        return Err(err);
    }

    info!(
        "event=wireguard.connect.accepted interface={} server_id={} request_id={}",
        config.interface_name, config.server_id, request_id
    );

    Ok(WireguardConnection {
        interface_name: config.interface_name.clone(),
        peer_public_key: config.peer_public_key.clone(),
        server_name: config.server_name.clone(),
        server_id: config.server_id.clone(),
    })
}

pub async fn disconnect(connection: WireguardConnection) -> Result<(), String> {
    info!(
        "event=wireguard.disconnect.request interface={} server_id={}",
        connection.interface_name, connection.server_id
    );

    let mut client = connect_daemon().await?;
    let request_id = Uuid::new_v4().to_string();

    let request = DisconnectRequest {
        request_id: request_id.clone(),
        interface_name: connection.interface_name.clone(),
    };

    info!(
        "event=wireguard.disconnect.rpc interface={} request_id={}",
        connection.interface_name, request_id
    );

    let response = client
        .stop_session(Request::new(request))
        .await
        .map_err(|err| format!("vpn9-daemon disconnect RPC failed: {err}"))?
        .into_inner();

    if let Err(err) = map_operation_status(response.status, &response.message) {
        warn!(
            "event=wireguard.disconnect.failed interface={} server_id={} err={}",
            connection.interface_name, connection.server_id, err
        );
        return Err(err);
    }

    info!(
        "event=wireguard.disconnect.ack interface={} server_id={} request_id={}",
        connection.interface_name, connection.server_id, request_id
    );

    Ok(())
}

#[derive(Debug, Clone, Serialize)]
struct WireguardSnapshotPayload {
    state: String,
    server_id: String,
    server_name: String,
    tx_bytes: u64,
    rx_bytes: u64,
    last_handshake_unix: u64,
    message: String,
}

#[derive(Debug, Clone, Serialize)]
struct WireguardEventPayload {
    request_id: String,
    event_type: String,
    status: String,
    interface_name: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    snapshot: Option<WireguardSnapshotPayload>,
}

pub fn spawn_watch_task(app: &AppHandle) {
    let app_handle = app.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            match watch_daemon_events(&app_handle).await {
                Ok(()) => {
                    sleep(WATCH_RETRY_DELAY).await;
                }
                Err(err) => {
                    warn!("event=wireguard.daemon.watch_failed err={err}");
                    sleep(WATCH_RETRY_DELAY).await;
                }
            }
        }
    });
}

async fn watch_daemon_events(app: &AppHandle) -> Result<(), String> {
    let mut client = connect_daemon().await?;
    let response = client
        .watch(Request::new(Empty {}))
        .await
        .map_err(|err| format!("vpn9-daemon watch RPC failed: {err}"))?;

    let mut stream = response.into_inner();
    while let Some(event) = stream.next().await {
        match event {
            Ok(ev) => {
                if let Some(payload) = map_daemon_event(ev) {
                    if let Err(err) = app.emit(WATCH_EVENT_NAME, payload) {
                        warn!("event=wireguard.daemon.emit_failed err={err}");
                    }
                }
            }
            Err(status) => {
                return Err(format!("vpn9-daemon watch stream error: {status}"));
            }
        }
    }

    Ok(())
}

fn map_daemon_event(event: DaemonEvent) -> Option<WireguardEventPayload> {
    let event_type = event_type_to_str(event.r#type)?;
    let status = operation_status_to_str(event.status);
    let snapshot_payload = event.snapshot.map(map_snapshot);

    let message = if !event.message.is_empty() {
        event.message.clone()
    } else {
        snapshot_payload
            .as_ref()
            .map(|snapshot| snapshot.message.clone())
            .unwrap_or_default()
    };

    Some(WireguardEventPayload {
        request_id: event.request_id,
        event_type,
        status,
        interface_name: event.interface_name,
        message,
        snapshot: snapshot_payload,
    })
}

fn map_snapshot(snapshot: StatusSnapshot) -> WireguardSnapshotPayload {
    WireguardSnapshotPayload {
        state: interface_state_to_str(snapshot.state).to_string(),
        server_id: snapshot.server_id,
        server_name: snapshot.server_name,
        tx_bytes: snapshot.tx_bytes,
        rx_bytes: snapshot.rx_bytes,
        last_handshake_unix: snapshot.last_handshake_unix,
        message: snapshot.message,
    }
}

fn event_type_to_str(value: i32) -> Option<String> {
    Some(
        match EventType::try_from(value).ok()? {
            EventType::Connect => "connect",
            EventType::Disconnect => "disconnect",
            EventType::Status => "status",
            EventType::Error => "error",
        }
        .to_string(),
    )
}

fn operation_status_to_str(value: i32) -> String {
    match OperationStatus::try_from(value).ok() {
        Some(OperationStatus::StatusOk) => "ok",
        Some(OperationStatus::StatusFailed) => "failed",
        Some(OperationStatus::StatusInProgress) => "in_progress",
        None => "unknown",
    }
    .to_string()
}

fn interface_state_to_str(value: i32) -> &'static str {
    match InterfaceState::try_from(value).ok() {
        Some(InterfaceState::Up) => "up",
        Some(InterfaceState::Down) => "down",
        Some(InterfaceState::Connecting) => "connecting",
        Some(InterfaceState::Disconnecting) => "disconnecting",
        None => "unknown",
    }
}
