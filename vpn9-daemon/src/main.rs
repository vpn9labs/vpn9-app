mod backend;
#[cfg(target_os = "macos")]
mod dns_proxy;
mod service;
mod signals;

use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use anyhow::Result;
use backend::PlatformBackend;
use log::{error, info, warn};
use service::{AllowedIp, ConnectParams, DeviceRuntime, PlatformError};
use tokio::net::UnixListener;
use tokio::sync::{broadcast, RwLock};
use tokio_stream::wrappers::{BroadcastStream, UnixListenerStream};
use tokio_stream::{Stream, StreamExt};
use tonic::{transport::Server, Request, Response, Status};
use vpn9_proto::daemon::{
    wireguard_control_server::{WireguardControl, WireguardControlServer},
    ConnectRequest, ConnectResponse, DisconnectRequest, DisconnectResponse, Empty, Event,
    EventType, InterfaceState, OperationStatus, StatusRequest, StatusSnapshot,
};

const SOCKET_DIR: &str = "/var/run/vpn9";
const SOCKET_PATH: &str = "/var/run/vpn9/vpn9d.sock";
const EVENT_QUEUE_SIZE: usize = 128;

#[derive(Clone)]
struct WireguardService {
    inner: Arc<InnerState>,
    backend: Arc<PlatformBackend>,
}

struct InnerState {
    interfaces: RwLock<HashMap<String, InterfaceEntry>>,
    events: broadcast::Sender<Event>,
}

struct InterfaceEntry {
    info: InterfaceInfo,
    runtime: Option<DeviceRuntime>,
    allowed_ips: Vec<AllowedIp>,
    endpoint: SocketAddr,
}

struct ShutdownJob {
    interface_name: String,
    request_id: String,
    peer_public_key: String,
    runtime: Option<DeviceRuntime>,
    allowed_ips: Vec<AllowedIp>,
    endpoint: SocketAddr,
}

#[derive(Clone, Debug)]
struct InterfaceInfo {
    server_id: String,
    server_name: String,
    peer_public_key: String,
    state: InterfaceState,
    message: String,
    tx_bytes: u64,
    rx_bytes: u64,
    last_handshake_unix: u64,
}

impl WireguardService {
    async fn new() -> Result<Self, PlatformError> {
        let backend = PlatformBackend::new().await?;
        let (tx, _) = broadcast::channel(EVENT_QUEUE_SIZE);
        Ok(Self {
            inner: Arc::new(InnerState {
                interfaces: RwLock::new(HashMap::new()),
                events: tx,
            }),
            backend: Arc::new(backend),
        })
    }

    async fn snapshot(&self, interface_name: &str) -> StatusSnapshot {
        let interfaces = self.inner.interfaces.read().await;
        if let Some(entry) = interfaces.get(interface_name) {
            return entry.info.to_snapshot(interface_name);
        }
        StatusSnapshot {
            interface_name: interface_name.to_string(),
            state: InterfaceState::Down as i32,
            server_id: String::new(),
            server_name: String::new(),
            tx_bytes: 0,
            rx_bytes: 0,
            last_handshake_unix: 0,
            message: "interface not managed".to_string(),
        }
    }

    async fn emit_event_with_snapshot(&self, mut event: Event, interface_name: &str) {
        if event.snapshot.is_none() {
            let snapshot = self.snapshot(interface_name).await;
            event.snapshot = Some(snapshot);
        }
        if let Err(err) = self.inner.events.send(event) {
            warn!("event=daemon.event_dropped reason={err}");
        }
    }

    async fn shutdown(&self) {
        let jobs = {
            let mut interfaces = self.inner.interfaces.write().await;
            let mut jobs = Vec::with_capacity(interfaces.len());
            for (interface_name, entry) in interfaces.iter_mut() {
                if entry.runtime.is_none() && entry.info.state == InterfaceState::Down {
                    continue;
                }
                let runtime = entry.runtime.take();
                entry.info.state = InterfaceState::Disconnecting;
                entry.info.message = "Disconnecting (daemon shutdown)".to_string();
                jobs.push(ShutdownJob {
                    interface_name: interface_name.clone(),
                    request_id: format!("daemon_shutdown::{}", interface_name),
                    peer_public_key: entry.info.peer_public_key.clone(),
                    runtime,
                    allowed_ips: entry.allowed_ips.clone(),
                    endpoint: entry.endpoint,
                });
            }
            jobs
        };

        if jobs.is_empty() {
            return;
        }

        info!(
            "event=daemon.shutdown.sessions total={} message=Disconnecting active interfaces",
            jobs.len()
        );

        for job in jobs {
            let ShutdownJob {
                interface_name,
                request_id,
                peer_public_key,
                runtime,
                allowed_ips,
                endpoint,
            } = job;

            self.emit_event_with_snapshot(
                Event {
                    request_id: request_id.clone(),
                    r#type: EventType::Disconnect as i32,
                    status: OperationStatus::StatusInProgress as i32,
                    interface_name: interface_name.clone(),
                    message: "Daemon shutting down".to_string(),
                    snapshot: None,
                },
                &interface_name,
            )
            .await;

            let backend = self.backend.clone();
            let interface_for_task = interface_name.clone();
            let peer_for_task = peer_public_key.clone();

            let stop_result = tokio::task::spawn_blocking(move || {
                backend.stop_session(
                    &interface_for_task,
                    &peer_for_task,
                    runtime,
                    &allowed_ips,
                    endpoint,
                )
            })
            .await;

            match stop_result {
                Ok(Ok(())) => {
                    info!(
                        "event=daemon.shutdown.disconnect_success interface={}",
                        interface_name
                    );
                    self.handle_disconnect_success(interface_name.clone(), request_id.clone())
                        .await;
                }
                Ok(Err(err)) => {
                    let message = err.to_string();
                    warn!(
                        "event=daemon.shutdown.disconnect_failed interface={} err={message}",
                        interface_name
                    );
                    self.handle_disconnect_failure(
                        interface_name.clone(),
                        request_id.clone(),
                        message,
                    )
                    .await;
                }
                Err(err) => {
                    let message = format!("stop_session join error: {err}");
                    warn!(
                        "event=daemon.shutdown.disconnect_join_failed interface={} err={message}",
                        interface_name
                    );
                    self.handle_disconnect_failure(
                        interface_name.clone(),
                        request_id.clone(),
                        message,
                    )
                    .await;
                }
            }
        }
    }

    async fn handle_connect_success(
        &self,
        interface_name: String,
        request_id: String,
        runtime: DeviceRuntime,
    ) {
        {
            let mut interfaces = self.inner.interfaces.write().await;
            if let Some(entry) = interfaces.get_mut(&interface_name) {
                entry.info.state = InterfaceState::Up;
                entry.info.message = format!("Connected to {}", entry.info.server_name);
                entry.info.last_handshake_unix = 0;
                entry.info.tx_bytes = 0;
                entry.info.rx_bytes = 0;
                entry.runtime = Some(runtime);
            }
        }

        self.emit_event_with_snapshot(
            Event {
                request_id,
                r#type: EventType::Status as i32,
                status: OperationStatus::StatusOk as i32,
                interface_name: interface_name.clone(),
                message: "Connection established".to_string(),
                snapshot: None,
            },
            &interface_name,
        )
        .await;
    }

    async fn handle_connect_failure(
        &self,
        interface_name: String,
        request_id: String,
        message: String,
    ) {
        {
            let mut interfaces = self.inner.interfaces.write().await;
            if let Some(entry) = interfaces.get_mut(&interface_name) {
                entry.info.state = InterfaceState::Down;
                entry.info.message = message.clone();
                entry.info.last_handshake_unix = 0;
                entry.runtime = None;
            }
        }

        self.emit_event_with_snapshot(
            Event {
                request_id,
                r#type: EventType::Error as i32,
                status: OperationStatus::StatusFailed as i32,
                interface_name: interface_name.clone(),
                message,
                snapshot: None,
            },
            &interface_name,
        )
        .await;
    }

    async fn handle_disconnect_success(&self, interface_name: String, request_id: String) {
        {
            let mut interfaces = self.inner.interfaces.write().await;
            if let Some(entry) = interfaces.get_mut(&interface_name) {
                entry.info.state = InterfaceState::Down;
                entry.info.message = format!("Disconnected from {}", entry.info.server_name);
                entry.info.last_handshake_unix = 0;
                entry.info.tx_bytes = 0;
                entry.info.rx_bytes = 0;
            }
        }

        self.emit_event_with_snapshot(
            Event {
                request_id,
                r#type: EventType::Disconnect as i32,
                status: OperationStatus::StatusOk as i32,
                interface_name: interface_name.clone(),
                message: "Disconnected".to_string(),
                snapshot: None,
            },
            &interface_name,
        )
        .await;
    }

    async fn handle_disconnect_failure(
        &self,
        interface_name: String,
        request_id: String,
        message: String,
    ) {
        {
            let mut interfaces = self.inner.interfaces.write().await;
            if let Some(entry) = interfaces.get_mut(&interface_name) {
                entry.info.state = InterfaceState::Down;
                entry.info.message = message.clone();
                entry.runtime = None;
            }
        }

        self.emit_event_with_snapshot(
            Event {
                request_id,
                r#type: EventType::Error as i32,
                status: OperationStatus::StatusFailed as i32,
                interface_name: interface_name.clone(),
                message,
                snapshot: None,
            },
            &interface_name,
        )
        .await;
    }
}

impl InterfaceInfo {
    fn to_snapshot(&self, interface_name: &str) -> StatusSnapshot {
        StatusSnapshot {
            interface_name: interface_name.to_string(),
            state: self.state as i32,
            server_id: self.server_id.clone(),
            server_name: self.server_name.clone(),
            tx_bytes: self.tx_bytes,
            rx_bytes: self.rx_bytes,
            last_handshake_unix: self.last_handshake_unix,
            message: self.message.clone(),
        }
    }
}

#[tonic::async_trait]
impl WireguardControl for WireguardService {
    async fn start_session(
        &self,
        request: Request<ConnectRequest>,
    ) -> Result<Response<ConnectResponse>, Status> {
        let req = request.into_inner();
        let params = ConnectParams::try_from(&req)?;
        let interface_name = params.interface_name.clone();
        let request_id = params.request_id.clone();

        {
            let mut interfaces = self.inner.interfaces.write().await;
            if let Some(entry) = interfaces.get(&interface_name) {
                if entry.runtime.is_some() {
                    return Err(Status::failed_precondition(
                        "interface already has an active session",
                    ));
                }
            }

            let info = InterfaceInfo {
                server_id: params.server_id.clone(),
                server_name: params.server_name.clone(),
                peer_public_key: params.peer_public_key.clone(),
                state: InterfaceState::Connecting,
                message: "Establishing connection".to_string(),
                tx_bytes: 0,
                rx_bytes: 0,
                last_handshake_unix: 0,
            };

            interfaces.insert(
                interface_name.clone(),
                InterfaceEntry {
                    info,
                    runtime: None,
                    allowed_ips: params.allowed_ips.clone(),
                    endpoint: params.endpoint,
                },
            );
        }

        self.emit_event_with_snapshot(
            Event {
                request_id: request_id.clone(),
                r#type: EventType::Connect as i32,
                status: OperationStatus::StatusInProgress as i32,
                interface_name: interface_name.clone(),
                message: "Connection request accepted".to_string(),
                snapshot: None,
            },
            &interface_name,
        )
        .await;

        let backend = self.backend.clone();
        let params_clone = params.clone();
        let runtime_result =
            tokio::task::spawn_blocking(move || backend.start_session(&params_clone))
                .await
                .map_err(|err| {
                    Status::internal(format!("start_session worker join error: {err}"))
                })?;

        match runtime_result {
            Ok(runtime) => {
                self.handle_connect_success(interface_name.clone(), request_id.clone(), runtime)
                    .await;

                Ok(Response::new(ConnectResponse {
                    request_id,
                    status: OperationStatus::StatusOk as i32,
                    message: "Connection established".to_string(),
                }))
            }
            Err(err) => {
                let message = err.to_string();
                self.handle_connect_failure(
                    interface_name.clone(),
                    request_id.clone(),
                    message.clone(),
                )
                .await;

                Ok(Response::new(ConnectResponse {
                    request_id,
                    status: OperationStatus::StatusFailed as i32,
                    message,
                }))
            }
        }
    }

    async fn stop_session(
        &self,
        request: Request<DisconnectRequest>,
    ) -> Result<Response<DisconnectResponse>, Status> {
        let req = request.into_inner();
        if req.interface_name.trim().is_empty() {
            return Err(Status::invalid_argument("interface_name is required"));
        }
        let interface_name = req.interface_name.clone();
        let request_id = req.request_id.clone();

        let (peer_public_key, runtime, allowed_ips, endpoint) = {
            let mut interfaces = self.inner.interfaces.write().await;
            match interfaces.get_mut(&interface_name) {
                Some(entry) => {
                    entry.info.state = InterfaceState::Disconnecting;
                    entry.info.message = "Disconnecting".to_string();
                    let runtime = entry.runtime.take();
                    (
                        entry.info.peer_public_key.clone(),
                        runtime,
                        entry.allowed_ips.clone(),
                        entry.endpoint,
                    )
                }
                None => {
                    drop(interfaces);
                    self.emit_event_with_snapshot(
                        Event {
                            request_id: request_id.clone(),
                            r#type: EventType::Error as i32,
                            status: OperationStatus::StatusFailed as i32,
                            interface_name: interface_name.clone(),
                            message: "Interface not found".to_string(),
                            snapshot: None,
                        },
                        &interface_name,
                    )
                    .await;

                    return Ok(Response::new(DisconnectResponse {
                        request_id,
                        status: OperationStatus::StatusFailed as i32,
                        message: "Interface not found".to_string(),
                    }));
                }
            }
        };

        self.emit_event_with_snapshot(
            Event {
                request_id: request_id.clone(),
                r#type: EventType::Disconnect as i32,
                status: OperationStatus::StatusInProgress as i32,
                interface_name: interface_name.clone(),
                message: "Disconnect requested".to_string(),
                snapshot: None,
            },
            &interface_name,
        )
        .await;

        let backend = self.backend.clone();
        let interface_for_task = interface_name.clone();
        let allowed_for_task = allowed_ips.clone();
        let endpoint_for_task = endpoint;
        let stop_result = tokio::task::spawn_blocking(move || {
            backend.stop_session(
                &interface_for_task,
                &peer_public_key,
                runtime,
                &allowed_for_task,
                endpoint_for_task,
            )
        })
        .await
        .map_err(|err| Status::internal(format!("stop_session worker join error: {err}")))?;

        match stop_result {
            Ok(()) => {
                self.handle_disconnect_success(interface_name.clone(), request_id.clone())
                    .await;
                info!(
                    "event=daemon.disconnect.success interface={} request_id={}",
                    interface_name, request_id
                );

                Ok(Response::new(DisconnectResponse {
                    request_id,
                    status: OperationStatus::StatusOk as i32,
                    message: "Disconnected".to_string(),
                }))
            }
            Err(err) => {
                let message = err.to_string();
                self.handle_disconnect_failure(
                    interface_name.clone(),
                    request_id.clone(),
                    message.clone(),
                )
                .await;

                Ok(Response::new(DisconnectResponse {
                    request_id,
                    status: OperationStatus::StatusFailed as i32,
                    message,
                }))
            }
        }
    }

    async fn get_status(
        &self,
        request: Request<StatusRequest>,
    ) -> Result<Response<StatusSnapshot>, Status> {
        let req = request.into_inner();
        if req.interface_name.trim().is_empty() {
            return Err(Status::invalid_argument("interface_name is required"));
        }
        let snapshot = self.snapshot(&req.interface_name).await;
        Ok(Response::new(snapshot))
    }

    type WatchStream = Pin<Box<dyn Stream<Item = Result<Event, Status>> + Send + 'static>>;

    async fn watch(&self, _request: Request<Empty>) -> Result<Response<Self::WatchStream>, Status> {
        let rx = self.inner.events.subscribe();
        let stream = BroadcastStream::new(rx).filter_map(|event| match event {
            Ok(ev) => Some(Ok(ev)),
            Err(err) => {
                warn!("event=daemon.watch.recv_error err={err}");
                None
            }
        });
        Ok(Response::new(Box::pin(stream)))
    }
}

fn prepare_socket_dir() -> Result<(), PlatformError> {
    let dir = Path::new(SOCKET_DIR);
    if !dir.exists() {
        fs::create_dir_all(dir)
            .map_err(|e| PlatformError::Io(format!("Failed to create socket dir: {e}")))?;
    }
    let mut permissions = fs::metadata(dir)
        .map_err(|e| PlatformError::Io(format!("Failed to read socket dir metadata: {e}")))?
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(dir, permissions)
        .map_err(|e| PlatformError::Io(format!("Failed to set socket dir permissions: {e}")))?;
    Ok(())
}

fn remove_stale_socket(path: &Path) {
    if path.exists() {
        if let Err(err) = fs::remove_file(path) {
            warn!(
                "event=daemon.cleanup_failed path={} err={err}",
                path.display()
            );
        }
    }
}

struct SocketGuard(PathBuf);

impl Drop for SocketGuard {
    fn drop(&mut self) {
        if let Err(err) = fs::remove_file(&self.0) {
            warn!(
                "event=daemon.socket_cleanup_failed path={} err={err}",
                self.0.display()
            );
        }
    }
}

fn socket_guard(path: &Path) -> SocketGuard {
    SocketGuard(path.to_path_buf())
}

fn init_logger() -> Result<()> {
    simple_logger::SimpleLogger::new()
        .with_level(log::LevelFilter::Info)
        .env()
        .init()
        .map_err(|err| anyhow::anyhow!("failed to initialize logger: {err}"))?;
    Ok(())
}

fn main() {
    if let Err(err) = run() {
        error!("vpn9-daemon stopped with error: {err:#}");
        std::process::exit(1);
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn run() -> Result<()> {
    init_logger()?;

    prepare_socket_dir().map_err(|err| anyhow::anyhow!(err.to_string()))?;

    let socket_path = Path::new(SOCKET_PATH);
    remove_stale_socket(socket_path);
    let listener = UnixListener::bind(socket_path)?;
    let mut socket_permissions = fs::metadata(socket_path)?.permissions();
    socket_permissions.set_mode(0o666);
    fs::set_permissions(socket_path, socket_permissions)?;
    let _guard = socket_guard(socket_path);

    info!(
        "event=daemon.listen path={} pid={}",
        SOCKET_PATH,
        std::process::id()
    );

    let incoming = UnixListenerStream::new(listener);

    signals::init().map_err(|err| anyhow::anyhow!(err.to_string()))?;
    let mut shutdown_rx = signals::subscribe().map_err(|err| {
        anyhow::anyhow!(format!("failed to subscribe to shutdown signals: {err}"))
    })?;

    let service = WireguardService::new()
        .await
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;
    let shutdown_service = service.clone();
    let server_service = service.clone();

    let shutdown_signal = async move {
        match shutdown_rx.recv().await {
            Ok(signal) => {
                info!(
                    "event=daemon.shutdown signal={}",
                    signals::signal_name(signal)
                );
            }
            Err(err) => {
                warn!("event=daemon.shutdown.signal_error source=receiver err={err}");
            }
        }
        shutdown_service.shutdown().await;
    };

    Server::builder()
        .add_service(WireguardControlServer::new(server_service))
        .serve_with_incoming_shutdown(incoming, shutdown_signal)
        .await?;

    service.shutdown().await;

    Ok(())
}
