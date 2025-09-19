use log::info;
use serde::Deserialize;

use crate::auth::{get_stored_tokens, ActionResponse};

#[derive(Deserialize)]
pub struct VpnConnectArgs {
    pub server_id: String,
    pub server_name: String,
    pub hostname: String,
    pub public_key: String,
    pub port: u16,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod platform {
    use std::sync::OnceLock;

    use defguard_wireguard_rs::net::IpAddrMask;
    use log::info;
    use tokio::sync::Mutex;

    use crate::devices::{ensure_device_registered, get_wireguard_keypair, DeviceRecord};
    use crate::wireguard::{self, WireguardConnectInfo, WireguardConnection};

    use super::VpnConnectArgs;

    #[cfg(target_os = "linux")]
    const WG_INTERFACE_NAME: &str = "wg-vpn9";
    #[cfg(target_os = "macos")]
    const WG_INTERFACE_NAME: &str = "utun9";
    const KEEPALIVE_SECONDS: u16 = 25;

    static WG_STATE: OnceLock<Mutex<Option<WireguardConnection>>> = OnceLock::new();

    fn state() -> &'static Mutex<Option<WireguardConnection>> {
        WG_STATE.get_or_init(|| Mutex::new(None))
    }

    fn parse_allowed_ips(raw: Option<&String>) -> Result<Vec<IpAddrMask>, String> {
        let Some(value) = raw else {
            return Err("Device configuration missing allowed IPs".to_string());
        };
        let mut ips = Vec::new();
        for entry in value.split(',') {
            let trimmed = entry.trim();
            if trimmed.is_empty() {
                continue;
            }
            let mask = trimmed
                .parse::<IpAddrMask>()
                .map_err(|_| format!("Invalid allowed IP entry returned by API: {trimmed}"))?;
            ips.push(mask);
        }
        if ips.is_empty() {
            return Err("Device configuration did not include any allowed IPs".to_string());
        }
        Ok(ips)
    }

    fn build_connect_info(
        args: &VpnConnectArgs,
        device: &DeviceRecord,
        private_key: &str,
    ) -> Result<WireguardConnectInfo, String> {
        let allowed_ips = parse_allowed_ips(device.allowed_ips.as_ref())?;
        let endpoint = format!("{}:{}", args.hostname, args.port);
        Ok(WireguardConnectInfo {
            interface_name: WG_INTERFACE_NAME.to_string(),
            private_key: private_key.to_string(),
            device: device.clone(),
            peer_public_key: args.public_key.clone(),
            endpoint,
            allowed_ips,
            mtu: None,
            persistent_keepalive: Some(KEEPALIVE_SECONDS),
            server_name: args.server_name.clone(),
            server_id: args.server_id.clone(),
        })
    }

    pub async fn connect(args: &VpnConnectArgs) -> Result<(), String> {
        let device_sync = ensure_device_registered(Some(args.server_id.clone())).await?;
        let device = device_sync.device;
        info!(
            "event=vpn.device.synced regenerated={} created={}",
            device_sync.keys_regenerated, device_sync.newly_created
        );

        let (private_key, _) = get_wireguard_keypair().await?;
        let connect_info = build_connect_info(args, &device, &private_key)?;

        let state = state();
        let mut guard = state.lock().await;
        if let Some(existing) = guard.take() {
            if let Err(err) = wireguard::disconnect(existing).await {
                info!("event=vpn.wireguard.disconnect.warning err={err}");
            }
        }

        let connection = wireguard::connect(connect_info).await?;
        *guard = Some(connection);
        Ok(())
    }

    pub async fn disconnect() -> Result<(), String> {
        let state = state();
        let mut guard = state.lock().await;
        if let Some(existing) = guard.take() {
            wireguard::disconnect(existing).await?;
        }
        Ok(())
    }

    pub async fn connection_snapshot() -> Option<(String, String)> {
        let state = state();
        let guard = state.lock().await;
        guard
            .as_ref()
            .map(|conn| (conn.server_id.clone(), conn.server_name.clone()))
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tauri::command]
pub async fn vpn_connect(
    server_id: String,
    server_name: String,
    hostname: String,
    public_key: String,
    port: u16,
    _app: tauri::AppHandle,
) -> Result<ActionResponse, String> {
    info!("event=vpn.connect.start server_id={server_id}");

    get_stored_tokens()
        .await
        .map_err(|e| format!("Not authenticated: {e}"))?;

    let args = VpnConnectArgs {
        server_id,
        server_name: server_name.clone(),
        hostname,
        public_key,
        port,
    };

    platform::connect(&args).await?;

    Ok(ActionResponse {
        message: format!("Connected to {}", server_name),
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[tauri::command]
pub async fn vpn_connect(
    server_id: String,
    server_name: String,
    hostname: String,
    public_key: String,
    port: u16,
    _app: tauri::AppHandle,
) -> Result<ActionResponse, String> {
    let _ = (server_id, server_name, hostname, public_key, port);
    Err("WireGuard connections are only supported on Linux or macOS in this build".to_string())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[tauri::command]
pub async fn vpn_disconnect() -> Result<ActionResponse, String> {
    info!("event=vpn.disconnect.start");
    platform::disconnect().await?;
    Ok(ActionResponse {
        message: "Disconnected from VPN".to_string(),
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[tauri::command]
pub async fn vpn_disconnect() -> Result<ActionResponse, String> {
    info!("event=vpn.disconnect.start");
    Ok(ActionResponse {
        message: "WireGuard disconnect is a no-op on unsupported platforms".to_string(),
    })
}

#[tauri::command]
pub async fn get_vpn_status() -> Result<serde_json::Value, String> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        if let Some((server_id, server_name)) = platform::connection_snapshot().await {
            return Ok(serde_json::json!({
                "connected": true,
                "server_id": server_id,
                "server_name": server_name,
            }));
        }
    }

    Ok(serde_json::json!({
        "connected": false,
        "server_id": null,
        "server_name": null,
    }))
}
