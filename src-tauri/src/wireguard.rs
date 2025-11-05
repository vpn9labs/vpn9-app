#[cfg(any(target_os = "linux", target_os = "macos"))]
mod daemon;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use daemon::{connect, disconnect, spawn_watch_task};

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
use tauri::AppHandle;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::devices::DeviceRecord;

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Clone, Debug)]
pub struct WireguardConnectInfo {
    pub interface_name: String,
    pub private_key: String,
    pub device: DeviceRecord,
    pub peer_public_key: String,
    pub endpoint: String,
    pub allowed_ips: Vec<String>,
    pub mtu: Option<u32>,
    pub persistent_keepalive: Option<u16>,
    pub server_name: String,
    pub server_id: String,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub struct WireguardConnection {
    pub(crate) interface_name: String,
    #[allow(dead_code)]
    pub(crate) peer_public_key: String,
    pub(crate) server_name: String,
    pub(crate) server_id: String,
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[derive(Clone, Debug)]
pub struct WireguardConnectInfo;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub struct WireguardConnection;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn spawn_watch_task(_app: &AppHandle) {}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub async fn connect(_info: WireguardConnectInfo) -> Result<WireguardConnection, String> {
    Err("WireGuard connections are only supported on Linux or macOS in this build".to_string())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub async fn disconnect(_conn: WireguardConnection) -> Result<(), String> {
    Ok(())
}
