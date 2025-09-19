#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "linux")]
pub use linux::{connect, disconnect};
#[cfg(target_os = "macos")]
pub use macos::{connect, disconnect};

#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::devices::DeviceRecord;
#[cfg(target_os = "macos")]
use boringtun::device::DeviceHandle;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use defguard_wireguard_rs::net::IpAddrMask;

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Clone, Debug)]
pub struct WireguardConnectInfo {
    pub interface_name: String,
    pub private_key: String,
    pub device: DeviceRecord,
    pub peer_public_key: String,
    pub endpoint: String,
    pub allowed_ips: Vec<IpAddrMask>,
    pub mtu: Option<u32>,
    pub persistent_keepalive: Option<u16>,
    pub server_name: String,
    pub server_id: String,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub struct WireguardConnection {
    pub(crate) interface_name: String,
    pub(crate) peer_public_key: String,
    pub(crate) server_name: String,
    pub(crate) server_id: String,
    #[cfg(target_os = "macos")]
    pub(crate) device_handle: DeviceHandle,
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[derive(Clone, Debug)]
pub struct WireguardConnectInfo;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub struct WireguardConnection;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub async fn connect(_info: WireguardConnectInfo) -> Result<WireguardConnection, String> {
    Err("WireGuard connections are only supported on Linux or macOS in this build".to_string())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub async fn disconnect(_conn: WireguardConnection) -> Result<(), String> {
    Ok(())
}
