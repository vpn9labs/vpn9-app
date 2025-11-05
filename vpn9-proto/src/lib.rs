pub mod daemon {
    tonic::include_proto!("vpn9.daemon");
}

pub use daemon::wireguard_control_client::WireguardControlClient;
pub use daemon::wireguard_control_server::{WireguardControl, WireguardControlServer};
