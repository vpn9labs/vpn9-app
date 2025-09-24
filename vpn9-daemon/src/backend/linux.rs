use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

use defguard_wireguard_rs::{
    host::Peer, key::Key, net::IpAddrMask, InterfaceConfiguration, Kernel, WGApi,
    WireguardInterfaceApi,
};

use crate::service::{AllowedIp, ConnectParams, DeviceRuntime, PlatformError};

pub struct PlatformBackend;

impl PlatformBackend {
    pub async fn new() -> Result<Self, PlatformError> {
        Ok(Self)
    }

    pub fn start_session(&self, params: &ConnectParams) -> Result<DeviceRuntime, PlatformError> {
        let api = WGApi::<Kernel>::new(params.interface_name.clone())
            .map_err(|e| PlatformError::Api(format!("Failed to initialize WireGuard API: {e}")))?;

        api.create_interface().map_err(|e| {
            PlatformError::Api(format!("Failed to create WireGuard interface: {e}"))
        })?;

        let peer = build_peer(params)?;
        let interface_config = build_interface_config(params, &peer)?;

        api.configure_interface(&interface_config).map_err(|e| {
            PlatformError::Api(format!("Failed to configure WireGuard interface: {e}"))
        })?;

        api.configure_peer(&peer)
            .map_err(|e| PlatformError::Api(format!("Failed to configure WireGuard peer: {e}")))?;

        api.configure_peer_routing(&[peer.clone()]).map_err(|e| {
            PlatformError::Api(format!("Failed to configure WireGuard routing: {e}"))
        })?;

        Ok(DeviceRuntime::Kernel)
    }

    pub fn stop_session(
        &self,
        interface_name: &str,
        peer_public_key: &str,
        runtime: Option<DeviceRuntime>,
        _allowed_ips: &[AllowedIp],
        _endpoint: SocketAddr,
    ) -> Result<(), PlatformError> {
        let api = WGApi::<Kernel>::new(interface_name.to_string())
            .map_err(|e| PlatformError::Api(format!("Failed to initialize WireGuard API: {e}")))?;

        if let Ok(key) = Key::from_str(peer_public_key) {
            let _ = api.remove_peer(&key);
        }

        api.remove_interface().map_err(|e| {
            PlatformError::Api(format!("Failed to remove WireGuard interface: {e}"))
        })?;

        if let Some(runtime) = runtime {
            runtime.shutdown();
        }

        Ok(())
    }
}

fn build_peer(params: &ConnectParams) -> Result<Peer, PlatformError> {
    let mut peer = Peer::new(Key::from_str(&params.peer_public_key).map_err(|e| {
        PlatformError::InvalidConfig(format!("Failed to parse peer public key: {e}"))
    })?);
    let allowed_ips = params
        .allowed_ips
        .iter()
        .map(|allowed| IpAddrMask::new(allowed.addr, allowed.cidr))
        .collect();
    peer.set_allowed_ips(allowed_ips);
    peer.set_endpoint(&params.endpoint.to_string())
        .map_err(|e| PlatformError::InvalidConfig(format!("Invalid relay endpoint: {e}")))?;
    peer.persistent_keepalive_interval = params.keepalive_seconds;
    Ok(peer)
}

fn interface_addresses(params: &ConnectParams) -> Result<Vec<IpAddrMask>, PlatformError> {
    let mut addresses = Vec::new();
    if let Some(ipv4) = params.device_ipv4 {
        addresses.push(IpAddrMask::host(IpAddr::V4(ipv4)));
    }
    if let Some(ipv6) = params.device_ipv6 {
        addresses.push(IpAddrMask::host(IpAddr::V6(ipv6)));
    }
    Ok(addresses)
}

fn build_interface_config(
    params: &ConnectParams,
    peer: &Peer,
) -> Result<InterfaceConfiguration, PlatformError> {
    let addresses = interface_addresses(params)?;
    Ok(InterfaceConfiguration {
        name: params.interface_name.clone(),
        prvkey: params.private_key.clone(),
        addresses,
        port: 0,
        peers: vec![peer.clone()],
        mtu: params.mtu,
    })
}
