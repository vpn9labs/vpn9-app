use std::str::FromStr;

use defguard_wireguard_rs::{host::Peer, key::Key, net::IpAddrMask, WGApi, WireguardInterfaceApi};
use defguard_wireguard_rs::{InterfaceConfiguration, Kernel};
use log::{debug, info, warn};

use crate::devices::DeviceRecord;

use super::{WireguardConnectInfo, WireguardConnection};

fn build_peer(config: &WireguardConnectInfo) -> Result<Peer, String> {
    let mut peer = Peer::new(
        Key::from_str(&config.peer_public_key)
            .map_err(|e| format!("Failed to parse relay public key: {e}"))?,
    );
    peer.set_allowed_ips(config.allowed_ips.clone());
    peer.set_endpoint(&config.endpoint)
        .map_err(|e| format!("Invalid relay endpoint: {e}"))?;
    peer.persistent_keepalive_interval = config.persistent_keepalive;
    Ok(peer)
}

fn interface_addresses(device: &DeviceRecord) -> Result<Vec<IpAddrMask>, String> {
    let mut addresses = Vec::new();
    if let Some(ipv4) = device.ipv4.as_ref() {
        let addr = ipv4
            .parse()
            .map_err(|e| format!("Invalid IPv4 address {ipv4}: {e}"))?;
        addresses.push(IpAddrMask::host(addr));
    }
    if let Some(ipv6) = device.ipv6.as_ref() {
        let addr = ipv6
            .parse()
            .map_err(|e| format!("Invalid IPv6 address {ipv6}: {e}"))?;
        addresses.push(IpAddrMask::host(addr));
    }
    Ok(addresses)
}

fn build_interface_config(
    config: &WireguardConnectInfo,
    peer: &Peer,
) -> Result<InterfaceConfiguration, String> {
    let addresses = interface_addresses(&config.device)?;

    Ok(InterfaceConfiguration {
        name: config.interface_name.clone(),
        prvkey: config.private_key.clone(),
        addresses,
        port: 0,
        peers: vec![peer.clone()],
        mtu: config.mtu,
    })
}

pub async fn connect(config: WireguardConnectInfo) -> Result<WireguardConnection, String> {
    let connect_fn = move || -> Result<WireguardConnection, String> {
        let api = WGApi::<Kernel>::new(config.interface_name.clone())
            .map_err(|e| format!("Failed to initialize WireGuard API: {e}"))?;

        info!("WGAPI ready");

        //let _ = api.remove_interface();
        api.create_interface()
            .map_err(|e| format!("Failed to create WireGuard interface: {e}"))?;

        info!("Interface created");

        info!("peer config = {config:?}");
        let peer = build_peer(&config)?;
        info!("peer = {peer:?}");
        let interface_config = build_interface_config(&config, &peer)?;

        info!("interface_config = {interface_config:?}");

        api.configure_interface(&interface_config)
            .map_err(|e| format!("Failed to configure WireGuard interface: {e}"))?;

        match api.read_interface_data() {
            Ok(host_before_peer) => {
                debug!(
                    "event=wireguard.interface_state.before_peer interface={} peer_count={}",
                    config.interface_name,
                    host_before_peer.peers.len()
                );
            }
            Err(err) => {
                debug!(
                    "event=wireguard.read_state_failed stage=before_peer interface={} err={}",
                    config.interface_name, err
                );
            }
        }

        api.configure_peer(&peer)
            .map_err(|e| format!("Failed to configure WireGuard peer: {e}"))?;

        match api.read_interface_data() {
            Ok(host_after_peer) => {
                debug!(
                    "event=wireguard.interface_state.after_peer interface={} peer_count={} listen_port={}",
                    config.interface_name,
                    host_after_peer.peers.len(),
                    host_after_peer.listen_port
                );
            }
            Err(err) => {
                warn!(
                    "event=wireguard.read_state_failed stage=after_peer interface={} err={}",
                    config.interface_name, err
                );
            }
        }

        api.configure_peer_routing(&[peer.clone()])
            .map_err(|e| format!("Failed to configure WireGuard routing: {e}"))?;

        Ok(WireguardConnection {
            interface_name: config.interface_name.clone(),
            peer_public_key: config.peer_public_key.clone(),
            server_name: config.server_name.clone(),
            server_id: config.server_id.clone(),
        })
    };

    tokio::task::spawn_blocking(connect_fn)
        .await
        .map_err(|e| format!("Failed to spawn wireguard task: {e}"))?
}

pub async fn disconnect(connection: WireguardConnection) -> Result<(), String> {
    let disconnect_fn = move || -> Result<(), String> {
        let api = WGApi::<Kernel>::new(connection.interface_name.clone())
            .map_err(|e| format!("Failed to initialize WireGuard API: {e}"))?;

        api.remove_peer(
            &Key::from_str(&connection.peer_public_key)
                .map_err(|e| format!("Failed to parse relay public key: {e}"))?,
        )
        .ok();

        api.remove_interface()
            .map_err(|e| format!("Failed to remove WireGuard interface: {e}"))?;
        Ok(())
    };

    tokio::task::spawn_blocking(disconnect_fn)
        .await
        .map_err(|e| format!("Failed to spawn wireguard task: {e}"))?
}
