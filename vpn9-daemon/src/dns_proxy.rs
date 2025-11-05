#![allow(dead_code)]

#[cfg(target_os = "macos")]
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    process::Command,
    sync::Arc,
    time::Duration,
};

#[cfg(target_os = "macos")]
use log::{debug, warn};

#[cfg(target_os = "macos")]
use rand::{seq::SliceRandom, Rng};

#[cfg(target_os = "macos")]
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::watch,
    time::timeout,
};

#[cfg(target_os = "macos")]
use crate::service::PlatformError;

#[cfg(target_os = "macos")]
const DNS_PORT: u16 = 53;

#[cfg(target_os = "macos")]
const UDP_BUFFER_SIZE: usize = 512;

#[cfg(target_os = "macos")]
const LOOPBACK_NETMASK: &str = "255.0.0.0";

#[cfg(target_os = "macos")]
const MAX_ALIAS_ATTEMPTS: usize = 32;

#[cfg(target_os = "macos")]
pub struct DnsProxy {
    listen_addr: SocketAddr,
    shutdown_tx: Option<watch::Sender<bool>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

#[cfg(target_os = "macos")]
impl DnsProxy {
    pub async fn start(upstreams: Vec<SocketAddr>) -> Result<Self, PlatformError> {
        if upstreams.is_empty() {
            return Err(PlatformError::InvalidConfig(
                "DNS proxy requires at least one upstream server".to_string(),
            ));
        }

        let proxy_ip = assign_loopback_alias()?;
        let listen_addr = SocketAddr::new(IpAddr::V4(proxy_ip), DNS_PORT);

        let udp_socket = match UdpSocket::bind(listen_addr).await {
            Ok(socket) => socket,
            Err(err) => {
                remove_loopback_alias(proxy_ip);
                return Err(PlatformError::Io(format!(
                    "failed to bind UDP DNS socket on {listen_addr}: {err}"
                )));
            }
        };

        let tcp_listener = match TcpListener::bind(listen_addr).await {
            Ok(listener) => listener,
            Err(err) => {
                remove_loopback_alias(proxy_ip);
                drop(udp_socket);
                return Err(PlatformError::Io(format!(
                    "failed to bind TCP DNS listener on {listen_addr}: {err}"
                )));
            }
        };

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let shared_shutdown = shutdown_rx.clone();
        let upstreams_arc = Arc::new(upstreams);

        let udp_task = tokio::spawn(run_udp_proxy(
            udp_socket,
            upstreams_arc.clone(),
            shutdown_rx,
        ));
        let tcp_task = tokio::spawn(run_tcp_proxy(tcp_listener, upstreams_arc, shared_shutdown));

        debug!(
            "dns_proxy: started listener address={} tasks=2",
            listen_addr
        );

        Ok(Self {
            listen_addr,
            shutdown_tx: Some(shutdown_tx),
            tasks: vec![udp_task, tcp_task],
        })
    }

    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }
}

#[cfg(target_os = "macos")]
impl Drop for DnsProxy {
    fn drop(&mut self) {
        let IpAddr::V4(addr) = self.listen_addr.ip() else {
            return;
        };

        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(true);
        }

        for task in &self.tasks {
            task.abort();
        }

        remove_loopback_alias(addr);
        debug!("dns_proxy: stopped listener address={}", self.listen_addr);
    }
}

#[cfg(target_os = "macos")]
fn assign_loopback_alias() -> Result<Ipv4Addr, PlatformError> {
    let mut rng = rand::thread_rng();
    for _ in 0..MAX_ALIAS_ATTEMPTS {
        let candidate = Ipv4Addr::new(
            127,
            rng.gen_range(2..=253),
            rng.gen_range(0..=255),
            rng.gen_range(2..=253),
        );

        match add_loopback_alias(candidate) {
            Ok(()) => return Ok(candidate),
            Err(PlatformError::Io(err)) if err.contains("File exists") => continue,
            Err(PlatformError::Io(err)) if err.contains("address already exists") => continue,
            Err(other) => return Err(other),
        }
    }

    Err(PlatformError::Io(
        "failed to allocate loopback alias after multiple attempts".to_string(),
    ))
}

#[cfg(target_os = "macos")]
fn add_loopback_alias(addr: Ipv4Addr) -> Result<(), PlatformError> {
    let output = Command::new("ifconfig")
        .args([
            "lo0",
            "alias",
            &addr.to_string(),
            "netmask",
            LOOPBACK_NETMASK,
        ])
        .output()
        .map_err(|err| PlatformError::Io(format!("failed to execute ifconfig: {err}")))?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(PlatformError::Io(format!(
            "ifconfig alias failed for {}: {}",
            addr,
            stderr.trim()
        )))
    }
}

#[cfg(target_os = "macos")]
fn remove_loopback_alias(addr: Ipv4Addr) {
    match Command::new("ifconfig")
        .args(["lo0", "-alias", &addr.to_string()])
        .output()
    {
        Ok(output) if output.status.success() => {}
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!(
                "dns_proxy: failed to remove loopback alias {}: {}",
                addr,
                stderr.trim()
            );
        }
        Err(err) => {
            warn!(
                "dns_proxy: failed to execute ifconfig -alias {} err={}",
                addr, err
            );
        }
    }
}

#[cfg(target_os = "macos")]
async fn run_udp_proxy(
    socket: UdpSocket,
    upstreams: Arc<Vec<SocketAddr>>,
    mut shutdown: watch::Receiver<bool>,
) {
    let socket = Arc::new(socket);
    loop {
        let mut buffer = [0u8; UDP_BUFFER_SIZE];
        let recv = tokio::select! {
            result = socket.recv_from(&mut buffer) => result,
            _ = shutdown.changed() => break,
        };

        let (len, peer) = match recv {
            Ok(value) => value,
            Err(err) => {
                warn!("dns_proxy: UDP recv error err={}", err);
                continue;
            }
        };

        let payload = buffer[..len].to_vec();
        let socket_clone = socket.clone();
        let upstreams_clone = upstreams.clone();

        tokio::spawn(async move {
            if let Err(err) = handle_udp_query(socket_clone, upstreams_clone, peer, payload).await {
                warn!("dns_proxy: UDP forward failed peer={} err={}", peer, err);
            }
        });
    }
}

#[cfg(target_os = "macos")]
async fn handle_udp_query(
    socket: Arc<UdpSocket>,
    upstreams: Arc<Vec<SocketAddr>>,
    peer: SocketAddr,
    payload: Vec<u8>,
) -> Result<(), String> {
    let upstream =
        select_upstream(upstreams.as_slice()).ok_or_else(|| "no upstream".to_string())?;

    let upstream_socket = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0)))
        .await
        .map_err(|err| format!("failed to bind ephemeral UDP socket: {err}"))?;
    upstream_socket
        .connect(upstream)
        .await
        .map_err(|err| format!("failed to connect to upstream {}: {err}", upstream))?;

    upstream_socket
        .send(&payload)
        .await
        .map_err(|err| format!("failed to send query to upstream: {err}"))?;

    let mut response = [0u8; UDP_BUFFER_SIZE];
    let response_len = timeout(Duration::from_secs(5), upstream_socket.recv(&mut response))
        .await
        .map_err(|_| "upstream UDP timeout".to_string())
        .and_then(|result| {
            result.map_err(|err| format!("failed to receive upstream response: {err}"))
        })?;

    socket
        .send_to(&response[..response_len], peer)
        .await
        .map_err(|err| format!("failed to send UDP response to client {}: {err}", peer))?;

    Ok(())
}

#[cfg(target_os = "macos")]
async fn run_tcp_proxy(
    listener: TcpListener,
    upstreams: Arc<Vec<SocketAddr>>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        let accept = tokio::select! {
            result = listener.accept() => result,
            _ = shutdown.changed() => break,
        };

        let (stream, peer_addr) = match accept {
            Ok(value) => value,
            Err(err) => {
                warn!("dns_proxy: TCP accept error err={}", err);
                continue;
            }
        };

        let upstreams_clone = upstreams.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_tcp_query(stream, upstreams_clone).await {
                warn!(
                    "dns_proxy: TCP forward failed peer={} err={}",
                    peer_addr, err
                );
            }
        });
    }
}

#[cfg(target_os = "macos")]
async fn handle_tcp_query(
    mut client_stream: TcpStream,
    upstreams: Arc<Vec<SocketAddr>>,
) -> Result<(), String> {
    let upstream =
        select_upstream(upstreams.as_slice()).ok_or_else(|| "no upstream".to_string())?;

    let mut upstream_stream = TcpStream::connect(upstream)
        .await
        .map_err(|err| format!("failed to connect to upstream {}: {err}", upstream))?;

    let mut length_bytes = [0u8; 2];
    timeout(
        Duration::from_secs(5),
        client_stream.read_exact(&mut length_bytes),
    )
    .await
    .map_err(|_| "client TCP read timeout".to_string())
    .and_then(|result| result.map_err(|err| format!("failed to read TCP length: {err}")))?;

    let query_length = u16::from_be_bytes(length_bytes) as usize;
    let mut query = vec![0u8; query_length];
    timeout(Duration::from_secs(5), client_stream.read_exact(&mut query))
        .await
        .map_err(|_| "client TCP query timeout".to_string())
        .and_then(|result| result.map_err(|err| format!("failed to read TCP query: {err}")))?;

    timeout(
        Duration::from_secs(5),
        upstream_stream.write_all(&length_bytes),
    )
    .await
    .map_err(|_| "upstream TCP write timeout".to_string())
    .and_then(|result| {
        result.map_err(|err| format!("failed to write length to upstream: {err}"))
    })?;
    timeout(Duration::from_secs(5), upstream_stream.write_all(&query))
        .await
        .map_err(|_| "upstream TCP write timeout".to_string())
        .and_then(|result| {
            result.map_err(|err| format!("failed to write query to upstream: {err}"))
        })?;

    timeout(
        Duration::from_secs(5),
        upstream_stream.read_exact(&mut length_bytes),
    )
    .await
    .map_err(|_| "upstream TCP read timeout".to_string())
    .and_then(|result| {
        result.map_err(|err| format!("failed to read upstream response length: {err}"))
    })?;

    let response_length = u16::from_be_bytes(length_bytes) as usize;
    let mut response = vec![0u8; response_length];
    timeout(
        Duration::from_secs(5),
        upstream_stream.read_exact(&mut response),
    )
    .await
    .map_err(|_| "upstream TCP response timeout".to_string())
    .and_then(|result| result.map_err(|err| format!("failed to read upstream response: {err}")))?;

    timeout(
        Duration::from_secs(5),
        client_stream.write_all(&length_bytes),
    )
    .await
    .map_err(|_| "client TCP write timeout".to_string())
    .and_then(|result| {
        result.map_err(|err| format!("failed to write response length to client: {err}"))
    })?;
    timeout(Duration::from_secs(5), client_stream.write_all(&response))
        .await
        .map_err(|_| "client TCP write timeout".to_string())
        .and_then(|result| {
            result.map_err(|err| format!("failed to write response to client: {err}"))
        })?;

    Ok(())
}

#[cfg(target_os = "macos")]
fn select_upstream(upstreams: &[SocketAddr]) -> Option<SocketAddr> {
    let mut rng = rand::thread_rng();
    upstreams.choose(&mut rng).copied()
}
