use std::{
    collections::HashSet,
    fs,
    io::{BufRead, BufReader, ErrorKind, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::unix::net::UnixStream,
    process::Command,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use boringtun::device::{DeviceConfig, DeviceHandle, Error as DeviceError};
use hex::encode as hex_encode;
use log::{debug, warn};

use crate::service::{AllowedIp, ConnectParams, DeviceRuntime, PlatformError};
use crate::signals;

const UAPI_SOCKET_DIR: &str = "/var/run/wireguard";
const UAPI_WAIT_INTERVAL: Duration = Duration::from_millis(25);
const UAPI_READY_TIMEOUT: Duration = Duration::from_secs(5);
const UAPI_READ_TIMEOUT: Duration = Duration::from_millis(250);
const UAPI_RESPONSE_TIMEOUT: Duration = Duration::from_secs(1);

static CLEANUP_TRACKER: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();

pub struct PlatformBackend;

impl PlatformBackend {
    pub fn new() -> Result<Self, PlatformError> {
        Ok(Self)
    }

    pub fn start_session(&self, params: &ConnectParams) -> Result<DeviceRuntime, PlatformError> {
        debug!(
            "macos backend: start session interface={} server_id={} endpoint={} allowed_ips={}",
            params.interface_name,
            params.server_id,
            params.endpoint,
            params.allowed_ips.len()
        );
        wait_for_cleanup_gate(&params.interface_name);
        wait_for_interface_cleanup(&params.interface_name)?;
        wait_for_uapi_socket_cleanup()?;

        let handle =
            DeviceHandle::new(&params.interface_name, DeviceConfig::default()).map_err(|err| {
                PlatformError::DeviceStart(map_device_error(&params.interface_name, err))
            })?;

        signals::rearm().map_err(|err| {
            PlatformError::Io(format!("failed to configure signal handlers: {err}"))
        })?;
        debug!(
            "macos backend: boringtun device ready interface={}",
            params.interface_name
        );

        wait_for_uapi_socket(&params.interface_name)?;
        debug!(
            "macos backend: UAPI socket detected interface={} configuring",
            params.interface_name
        );

        configure_interface(params)?;
        configure_peer_routes(&params.interface_name, &params.allowed_ips, params.endpoint)?;

        debug!(
            "macos backend: session initialized interface={} server_id={}",
            params.interface_name, params.server_id
        );
        Ok(DeviceRuntime::Macos(handle))
    }

    pub fn stop_session(
        &self,
        interface_name: &str,
        peer_public_key: &str,
        runtime: Option<DeviceRuntime>,
        allowed_ips: &[AllowedIp],
        endpoint: SocketAddr,
    ) -> Result<(), PlatformError> {
        debug!(
            "macos backend: stop session interface={} peer={} runtime_present={}",
            interface_name,
            peer_public_key,
            runtime.is_some()
        );
        let interface = interface_name.to_string();
        let peer = peer_public_key.to_string();
        let allowed = allowed_ips.to_vec();
        let teardown_endpoint = endpoint;
        {
            let mut tracker = cleanup_tracker().lock().unwrap();
            tracker.insert(interface.clone());
        }
        tokio::task::spawn_blocking(move || {
            if let Err(err) =
                teardown_session(interface.clone(), peer, runtime, allowed, teardown_endpoint)
            {
                warn!(
                    "event=macos.disconnect.teardown_failed interface={} err={err}",
                    interface
                );
            } else {
                debug!(
                    "macos backend: disconnect teardown complete interface={}",
                    interface
                );
            }
            cleanup_tracker().lock().unwrap().remove(&interface);
        });

        Ok(())
    }
}

fn teardown_session(
    interface: String,
    peer_public_key: String,
    runtime: Option<DeviceRuntime>,
    allowed_ips: Vec<AllowedIp>,
    endpoint: SocketAddr,
) -> Result<(), PlatformError> {
    let mut result: Result<(), PlatformError> = Ok(());

    if let Err(err) = cleanup_peer_routes(&interface, &allowed_ips, endpoint) {
        warn!(
            "event=macos.route_cleanup.failed interface={} err={err}",
            interface
        );
        result = Err(err);
    } else {
        debug!(
            "macos backend: route cleanup finished interface={} entries={}",
            interface,
            allowed_ips.len()
        );
    }

    if let Err(err) = remove_peer(&interface, &peer_public_key) {
        warn!(
            "event=macos.peer_removal.failed interface={} err={err}",
            interface
        );
        result = Err(err);
    }

    if let Some(runtime) = runtime {
        runtime.shutdown();
        debug!(
            "macos backend: boringtun runtime shutdown interface={}",
            interface
        );
    }

    cleanup_uapi_socket(&interface);

    if let Err(err) = teardown_interface(&interface) {
        warn!(
            "event=macos.interface_teardown.failed interface={} err={err}",
            interface
        );
        result = Err(err);
    }

    // Remove the interface from the cleanup tracker to allow reconnection
    {
        let mut tracker = cleanup_tracker().lock().unwrap();
        tracker.remove(&interface);
        debug!(
            "macos backend: interface removed from cleanup tracker interface={}",
            interface
        );
    }

    result
}

fn cleanup_tracker() -> &'static Mutex<HashSet<String>> {
    CLEANUP_TRACKER.get_or_init(|| Mutex::new(HashSet::new()))
}

fn wait_for_cleanup_gate(interface: &str) {
    loop {
        let pending = {
            let tracker = cleanup_tracker().lock().unwrap();
            tracker.contains(interface)
        };
        if !pending {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn wait_for_interface_cleanup(interface: &str) -> Result<(), PlatformError> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match Command::new("ifconfig").arg(interface).status() {
            Ok(status) if status.success() => {
                if Instant::now() >= deadline {
                    return Err(PlatformError::Timeout(format!(
                        "Timed out waiting for interface {} to become available",
                        interface
                    )));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Ok(_) => return Ok(()),
            Err(err) => {
                return Err(PlatformError::Io(format!(
                    "failed to check interface {interface} state: {err}"
                )));
            }
        }
    }
}

fn teardown_interface(interface: &str) -> Result<(), PlatformError> {
    debug!("macos backend: teardown interface interface={}", interface);

    run_command_allow_absent("ifconfig", &[interface, "down"])?;
    run_command_allow_absent("ifconfig", &[interface, "destroy"])?;
    wait_for_interface_cleanup(interface)?;

    Ok(())
}

fn cleanup_uapi_socket(interface: &str) {
    let socket_path = format!("{UAPI_SOCKET_DIR}/{interface}.sock");
    match fs::remove_file(&socket_path) {
        Ok(()) => {
            debug!(
                "macos backend: removed UAPI socket path={} interface={}",
                socket_path, interface
            );
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => {
            warn!(
                "event=macos.uapi.cleanup_failed interface={} path={} err={err}",
                interface, socket_path
            );
        }
    }
}

fn run_command_allow_absent(cmd: &str, args: &[&str]) -> Result<(), PlatformError> {
    debug!("macos backend: exec `{cmd}` args={args:?}");
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|err| PlatformError::Io(format!("failed to execute {cmd}: {err}")))?;

    if output.status.success() {
        debug!(
            "macos backend: `{cmd}` completed status={:?}",
            output.status
        );
        return Ok(());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    let stdout_lower = stdout.to_ascii_lowercase();
    let stderr_lower = stderr.to_ascii_lowercase();

    if stdout.contains("does not exist")
        || stderr.contains("does not exist")
        || stdout_lower.contains("not found")
        || stderr_lower.contains("not found")
    {
        debug!(
            "macos backend: `{cmd}` reports missing target; treating as success stdout={:?} stderr={:?}",
            stdout.trim(),
            stderr.trim()
        );
        return Ok(());
    }

    Err(PlatformError::Api(format!(
        "Command `{cmd}` failed (status: {:?}): stdout: {} stderr: {}",
        output.status,
        stdout.trim(),
        stderr.trim()
    )))
}

fn configure_interface(params: &ConnectParams) -> Result<(), PlatformError> {
    debug!(
        "macos backend: configure interface={} device_ipv4={:?} device_ipv6={:?} mtu={:?}",
        params.interface_name, params.device_ipv4, params.device_ipv6, params.mtu
    );
    bring_interface_up(&params.interface_name)?;
    assign_addresses(
        &params.interface_name,
        params.device_ipv4,
        params.device_ipv6,
    )?;
    apply_wireguard_config(params)?;
    set_mtu(&params.interface_name, params.mtu)?;
    debug!(
        "macos backend: interface configuration complete interface={} allowed_ips={}",
        params.interface_name,
        params.allowed_ips.len()
    );
    Ok(())
}

fn bring_interface_up(interface: &str) -> Result<(), PlatformError> {
    run_command("ifconfig", &[interface, "up"], true)
}

fn assign_addresses(
    interface: &str,
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
) -> Result<(), PlatformError> {
    if let Some(addr) = ipv4 {
        let addr_str = addr.to_string();
        debug!("macos backend: assign IPv4 interface={interface} addr={addr_str}");
        run_command(
            "ifconfig",
            &[interface, "inet", &addr_str, &addr_str, "alias"],
            true,
        )?;
    }

    if let Some(addr) = ipv6 {
        let addr_str = addr.to_string();
        debug!("macos backend: assign IPv6 interface={interface} addr={addr_str}");
        run_command(
            "ifconfig",
            &[interface, "inet6", &addr_str, "prefixlen", "128", "alias"],
            true,
        )?;
    }

    Ok(())
}

fn set_mtu(interface: &str, mtu: Option<u32>) -> Result<(), PlatformError> {
    if let Some(mtu) = mtu {
        let mtu_str = mtu.to_string();
        debug!("macos backend: set MTU interface={interface} mtu={mtu}");
        run_command("ifconfig", &[interface, "mtu", &mtu_str], false)?;
    }
    Ok(())
}

fn configure_peer_routes(
    interface: &str,
    allowed_ips: &[AllowedIp],
    endpoint: SocketAddr,
) -> Result<(), PlatformError> {
    debug!(
        "macos backend: configure routing interface={} allowed_ips={} endpoint={}",
        interface,
        allowed_ips.len(),
        endpoint
    );
    let mut has_default_v4 = false;
    let mut has_default_v6 = false;

    for allowed in allowed_ips {
        if allowed.is_default_route() {
            if allowed.is_ipv4() {
                debug!("macos backend: enable IPv4 default route shim interface={interface}");
                add_default_routes_v4(interface)?;
                has_default_v4 = true;
            } else {
                debug!("macos backend: enable IPv6 default route shim interface={interface}");
                add_default_routes_v6(interface)?;
                has_default_v6 = true;
            }
        } else {
            debug!(
                "macos backend: add route interface={} cidr={}",
                interface, allowed
            );
            add_interface_route(interface, allowed)?;
        }
    }

    if has_default_v4 && endpoint.is_ipv4() {
        debug!(
            "macos backend: install endpoint IPv4 route interface={} endpoint={}",
            interface, endpoint
        );
        route_endpoint(interface, endpoint, IpFamily::V4)?;
    }

    if has_default_v6 && endpoint.is_ipv6() {
        debug!(
            "macos backend: install endpoint IPv6 route interface={} endpoint={}",
            interface, endpoint
        );
        route_endpoint(interface, endpoint, IpFamily::V6)?;
    }

    Ok(())
}

fn add_interface_route(interface: &str, allowed: &AllowedIp) -> Result<(), PlatformError> {
    debug!(
        "macos backend: run route add interface={} cidr={}",
        interface, allowed
    );
    let mut args = vec!["-q", "-n", "add"];
    let destination = allowed.to_string();
    if allowed.is_ipv4() {
        args.push("-inet");
    } else {
        args.push("-inet6");
    }
    args.push(destination.as_str());
    args.push("-interface");
    args.push(interface);
    run_command("route", &args, true)
}

fn cleanup_peer_routes(
    interface: &str,
    allowed_ips: &[AllowedIp],
    endpoint: SocketAddr,
) -> Result<(), PlatformError> {
    if allowed_ips.is_empty() {
        return Ok(());
    }

    debug!(
        "macos backend: cleanup routing interface={} allowed_ips={} endpoint={}",
        interface,
        allowed_ips.len(),
        endpoint
    );

    let mut removed_default_v4 = false;
    let mut removed_default_v6 = false;

    for allowed in allowed_ips {
        if allowed.is_default_route() {
            if allowed.is_ipv4() {
                remove_default_routes_v4(interface)?;
                removed_default_v4 = true;
            } else {
                remove_default_routes_v6(interface)?;
                removed_default_v6 = true;
            }
        } else {
            remove_interface_route(interface, allowed)?;
        }
    }

    if removed_default_v4 && endpoint.is_ipv4() {
        remove_endpoint_route(endpoint, IpFamily::V4)?;
    }

    if removed_default_v6 && endpoint.is_ipv6() {
        remove_endpoint_route(endpoint, IpFamily::V6)?;
    }

    Ok(())
}

fn add_default_routes_v4(interface: &str) -> Result<(), PlatformError> {
    debug!("macos backend: install IPv4 default shim routes interface={interface}");
    let defaults = [
        AllowedIp {
            addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            cidr: 1,
        },
        AllowedIp {
            addr: IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)),
            cidr: 1,
        },
    ];

    for allowed in &defaults {
        add_interface_route(interface, allowed)?;
    }

    Ok(())
}

fn add_default_routes_v6(interface: &str) -> Result<(), PlatformError> {
    debug!("macos backend: install IPv6 default shim routes interface={interface}");
    let defaults = [
        AllowedIp {
            addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            cidr: 1,
        },
        AllowedIp {
            addr: IpAddr::V6(Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0)),
            cidr: 1,
        },
    ];

    for allowed in &defaults {
        add_interface_route(interface, allowed)?;
    }

    Ok(())
}

fn remove_interface_route(interface: &str, allowed: &AllowedIp) -> Result<(), PlatformError> {
    debug!(
        "macos backend: run route delete interface={} cidr={}",
        interface, allowed
    );
    let mut args = vec!["-q", "-n", "delete"];
    let destination = allowed.to_string();
    if allowed.is_ipv4() {
        args.push("-inet");
    } else {
        args.push("-inet6");
    }
    args.push(destination.as_str());
    args.push("-interface");
    args.push(interface);
    run_command("route", &args, true)
}

fn remove_default_routes_v4(interface: &str) -> Result<(), PlatformError> {
    debug!("macos backend: remove IPv4 default shim routes interface={interface}");
    let defaults = [
        AllowedIp {
            addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            cidr: 1,
        },
        AllowedIp {
            addr: IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)),
            cidr: 1,
        },
    ];

    for allowed in &defaults {
        let _ = remove_interface_route(interface, allowed);
    }

    Ok(())
}

fn remove_default_routes_v6(interface: &str) -> Result<(), PlatformError> {
    debug!("macos backend: remove IPv6 default shim routes interface={interface}");
    let defaults = [
        AllowedIp {
            addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            cidr: 1,
        },
        AllowedIp {
            addr: IpAddr::V6(Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0)),
            cidr: 1,
        },
    ];

    for allowed in &defaults {
        let _ = remove_interface_route(interface, allowed);
    }

    Ok(())
}

fn apply_wireguard_config(params: &ConnectParams) -> Result<(), PlatformError> {
    debug!(
        "macos backend: apply WireGuard config interface={} allowed_ips={} keepalive={:?}",
        params.interface_name,
        params.allowed_ips.len(),
        params.keepalive_seconds
    );
    let mut socket = open_uapi_socket(&params.interface_name)?;
    let configuration = build_host_configuration(params)?;

    socket
        .write_all(b"set=1\n")
        .map_err(|err| PlatformError::Api(format!("failed to write WireGuard command: {err}")))?;
    socket.write_all(configuration.as_bytes()).map_err(|err| {
        PlatformError::Api(format!("failed to write WireGuard configuration: {err}"))
    })?;
    socket.write_all(b"\n").map_err(|err| {
        PlatformError::Api(format!("failed to finalize WireGuard configuration: {err}"))
    })?;

    match read_errno(socket, false)? {
        0 => Ok(()),
        errno => Err(PlatformError::Api(format!(
            "WireGuard userspace API returned errno={errno}"
        ))),
    }
}

fn build_host_configuration(params: &ConnectParams) -> Result<String, PlatformError> {
    let private_key = encode_key_for_uapi(&params.private_key)?;
    let peer_public_key = encode_key_for_uapi(&params.peer_public_key)?;

    let mut config = String::new();
    config.push_str("listen_port=0\n");
    config.push_str("private_key=");
    config.push_str(&private_key);
    config.push('\n');
    config.push_str("replace_peers=true\n");

    config.push_str("public_key=");
    config.push_str(&peer_public_key);
    config.push('\n');
    config.push_str("replace_allowed_ips=true\n");
    config.push_str("endpoint=");
    config.push_str(&params.endpoint.to_string());
    config.push('\n');
    if let Some(keepalive) = params.keepalive_seconds {
        config.push_str("persistent_keepalive_interval=");
        config.push_str(&keepalive.to_string());
        config.push('\n');
    }
    for allowed in &params.allowed_ips {
        config.push_str("allowed_ip=");
        config.push_str(&allowed.to_string());
        config.push('\n');
    }

    Ok(config)
}

fn open_uapi_socket(interface: &str) -> Result<UnixStream, PlatformError> {
    let path = format!("{UAPI_SOCKET_DIR}/{interface}.sock");
    let socket = UnixStream::connect(&path)
        .map_err(|err| PlatformError::Api(format!("failed to open UAPI socket {path}: {err}")))?;
    socket
        .set_read_timeout(Some(UAPI_READ_TIMEOUT))
        .map_err(|err| {
            PlatformError::Api(format!("failed to set timeout on UAPI socket: {err}"))
        })?;
    debug!("macos backend: opened UAPI socket interface={interface}");
    Ok(socket)
}

fn read_errno(stream: UnixStream, assume_success_on_timeout: bool) -> Result<i32, PlatformError> {
    let mut reader = BufReader::new(stream);
    let deadline = Instant::now() + UAPI_RESPONSE_TIMEOUT;
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => {
                debug!("macos backend: UAPI response missing errno, assuming success");
                return Ok(0);
            }
            Ok(_) => {
                if let Some(value) = line.strip_prefix("errno=") {
                    if let Ok(errno) = value.trim().parse::<i32>() {
                        debug!("macos backend: UAPI errno={errno}");
                        return Ok(errno);
                    }
                }
            }
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err)
                if err.kind() == ErrorKind::WouldBlock || err.kind() == ErrorKind::TimedOut =>
            {
                if Instant::now() >= deadline {
                    if assume_success_on_timeout {
                        debug!(
                            "macos backend: UAPI response still pending after {:?}, assuming success",
                            UAPI_RESPONSE_TIMEOUT
                        );
                        return Ok(0);
                    }
                    return Err(PlatformError::Timeout(
                        "Timed out waiting for response from WireGuard API".to_string(),
                    ));
                }
                std::thread::sleep(UAPI_WAIT_INTERVAL);
            }
            Err(err) => {
                return Err(PlatformError::Api(format!(
                    "failed to read response from WireGuard API: {err}"
                )));
            }
        }
    }
}

fn remove_peer(interface: &str, peer_public_key: &str) -> Result<(), PlatformError> {
    let encoded_peer_key = encode_key_for_uapi(peer_public_key)?;
    let path = format!("{UAPI_SOCKET_DIR}/{interface}.sock");
    let mut socket = match UnixStream::connect(&path) {
        Ok(socket) => socket,
        Err(err) => {
            if err.kind() == std::io::ErrorKind::NotFound {
                debug!(
                    "macos backend: remove_peer skipped interface={} reason=socket_missing",
                    interface
                );
                return Ok(());
            }
            return Err(PlatformError::Api(format!(
                "failed to open UAPI socket {path}: {err}"
            )));
        }
    };
    socket
        .set_read_timeout(Some(UAPI_READ_TIMEOUT))
        .map_err(|err| {
            PlatformError::Api(format!("failed to set timeout on UAPI socket: {err}"))
        })?;
    debug!(
        "macos backend: initiating peer removal interface={} peer={}",
        interface, peer_public_key
    );

    socket
        .write_all(b"set=1\n")
        .map_err(|err| PlatformError::Api(format!("failed to write WireGuard command: {err}")))?;
    socket
        .write_all(format!("public_key={}\nremove=true\n", encoded_peer_key).as_bytes())
        .map_err(|err| PlatformError::Api(format!("failed to write peer removal: {err}")))?;
    socket
        .write_all(b"\n")
        .map_err(|err| PlatformError::Api(format!("failed to finalize peer removal: {err}")))?;

    match read_errno(socket, true)? {
        0 => {
            debug!(
                "macos backend: peer removal succeeded interface={} peer={}",
                interface, peer_public_key
            );
            Ok(())
        }
        errno => Err(PlatformError::Api(format!(
            "WireGuard userspace API returned errno={errno} during peer removal"
        ))),
    }
}

fn encode_key_for_uapi(raw: &str) -> Result<String, PlatformError> {
    let trimmed = raw.trim();
    if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(trimmed.to_lowercase());
    }

    let decoded = STANDARD.decode(trimmed).map_err(|err| {
        PlatformError::InvalidConfig(format!("invalid WireGuard key encoding: {err}"))
    })?;

    if decoded.len() != 32 {
        return Err(PlatformError::InvalidConfig(
            "invalid WireGuard key length after decoding".to_string(),
        ));
    }

    Ok(hex_encode(decoded))
}

fn wait_for_uapi_socket(interface_name: &str) -> Result<(), PlatformError> {
    let socket_path = format!("{UAPI_SOCKET_DIR}/{interface_name}.sock");
    let start = Instant::now();
    loop {
        match fs::metadata(&socket_path) {
            Ok(_) => return Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                if start.elapsed() >= UAPI_READY_TIMEOUT {
                    return Err(PlatformError::Timeout(format!(
                        "Timed out waiting for WireGuard userspace socket at {socket_path}"
                    )));
                }
                debug!(
                    "macos backend: waiting for UAPI socket interface={} elapsed_ms={}",
                    interface_name,
                    start.elapsed().as_millis()
                );
                std::thread::sleep(UAPI_WAIT_INTERVAL);
            }
            Err(err) => {
                return Err(PlatformError::Io(format!(
                    "Failed to check userspace socket {socket_path}: {err}"
                )));
            }
        }
    }
}

fn wait_for_uapi_socket_cleanup() -> Result<(), PlatformError> {
    if let Ok(entries) = fs::read_dir(UAPI_SOCKET_DIR) {
        for entry in entries.flatten() {
            if entry
                .path()
                .extension()
                .map(|ext| ext == "sock")
                .unwrap_or(false)
            {
                debug!(
                    "macos backend: removing stale socket path={}",
                    entry.path().display()
                );
                let _ = fs::remove_file(entry.path());
            }
        }
    }
    Ok(())
}

fn map_device_error(interface: &str, err: DeviceError) -> String {
    match err {
        DeviceError::Connect(msg) if msg.contains("Operation not permitted") => format!(
            "macOS denied permission to create WireGuard interface {interface}. Run the daemon with elevated privileges. Original error: {msg}"
        ),
        DeviceError::Connect(msg) => format!("Failed to start WireGuard interface {interface}: {msg}"),
        DeviceError::InvalidTunnelName => format!(
            "Failed to start WireGuard interface {interface}: invalid tunnel name"
        ),
        DeviceError::Socket(msg)
        | DeviceError::Bind(msg)
        | DeviceError::FCntl(msg)
        | DeviceError::EventQueue(msg)
        | DeviceError::IOCtl(msg)
        | DeviceError::SetSockOpt(msg)
        | DeviceError::GetSockOpt(msg)
        | DeviceError::GetSockName(msg) => format!(
            "Failed to start WireGuard interface {interface}: {msg}"
        ),
        other => format!(
            "Failed to start BoringTun device for {interface}: {other:?}"
        ),
    }
}

#[derive(Copy, Clone, Debug)]
enum IpFamily {
    V4,
    V6,
}

fn route_endpoint(
    _interface: &str,
    endpoint: SocketAddr,
    family: IpFamily,
) -> Result<(), PlatformError> {
    let endpoint_ip = endpoint.ip().to_string();
    debug!(
        "macos backend: ensure endpoint route endpoint={} family={:?}",
        endpoint_ip, family
    );
    let mut delete_args = vec!["-q", "-n", "delete"];
    match family {
        IpFamily::V4 => delete_args.push("-inet"),
        IpFamily::V6 => delete_args.push("-inet6"),
    }
    delete_args.push(endpoint_ip.as_str());
    let _ = run_command("route", &delete_args, true);

    if let Some(gateway) = default_gateway(family)? {
        let mut add_args = vec!["-q", "-n", "add"];
        match (family, gateway) {
            (IpFamily::V4, IpAddr::V4(addr)) => {
                add_args.push("-inet");
                add_args.push(endpoint_ip.as_str());
                let gateway_str = addr.to_string();
                add_args.push(gateway_str.as_str());
                debug!(
                    "macos backend: add endpoint route endpoint={} gateway={gateway_str}",
                    endpoint_ip
                );
                run_command("route", &add_args, true)?;
            }
            (IpFamily::V6, IpAddr::V6(addr)) => {
                add_args.push("-inet6");
                add_args.push(endpoint_ip.as_str());
                let gateway_str = addr.to_string();
                add_args.push(gateway_str.as_str());
                debug!(
                    "macos backend: add endpoint route endpoint={} gateway={gateway_str}",
                    endpoint_ip
                );
                run_command("route", &add_args, true)?;
            }
            _ => {}
        }
    }

    Ok(())
}

fn remove_endpoint_route(endpoint: SocketAddr, family: IpFamily) -> Result<(), PlatformError> {
    let endpoint_ip = endpoint.ip().to_string();
    debug!(
        "macos backend: remove endpoint route endpoint={} family={:?}",
        endpoint_ip, family
    );
    let mut delete_args = vec!["-q", "-n", "delete"];
    match family {
        IpFamily::V4 => delete_args.push("-inet"),
        IpFamily::V6 => delete_args.push("-inet6"),
    }
    delete_args.push(endpoint_ip.as_str());
    let _ = run_command("route", &delete_args, true);
    Ok(())
}

fn default_gateway(family: IpFamily) -> Result<Option<IpAddr>, PlatformError> {
    let args = match family {
        IpFamily::V4 => vec!["-n", "get", "default"],
        IpFamily::V6 => vec!["-n", "get", "-inet6", "default"],
    };

    let output = Command::new("route")
        .args(&args)
        .output()
        .map_err(|err| PlatformError::Io(format!("failed to execute route command: {err}")))?;

    if !output.status.success() {
        debug!(
            "macos backend: default gateway lookup failed family={:?} status={:?}",
            family, output.status
        );
        return Ok(None);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if let Some(rest) = line.trim().strip_prefix("gateway:") {
            let raw = rest.trim();
            let address = raw.split('%').next().unwrap_or("");
            if address.is_empty() {
                continue;
            }
            if let Ok(parsed) = address.parse::<IpAddr>() {
                debug!(
                    "macos backend: default gateway detected family={:?} gateway={}",
                    family, parsed
                );
                return Ok(Some(parsed));
            }
        }
    }

    debug!(
        "macos backend: default gateway not found family={:?} output={:?}",
        family,
        stdout.trim()
    );

    Ok(None)
}

fn run_command(cmd: &str, args: &[&str], ignore_exists: bool) -> Result<(), PlatformError> {
    debug!("macos backend: exec `{cmd}` args={args:?}");
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|err| PlatformError::Io(format!("failed to execute {cmd}: {err}")))?;

    if output.status.success() {
        debug!(
            "macos backend: `{cmd}` completed status={:?}",
            output.status
        );
        return Ok(());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if ignore_exists
        && (stdout.contains("File exists")
            || stderr.contains("File exists")
            || stderr.contains("EEXIST")
            || stdout.contains("not in table")
            || stderr.contains("not in table")
            || stdout.contains("No such process")
            || stderr.contains("No such process"))
    {
        debug!(
            "macos backend: `{cmd}` reported existing entry; treating as success stdout={:?} stderr={:?}",
            stdout.trim(),
            stderr.trim()
        );
        return Ok(());
    }

    Err(PlatformError::Api(format!(
        "Command `{cmd}` failed (status: {:?}): stdout: {} stderr: {}",
        output.status,
        stdout.trim(),
        stderr.trim()
    )))
}
