use std::{
    collections::HashSet,
    fs,
    io::{BufRead, BufReader, ErrorKind, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::unix::net::UnixStream,
    panic::AssertUnwindSafe,
    process::Command,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

use core_foundation::{
    array::CFArray,
    base::{CFType, TCFType, ToVoid},
    dictionary::{CFDictionary, CFMutableDictionary},
    number::CFNumber,
    propertylist::{CFPropertyList, CFPropertyListSubClass},
    string::CFString,
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use boringtun::device::{DeviceConfig, DeviceHandle, Error as DeviceError};
use hex::encode as hex_encode;
use log::{debug, warn};
use system_configuration::{
    dynamic_store::{SCDynamicStore, SCDynamicStoreBuilder},
    sys::schema_definitions::{
        kSCPropNetDNSSearchDomains, kSCPropNetDNSServerAddresses, kSCPropNetDNSServerPort,
        kSCPropNetDNSSupplementalMatchDomains, kSCPropNetDNSSupplementalMatchOrders,
        kSCPropNetInterfaceDeviceName,
    },
};

use crate::dns_proxy::DnsProxy;
use crate::service::{
    AllowedIp, ConnectParams, DeviceRuntime, DnsServiceSnapshot, DnsSettings, DnsSnapshot,
    MacosRuntime, PlatformError,
};
use crate::signals;

const UAPI_SOCKET_DIR: &str = "/var/run/wireguard";
const UAPI_WAIT_INTERVAL: Duration = Duration::from_millis(25);
const UAPI_READY_TIMEOUT: Duration = Duration::from_secs(5);
const UAPI_READ_TIMEOUT: Duration = Duration::from_millis(250);
const UAPI_RESPONSE_TIMEOUT: Duration = Duration::from_secs(1);

const CLOUDFLARE_DNS_SERVERS: &[&str] = &[
    "1.1.1.1",
    "1.0.0.1",
    "2606:4700:4700::1111",
    "2606:4700:4700::1001",
];

fn cloudflare_upstream_socket_addrs() -> Result<Vec<SocketAddr>, PlatformError> {
    let mut addrs = Vec::with_capacity(CLOUDFLARE_DNS_SERVERS.len());
    for entry in CLOUDFLARE_DNS_SERVERS {
        let ip = entry.parse::<IpAddr>().map_err(|err| {
            PlatformError::InvalidConfig(format!(
                "invalid Cloudflare DNS address {}: {}",
                entry, err
            ))
        })?;
        addrs.push(SocketAddr::new(ip, 53));
    }
    Ok(addrs)
}

static CLEANUP_TRACKER: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();

pub struct PlatformBackend {
    dns_proxy: Arc<DnsProxy>,
}

impl PlatformBackend {
    pub async fn new() -> Result<Self, PlatformError> {
        let upstreams = cloudflare_upstream_socket_addrs()?;
        let proxy = DnsProxy::start(upstreams).await?;
        Ok(Self {
            dns_proxy: Arc::new(proxy),
        })
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

        let mut dns_snapshot = match capture_dns_state(&params.interface_name) {
            Ok(snapshot) => {
                debug!(
                    "macos backend: DNS state captured interface={} entries={}",
                    params.interface_name,
                    snapshot.entries.len()
                );
                snapshot
            }
            Err(err) => {
                warn!(
                    "event=macos.dns.capture_failed interface={} err={} fallback=default_snapshot",
                    params.interface_name, err
                );
                // Use default snapshot as fallback - DNS override may still work
                DnsSnapshot::default()
            }
        };

        // Always attempt DNS override, even with default snapshot
        let dns_servers = vec![self.dns_proxy.listen_addr().ip().to_string()];

        match apply_dns_override(&params.interface_name, &mut dns_snapshot, &dns_servers) {
            Ok(()) => {
                if dns_snapshot.applied_override {
                    debug!(
                        "macos backend: DNS override applied successfully interface={}",
                        params.interface_name
                    );
                } else {
                    debug!(
                        "macos backend: DNS override skipped interface={} reason=no_applicable_entries",
                        params.interface_name
                    );
                }
            }
            Err(err) => {
                warn!(
                    "event=macos.dns.apply_failed interface={} err={} impact=dns_may_not_work",
                    params.interface_name, err
                );
                // Don't fail the entire connection for DNS issues
                // The VPN tunnel should still work, just DNS might not be overridden
            }
        }

        debug!(
            "macos backend: session initialized interface={} server_id={}",
            params.interface_name, params.server_id
        );
        Ok(DeviceRuntime::Macos(MacosRuntime::new(
            handle,
            dns_snapshot,
        )))
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
            let teardown_result = std::panic::catch_unwind(AssertUnwindSafe(|| {
                teardown_session(interface.clone(), peer, runtime, allowed, teardown_endpoint)
            }));

            match teardown_result {
                Ok(Ok(())) => {
                    debug!(
                        "macos backend: disconnect teardown complete interface={}",
                        interface
                    );
                }
                Ok(Err(err)) => {
                    warn!(
                        "event=macos.disconnect.teardown_failed interface={} err={err}",
                        interface
                    );
                }
                Err(panic_payload) => {
                    warn!(
                        "event=macos.disconnect.teardown_panicked interface={} payload={:?}",
                        interface, panic_payload
                    );
                }
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

    let mut macos_runtime = runtime.map(|runtime| match runtime {
        DeviceRuntime::Macos(rt) => rt,
    });

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

    let mut maybe_handle = None;

    if let Some(runtime) = macos_runtime.take() {
        let MacosRuntime {
            handle,
            dns_snapshot,
        } = runtime;
        if let Err(err) = restore_dns(&interface, &dns_snapshot) {
            if result.is_ok() {
                result = Err(err);
            }
        }
        maybe_handle = Some(handle);
    }

    if let Err(err) = teardown_interface(&interface) {
        warn!(
            "event=macos.interface_teardown.failed interface={} err={err}",
            interface
        );
        result = Err(err);
    }

    cleanup_uapi_socket(&interface);

    if let Some(mut handle) = maybe_handle {
        debug!(
            "macos backend: waiting for boringtun worker threads interface={}",
            interface
        );
        handle.wait();
        debug!(
            "macos backend: boringtun runtime shutdown interface={}",
            interface
        );
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

fn dns_store() -> SCDynamicStore {
    SCDynamicStoreBuilder::new("vpn9-daemon-dns").build()
}

fn validate_dns_server(addr_str: &str) -> Result<String, PlatformError> {
    let addr = addr_str.parse::<IpAddr>().map_err(|err| {
        PlatformError::InvalidConfig(format!(
            "Invalid DNS server address '{}': {}",
            addr_str, err
        ))
    })?;

    // Additional validation rules
    match addr {
        IpAddr::V4(ipv4) => {
            if ipv4.is_unspecified() {
                return Err(PlatformError::InvalidConfig(
                    "DNS server cannot be 0.0.0.0".to_string(),
                ));
            }
            if ipv4.is_broadcast() {
                return Err(PlatformError::InvalidConfig(
                    "DNS server cannot be broadcast address".to_string(),
                ));
            }
            if ipv4.is_multicast() {
                return Err(PlatformError::InvalidConfig(
                    "DNS server cannot be multicast address".to_string(),
                ));
            }
        }
        IpAddr::V6(ipv6) => {
            if ipv6.is_unspecified() {
                return Err(PlatformError::InvalidConfig(
                    "DNS server cannot be ::".to_string(),
                ));
            }
            if ipv6.is_multicast() {
                return Err(PlatformError::InvalidConfig(
                    "DNS server cannot be multicast address".to_string(),
                ));
            }
        }
    }

    debug!("macos backend: validated DNS server addr={}", addr);
    Ok(addr.to_string())
}

fn capture_dns_state(interface: &str) -> Result<DnsSnapshot, PlatformError> {
    let store = dns_store();
    let mut snapshot = DnsSnapshot::default();
    let mut entries = Vec::new();
    let mut seen = HashSet::new();
    let mut capture_errors = Vec::new();

    debug!("macos backend: capturing DNS state interface={}", interface);

    // Try to find services for the specific interface
    match find_services_for_interface(&store, interface) {
        Ok(service_paths) if !service_paths.is_empty() => {
            debug!(
                "macos backend: found {} interface-specific services interface={}",
                service_paths.len(),
                interface
            );
            for (state_path, setup_path) in service_paths {
                push_dns_snapshot(
                    &store,
                    &mut entries,
                    &mut seen,
                    state_path,
                    Some(setup_path),
                );
            }
        }
        Ok(_) => {
            debug!(
                "macos backend: no interface-specific services found interface={}",
                interface
            );
        }
        Err(err) => {
            let error_msg = format!("Service lookup failed for interface {}: {}", interface, err);
            capture_errors.push(error_msg.clone());
            warn!(
                "event=macos.dns.service_lookup_failed interface={} err={}",
                interface, err
            );
        }
    }

    // Always capture interface-specific DNS path
    let interface_state_path = format!("State:/Network/Interface/{interface}/DNS");
    push_dns_snapshot(&store, &mut entries, &mut seen, interface_state_path, None);

    // Capture primary services
    let primary_services = primary_service_ids(&store);
    debug!(
        "macos backend: found {} primary services interface={}",
        primary_services.len(),
        interface
    );

    for service_id in primary_services {
        let state_path = format!("State:/Network/Service/{service_id}/DNS");
        let setup_path = format!("Setup:/Network/Service/{service_id}/DNS");
        push_dns_snapshot(
            &store,
            &mut entries,
            &mut seen,
            state_path,
            Some(setup_path),
        );
    }

    // Capture global DNS settings
    push_dns_snapshot(
        &store,
        &mut entries,
        &mut seen,
        "State:/Network/Global/DNS".to_string(),
        Some("Setup:/Network/Global/DNS".to_string()),
    );

    snapshot.entries = entries;

    debug!(
        "macos backend: DNS state captured interface={} entries={} errors={}",
        interface,
        snapshot.entries.len(),
        capture_errors.len()
    );

    // Log capture errors but don't fail - we can still proceed with partial state
    if !capture_errors.is_empty() {
        warn!(
            "event=macos.dns.capture_partial_failure interface={} errors={:?}",
            interface, capture_errors
        );
    }

    // Ensure we have at least some DNS entries to work with
    if snapshot.entries.is_empty() {
        return Err(PlatformError::Api(format!(
            "No DNS configuration found for interface {}: {}",
            interface,
            if capture_errors.is_empty() {
                "No active DNS services detected".to_string()
            } else {
                capture_errors.join(", ")
            }
        )));
    }

    Ok(snapshot)
}

fn build_dns_dictionary(
    servers: &[CFString],
    search_domains: Option<&[CFString]>,
    port: Option<u16>,
    supplemental_match_domains: Option<&[CFString]>,
    supplemental_match_order: Option<&[CFNumber]>,
) -> CFDictionary<CFString, CFType> {
    let mut dict: CFMutableDictionary<CFString, CFType> = CFMutableDictionary::new();

    let address_key = unsafe { CFString::wrap_under_get_rule(kSCPropNetDNSServerAddresses) };
    let addresses_array = CFArray::from_CFTypes(servers);
    let addresses_cf = addresses_array.as_CFType();
    dict.add(&address_key, &addresses_cf);

    if let Some(domains) = search_domains {
        if !domains.is_empty() {
            let search_key = unsafe { CFString::wrap_under_get_rule(kSCPropNetDNSSearchDomains) };
            let search_array = CFArray::from_CFTypes(domains);
            let search_cf = search_array.as_CFType();
            dict.add(&search_key, &search_cf);
        }
    }

    if let Some(port) = port.filter(|value| *value != 53) {
        let port_key = unsafe { CFString::wrap_under_get_rule(kSCPropNetDNSServerPort) };
        let port_value = CFNumber::from(port as i32);
        let port_cf = port_value.as_CFType();
        dict.add(&port_key, &port_cf);
    }

    if let Some(domains) = supplemental_match_domains {
        if !domains.is_empty() {
            let match_key =
                unsafe { CFString::wrap_under_get_rule(kSCPropNetDNSSupplementalMatchDomains) };
            let match_array = CFArray::from_CFTypes(domains);
            let match_cf = match_array.as_CFType();
            dict.add(&match_key, &match_cf);
        }
    }

    if let Some(order) = supplemental_match_order {
        let order_key =
            unsafe { CFString::wrap_under_get_rule(kSCPropNetDNSSupplementalMatchOrders) };
        let order_array = CFArray::from_CFTypes(order);
        dict.add(&order_key, &order_array.as_CFType());
    }

    dict.to_immutable()
}

fn build_dns_dictionary_from_settings(
    settings: &DnsSettings,
) -> Option<CFDictionary<CFString, CFType>> {
    if settings.servers.is_empty() {
        return None;
    }

    let server_cf: Vec<CFString> = settings
        .servers
        .iter()
        .map(|addr| CFString::new(addr))
        .collect();
    let search_cf: Option<Vec<CFString>> = if settings.search_domains.is_empty() {
        None
    } else {
        Some(
            settings
                .search_domains
                .iter()
                .map(|domain| CFString::new(domain))
                .collect(),
        )
    };

    Some(build_dns_dictionary(
        &server_cf,
        search_cf.as_ref().map(|vec| vec.as_slice()),
        settings.port,
        None,
        None,
    ))
}

fn apply_dns_override(
    interface: &str,
    snapshot: &mut DnsSnapshot,
    servers: &[String],
) -> Result<(), PlatformError> {
    if servers.is_empty() {
        debug!(
            "macos backend: skipping DNS override interface={} reason=no_servers",
            interface
        );
        return Ok(());
    }

    if snapshot.entries.is_empty() {
        debug!(
            "macos backend: DNS snapshot empty; creating interface entry interface={}",
            interface
        );
    }

    let store = dns_store();

    // Validate DNS servers before applying
    let validated_servers: Result<Vec<_>, PlatformError> = servers
        .iter()
        .map(|addr| validate_dns_server(addr))
        .collect();

    let servers: Vec<CFString> = validated_servers?
        .into_iter()
        .map(|addr| CFString::new(&addr))
        .collect();

    // Create dictionary for primary services and global DNS
    let primary_dictionary = build_dns_dictionary(&servers, None, None, None, None);

    // Create dictionary for supplemental match (interface-specific)
    let match_domains: Vec<CFString> = vec![CFString::new("")];
    let match_order: Vec<CFNumber> = vec![CFNumber::from(100_i32)]; // Higher order for supplemental
    let supplemental_dictionary = build_dns_dictionary(
        &servers,
        None,
        None,
        Some(match_domains.as_slice()),
        Some(match_order.as_slice()),
    );

    let interface_state_path = format!("State:/Network/Interface/{interface}/DNS");
    let mut applied_count = 0;
    let mut errors = Vec::new();

    // Apply DNS override to existing entries
    for entry in &snapshot.entries {
        let dictionary = if entry.state_path == interface_state_path {
            &supplemental_dictionary
        } else if entry.state_path.contains("/Global/DNS") || entry.state_path.contains("/Service/")
        {
            &primary_dictionary
        } else {
            continue; // Skip other types of DNS entries
        };

        match set_dns_entry(&store, &entry.state_path, dictionary) {
            Ok(()) => {
                applied_count += 1;
                debug!(
                    "macos backend: DNS override applied path={} interface={}",
                    entry.state_path, interface
                );
            }
            Err(err) => {
                errors.push(format!(
                    "Failed to set DNS for {}: {}",
                    entry.state_path, err
                ));
                warn!(
                    "event=macos.dns.override_failed interface={} path={} err={}",
                    interface, entry.state_path, err
                );
            }
        }
    }

    // If no interface-specific entry exists, create one
    if !snapshot
        .entries
        .iter()
        .any(|e| e.state_path == interface_state_path)
    {
        match set_dns_entry(&store, &interface_state_path, &supplemental_dictionary) {
            Ok(()) => {
                snapshot.entries.push(DnsServiceSnapshot {
                    state_path: interface_state_path.clone(),
                    setup_path: None,
                    previous_state: None,
                    previous_setup: None,
                });
                applied_count += 1;
                debug!(
                    "macos backend: DNS override created interface_path={} interface={}",
                    interface_state_path, interface
                );
            }
            Err(err) => {
                errors.push(format!("Failed to create interface DNS entry: {}", err));
                warn!(
                    "event=macos.dns.interface_create_failed interface={} err={}",
                    interface, err
                );
            }
        }
    }

    if applied_count == 0 && !errors.is_empty() {
        return Err(PlatformError::Api(format!(
            "Failed to apply DNS override to any entries: {}",
            errors.join(", ")
        )));
    }

    if !errors.is_empty() {
        warn!(
            "event=macos.dns.partial_override_failure interface={} applied={} errors={}",
            interface,
            applied_count,
            errors.len()
        );
    }

    snapshot.applied_override = applied_count > 0;
    debug!(
        "macos backend: DNS override completed interface={} applied_entries={} total_entries={}",
        interface,
        applied_count,
        snapshot.entries.len()
    );

    Ok(())
}

fn restore_dns(interface: &str, snapshot: &DnsSnapshot) -> Result<(), PlatformError> {
    if !snapshot.applied_override {
        debug!(
            "macos backend: skipping DNS restore interface={} reason=no_override_applied",
            interface
        );
        return Ok(());
    }

    debug!(
        "macos backend: restoring DNS state interface={} entries={}",
        interface,
        snapshot.entries.len()
    );

    let store = dns_store();
    let mut restore_errors = Vec::new();
    let mut restored_count = 0;

    for entry in &snapshot.entries {
        match restore_dns_entry(&store, entry) {
            Ok(()) => {
                restored_count += 1;
                debug!(
                    "macos backend: DNS entry restored interface={} path={}",
                    interface, entry.state_path
                );
            }
            Err(err) => {
                let error_msg = format!("Failed to restore {}: {}", entry.state_path, err);
                restore_errors.push(error_msg);
                warn!(
                    "event=macos.dns.restore_failed interface={} state_path={} err={}",
                    interface, entry.state_path, err
                );
            }
        }
    }

    debug!(
        "macos backend: DNS restore completed interface={} restored={} errors={}",
        interface,
        restored_count,
        restore_errors.len()
    );

    // If we couldn't restore any entries, return an error
    if restored_count == 0 && !restore_errors.is_empty() {
        return Err(PlatformError::Api(format!(
            "Failed to restore any DNS entries for interface {}: {}",
            interface,
            restore_errors.join(", ")
        )));
    }

    // If we had partial failures, log them but don't fail the operation
    if !restore_errors.is_empty() {
        warn!(
            "event=macos.dns.restore_partial_failure interface={} restored={} errors={:?}",
            interface, restored_count, restore_errors
        );
    }

    Ok(())
}

fn set_dns_entry(
    store: &SCDynamicStore,
    path: &str,
    dict: &CFDictionary<CFString, CFType>,
) -> Result<(), PlatformError> {
    let key = CFString::new(path);
    let untyped = dict.to_untyped();
    let plist = untyped.into_CFPropertyList();
    if store.set_raw(key, &plist) {
        debug!("macos backend: DNS entry set path={path}");
        Ok(())
    } else {
        Err(PlatformError::Api(format!(
            "failed to update DNS entry at {path}"
        )))
    }
}

fn clear_dns_entry(store: &SCDynamicStore, path: &str) {
    let key = CFString::new(path);
    if store.remove(key.clone()) {
        debug!("macos backend: DNS entry removed path={path}");
    } else {
        debug!("macos backend: DNS entry remove skipped path={path} reason=missing");
    }
}

fn restore_dns_entry(
    store: &SCDynamicStore,
    entry: &DnsServiceSnapshot,
) -> Result<(), PlatformError> {
    restore_single(store, &entry.state_path, entry.previous_state.as_ref())?;
    if let Some(setup_path) = &entry.setup_path {
        restore_single(store, setup_path, entry.previous_setup.as_ref())?;
    }
    Ok(())
}

fn restore_single(
    store: &SCDynamicStore,
    path: &str,
    settings: Option<&DnsSettings>,
) -> Result<(), PlatformError> {
    if let Some(settings) = settings {
        if let Some(dict) = build_dns_dictionary_from_settings(settings) {
            set_dns_entry(store, path, &dict)?;
        } else {
            clear_dns_entry(store, path);
        }
    } else {
        clear_dns_entry(store, path);
    }
    Ok(())
}

fn collect_strings_from_array(array: &CFArray) -> Vec<String> {
    let mut values = Vec::with_capacity(array.len() as usize);
    for element_ptr in array.iter() {
        if let Some(cf_string) =
            unsafe { CFType::wrap_under_get_rule(*element_ptr) }.downcast::<CFString>()
        {
            values.push(cf_string.to_string());
        }
    }
    values
}

fn push_dns_snapshot(
    store: &SCDynamicStore,
    entries: &mut Vec<DnsServiceSnapshot>,
    seen: &mut HashSet<String>,
    state_path: String,
    setup_path: Option<String>,
) {
    if !seen.insert(state_path.clone()) {
        return;
    }

    let previous_state = fetch_dns(store, &state_path);
    let previous_setup = setup_path.as_ref().and_then(|path| fetch_dns(store, path));

    entries.push(DnsServiceSnapshot {
        state_path,
        setup_path,
        previous_state,
        previous_setup,
    });
}

fn primary_service_ids(store: &SCDynamicStore) -> Vec<String> {
    let mut ids = HashSet::new();
    let primary_key = CFString::new("PrimaryService");
    let candidate_paths = ["State:/Network/Global/IPv4", "State:/Network/Global/IPv6"];

    for path in candidate_paths {
        if let Some(plist) = store.get(CFString::new(path)) {
            if let Some(dict) = CFPropertyList::downcast_into::<CFDictionary>(plist) {
                if let Some(service_id) = dict
                    .find(primary_key.to_void())
                    .map(|ptr| unsafe { CFType::wrap_under_get_rule(*ptr) })
                    .and_then(|ty| ty.downcast::<CFString>())
                {
                    ids.insert(service_id.to_string());
                }
            }
        }
    }

    ids.into_iter().collect()
}

fn fetch_dns(store: &SCDynamicStore, path: &str) -> Option<DnsSettings> {
    store
        .get(CFString::new(path))
        .and_then(CFPropertyList::downcast_into::<CFDictionary>)
        .and_then(|dict| {
            let servers = dict
                .find(unsafe { kSCPropNetDNSServerAddresses }.to_void())
                .map(|ptr| unsafe { CFType::wrap_under_get_rule(*ptr) })
                .and_then(|plist| plist.downcast::<CFArray>())
                .map(|array| collect_strings_from_array(&array))
                .unwrap_or_default();

            if servers.is_empty() {
                return None;
            }

            let search_domains = dict
                .find(unsafe { kSCPropNetDNSSearchDomains }.to_void())
                .map(|ptr| unsafe { CFType::wrap_under_get_rule(*ptr) })
                .and_then(|plist| plist.downcast::<CFArray>())
                .map(|array| collect_strings_from_array(&array))
                .unwrap_or_default();

            let port = dict
                .find(unsafe { kSCPropNetDNSServerPort }.to_void())
                .map(|ptr| unsafe { CFType::wrap_under_get_rule(*ptr) })
                .and_then(|plist| plist.downcast::<CFNumber>())
                .and_then(|number| number.to_i32())
                .and_then(|value| u16::try_from(value).ok())
                .filter(|value| *value != 53);

            Some(DnsSettings {
                servers,
                search_domains,
                port,
            })
        })
}

fn find_services_for_interface(
    store: &SCDynamicStore,
    interface: &str,
) -> Result<Vec<(String, String)>, PlatformError> {
    let mut matches = Vec::new();
    let Some(state_paths) = store.get_keys("State:/Network/Service/.*/DNS") else {
        return Ok(matches);
    };

    for state_path in state_paths.iter() {
        let state_path_str = state_path.to_string();
        let setup_path = match state_to_setup_path(&state_path_str) {
            Ok(path) => path,
            Err(err) => {
                warn!(
                    "event=macos.dns.path_parse_failed path={} err={err}",
                    state_path_str
                );
                continue;
            }
        };

        match interface_name(store, &state_path_str)? {
            Some(name) if name == interface => matches.push((state_path_str, setup_path)),
            _ => {}
        }
    }

    Ok(matches)
}

fn interface_name(
    store: &SCDynamicStore,
    dns_state_path: &str,
) -> Result<Option<String>, PlatformError> {
    let interface_path = state_to_interface_path(dns_state_path)?;
    Ok(store
        .get(CFString::new(interface_path.as_str()))
        .and_then(CFPropertyList::downcast_into::<CFDictionary>)
        .and_then(|dict| {
            dict.find(unsafe { kSCPropNetInterfaceDeviceName }.to_void())
                .map(|ptr| unsafe { CFType::wrap_under_get_rule(*ptr) })
                .and_then(|cf_ty| cf_ty.downcast::<CFString>())
                .map(|cf_str| cf_str.to_string())
        }))
}

fn state_to_setup_path(state_path: &str) -> Result<String, PlatformError> {
    if let Some(rest) = state_path.strip_prefix("State") {
        Ok(format!("Setup{rest}"))
    } else {
        Err(PlatformError::Api(format!(
            "unexpected DNS path format: {state_path}"
        )))
    }
}

fn state_to_interface_path(state_path: &str) -> Result<String, PlatformError> {
    let setup_path = state_to_setup_path(state_path)?;
    if let Some(prefix) = setup_path.strip_suffix("/DNS") {
        Ok(format!("{prefix}/Interface"))
    } else {
        Err(PlatformError::Api(format!(
            "unexpected DNS path format: {state_path}"
        )))
    }
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
