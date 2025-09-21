use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    str::FromStr,
};

use tonic::Status;
use vpn9_proto::daemon::ConnectRequest;

#[cfg(target_os = "macos")]
use boringtun::device::DeviceHandle;

#[derive(Clone, Debug)]
pub struct ConnectParams {
    pub request_id: String,
    pub interface_name: String,
    pub server_id: String,
    pub server_name: String,
    pub endpoint: SocketAddr,
    pub peer_public_key: String,
    pub private_key: String,
    pub allowed_ips: Vec<AllowedIp>,
    pub device_ipv4: Option<Ipv4Addr>,
    pub device_ipv6: Option<Ipv6Addr>,
    pub mtu: Option<u32>,
    pub keepalive_seconds: Option<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AllowedIp {
    pub addr: IpAddr,
    pub cidr: u8,
}

impl AllowedIp {
    pub fn is_ipv4(&self) -> bool {
        self.addr.is_ipv4()
    }

    pub fn is_default_route(&self) -> bool {
        self.addr.is_unspecified() && self.cidr == 0
    }
}

impl fmt::Display for AllowedIp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.cidr)
    }
}

#[derive(Debug)]
pub enum PlatformError {
    InvalidConfig(String),
    Api(String),
    DeviceStart(String),
    Timeout(String),
    Io(String),
}

impl From<PlatformError> for Status {
    fn from(value: PlatformError) -> Self {
        match value {
            PlatformError::InvalidConfig(msg) => Status::invalid_argument(msg),
            PlatformError::Api(msg) | PlatformError::DeviceStart(msg) | PlatformError::Io(msg) => {
                Status::internal(msg)
            }
            PlatformError::Timeout(msg) => Status::deadline_exceeded(msg),
        }
    }
}

impl fmt::Display for PlatformError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlatformError::InvalidConfig(msg)
            | PlatformError::Api(msg)
            | PlatformError::DeviceStart(msg)
            | PlatformError::Timeout(msg)
            | PlatformError::Io(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for PlatformError {}

impl TryFrom<&ConnectRequest> for ConnectParams {
    type Error = Status;

    fn try_from(req: &ConnectRequest) -> Result<Self, Self::Error> {
        if req.interface_name.trim().is_empty() {
            return Err(Status::invalid_argument("interface_name is required"));
        }
        if req.server_id.trim().is_empty() {
            return Err(Status::invalid_argument("server_id is required"));
        }
        if req.peer_public_key.trim().is_empty() {
            return Err(Status::invalid_argument("peer_public_key is required"));
        }
        if req.private_key.trim().is_empty() {
            return Err(Status::invalid_argument("private_key is required"));
        }
        if req.allowed_ips.is_empty() {
            return Err(Status::invalid_argument("allowed_ips must not be empty"));
        }

        let mut allowed_ips = Vec::with_capacity(req.allowed_ips.len());
        for entry in &req.allowed_ips {
            let mask = AllowedIp::from_str(entry).map_err(|err| {
                Status::invalid_argument(format!("invalid allowed IP entry {entry}: {err}"))
            })?;
            allowed_ips.push(mask);
        }

        let keepalive_seconds = match req.keepalive_seconds {
            Some(value) => Some(u16::try_from(value).map_err(|_| {
                Status::invalid_argument("keepalive_seconds value exceeds u16 range")
            })?),
            None => None,
        };

        let endpoint = resolve_endpoint(&req.endpoint).map_err(|err| {
            Status::invalid_argument(format!("invalid endpoint {}: {err}", req.endpoint))
        })?;

        let device_ipv4 = match req.device_ipv4.as_deref() {
            Some(ip) => Some(ip.parse().map_err(|err| {
                Status::invalid_argument(format!("invalid IPv4 address {ip}: {err}"))
            })?),
            None => None,
        };

        let device_ipv6 = match req.device_ipv6.as_deref() {
            Some(ip) => Some(ip.parse().map_err(|err| {
                Status::invalid_argument(format!("invalid IPv6 address {ip}: {err}"))
            })?),
            None => None,
        };

        Ok(Self {
            request_id: req.request_id.clone(),
            interface_name: req.interface_name.clone(),
            server_id: req.server_id.clone(),
            server_name: req.server_name.clone(),
            endpoint,
            peer_public_key: req.peer_public_key.clone(),
            private_key: req.private_key.clone(),
            allowed_ips,
            device_ipv4,
            device_ipv6,
            mtu: req.mtu,
            keepalive_seconds,
        })
    }
}

#[derive(Debug)]
pub struct AllowedIpParseError;

impl fmt::Display for AllowedIpParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid CIDR notation")
    }
}

impl std::error::Error for AllowedIpParseError {}

impl FromStr for AllowedIp {
    type Err = AllowedIpParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr_str, cidr_str) = match s.split_once('/') {
            Some(parts) => parts,
            None => (s, if s.contains(':') { "128" } else { "32" }),
        };

        let addr = addr_str
            .parse::<IpAddr>()
            .map_err(|_| AllowedIpParseError)?;
        let cidr = cidr_str.parse::<u8>().map_err(|_| AllowedIpParseError)?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if cidr > max {
            return Err(AllowedIpParseError);
        }
        Ok(AllowedIp { addr, cidr })
    }
}

fn resolve_endpoint(endpoint: &str) -> Result<SocketAddr, String> {
    endpoint
        .to_socket_addrs()
        .map_err(|err| err.to_string())?
        .next()
        .ok_or_else(|| "endpoint did not resolve to any address".to_string())
}

#[allow(clippy::large_enum_variant)]
pub enum DeviceRuntime {
    #[cfg(target_os = "macos")]
    Macos(DeviceHandle),
    #[cfg(target_os = "linux")]
    Kernel,
}

impl DeviceRuntime {
    pub fn shutdown(self) {
        match self {
            #[cfg(target_os = "macos")]
            DeviceRuntime::Macos(mut handle) => handle.wait(),
            #[cfg(target_os = "linux")]
            DeviceRuntime::Kernel => {}
        }
    }
}
