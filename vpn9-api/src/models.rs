use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
pub struct AuthRequest {
    pub passphrase: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_label: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifyDeviceRequest {
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateDeviceRequest {
    pub device: CreateDevicePayload,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateDevicePayload {
    pub public_key: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthResponse {
    pub token: String,
    pub refresh_token: String,
    pub expires_in: u64,
    #[serde(default)]
    pub token_type: Option<String>,
    #[serde(default)]
    pub subscription_status: Option<String>,
    pub subscription_expires_at: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DeviceRecord {
    pub id: String,
    pub name: String,
    pub public_key: String,
    pub status: String,
    #[serde(default)]
    pub ipv4: Option<String>,
    #[serde(default)]
    pub ipv6: Option<String>,
    #[serde(default)]
    pub allowed_ips: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct VerifyDeviceResponse {
    pub device: DeviceRecord,
}

#[derive(Debug, Deserialize)]
pub struct CreateDeviceResponse {
    pub device: DeviceRecord,
}

pub type RelayTopology = serde_json::Value;
