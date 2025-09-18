use std::path::PathBuf;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use keyring::Entry;
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::Emitter;
use uuid::Uuid;

use crate::devices::{clear_wireguard_credentials, ensure_device_registered};
use crate::http::{default_timeout, request_with_retry};
use crate::util::short_hash;

pub(crate) const KEYRING_SERVICE: &str = "vpn9-client";
const CLIENT_LABEL: &str = "vpn9-desktop";

// --- Optional AEAD-encrypted file fallback (feature: file-fallback-aead) ---
#[cfg(feature = "file-fallback-aead")]
mod aead_fallback {
    use super::*;
    use base64::engine::general_purpose;
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
    use hkdf::Hkdf;
    use rand::RngCore;

    #[derive(Serialize, Deserialize)]
    struct AeadTokenFile {
        v: u8,
        salt: String,
        nonce: String,
        ct: String,
    }

    fn derive_key(machine_id: &str, salt: &[u8]) -> Result<Key, String> {
        let hk = Hkdf::<Sha256>::new(Some(salt), machine_id.as_bytes());
        let mut okm = [0u8; 32];
        hk.expand(b"vpn9-aead-token-key-v1", &mut okm)
            .map_err(|_| "HKDF expand failed".to_string())?;
        Ok(Key::from_slice(&okm).clone())
    }

    pub async fn store_tokens_to_file_aead(
        access_token: &str,
        refresh_token: &str,
    ) -> Result<(), String> {
        let file_path = super::get_token_file_path()?;

        // Random salt and nonce
        let mut salt = [0u8; 16];
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut salt);
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        let machine_id = super::get_os_machine_id()
            .await
            .unwrap_or_else(|_| "fallback".to_string());
        let key = derive_key(&machine_id, &salt)?;
        let cipher = ChaCha20Poly1305::new(&key);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Prepare plaintext as JSON
        let pt = serde_json::to_vec(&serde_json::json!({
            "access_token": access_token,
            "refresh_token": refresh_token,
        }))
        .map_err(|e| format!("Failed to serialize tokens: {e}"))?;

        let ct = cipher
            .encrypt(nonce, pt.as_slice())
            .map_err(|_| "AEAD encryption failed".to_string())?;

        let file = AeadTokenFile {
            v: 1,
            salt: general_purpose::STANDARD.encode(salt),
            nonce: general_purpose::STANDARD.encode(nonce_bytes),
            ct: general_purpose::STANDARD.encode(ct),
        };

        let json = serde_json::to_string(&file)
            .map_err(|e| format!("Failed to serialize token file: {e}"))?;

        tokio::fs::write(&file_path, json)
            .await
            .map_err(|e| format!("Failed to write token file: {e}"))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = std::fs::metadata(&file_path)
                .map_err(|e| format!("Failed to get file metadata: {e}"))?;
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o600);
            std::fs::set_permissions(&file_path, permissions)
                .map_err(|e| format!("Failed to set file permissions: {e}"))?;
        }

        Ok(())
    }

    pub async fn get_tokens_from_file_aead() -> Result<(String, String), String> {
        let file_path = super::get_token_file_path()?;
        let json = tokio::fs::read_to_string(&file_path)
            .await
            .map_err(|e| format!("Failed to read token file: {e}"))?;
        let file: AeadTokenFile =
            serde_json::from_str(&json).map_err(|e| format!("Failed to parse token file: {e}"))?;

        let salt = general_purpose::STANDARD
            .decode(file.salt)
            .map_err(|e| format!("Failed to decode salt: {e}"))?;
        let nonce_bytes = general_purpose::STANDARD
            .decode(file.nonce)
            .map_err(|e| format!("Failed to decode nonce: {e}"))?;
        let ct = general_purpose::STANDARD
            .decode(file.ct)
            .map_err(|e| format!("Failed to decode ciphertext: {e}"))?;

        let machine_id = super::get_os_machine_id()
            .await
            .unwrap_or_else(|_| "fallback".to_string());
        let key = derive_key(&machine_id, &salt)?;
        let cipher = ChaCha20Poly1305::new(&key);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let pt = cipher
            .decrypt(nonce, ct.as_slice())
            .map_err(|_| "AEAD decryption failed".to_string())?;

        let val: serde_json::Value =
            serde_json::from_slice(&pt).map_err(|e| format!("Failed to parse plaintext: {e}"))?;
        let access_token = val
            .get("access_token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing access_token".to_string())?
            .to_string();
        let refresh_token = val
            .get("refresh_token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing refresh_token".to_string())?
            .to_string();

        Ok((access_token, refresh_token))
    }
}

// Authentication data structures
#[derive(Debug, Serialize, Deserialize)]
struct AuthRequest {
    passphrase: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_label: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthResponse {
    token: String,
    refresh_token: String,
    expires_in: u64,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    subscription_status: Option<String>,
    subscription_expires_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct RefreshRequest {
    refresh_token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String, // user_uuid
    pub iat: u64,    // issued at
    pub exp: u64,    // expires at
    pub aud: String, // audience
    pub device_id: String,
    pub subscription_valid: bool,
    pub subscription_expires: u64,
}

#[derive(Clone, Serialize)]
pub struct LoginSuccessPayload {
    pub message: String,
    pub subscription_expires_at: String,
}

#[derive(Clone, Serialize)]
pub struct LoginErrorPayload {
    pub error: String,
}

#[derive(Serialize)]
pub struct ActionResponse {
    pub message: String,
}

#[derive(Serialize)]
pub struct AuthStatus {
    pub authenticated: bool,
    pub token_present: bool,
}

// Device ID generation - Hybrid approach
#[tauri::command]
pub async fn get_device_id(app: tauri::AppHandle) -> Result<String, String> {
    // Try OS machine ID first (most reliable)
    if let Ok(machine_id) = get_os_machine_id().await {
        return Ok(format!("os-{machine_id}"));
    }

    // Fallback to persistent UUID
    if let Ok(stored_id) = get_or_create_stored_device_id(app).await {
        return Ok(format!("uuid-{stored_id}"));
    }

    // Last resort: hardware fingerprint
    get_hardware_fingerprint()
        .await
        .map(|fp| format!("hw-{fp}"))
}

pub async fn get_os_machine_id() -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        use winreg::{enums::*, RegKey};
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let crypto_key = hklm
            .open_subkey("SOFTWARE\\Microsoft\\Cryptography")
            .map_err(|e| format!("Failed to open registry: {e}"))?;
        let machine_guid: String = crypto_key
            .get_value("MachineGuid")
            .map_err(|e| format!("Failed to read MachineGuid: {e}"))?;
        Ok(machine_guid)
    }

    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        let output = Command::new("ioreg")
            .args(&["-rd1", "-c", "IOPlatformExpertDevice"])
            .output()
            .map_err(|e| format!("Failed to run ioreg: {e}"))?;

        let output_str = String::from_utf8_lossy(&output.stdout);
        for line in output_str.lines() {
            if line.contains("IOPlatformUUID") {
                if let Some(uuid_start) = line.find('"') {
                    if let Some(uuid_end) = line.rfind('"') {
                        if uuid_start != uuid_end {
                            let uuid = &line[uuid_start + 1..uuid_end];
                            return Ok(uuid.to_string());
                        }
                    }
                }
            }
        }
        Err("IOPlatformUUID not found".to_string())
    }

    #[cfg(target_os = "linux")]
    {
        match tokio::fs::read_to_string("/etc/machine-id").await {
            Ok(content) => Ok(content.trim().to_string()),
            Err(_) => match tokio::fs::read_to_string("/var/lib/dbus/machine-id").await {
                Ok(content) => Ok(content.trim().to_string()),
                Err(e) => Err(format!("Failed to read machine-id: {e}")),
            },
        }
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        Err("Unsupported operating system".to_string())
    }
}

async fn get_or_create_stored_device_id(_app: tauri::AppHandle) -> Result<String, String> {
    let device_entry = get_keyring_entry("device_id")?;

    // Try to read existing device ID from keyring
    match device_entry.get_password() {
        Ok(existing_id) => {
            let trimmed = existing_id.trim();
            if !trimmed.is_empty() {
                return Ok(trimmed.to_string());
            }
        }
        Err(_) => {
            // No existing device ID, generate a new one
        }
    }

    let new_id = Uuid::new_v4().to_string();

    device_entry
        .set_password(&new_id)
        .map_err(|e| format!("Failed to save device ID: {e}"))?;

    Ok(new_id)
}

async fn get_hardware_fingerprint() -> Result<String, String> {
    use sysinfo::System;

    let mut system = System::new_all();
    system.refresh_all();

    let components = [
        System::host_name().unwrap_or_default(),
        System::kernel_version().unwrap_or_default(),
        System::os_version().unwrap_or_default(),
        system
            .cpus()
            .first()
            .map(|cpu| cpu.brand())
            .unwrap_or("unknown")
            .to_string(),
        system.total_memory().to_string(),
    ];

    let combined = components.join("|");
    let mut hasher = Sha256::new();
    hasher.update(combined.as_bytes());
    let hash = hasher.finalize();

    Ok(format!("{hash:x}")[..16].to_string())
}

// Token storage (keyring only)

fn get_token_file_path() -> Result<PathBuf, String> {
    let config_dir =
        dirs::config_dir().ok_or_else(|| "Could not determine config directory".to_string())?;
    let app_dir = config_dir.join("vpn9-client");

    // Create directory if it doesn't exist
    std::fs::create_dir_all(&app_dir)
        .map_err(|e| format!("Failed to create config directory: {e}"))?;

    Ok(app_dir.join(".tokens"))
}

fn get_keyring_entry(key: &str) -> Result<Entry, String> {
    Entry::new(KEYRING_SERVICE, key).map_err(|e| format!("Failed to create keyring entry: {e}"))
}

async fn store_tokens_to_keyring(access_token: &str, refresh_token: &str) -> Result<(), String> {
    let access_entry = get_keyring_entry("access_token")?;
    let refresh_entry = get_keyring_entry("refresh_token")?;

    access_entry
        .set_password(access_token)
        .map_err(|e| format!("Failed to store access token: {e}"))?;
    refresh_entry
        .set_password(refresh_token)
        .map_err(|e| format!("Failed to store refresh token: {e}"))?;

    Ok(())
}

async fn store_tokens(access_token: &str, refresh_token: &str) -> Result<(), String> {
    match store_tokens_to_keyring(access_token, refresh_token).await {
        Ok(_) => {
            debug!("event=tokens.store backend=keyring");
            Ok(())
        }
        Err(e) => {
            #[cfg(feature = "file-fallback-aead")]
            {
                warn!(
                    "event=tokens.store keyring_failed using=aead_file err={}",
                    e
                );
                aead_fallback::store_tokens_to_file_aead(access_token, refresh_token).await?;
                debug!("event=tokens.store backend=aead_file");
                Ok(())
            }
            #[cfg(not(feature = "file-fallback-aead"))]
            {
                Err(format!("Keyring storage failed: {e}"))
            }
        }
    }
}

async fn get_tokens_from_keyring() -> Result<(String, String), String> {
    let access_entry = get_keyring_entry("access_token")?;
    let refresh_entry = get_keyring_entry("refresh_token")?;

    let access_token = access_entry
        .get_password()
        .map_err(|e| format!("Failed to get access token: {e}"))?;
    let refresh_token = refresh_entry
        .get_password()
        .map_err(|e| format!("Failed to get refresh token: {e}"))?;

    Ok((access_token, refresh_token))
}

pub(crate) async fn get_stored_tokens() -> Result<(String, String), String> {
    match get_tokens_from_keyring().await {
        Ok(tokens) => Ok(tokens),
        Err(e) => {
            #[cfg(feature = "file-fallback-aead")]
            {
                debug!(
                    "event=tokens.read keyring_failed trying=aead_file err={}",
                    e
                );
                aead_fallback::get_tokens_from_file_aead().await
            }
            #[cfg(not(feature = "file-fallback-aead"))]
            {
                Err(e)
            }
        }
    }
}

pub(crate) async fn clear_stored_tokens() -> Result<(), String> {
    // Clear from keyring (ignore missing entries)
    if let Ok(access_entry) = get_keyring_entry("access_token") {
        let _ = access_entry.delete_password();
    }
    if let Ok(refresh_entry) = get_keyring_entry("refresh_token") {
        let _ = refresh_entry.delete_password();
    }

    // Remove legacy token file if present
    if let Ok(file_path) = get_token_file_path() {
        if let Err(e) = tokio::fs::remove_file(&file_path).await {
            if e.kind() != std::io::ErrorKind::NotFound {
                return Err(format!("Failed to remove token file: {e}"));
            }
        }
    }

    Ok(())
}

pub fn parse_jwt_claims(token: &str) -> Result<TokenClaims, String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid JWT format".to_string());
    }
    let payload_b64 = parts[1];
    let payload = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| format!("Failed to base64url-decode JWT payload: {e}"))?;
    serde_json::from_slice::<TokenClaims>(&payload)
        .map_err(|e| format!("Failed to parse JWT claims: {e}"))
}

pub(crate) fn is_jwt_expired(token: &str, skew_seconds: i64) -> Result<bool, String> {
    let claims = parse_jwt_claims(token)?;
    let exp = claims.exp as i64;
    let now = chrono::Utc::now().timestamp();
    Ok(exp <= now + skew_seconds)
}

// Authentication functions
#[tauri::command]
pub async fn login(passphrase: String, app: tauri::AppHandle) {
    info!("event=login.start");

    // Emit initial status
    let _ = app.emit("login-status", "Authenticating with VPN9 servers...");

    // Validate passphrase is not empty
    if passphrase.trim().is_empty() {
        let _ = app.emit(
            "login-error",
            LoginErrorPayload {
                error: "Please enter your passphrase".to_string(),
            },
        );
        return;
    }

    // Get device information
    let device_id = match get_device_id(app.clone()).await {
        Ok(id) => id,
        Err(e) => {
            let _ = app.emit(
                "login-error",
                LoginErrorPayload {
                    error: format!("Failed to get device ID: {e}"),
                },
            );
            return;
        }
    };
    // Do not log secrets. Provide only safe, structured context.
    info!(
        "event=login.device_info device_id_hash={}",
        short_hash(&device_id)
    );

    // Prepare authentication request
    let auth_request = AuthRequest {
        passphrase,
        client_label: Some(CLIENT_LABEL.to_string()),
    };

    // Make API call to Rails backend (with timeout + minimal retry)
    let client = match reqwest::Client::builder()
        .timeout(default_timeout())
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            let _ = app.emit(
                "login-error",
                LoginErrorPayload {
                    error: format!("Failed to build HTTP client: {e}"),
                },
            );
            return;
        }
    };
    let response = match request_with_retry(
        || {
            client
                .post("https://vpn9.com/api/v1/auth/token") // Replace with actual API URL
                .header("Content-Type", "application/json")
                .json(&auth_request)
                .timeout(default_timeout())
        },
        3,
    )
    .await
    {
        Ok(resp) => resp,
        Err(msg) => {
            let _ = app.emit("login-error", LoginErrorPayload { error: msg });
            return;
        }
    };

    if !response.status().is_success() {
        debug!("response is not success, status: {}", response.status());
        let status = response.status();
        let error_text = response.text().await.unwrap_or_default();

        // Parse specific error messages based on status codes
        let error_message = match status.as_u16() {
            401 => "Invalid passphrase. Please check your credentials and try again.".to_string(),
            402 => "Payment required. Please check your subscription status.".to_string(),
            403 => "Access forbidden. Your account may be suspended or inactive.".to_string(),
            404 => "Authentication service not found. Please try again later.".to_string(),
            429 => "Too many login attempts. Please wait a few minutes and try again.".to_string(),
            500..=599 => "VPN9 server error. Please try again later.".to_string(),
            _ => {
                // Try to parse error message from response body
                if let Ok(error_json) = serde_json::from_str::<serde_json::Value>(&error_text) {
                    if let Some(message) = error_json.get("error").and_then(|e| e.as_str()) {
                        message.to_string()
                    } else if let Some(message) = error_json.get("message").and_then(|m| m.as_str())
                    {
                        message.to_string()
                    } else {
                        format!("Authentication failed: {error_text}")
                    }
                } else {
                    format!("Authentication failed: {error_text}")
                }
            }
        };

        let _ = app.emit(
            "login-error",
            LoginErrorPayload {
                error: error_message,
            },
        );
        return;
    } else {
        debug!("response is success");
    }

    // Get the response text without logging sensitive contents
    let response_text = match response.text().await {
        Ok(text) => text,
        Err(e) => {
            let _ = app.emit(
                "login-error",
                LoginErrorPayload {
                    error: format!("Failed to read response: {e}"),
                },
            );
            return;
        }
    };
    // Log only metadata, not the payload (may contain tokens)
    debug!(
        "event=login.response received_bytes={} json_parse_attempt=true",
        response_text.len()
    );

    let auth_response: AuthResponse = match serde_json::from_str(&response_text) {
        Ok(resp) => resp,
        Err(e) => {
            let _ = app.emit(
                "login-error",
                LoginErrorPayload {
                    error: format!("Failed to parse authentication response: {e}"),
                },
            );
            return;
        }
    };

    // Store tokens securely
    if let Err(e) = store_tokens(&auth_response.token, &auth_response.refresh_token).await {
        let _ = app.emit(
            "login-error",
            LoginErrorPayload {
                error: format!("Failed to store authentication tokens: {e}"),
            },
        );
        return;
    }

    let _ = app.emit("login-status", "Registering this device with VPN9...");

    match ensure_device_registered(None).await {
        Ok(outcome) => {
            info!(
                "event=login.device_synced regenerated={} created={}",
                outcome.keys_regenerated, outcome.newly_created
            );
        }
        Err(e) => {
            warn!("event=login.device_sync_failed err={}", e);
            let _ = clear_wireguard_credentials().await;
            let _ = clear_stored_tokens().await;
            let _ = app.emit(
                "login-error",
                LoginErrorPayload {
                    error: format!("Failed to initialize device record: {e}"),
                },
            );
            return;
        }
    }

    // Emit success event
    let _ = app.emit(
        "login-success",
        LoginSuccessPayload {
            message: "Login successful!".to_string(),
            subscription_expires_at: auth_response.subscription_expires_at.clone(),
        },
    );
}

#[tauri::command]
pub async fn refresh_token() -> Result<String, String> {
    // Get stored refresh token
    let (_, refresh_token) = get_stored_tokens().await?;

    // Make refresh request with timeout + minimal retry
    let client = reqwest::Client::builder()
        .timeout(default_timeout())
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {e}"))?;
    let response = request_with_retry(
        || {
            client
                .post("https://vpn9.com/api/v1/auth/refresh") // Replace with actual API URL
                .header("Content-Type", "application/json")
                .json(&RefreshRequest {
                    refresh_token: refresh_token.clone(),
                })
                .timeout(default_timeout())
        },
        3,
    )
    .await
    .map_err(|e| format!("Token refresh request failed: {e}"))?;

    if !response.status().is_success() {
        let error_text = response.text().await.unwrap_or_default();
        clear_stored_tokens().await?;
        return Err(format!(
            "Token refresh failed: {error_text}. Please login again."
        ));
    }

    let auth_response: AuthResponse = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse refresh response: {e}"))?;

    // Store new tokens
    store_tokens(&auth_response.token, &auth_response.refresh_token).await?;

    Ok("Token refreshed successfully".to_string())
}

#[tauri::command]
pub async fn logout() -> Result<crate::auth::ActionResponse, String> {
    clear_stored_tokens().await?;
    Ok(ActionResponse {
        message: "Logged out successfully".to_string(),
    })
}

#[tauri::command]
pub async fn get_auth_status() -> Result<crate::auth::AuthStatus, String> {
    let status = match get_stored_tokens().await {
        Ok((access_token, _)) => {
            let expired = is_jwt_expired(&access_token, 0).unwrap_or(true);
            let authenticated = !expired;
            if authenticated {
                if let Err(e) = ensure_device_registered(None).await {
                    warn!("event=auth.status.device_sync_failed err={}", e);
                }
            }
            AuthStatus {
                authenticated,
                token_present: true,
            }
        }
        Err(_) => AuthStatus {
            authenticated: false,
            token_present: false,
        },
    };
    Ok(status)
}
