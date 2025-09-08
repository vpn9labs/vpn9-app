use std::collections::HashMap;
use std::path::PathBuf;

use keyring::Entry;
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::Emitter;
use uuid::Uuid;

// --- Logging helpers (sanitize + structure) ---
fn short_hash(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let out = hasher.finalize();
    // first 8 hex chars is enough for correlation without leaking the value
    format!("{:x}", out)[..8].to_string()
}



// --- Optional AEAD-encrypted file fallback (feature: file-fallback-aead) ---
#[cfg(feature = "file-fallback-aead")]
mod aead_fallback {
    use super::*;
    use base64::{engine::general_purpose, Engine as _};
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
        let file_path = get_token_file_path()?;

        // Random salt and nonce
        let mut salt = [0u8; 16];
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut salt);
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        let machine_id = get_os_machine_id().await.unwrap_or_else(|_| "fallback".to_string());
        let key = derive_key(&machine_id, &salt)?;
        let cipher = ChaCha20Poly1305::new(&key);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Prepare plaintext as JSON
        let pt = serde_json::to_vec(&serde_json::json!({
            "access_token": access_token,
            "refresh_token": refresh_token,
        }))
        .map_err(|e| format!("Failed to serialize tokens: {}", e))?;

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
            .map_err(|e| format!("Failed to serialize token file: {}", e))?;

        tokio::fs::write(&file_path, json)
            .await
            .map_err(|e| format!("Failed to write token file: {}", e))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = std::fs::metadata(&file_path)
                .map_err(|e| format!("Failed to get file metadata: {}", e))?;
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o600);
            std::fs::set_permissions(&file_path, permissions)
                .map_err(|e| format!("Failed to set file permissions: {}", e))?;
        }

        Ok(())
    }

    pub async fn get_tokens_from_file_aead() -> Result<(String, String), String> {
        let file_path = get_token_file_path()?;
        let json = tokio::fs::read_to_string(&file_path)
            .await
            .map_err(|e| format!("Failed to read token file: {}", e))?;
        let file: AeadTokenFile =
            serde_json::from_str(&json).map_err(|e| format!("Failed to parse token file: {}", e))?;

        let salt = general_purpose::STANDARD
            .decode(file.salt)
            .map_err(|e| format!("Failed to decode salt: {}", e))?;
        let nonce_bytes = general_purpose::STANDARD
            .decode(file.nonce)
            .map_err(|e| format!("Failed to decode nonce: {}", e))?;
        let ct = general_purpose::STANDARD
            .decode(file.ct)
            .map_err(|e| format!("Failed to decode ciphertext: {}", e))?;

        let machine_id = get_os_machine_id().await.unwrap_or_else(|_| "fallback".to_string());
        let key = derive_key(&machine_id, &salt)?;
        let cipher = ChaCha20Poly1305::new(&key);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let pt = cipher
            .decrypt(nonce, ct.as_slice())
            .map_err(|_| "AEAD decryption failed".to_string())?;

        let val: serde_json::Value =
            serde_json::from_slice(&pt).map_err(|e| format!("Failed to parse plaintext: {}", e))?;
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
    device_name: String,
    device_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthResponse {
    access_token: String,
    refresh_token: String,
    expires_in: u64,
    token_type: String,
    subscription_status: String,
    subscription_expires_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct RefreshRequest {
    refresh_token: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct TokenClaims {
    sub: String, // user_uuid
    iat: u64,    // issued at
    exp: u64,    // expires at
    aud: String, // audience
    device_id: String,
    subscription_valid: bool,
    subscription_expires: u64,
}

// Device ID generation - Hybrid approach
#[tauri::command]
async fn get_device_id(app: tauri::AppHandle) -> Result<String, String> {
    // Try OS machine ID first (most reliable)
    if let Ok(machine_id) = get_os_machine_id().await {
        return Ok(format!("os-{}", machine_id));
    }

    // Fallback to persistent UUID
    if let Ok(stored_id) = get_or_create_stored_device_id(app).await {
        return Ok(format!("uuid-{}", stored_id));
    }

    // Last resort: hardware fingerprint
    get_hardware_fingerprint()
        .await
        .map(|fp| format!("hw-{}", fp))
}

async fn get_os_machine_id() -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        use winreg::{enums::*, RegKey};
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let crypto_key = hklm
            .open_subkey("SOFTWARE\\Microsoft\\Cryptography")
            .map_err(|e| format!("Failed to open registry: {}", e))?;
        let machine_guid: String = crypto_key
            .get_value("MachineGuid")
            .map_err(|e| format!("Failed to read MachineGuid: {}", e))?;
        Ok(machine_guid)
    }

    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        let output = Command::new("ioreg")
            .args(&["-rd1", "-c", "IOPlatformExpertDevice"])
            .output()
            .map_err(|e| format!("Failed to run ioreg: {}", e))?;

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
                Err(e) => Err(format!("Failed to read machine-id: {}", e)),
            },
        }
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        Err("Unsupported operating system".to_string())
    }
}

async fn get_or_create_stored_device_id(_app: tauri::AppHandle) -> Result<String, String> {
    // For simplicity, we'll store the device ID in the keyring instead of a file
    // This is actually more secure and avoids cross-platform path issues
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

    // Generate new UUID
    let new_id = Uuid::new_v4().to_string();

    // Save the new ID to keyring
    device_entry
        .set_password(&new_id)
        .map_err(|e| format!("Failed to save device ID: {}", e))?;

    Ok(new_id)
}

async fn get_hardware_fingerprint() -> Result<String, String> {
    use sysinfo::System;

    let mut system = System::new_all();
    system.refresh_all();

    let components = vec![
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

    Ok(format!("{:x}", hash)[..16].to_string())
}

// Token storage (keyring only)

fn get_token_file_path() -> Result<PathBuf, String> {
    let config_dir =
        dirs::config_dir().ok_or_else(|| "Could not determine config directory".to_string())?;
    let app_dir = config_dir.join("vpn9-client");

    // Create directory if it doesn't exist
    std::fs::create_dir_all(&app_dir)
        .map_err(|e| format!("Failed to create config directory: {}", e))?;

    Ok(app_dir.join(".tokens"))
}

fn get_keyring_entry(key: &str) -> Result<Entry, String> {
    Entry::new("vpn9-client", key).map_err(|e| format!("Failed to create keyring entry: {}", e))
}

async fn store_tokens_to_keyring(access_token: &str, refresh_token: &str) -> Result<(), String> {
    let access_entry = get_keyring_entry("access_token")?;
    let refresh_entry = get_keyring_entry("refresh_token")?;

    access_entry
        .set_password(access_token)
        .map_err(|e| format!("Failed to store access token: {}", e))?;
    refresh_entry
        .set_password(refresh_token)
        .map_err(|e| format!("Failed to store refresh token: {}", e))?;

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
                warn!("event=tokens.store keyring_failed using=aead_file err={}", e);
                aead_fallback::store_tokens_to_file_aead(access_token, refresh_token).await?;
                debug!("event=tokens.store backend=aead_file");
                Ok(())
            }
            #[cfg(not(feature = "file-fallback-aead"))]
            {
                Err(format!("Keyring storage failed: {}", e))
            }
        }
    }
}

async fn get_tokens_from_keyring() -> Result<(String, String), String> {
    let access_entry = get_keyring_entry("access_token")?;
    let refresh_entry = get_keyring_entry("refresh_token")?;

    let access_token = access_entry
        .get_password()
        .map_err(|e| format!("Failed to get access token: {}", e))?;
    let refresh_token = refresh_entry
        .get_password()
        .map_err(|e| format!("Failed to get refresh token: {}", e))?;

    Ok((access_token, refresh_token))
}

async fn get_stored_tokens() -> Result<(String, String), String> {
    match get_tokens_from_keyring().await {
        Ok(tokens) => Ok(tokens),
        Err(e) => {
            #[cfg(feature = "file-fallback-aead")]
            {
                debug!("event=tokens.read keyring_failed trying=aead_file err={}", e);
                aead_fallback::get_tokens_from_file_aead().await
            }
            #[cfg(not(feature = "file-fallback-aead"))]
            {
                Err(e)
            }
        }
    }
}


async fn clear_stored_tokens() -> Result<(), String> {
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
                return Err(format!("Failed to remove token file: {}", e));
            }
        }
    }

    Ok(())
}

// Event payload structures
#[derive(Clone, Serialize)]
struct LoginSuccessPayload {
    message: String,
    subscription_status: String,
    subscription_expires_at: String,
}

#[derive(Clone, Serialize)]
struct LoginErrorPayload {
    error: String,
}

// Authentication functions
#[tauri::command]
async fn login(passphrase: String, app: tauri::AppHandle) {
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
                    error: format!("Failed to get device ID: {}", e),
                },
            );
            return;
        }
    };
    let device_name = get_device_name();
    // Do not log secrets. Provide only safe, structured context.
    info!(
        "event=login.device_info device_id_hash={} device_name_len={}",
        short_hash(&device_id),
        device_name.len()
    );

    // Prepare authentication request
    let auth_request = AuthRequest {
        passphrase,
        device_name,
        device_id,
    };

    // Make API call to Rails backend
    let client = reqwest::Client::new();
    let response = match client
        .post("https://vpn9.com/api/v1/auth/token") // Replace with actual API URL
        .header("Content-Type", "application/json")
        .json(&auth_request)
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            let error_msg = if e.is_connect() {
                "Cannot connect to VPN9 servers. Please check your internet connection.".to_string()
            } else if e.is_timeout() {
                "Connection to VPN9 servers timed out. Please try again.".to_string()
            } else {
                format!("Network error: {}", e)
            };
            let _ = app.emit("login-error", LoginErrorPayload { error: error_msg });
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
                        format!("Authentication failed: {}", error_text)
                    }
                } else {
                    format!("Authentication failed: {}", error_text)
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
                    error: format!("Failed to read response: {}", e),
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
                    error: format!("Failed to parse authentication response: {}", e),
                },
            );
            return;
        }
    };

    // Store tokens securely
    if let Err(e) = store_tokens(&auth_response.access_token, &auth_response.refresh_token).await {
        let _ = app.emit(
            "login-error",
            LoginErrorPayload {
                error: format!("Failed to store authentication tokens: {}", e),
            },
        );
        return;
    }

    // Emit success event
    let _ = app.emit(
        "login-success",
        LoginSuccessPayload {
            message: "Login successful!".to_string(),
            subscription_status: auth_response.subscription_status,
            subscription_expires_at: auth_response.subscription_expires_at,
        },
    );
}

#[tauri::command]
async fn refresh_token() -> Result<String, String> {
    // Get stored refresh token
    let (_, refresh_token) = get_stored_tokens().await?;

    // Make refresh request
    let client = reqwest::Client::new();
    let response = client
        .post("https://vpn9.com/api/v1/auth/refresh") // Replace with actual API URL
        .header("Authorization", format!("Bearer {}", refresh_token))
        .send()
        .await
        .map_err(|e| format!("Token refresh request failed: {}", e))?;

    if !response.status().is_success() {
        let error_text = response.text().await.unwrap_or_default();
        clear_stored_tokens().await?;
        return Err(format!(
            "Token refresh failed: {}. Please login again.",
            error_text
        ));
    }

    let auth_response: AuthResponse = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse refresh response: {}", e))?;

    // Store new tokens
    store_tokens(&auth_response.access_token, &auth_response.refresh_token).await?;

    Ok("Token refreshed successfully".to_string())
}

#[tauri::command]
async fn logout() -> Result<String, String> {
    clear_stored_tokens().await?;
    Ok("Logged out successfully".to_string())
}

#[tauri::command]
async fn get_auth_status() -> Result<HashMap<String, String>, String> {
    let mut status = HashMap::new();

    match get_stored_tokens().await {
        Ok((_access_token, _refresh_token)) => {
            // TODO: Decode JWT to check expiration
            // For now, just check if tokens exist
            status.insert("authenticated".to_string(), "true".to_string());
            status.insert("token_present".to_string(), "true".to_string());
        }
        Err(_) => {
            status.insert("authenticated".to_string(), "false".to_string());
            status.insert("token_present".to_string(), "false".to_string());
        }
    }

    Ok(status)
}

fn get_device_name() -> String {
    use sysinfo::System;

    let os_name = System::name().unwrap_or_default();
    let hostname = System::host_name().unwrap_or_default();

    if hostname.is_empty() {
        format!("Desktop {}", os_name)
    } else {
        format!("{} ({})", hostname, os_name)
    }
}

// VPN connection commands
#[tauri::command]
async fn vpn_connect(server_id: String, _app: tauri::AppHandle) -> Result<String, String> {
    info!("event=vpn.connect.start server_id={}", server_id);

    // Get stored access token
    let (_access_token, _) = get_stored_tokens()
        .await
        .map_err(|e| format!("Not authenticated: {}", e))?;

    // TODO: Implement actual VPN connection logic
    // This would typically involve:
    // 1. Fetching server configuration from API
    // 2. Setting up WireGuard/OpenVPN configuration
    // 3. Establishing the connection
    // 4. Monitoring connection status

    // For now, just return success
    Ok(format!("Connected to server: {}", server_id))
}

#[tauri::command]
async fn vpn_disconnect() -> Result<String, String> {
    info!("event=vpn.disconnect.start");

    // TODO: Implement actual VPN disconnection logic
    // This would typically involve:
    // 1. Stopping the VPN service
    // 2. Cleaning up configuration
    // 3. Updating connection status

    Ok("Disconnected from VPN".to_string())
}

#[tauri::command]
async fn get_vpn_servers() -> Result<Vec<serde_json::Value>, String> {
    info!("event=relays.fetch.start");

    // Get stored access token
    let (access_token, _) = get_stored_tokens()
        .await
        .map_err(|e| format!("Not authenticated: {}", e))?;

    // Fetch actual server list from API
    let client = reqwest::Client::new();
    let response = match client
        .get("https://vpn9.com/api/v1/relays")
        .header("Authorization", format!("Bearer {}", access_token))
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            let error_msg = if e.is_connect() {
                "Cannot connect to VPN9 servers. Please check your internet connection.".to_string()
            } else if e.is_timeout() {
                "Connection to VPN9 servers timed out. Please try again.".to_string()
            } else {
                format!("Network error: {}", e)
            };
            return Err(error_msg);
        }
    };

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await.unwrap_or_default();
        return Err(format!(
            "Failed to fetch servers ({}): {}",
            status, error_text
        ));
    }

    // Get the response text without logging sensitive contents
    let response_text = match response.text().await {
        Ok(text) => text,
        Err(e) => {
            return Err(format!("Failed to read response: {}", e));
        }
    };
    // Log only metadata, not the payload
    debug!(
        "event=relays.response received_bytes={} json_parse_attempt=true",
        response_text.len()
    );

    // Parse the JSON response with the expected structure
    let response_json: serde_json::Value = match serde_json::from_str(&response_text) {
        Ok(data) => data,
        Err(e) => {
            return Err(format!("Failed to parse server response: {}", e));
        }
    };

    // Extract and flatten the nested structure: countries -> cities -> relays
    let mut servers = Vec::new();

    if let Some(countries) = response_json.get("countries").and_then(|c| c.as_array()) {
        for country in countries {
            let country_name = country
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("Unknown");
            let country_code = country.get("code").and_then(|c| c.as_str()).unwrap_or("");

            if let Some(cities) = country.get("cities").and_then(|c| c.as_array()) {
                for city in cities {
                    let city_name = city
                        .get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or("Unknown");
                    let city_code = city.get("code").and_then(|c| c.as_str()).unwrap_or("");
                    let latitude = city.get("latitude").and_then(|l| l.as_str()).unwrap_or("0");
                    let longitude = city
                        .get("longitude")
                        .and_then(|l| l.as_str())
                        .unwrap_or("0");

                    if let Some(relays) = city.get("relays").and_then(|r| r.as_array()) {
                        for relay in relays {
                            let hostname =
                                relay.get("hostname").and_then(|h| h.as_str()).unwrap_or("");
                            let ipv4_addr = relay
                                .get("ipv4_addr_in")
                                .and_then(|i| i.as_str())
                                .unwrap_or("");
                            let public_key = relay
                                .get("public_key")
                                .and_then(|p| p.as_str())
                                .unwrap_or("");
                            let multihop_port = relay
                                .get("multihop_port")
                                .and_then(|m| m.as_u64())
                                .unwrap_or(51820);

                            // Create a flattened server object for the UI
                            let server = serde_json::json!({
                                "id": hostname,
                                "hostname": hostname,
                                "name": format!("{}, {}", city_name, country_name),
                                "country": country_name,
                                "country_code": country_code,
                                "city": city_name,
                                "city_code": city_code,
                                "latitude": latitude,
                                "longitude": longitude,
                                "ipv4_addr_in": ipv4_addr,
                                "public_key": public_key,
                                "multihop_port": multihop_port,
                                "load": 0.0  // Load would need to come from a separate endpoint
                            });

                            servers.push(server);
                        }
                    }
                }
            }
        }
    }

    // If no servers were found, use mock data as fallback
    if servers.is_empty() {
        warn!("event=relays.empty using=mock_data");
        let mock_servers = vec![
            serde_json::json!({
                "id": "us-east-1",
                "name": "US East",
                "country": "United States",
                "city": "New York",
                "load": 45.0
            }),
            serde_json::json!({
                "id": "us-west-1",
                "name": "US West",
                "country": "United States",
                "city": "Los Angeles",
                "load": 62.0
            }),
            serde_json::json!({
                "id": "eu-west-1",
                "name": "EU West",
                "country": "Germany",
                "city": "Frankfurt",
                "load": 38.0
            }),
            serde_json::json!({
                "id": "asia-1",
                "name": "Asia Pacific",
                "country": "Japan",
                "city": "Tokyo",
                "load": 71.0
            }),
        ];
        return Ok(mock_servers);
    }

    info!("event=relays.parsed count={}", servers.len());
    Ok(servers)
}

#[tauri::command]
async fn get_vpn_status() -> Result<serde_json::Value, String> {
    // TODO: Implement actual VPN status checking
    Ok(serde_json::json!({
        "connected": false,
        "server_id": null,
        "connection_time": null,
        "bytes_sent": 0,
        "bytes_received": 0
    }))
}

// Legacy commands
#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

#[tauri::command]
async fn open_url(url: String) -> Result<(), String> {
    tauri_plugin_opener::open_url(url, None::<String>)
        .map_err(|e| format!("Failed to open URL: {}", e))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Configure logging: JSON format, level by environment (dev vs prod)
    let level = if cfg!(debug_assertions) {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };

    let log_plugin = tauri_plugin_log::Builder::new()
        .level(level)
        .format(|out, message, record| {
            let ts = chrono::Utc::now()
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
            // Build a compact JSON line
            let obj = serde_json::json!({
                "ts": ts,
                "level": record.level().to_string().to_lowercase(),
                "target": record.target(),
                "module_path": record.module_path(),
                "file": record.file(),
                "line": record.line(),
                "msg": message.to_string(),
            });
            out.finish(format_args!("{}", obj.to_string()))
        })
        .build();

    tauri::Builder::default()
        .plugin(log_plugin)
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            greet,
            open_url,
            login,
            refresh_token,
            logout,
            get_auth_status,
            get_device_id,
            vpn_connect,
            vpn_disconnect,
            get_vpn_servers,
            get_vpn_status
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
