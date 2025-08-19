use std::collections::HashMap;
use std::path::PathBuf;

use base64::{Engine as _, engine::general_purpose};
use keyring::Entry;
use log::debug;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::Emitter;
use uuid::Uuid;

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
        use winreg::prelude::*;
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

// Token storage with fallback mechanism
#[derive(Serialize, Deserialize)]
struct TokenStorage {
    access_token: String,
    refresh_token: String,
    // Store as base64 encoded encrypted data
    encrypted: bool,
}

fn get_token_file_path() -> Result<PathBuf, String> {
    let config_dir = dirs::config_dir()
        .ok_or_else(|| "Could not determine config directory".to_string())?;
    let app_dir = config_dir.join("vpn9-client");
    
    // Create directory if it doesn't exist
    std::fs::create_dir_all(&app_dir)
        .map_err(|e| format!("Failed to create config directory: {}", e))?;
    
    Ok(app_dir.join(".tokens"))
}

fn simple_encrypt(data: &str, key: &str) -> String {
    // Simple XOR encryption with SHA256 of a hardcoded key
    // This is not cryptographically secure but better than plaintext
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hasher.update(b"vpn9-client-salt-2024");
    let key_hash = hasher.finalize();
    
    let encrypted: Vec<u8> = data.bytes()
        .zip(key_hash.iter().cycle())
        .map(|(d, k)| d ^ k)
        .collect();
    
    general_purpose::STANDARD.encode(encrypted)
}

fn simple_decrypt(encrypted: &str, key: &str) -> Result<String, String> {
    let data = general_purpose::STANDARD.decode(encrypted)
        .map_err(|e| format!("Failed to decode encrypted data: {}", e))?;
    
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hasher.update(b"vpn9-client-salt-2024");
    let key_hash = hasher.finalize();
    
    let decrypted: Vec<u8> = data.iter()
        .zip(key_hash.iter().cycle())
        .map(|(d, k)| d ^ k)
        .collect();
    
    String::from_utf8(decrypted)
        .map_err(|e| format!("Failed to decrypt data: {}", e))
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

async fn store_tokens_to_file(access_token: &str, refresh_token: &str) -> Result<(), String> {
    let file_path = get_token_file_path()?;
    
    // Get a machine-specific key for encryption
    let machine_id = get_os_machine_id().await
        .unwrap_or_else(|_| "fallback-key".to_string());
    
    let storage = TokenStorage {
        access_token: simple_encrypt(access_token, &machine_id),
        refresh_token: simple_encrypt(refresh_token, &machine_id),
        encrypted: true,
    };
    
    let json = serde_json::to_string(&storage)
        .map_err(|e| format!("Failed to serialize tokens: {}", e))?;
    
    tokio::fs::write(&file_path, json)
        .await
        .map_err(|e| format!("Failed to write token file: {}", e))?;
    
    // Set restrictive permissions on Unix systems
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(&file_path)
            .map_err(|e| format!("Failed to get file metadata: {}", e))?;
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o600); // Read/write for owner only
        std::fs::set_permissions(&file_path, permissions)
            .map_err(|e| format!("Failed to set file permissions: {}", e))?;
    }
    
    Ok(())
}

async fn store_tokens(access_token: &str, refresh_token: &str) -> Result<(), String> {
    // Try keyring first
    match store_tokens_to_keyring(access_token, refresh_token).await {
        Ok(_) => {
            debug!("Tokens stored in keyring");
            Ok(())
        },
        Err(keyring_err) => {
            // Fallback to file storage
            debug!("Keyring failed: {}, using file storage", keyring_err);
            store_tokens_to_file(access_token, refresh_token).await
                .map_err(|e| format!("Both keyring and file storage failed. Keyring: {}, File: {}", keyring_err, e))
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

async fn get_tokens_from_file() -> Result<(String, String), String> {
    let file_path = get_token_file_path()?;
    
    let json = tokio::fs::read_to_string(&file_path)
        .await
        .map_err(|e| format!("Failed to read token file: {}", e))?;
    
    let storage: TokenStorage = serde_json::from_str(&json)
        .map_err(|e| format!("Failed to parse token file: {}", e))?;
    
    if storage.encrypted {
        let machine_id = get_os_machine_id().await
            .unwrap_or_else(|_| "fallback-key".to_string());
        
        let access_token = simple_decrypt(&storage.access_token, &machine_id)?;
        let refresh_token = simple_decrypt(&storage.refresh_token, &machine_id)?;
        Ok((access_token, refresh_token))
    } else {
        Ok((storage.access_token, storage.refresh_token))
    }
}

async fn get_stored_tokens() -> Result<(String, String), String> {
    // Try keyring first
    match get_tokens_from_keyring().await {
        Ok(tokens) => Ok(tokens),
        Err(_) => {
            // Fallback to file storage
            get_tokens_from_file().await
        }
    }
}

async fn clear_stored_tokens() -> Result<(), String> {
    // Try to clear from both storage mechanisms
    let mut errors = Vec::new();
    
    // Clear keyring
    if let Ok(access_entry) = get_keyring_entry("access_token") {
        let _ = access_entry.delete_password();
    }
    if let Ok(refresh_entry) = get_keyring_entry("refresh_token") {
        let _ = refresh_entry.delete_password();
    }
    
    // Clear file
    if let Ok(file_path) = get_token_file_path() {
        if let Err(e) = tokio::fs::remove_file(&file_path).await {
            if e.kind() != std::io::ErrorKind::NotFound {
                errors.push(format!("Failed to remove token file: {}", e));
            }
        }
    }
    
    if !errors.is_empty() {
        Err(errors.join(", "))
    } else {
        Ok(())
    }
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
    debug!("login command");

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
    debug!("passphrase: {passphrase}");
    debug!("device id: {device_id}");
    debug!("device name: {device_name}");

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

    // Get the response text first for debugging
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

    // Print the raw response for debugging
    println!("Raw server response: {}", response_text);

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
    debug!("Connecting to VPN server: {}", server_id);

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
    debug!("Disconnecting from VPN");

    // TODO: Implement actual VPN disconnection logic
    // This would typically involve:
    // 1. Stopping the VPN service
    // 2. Cleaning up configuration
    // 3. Updating connection status

    Ok("Disconnected from VPN".to_string())
}

#[tauri::command]
async fn get_vpn_servers() -> Result<Vec<serde_json::Value>, String> {
    debug!("Fetching VPN servers");

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

    // Get the response text first for debugging
    let response_text = match response.text().await {
        Ok(text) => text,
        Err(e) => {
            return Err(format!("Failed to read response: {}", e));
        }
    };

    // Print the raw JSON response for debugging
    println!("VPN9 API /api/v1/relays response:");
    println!("{}", response_text);

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
        println!("No servers returned from API, using mock data");
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

    println!("Parsed {} servers from API response", servers.len());
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
    tauri::Builder::default()
        .plugin(tauri_plugin_log::Builder::new().build())
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
