use base64::{engine::general_purpose::STANDARD, Engine as _};
use keyring::{Entry, Error as KeyringError};
use log::{debug, info, warn};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::auth::{get_os_machine_id, KEYRING_SERVICE};
use crate::http::authorized_post_json_with_refresh;
use crate::util::short_hash;

const WG_PRIVATE_KEY: &str = "wg_private_key";
const WG_PUBLIC_KEY: &str = "wg_public_key";
const WG_FALLBACK_FILE: &str = "wg-keys";

#[cfg(feature = "file-fallback-aead")]
mod fallback_store {
    use super::*;
    use base64::engine::general_purpose;
    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
    use hkdf::Hkdf;
    use rand::RngCore;
    use sha2::Sha256;
    use tokio::fs;

    #[derive(Serialize, Deserialize)]
    struct StoredKeysFile {
        v: u8,
        salt: String,
        nonce: String,
        ct: String,
    }

    fn derive_key(machine_id: &str, salt: &[u8]) -> Result<Key, String> {
        let hk = Hkdf::<Sha256>::new(Some(salt), machine_id.as_bytes());
        let mut okm = [0u8; 32];
        hk.expand(b"vpn9-aead-wg-keys-v1", &mut okm)
            .map_err(|_| "HKDF expand failed".to_string())?;
        Ok(Key::from_slice(&okm).clone())
    }

    fn keys_file_path() -> Result<PathBuf, String> {
        let config_dir =
            dirs::config_dir().ok_or_else(|| "Could not determine config directory".to_string())?;
        let app_dir = config_dir.join("vpn9-client");
        std::fs::create_dir_all(&app_dir)
            .map_err(|e| format!("Failed to create config directory: {e}"))?;
        Ok(app_dir.join(super::WG_FALLBACK_FILE))
    }

    pub async fn store_keys(private_b64: &str, public_b64: &str) -> Result<(), String> {
        let path = keys_file_path()?;

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

        let plaintext = serde_json::to_vec(&serde_json::json!({
            "private": private_b64,
            "public": public_b64,
        }))
        .map_err(|e| format!("Failed to serialize key payload: {e}"))?;

        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_slice())
            .map_err(|_| "AEAD encryption failed".to_string())?;

        let file = StoredKeysFile {
            v: 1,
            salt: general_purpose::STANDARD.encode(salt),
            nonce: general_purpose::STANDARD.encode(nonce_bytes),
            ct: general_purpose::STANDARD.encode(ciphertext),
        };

        let json = serde_json::to_string(&file)
            .map_err(|e| format!("Failed to serialize key file: {e}"))?;

        fs::write(&path, json)
            .await
            .map_err(|e| format!("Failed to write key file: {e}"))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = std::fs::metadata(&path)
                .map_err(|e| format!("Failed to get file metadata: {e}"))?;
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o600);
            std::fs::set_permissions(&path, permissions)
                .map_err(|e| format!("Failed to set file permissions: {e}"))?;
        }

        Ok(())
    }

    pub async fn load_keys() -> Result<Option<(String, String)>, String> {
        let path = keys_file_path()?;
        let contents = match fs::read_to_string(&path).await {
            Ok(data) => data,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("Failed to read key file: {e}")),
        };

        let file: StoredKeysFile = serde_json::from_str(&contents)
            .map_err(|e| format!("Failed to parse key file: {e}"))?;

        let salt = general_purpose::STANDARD
            .decode(file.salt)
            .map_err(|e| format!("Failed to decode salt: {e}"))?;
        let nonce_bytes = general_purpose::STANDARD
            .decode(file.nonce)
            .map_err(|e| format!("Failed to decode nonce: {e}"))?;
        let ciphertext = general_purpose::STANDARD
            .decode(file.ct)
            .map_err(|e| format!("Failed to decode ciphertext: {e}"))?;

        let machine_id = super::get_os_machine_id()
            .await
            .unwrap_or_else(|_| "fallback".to_string());
        let key = derive_key(&machine_id, &salt)?;
        let cipher = ChaCha20Poly1305::new(&key);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_slice())
            .map_err(|_| "AEAD decryption failed".to_string())?;

        let json: serde_json::Value = serde_json::from_slice(&plaintext)
            .map_err(|e| format!("Failed to parse decrypted payload: {e}"))?;
        let private = json
            .get("private")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing private key".to_string())?
            .to_string();
        let public = json
            .get("public")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Missing public key".to_string())?
            .to_string();

        Ok(Some((private, public)))
    }

    pub async fn clear_keys() -> Result<(), String> {
        let path = keys_file_path()?;
        match fs::remove_file(&path).await {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("Failed to remove key file: {e}")),
        }
    }
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
struct VerifyDeviceResponse {
    device: DeviceRecord,
}

#[derive(Debug, Deserialize)]
struct CreateDeviceResponse {
    device: DeviceRecord,
}

#[derive(Debug)]
enum DeviceApiError {
    NotFound,
    Api(String),
}

#[derive(Debug)]
pub struct DeviceSyncOutcome {
    pub device: DeviceRecord,
    pub keys_regenerated: bool,
    pub newly_created: bool,
}

pub async fn ensure_device_registered(
    relay_hint: Option<String>,
) -> Result<DeviceSyncOutcome, String> {
    let mut keys_regenerated = false;

    // Load existing keys or generate new ones if missing
    let mut keys = match load_wireguard_keys().await? {
        Some(pair) => pair,
        None => {
            let generated = generate_wireguard_keypair()?;
            store_wireguard_keys(&generated.0, &generated.1).await?;
            keys_regenerated = true;
            info!("event=device.keys.generated initial=true");
            generated
        }
    };

    if keys.1.is_empty() {
        keys.1 = derive_public_from_private(&keys.0)?;
        store_wireguard_keys(&keys.0, &keys.1).await?;
    }

    match verify_device(&keys.1).await {
        Ok(device) => {
            debug!(
                "event=device.verify.success device_hash={}",
                short_hash(&device.id)
            );
            return Ok(DeviceSyncOutcome {
                device,
                keys_regenerated,
                newly_created: false,
            });
        }
        Err(DeviceApiError::NotFound) => {
            info!("event=device.verify.missing remote=not_found regenerating_keys=true");
            clear_wireguard_keys().await?;
        }
        Err(DeviceApiError::Api(err)) => {
            return Err(err);
        }
    }

    // Generate brand new keys after clearing
    let new_keys = generate_wireguard_keypair()?;
    keys_regenerated = true;

    if relay_hint.is_some() {
        warn!("event=device.relay.ignored relay_hint_provided=true");
    }

    let registration = create_device(&new_keys.1).await?;
    let CreateDeviceResponse { device } = registration;

    store_wireguard_keys(&new_keys.0, &new_keys.1).await?;

    debug!(
        "event=device.registered device_hash={}",
        short_hash(&device.id)
    );

    Ok(DeviceSyncOutcome {
        device,
        keys_regenerated,
        newly_created: true,
    })
}

pub async fn clear_wireguard_credentials() -> Result<(), String> {
    clear_wireguard_keys().await
}

fn generate_wireguard_keypair() -> Result<(String, String), String> {
    let mut private_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut private_bytes);
    // Clamp per X25519 requirements
    private_bytes[0] &= 248;
    private_bytes[31] &= 127;
    private_bytes[31] |= 64;

    let secret = StaticSecret::from(private_bytes);
    let public = PublicKey::from(&secret);

    let private_b64 = STANDARD.encode(secret.to_bytes());
    let public_b64 = STANDARD.encode(public.to_bytes());

    Ok((private_b64, public_b64))
}

fn derive_public_from_private(private_b64: &str) -> Result<String, String> {
    let private_bytes = STANDARD
        .decode(private_b64)
        .map_err(|e| format!("Failed to decode WireGuard private key: {e}"))?;
    if private_bytes.len() != 32 {
        return Err("Invalid WireGuard private key length".to_string());
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&private_bytes);
    let secret = StaticSecret::from(bytes);
    let public = PublicKey::from(&secret);
    Ok(STANDARD.encode(public.to_bytes()))
}

async fn load_wireguard_keys() -> Result<Option<(String, String)>, String> {
    match read_secret(WG_PRIVATE_KEY) {
        Ok(Some(private)) => {
            let public = match read_secret(WG_PUBLIC_KEY) {
                Ok(Some(value)) => value,
                Ok(None) => match derive_public_from_private(&private) {
                    Ok(pk) => {
                        if let Err(e) = store_secret(WG_PUBLIC_KEY, &pk) {
                            warn!(
                                "event=device.keys.store_public_failed err={} using=fallback",
                                e
                            );
                            #[cfg(feature = "file-fallback-aead")]
                            {
                                fallback_store::store_keys(&private, &pk).await?;
                            }
                            #[cfg(not(feature = "file-fallback-aead"))]
                            {
                                return Err(e);
                            }
                        }
                        pk
                    }
                    Err(_) => {
                        warn!("event=device.keys.invalid action=regenerate");
                        clear_wireguard_keys().await?;
                        return Ok(None);
                    }
                },
                Err(err) => {
                    warn!(
                        "event=device.keys.read_public_failed err={} using=fallback",
                        err
                    );
                    #[cfg(feature = "file-fallback-aead")]
                    {
                        if let Some(pair) = fallback_store::load_keys().await? {
                            return Ok(Some(pair));
                        }
                    }
                    #[cfg(not(feature = "file-fallback-aead"))]
                    {
                        return Err(err);
                    }
                    return Ok(None);
                }
            };
            Ok(Some((private, public)))
        }
        Ok(None) => {
            #[cfg(feature = "file-fallback-aead")]
            {
                if let Some(pair) = fallback_store::load_keys().await? {
                    return Ok(Some(pair));
                }
            }
            Ok(None)
        }
        Err(err) => {
            warn!(
                "event=device.keys.read_private_failed err={} using=fallback",
                err
            );
            #[cfg(feature = "file-fallback-aead")]
            {
                if let Some(pair) = fallback_store::load_keys().await? {
                    return Ok(Some(pair));
                }
            }
            #[cfg(not(feature = "file-fallback-aead"))]
            {
                return Err(err);
            }
            Ok(None)
        }
    }
}

async fn store_wireguard_keys(private_b64: &str, public_b64: &str) -> Result<(), String> {
    let private_res = store_secret(WG_PRIVATE_KEY, private_b64);
    let public_res = store_secret(WG_PUBLIC_KEY, public_b64);

    if private_res.is_ok() && public_res.is_ok() {
        return Ok(());
    }

    let mut errors = Vec::new();
    if let Err(e) = private_res {
        errors.push(e);
    }
    if let Err(ref e) = public_res {
        errors.push(e.to_string());
    }

    if public_res.is_err() {
        let _ = delete_secret(WG_PRIVATE_KEY);
    }

    #[cfg(feature = "file-fallback-aead")]
    {
        warn!(
            "event=device.keys.store keyring_failed using=aead_file err={}",
            errors.join(" | ")
        );
        fallback_store::store_keys(private_b64, public_b64).await?;
        debug!("event=device.keys.store backend=aead_file");
        return Ok(());
    }

    #[cfg(not(feature = "file-fallback-aead"))]
    {
        return Err(errors.join(" | "));
    }
}

async fn clear_wireguard_keys() -> Result<(), String> {
    if let Err(e) = delete_secret(WG_PRIVATE_KEY) {
        warn!("event=device.keys.clear_private_failed err={}", e);
    }
    if let Err(e) = delete_secret(WG_PUBLIC_KEY) {
        warn!("event=device.keys.clear_public_failed err={}", e);
    }

    #[cfg(feature = "file-fallback-aead")]
    {
        fallback_store::clear_keys().await?;
    }

    Ok(())
}

fn keyring_entry(key: &str) -> Result<Entry, String> {
    Entry::new(KEYRING_SERVICE, key)
        .map_err(|e| format!("Failed to access secure storage for {key}: {e}"))
}

fn read_secret(key: &str) -> Result<Option<String>, String> {
    let entry = keyring_entry(key)?;
    match entry.get_password() {
        Ok(value) => {
            let trimmed = value.trim().to_string();
            if trimmed.is_empty() {
                Ok(None)
            } else {
                Ok(Some(trimmed))
            }
        }
        Err(KeyringError::NoEntry) => Ok(None),
        Err(e) => Err(format!("Failed to read {key} from secure storage: {e}")),
    }
}

fn store_secret(key: &str, value: &str) -> Result<(), String> {
    keyring_entry(key)?
        .set_password(value)
        .map_err(|e| format!("Failed to store {key} in secure storage: {e}"))
}

fn delete_secret(key: &str) -> Result<(), String> {
    match keyring_entry(key) {
        Ok(entry) => match entry.delete_password() {
            Ok(_) | Err(KeyringError::NoEntry) => Ok(()),
            Err(e) => Err(format!("Failed to remove {key} from secure storage: {e}")),
        },
        Err(_e) => Ok(()),
    }
}

async fn verify_device(public_key: &str) -> Result<DeviceRecord, DeviceApiError> {
    let payload = serde_json::json!({ "public_key": public_key });
    let response =
        authorized_post_json_with_refresh("https://vpn9.com/api/v1/devices/verify", &payload)
            .await
            .map_err(DeviceApiError::Api)?;

    let status = response.status();
    if status.is_success() {
        let device: VerifyDeviceResponse = response.json().await.map_err(|e| {
            DeviceApiError::Api(format!("Failed to parse verification response: {e}"))
        })?;
        if device.device.status != "active" {
            return Err(DeviceApiError::Api(
                "Device is inactive. Please check your subscription.".to_string(),
            ));
        }
        return Ok(device.device);
    }

    let body = response.text().await.unwrap_or_default();
    if status.as_u16() == 404 {
        return Err(DeviceApiError::NotFound);
    }

    Err(DeviceApiError::Api(format!(
        "Device verification failed ({status}): {body}"
    )))
}

async fn create_device(public_key: &str) -> Result<CreateDeviceResponse, String> {
    let mut root = serde_json::Map::new();
    root.insert(
        "device".to_string(),
        serde_json::json!({
            "public_key": public_key,
        }),
    );

    let payload = serde_json::Value::Object(root);

    let response =
        authorized_post_json_with_refresh("https://vpn9.com/api/v1/devices", &payload).await?;

    let status = response.status();
    if status.as_u16() == 201 || status.is_success() {
        let registration: CreateDeviceResponse = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse device registration response: {e}"))?;
        return Ok(registration);
    }

    let body = response.text().await.unwrap_or_default();

    if status.as_u16() == 422 {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
            if let Some(limit) = json.get("device_limit").and_then(|v| v.as_u64()) {
                let registered = json
                    .get("devices_registered")
                    .and_then(|v| v.as_u64())
                    .unwrap_or_default();
                return Err(format!(
                    "Device limit reached. You have {registered}/{limit} devices registered. Remove one in VPN9 settings and try again."
                ));
            }

            if let Some(errors) = json.get("errors").and_then(|v| v.as_array()) {
                let combined = errors
                    .iter()
                    .filter_map(|e| e.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                if !combined.is_empty() {
                    return Err(format!("Device registration failed: {combined}"));
                }
            }

            if let Some(error) = json.get("error").and_then(|v| v.as_str()) {
                return Err(format!("Device registration failed: {error}"));
            }
        }
    }

    Err(format!("Device registration failed ({status}): {body}"))
}
