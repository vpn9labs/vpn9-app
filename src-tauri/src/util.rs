use sha2::{Digest, Sha256};

// Logging helpers (sanitize + structure)
pub fn short_hash(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let out = hasher.finalize();
    format!("{out:x}")[..8].to_string()
}

pub fn get_device_name() -> String {
    use sysinfo::System;

    let os_name = System::name().unwrap_or_default();
    let hostname = System::host_name().unwrap_or_default();

    if hostname.is_empty() {
        format!("Desktop {os_name}")
    } else {
        format!("{hostname} ({os_name})")
    }
}
