use sha2::{Digest, Sha256};

// Logging helpers (sanitize + structure)
pub fn short_hash(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let out = hasher.finalize();
    format!("{out:x}")[..8].to_string()
}
