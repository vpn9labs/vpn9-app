use reqwest::header::RETRY_AFTER;
use std::time::Duration;
use tokio::time::sleep;

use crate::auth::{clear_stored_tokens, get_stored_tokens, is_jwt_expired, refresh_token};

pub fn default_timeout() -> Duration {
    Duration::from_secs(10)
}

pub async fn request_with_retry<F>(
    mut build: F,
    max_retries: usize,
) -> Result<reqwest::Response, String>
where
    F: FnMut() -> reqwest::RequestBuilder,
{
    let mut attempt: usize = 0;
    let mut backoff_ms: u64 = 200;

    loop {
        attempt += 1;
        let req = build();
        let result = req.send().await;

        match result {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    return Ok(resp);
                }
                // Retry on 408, 429, and 5xx
                let should_retry_status = status.as_u16() == 408
                    || status == reqwest::StatusCode::TOO_MANY_REQUESTS
                    || status.is_server_error();
                if should_retry_status && attempt < max_retries {
                    // Honor Retry-After header if present (seconds)
                    let mut wait = backoff_ms;
                    if let Some(hv) = resp.headers().get(RETRY_AFTER) {
                        if let Ok(s) = hv.to_str() {
                            if let Ok(secs) = s.parse::<u64>() {
                                wait = secs.saturating_mul(1000);
                            }
                        }
                    }
                    sleep(Duration::from_millis(wait)).await;
                    backoff_ms = (backoff_ms * 2).min(1500);
                    continue;
                }
                return Ok(resp);
            }
            Err(e) => {
                if attempt < max_retries && (e.is_connect() || e.is_timeout()) {
                    sleep(Duration::from_millis(backoff_ms)).await;
                    backoff_ms = (backoff_ms * 2).min(1500);
                    continue;
                }
                let msg = if e.is_connect() {
                    "Cannot connect to VPN9 servers. Please check your internet connection."
                        .to_string()
                } else if e.is_timeout() {
                    "Connection to VPN9 servers timed out. Please try again.".to_string()
                } else {
                    format!("Network error: {e}")
                };
                return Err(msg);
            }
        }
    }
}

pub async fn authorized_get_with_refresh(url: &str) -> Result<reqwest::Response, String> {
    let (access_token, _refresh_token) = get_stored_tokens()
        .await
        .map_err(|e| format!("Not authenticated: {e}"))?;

    // Proactive refresh if token appears expired (with small skew)
    if let Ok(true) = is_jwt_expired(&access_token, 30) {
        let _ = refresh_token().await; // Ignore message; errors handled by retry below
    }

    // Load (possibly refreshed) token
    let (access_token, _) = get_stored_tokens()
        .await
        .map_err(|e| format!("Not authenticated: {e}"))?;

    let client = reqwest::Client::builder()
        .timeout(default_timeout())
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {e}"))?;

    let resp = request_with_retry(
        || {
            client
                .get(url)
                .header("Authorization", format!("Bearer {access_token}"))
                .timeout(default_timeout())
        },
        3,
    )
    .await?;

    if resp.status().as_u16() != 401 {
        return Ok(resp);
    }

    // 401 -> try refresh once, then retry
    let _ = refresh_token().await?;
    let (new_access, _) = get_stored_tokens().await?;
    let retry = request_with_retry(
        || {
            client
                .get(url)
                .header("Authorization", format!("Bearer {new_access}"))
                .timeout(default_timeout())
        },
        3,
    )
    .await?;

    if retry.status().as_u16() == 401 {
        // Clear tokens to force re-login path
        let _ = clear_stored_tokens().await;
        return Err("Unauthorized. Please login again.".to_string());
    }

    Ok(retry)
}
