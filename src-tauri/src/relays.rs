use log::{debug, info, warn};
use reqwest::Error as ReqwestError;

use crate::auth::{
    access_token_with_refresh, clear_stored_tokens, get_stored_tokens, refresh_token, API_BASE_URL,
};
use vpn9_api::{ApiError as Vpn9ApiError, Client as Vpn9ApiClient};

#[tauri::command]
pub async fn get_vpn_servers() -> Result<Vec<serde_json::Value>, String> {
    info!("event=relays.fetch.start");

    let response_json = fetch_relays().await?;

    let response_size = serde_json::to_vec(&response_json)
        .map(|bytes| bytes.len())
        .unwrap_or(0);
    debug!(
        "event=relays.response received_bytes={} json_parse_attempt=true",
        response_size
    );

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
                            let status = relay
                                .get("status")
                                .and_then(|s| s.as_str())
                                .unwrap_or("active");
                            if status != "active" {
                                continue;
                            }

                            let hostname =
                                relay.get("hostname").and_then(|h| h.as_str()).unwrap_or("");
                            let relay_id =
                                relay.get("id").and_then(|i| i.as_str()).unwrap_or(hostname);
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
                                "id": relay_id,
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
                                "port": multihop_port,
                                "multihop_port": multihop_port,
                                "load": 0.0
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

async fn fetch_relays() -> Result<serde_json::Value, String> {
    let client = Vpn9ApiClient::new(API_BASE_URL)
        .map_err(|e| format!("Failed to initialize API client: {e}"))?;

    let mut access_token = access_token_with_refresh(4 * 3600).await?;

    match client.list_relays(&access_token).await {
        Ok(data) => Ok(data),
        Err(Vpn9ApiError::Unauthorized) => {
            let _ = refresh_token().await?;
            access_token = get_stored_tokens().await?.0;

            match client.list_relays(&access_token).await {
                Ok(data) => Ok(data),
                Err(Vpn9ApiError::Unauthorized) => {
                    clear_stored_tokens().await?;
                    Err("Unauthorized. Please login again.".to_string())
                }
                Err(err) => Err(relay_error_message(&err)),
            }
        }
        Err(err) => Err(relay_error_message(&err)),
    }
}

fn relay_error_message(err: &Vpn9ApiError) -> String {
    match err {
        Vpn9ApiError::Unauthorized => "Unauthorized. Please login again.".to_string(),
        Vpn9ApiError::HttpClient(inner) => describe_network_error(inner),
        Vpn9ApiError::UnexpectedStatus { status, body } => {
            if body.trim().is_empty() {
                format!("Failed to fetch servers ({status}). Please try again.")
            } else {
                format!("Failed to fetch servers ({status}): {body}")
            }
        }
        Vpn9ApiError::UnprocessableEntity(body) => {
            format!("Failed to fetch servers: {body}")
        }
        Vpn9ApiError::NotFound => {
            "Server list endpoint not found. Please try again later.".to_string()
        }
        _ => format!("Failed to fetch servers: {err}"),
    }
}

fn describe_network_error(err: &ReqwestError) -> String {
    if err.is_connect() {
        "Cannot connect to VPN9 servers. Please check your internet connection.".to_string()
    } else if err.is_timeout() {
        "Connection to VPN9 servers timed out. Please try again.".to_string()
    } else {
        format!("Network error: {err}")
    }
}
