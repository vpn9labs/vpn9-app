use log::{debug, info, warn};

use crate::http::authorized_get_with_refresh;

#[tauri::command]
pub async fn get_vpn_servers() -> Result<Vec<serde_json::Value>, String> {
    info!("event=relays.fetch.start");

    // Fetch actual server list from API with auto-refresh on 401
    let response = authorized_get_with_refresh("https://vpn9.com/api/v1/relays").await?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await.unwrap_or_default();
        return Err(format!("Failed to fetch servers ({status}): {error_text}"));
    }

    // Get the response text without logging sensitive contents
    let response_text = match response.text().await {
        Ok(text) => text,
        Err(e) => {
            return Err(format!("Failed to read response: {e}"));
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
            return Err(format!("Failed to parse server response: {e}"));
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
