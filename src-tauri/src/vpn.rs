use log::info;

use crate::auth::{get_stored_tokens, ActionResponse};
use crate::devices::ensure_device_registered;

// VPN connection commands
#[tauri::command]
pub async fn vpn_connect(
    server_id: String,
    _app: tauri::AppHandle,
) -> Result<ActionResponse, String> {
    info!("event=vpn.connect.start server_id={server_id}");

    // Get stored access token
    get_stored_tokens()
        .await
        .map_err(|e| format!("Not authenticated: {e}"))?;

    let device_sync = ensure_device_registered(Some(server_id.clone())).await?;
    info!(
        "event=vpn.device.synced regenerated={} created={}",
        device_sync.keys_regenerated, device_sync.newly_created
    );

    // TODO: Implement actual VPN connection logic

    Ok(ActionResponse {
        message: format!("Connected to server: {server_id}"),
    })
}

#[tauri::command]
pub async fn vpn_disconnect() -> Result<ActionResponse, String> {
    info!("event=vpn.disconnect.start");

    // TODO: Implement actual VPN disconnection logic

    Ok(ActionResponse {
        message: "Disconnected from VPN".to_string(),
    })
}

#[tauri::command]
pub async fn get_vpn_status() -> Result<serde_json::Value, String> {
    // TODO: Implement actual VPN status checking
    Ok(serde_json::json!({
        "connected": false,
        "server_id": null,
        "connection_time": null,
        "bytes_sent": 0,
        "bytes_received": 0
    }))
}
