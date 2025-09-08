#[tauri::command]
pub fn greet(name: &str) -> String {
    format!("Hello, {name}! You've been greeted from Rust!")
}

#[tauri::command]
pub async fn open_url(url: String) -> Result<(), String> {
    tauri_plugin_opener::open_url(url, None::<String>)
        .map_err(|e| format!("Failed to open URL: {e}"))
}
