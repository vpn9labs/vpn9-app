pub mod auth;
pub mod devices;
pub mod misc;
pub mod relays;
pub mod util;
pub mod vpn;
pub mod wireguard;

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
            let ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
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
            out.finish(format_args!("{obj}"))
        })
        .build();

    tauri::Builder::default()
        .plugin(log_plugin)
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            crate::wireguard::spawn_watch_task(&app.handle());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            crate::misc::greet,
            crate::misc::open_url,
            crate::auth::login,
            crate::auth::refresh_token,
            crate::auth::logout,
            crate::auth::get_auth_status,
            crate::auth::get_device_id,
            crate::vpn::vpn_connect,
            crate::vpn::vpn_disconnect,
            crate::relays::get_vpn_servers,
            crate::vpn::get_vpn_status
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
