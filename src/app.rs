use leptos::task::spawn_local;
use leptos::{ev::SubmitEvent, prelude::*};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use wasm_bindgen::{closure::Closure, JsCast};

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = ["window", "__TAURI__", "core"])]
    async fn invoke(cmd: &str, args: JsValue) -> JsValue;

    #[wasm_bindgen(js_namespace = ["window", "__TAURI__", "event"])]
    fn once(event: &str, handler: &js_sys::Function) -> js_sys::Promise;
}

// Event payload structures
#[derive(Debug, Deserialize)]
struct LoginSuccessPayload {
    message: String,
}

#[derive(Debug, Deserialize)]
struct LoginErrorPayload {
    error: String,
}

// Typed invoke helper (no unwraps)
async fn invoke_typed<T, A>(cmd: &str, args: &A) -> Result<T, String>
where
    T: for<'de> Deserialize<'de>,
    A: ?Sized + Serialize,
{
    let args_js =
        serde_wasm_bindgen::to_value(args).map_err(|e| format!("Failed to serialize args: {e}"))?;
    let value = invoke(cmd, args_js).await;
    serde_wasm_bindgen::from_value::<T>(value.clone()).map_err(|e| {
        let fallback = value
            .as_string()
            .unwrap_or_else(|| "Unknown response".to_string());
        format!("Failed to decode response: {e}; data={fallback}")
    })
}

// LoginArgs struct removed - now handled by backend

// VPN connection states
#[derive(Debug, Clone, PartialEq)]
enum VpnConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
    Error(String),
}

// VPN server location
#[derive(Debug, Clone, Deserialize)]
struct VpnServer {
    id: String,
    name: String,
    country: String,
    city: String,
    load: f32,
    hostname: String,
    #[serde(default)]
    public_key: String,
    #[serde(default = "default_wireguard_port")]
    port: u16,
}

fn default_wireguard_port() -> u16 {
    51820
}

#[derive(Debug, Clone, Deserialize)]
struct ActionResponse {
    message: String,
}

#[derive(Debug, Clone, Deserialize)]
struct AuthStatus {
    authenticated: bool,
    #[serde(rename = "token_present")]
    _token_present: bool,
}

#[component]
fn VpnConnectionPanel() -> impl IntoView {
    let (connection_state, set_connection_state) = signal(VpnConnectionState::Disconnected);
    let (selected_server, set_selected_server) = signal(None::<VpnServer>);
    let (servers, set_servers) = signal(Vec::<VpnServer>::new());
    let (connection_info, set_connection_info) = signal(String::new());

    // Load available servers on mount
    spawn_local(async move {
        match invoke_typed::<Vec<VpnServer>, _>("get_vpn_servers", &serde_json::json!({})).await {
            Ok(server_list) => {
                if let Some(first_server) = server_list.first() {
                    set_selected_server.set(Some(first_server.clone()));
                }
                set_servers.set(server_list);
            }
            Err(e) => set_connection_info.set(format!("Error loading servers: {e}")),
        }
    });

    let handle_connect = move |_| {
        let server = match selected_server.get_untracked() {
            Some(s) => s,
            None => {
                set_connection_info.set("Please select a server first".to_string());
                return;
            }
        };
        set_connection_state.set(VpnConnectionState::Connecting);
        set_connection_info.set(format!("Connecting to {}...", server.name));

        let server_clone = server.clone();
        spawn_local(async move {
            let args = serde_json::json!({
                "serverId": server_clone.id,
                "serverName": server_clone.name,
                "hostname": server_clone.hostname,
                "publicKey": server_clone.public_key,
                "port": server_clone.port,
            });
            match invoke_typed::<ActionResponse, _>("vpn_connect", &args).await {
                Ok(_resp) => {
                    set_connection_state.set(VpnConnectionState::Connected);
                    set_connection_info.set(format!("Connected to {}", server_clone.name));
                }
                Err(e) => {
                    set_connection_state.set(VpnConnectionState::Error(e.clone()));
                    set_connection_info.set(format!("Connection failed: {e}"));
                }
            }
        });
    };

    let handle_disconnect = move |_| {
        set_connection_state.set(VpnConnectionState::Disconnecting);
        set_connection_info.set("Disconnecting...".to_string());

        spawn_local(async move {
            // Call Tauri command to disconnect
            match invoke_typed::<ActionResponse, _>("vpn_disconnect", &serde_json::json!({})).await
            {
                Ok(_resp) => {
                    set_connection_state.set(VpnConnectionState::Disconnected);
                    set_connection_info.set("Disconnected".to_string());
                }
                Err(e) => {
                    set_connection_state.set(VpnConnectionState::Error(e.clone()));
                    set_connection_info.set(format!("Disconnect failed: {e}"));
                }
            }
        });
    };

    let handle_server_change = move |ev| {
        let value = event_target_value(&ev);
        if let Some(server) = servers.get_untracked().into_iter().find(|s| s.id == value) {
            set_selected_server.set(Some(server));
        }
    };

    view! {
        <div class="vpn-panel">
            <h3 class="vpn-title">"VPN Connection"</h3>

            // Connection status
            <div class="connection-status">
                <div class="status-indicator" class:connected=move || matches!(connection_state.get(), VpnConnectionState::Connected)>
                    <span class="status-dot"></span>
                    <span class="status-text">
                        {move || match connection_state.get() {
                            VpnConnectionState::Disconnected => "Disconnected",
                            VpnConnectionState::Connecting => "Connecting...",
                            VpnConnectionState::Connected => "Connected",
                            VpnConnectionState::Disconnecting => "Disconnecting...",
                            VpnConnectionState::Error(_) => "Error",
                        }}
                    </span>
                </div>
                <div class="connection-info">
                    {move || connection_info.get()}
                </div>
            </div>

            // Server selection
            <div class="server-selection">
                <label for="server-select">"Select Server:"</label>
                <select
                    id="server-select"
                    class="server-select"
                    on:change=handle_server_change
                    disabled=move || !matches!(connection_state.get(), VpnConnectionState::Disconnected)
                >
                    <For
                        each=move || servers.get()
                        key=|server| server.id.clone()
                        children=move |server| {
                            view! {
                                <option value={server.id.clone()}>
                                    {format!("{} - {}, {} ({:.0}% load)", server.name, server.city, server.country, server.load)}
                                </option>
                            }
                        }
                    />
                </select>
            </div>

            // Connection button
            <div class="vpn-button-group">
                <Show
                    when=move || matches!(connection_state.get(), VpnConnectionState::Disconnected)
                    fallback=move || view! {
                        <button
                            type="button"
                            class="disconnect-button"
                            on:click=handle_disconnect
                            disabled=move || matches!(connection_state.get(), VpnConnectionState::Connecting | VpnConnectionState::Disconnecting)
                        >
                            "Disconnect"
                        </button>
                    }
                >
                    <button
                        type="button"
                        class="connect-button"
                        on:click=handle_connect
                    >
                        "Connect"
                    </button>
                </Show>
            </div>
        </div>
    }
}

#[component]
pub fn App() -> impl IntoView {
    let (passphrase, set_passphrase) = signal(String::new());
    let (login_status, set_login_status) = signal(String::new());
    let (is_authenticated, set_is_authenticated) = signal(false);

    // Load auth status on component mount
    spawn_local(async move {
        match invoke_typed::<AuthStatus, _>("get_auth_status", &serde_json::json!({})).await {
            Ok(status) => set_is_authenticated.set(status.authenticated),
            Err(_) => set_is_authenticated.set(false),
        }
    });

    let update_passphrase = move |ev| {
        let v = event_target_value(&ev);
        set_passphrase.set(v);
    };

    let handle_login = move |ev: SubmitEvent| {
        ev.prevent_default();

        let passphrase_value = passphrase.get_untracked();
        let set_login_status = set_login_status;
        let set_is_authenticated = set_is_authenticated;

        spawn_local(async move {
            // Clear any previous status
            set_login_status.set("Authenticating with VPN9 servers...".to_string());

            // Create closures for event handlers
            let set_status_clone = set_login_status;
            let status_handler = Closure::wrap(Box::new(move |event: JsValue| {
                if let Some(payload) = event.as_string() {
                    set_status_clone.set(payload);
                }
            }) as Box<dyn FnMut(JsValue)>);

            let set_status_error = set_login_status;
            let set_auth_error = set_is_authenticated;
            let error_handler = Closure::wrap(Box::new(move |event: JsValue| {
                // Parse the event payload
                if let Ok(payload_obj) = js_sys::Reflect::get(&event, &"payload".into()) {
                    if let Ok(json_str) = js_sys::JSON::stringify(&payload_obj) {
                        if let Some(json) = json_str.as_string() {
                            if let Ok(payload) = serde_json::from_str::<LoginErrorPayload>(&json) {
                                set_status_error.set(payload.error);
                                set_auth_error.set(false);
                            }
                        }
                    }
                }
            }) as Box<dyn FnMut(JsValue)>);

            let set_status_success = set_login_status;
            let set_auth_success = set_is_authenticated;
            let set_passphrase_success = set_passphrase;
            let success_handler = Closure::wrap(Box::new(move |event: JsValue| {
                // Parse the event payload
                if let Ok(payload_obj) = js_sys::Reflect::get(&event, &"payload".into()) {
                    if let Ok(json_str) = js_sys::JSON::stringify(&payload_obj) {
                        if let Some(json) = json_str.as_string() {
                            if let Ok(payload) = serde_json::from_str::<LoginSuccessPayload>(&json)
                            {
                                set_status_success.set(payload.message);
                                set_auth_success.set(true);
                                // Clear passphrase from input/state on success
                                set_passphrase_success.set(String::new());
                            }
                        }
                    }
                }
            }) as Box<dyn FnMut(JsValue)>);

            // Listen for events
            let _ = once("login-status", status_handler.as_ref().unchecked_ref());
            let _ = once("login-error", error_handler.as_ref().unchecked_ref());
            let _ = once("login-success", success_handler.as_ref().unchecked_ref());

            // Keep closures alive during the request
            let _status_handler = status_handler;
            let _error_handler = error_handler;
            let _success_handler = success_handler;

            // Call the login command
            let login_args = match serde_wasm_bindgen::to_value(&serde_json::json!({
                "passphrase": passphrase_value
            })) {
                Ok(v) => v,
                Err(e) => {
                    set_login_status.set(format!("Failed to serialize login args: {e}"));
                    return;
                }
            };

            // The login command emits events; ignore return value
            let _ = invoke("login", login_args).await;
        });
    };

    let handle_logout = move |_| {
        spawn_local(async move {
            set_login_status.set("Logging out...".to_string());

            match invoke_typed::<ActionResponse, _>("logout", &serde_json::json!({})).await {
                Ok(resp) => {
                    set_login_status.set(resp.message);
                    set_is_authenticated.set(false);
                    set_passphrase.set(String::new());
                }
                Err(error) => {
                    set_login_status.set(format!("Logout failed: {error}"));
                }
            }
        });
    };

    let open_signup = move |_| {
        // Open signup page in external browser using custom Tauri command
        spawn_local(async move {
            let url = "https://vpn9.com/signup";
            let args_js = match serde_wasm_bindgen::to_value(&serde_json::json!({ "url": url })) {
                Ok(v) => v,
                Err(_) => return,
            };
            let _ = invoke("open_url", args_js).await;
        });
    };

    view! {
        <main class="login-container">
            <div class="login-card">
                // VPN9 Logo
                <div class="logo-section">
                    <h1 class="vpn9-logo">"VPN9"</h1>
                </div>

                // Authenticated state content
                <Show when=move || is_authenticated.get()>
                    <div class="authenticated-content">
                        <h2 class="welcome-title">"Welcome back!"</h2>
                        <p class="auth-status">"You are successfully authenticated with VPN9"</p>

                        // Status message
                        <div class="status-message">
                            { move || login_status.get() }
                        </div>

                        // VPN connection controls
                        <div class="vpn-controls">
                            <VpnConnectionPanel />
                        </div>

                        // Logout button
                        <div class="button-group">
                            <button type="button" class="logout-button" on:click=handle_logout>
                                "Logout"
                            </button>
                        </div>
                    </div>
                </Show>

                // Login form (shown when not authenticated)
                <Show when=move || !is_authenticated.get()>
                    <div class="login-form">
                        <h2 class="login-title">"Enter your login passphrase"</h2>

                        // Status message
                        <div class="status-message">
                            { move || {
                                let status = login_status.get();
                                if !status.is_empty() {
                                    status
                                } else {
                                    String::new()
                                }
                            }}
                        </div>

                        <form on:submit=handle_login>
                            <div class="input-group">
                                <input
                                    type="text"
                                    id="passphrase-input"
                                    class="passphrase-input"
                                    placeholder="xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx"
                                    value=move || passphrase.get()
                                    on:input=update_passphrase
                                />
                            </div>

                            <div class="button-group">
                                <button type="submit" class="login-button">"Login"</button>
                            </div>
                        </form>

                        // Create account button
                        <div class="signup-section">
                            <button type="button" class="signup-button" on:click=open_signup>
                                "Create an account"
                            </button>
                        </div>
                    </div>
                </Show>
            </div>
        </main>
    }
}
