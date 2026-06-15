use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tauri::{
    plugin::{Builder, TauriPlugin},
    Listener, Manager, Runtime,
};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_tungstenite::tungstenite::Message;

const LISTEN_ADDR: &str = "127.0.0.1:31337";
const RESPONSE_TIMEOUT_SECS: u64 = 10;

// ---------------------------------------------------------------------------
// Protocol types (shared between plugin and Python orchestrator)
// ---------------------------------------------------------------------------

/// Incoming fuzz request from the Python orchestrator.
#[derive(Debug, Deserialize)]
struct FuzzRequest {
    /// Unique identifier to correlate request ↔ response.
    id: String,
    /// The Tauri command to invoke (e.g. "read_file").
    command: String,
    /// Arguments to pass to the command, forwarded as-is to invoke().
    args: serde_json::Value,
}

/// Result sent back to the orchestrator (and also emitted as a Tauri event
/// from the injected JavaScript).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FuzzResult {
    id: String,
    /// "success", "error", or "timeout"
    status: String,
    command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Map of pending request IDs → oneshot senders waiting for the JS callback.
type PendingMap = Arc<Mutex<HashMap<String, oneshot::Sender<FuzzResult>>>>;

// ---------------------------------------------------------------------------
// Command registry (populated by the generate_handler! macro)
// ---------------------------------------------------------------------------

static REGISTERED_COMMANDS: OnceLock<Vec<&'static str>> = OnceLock::new();

/// Called by the [`generate_handler!`] macro to record the list of command
/// names. Should not be called directly.
pub fn register_commands(commands: Vec<&'static str>) {
    REGISTERED_COMMANDS.set(commands).ok();
}

/// Returns the list of registered Tauri command names, or an empty slice if
/// the app did not use [`generate_handler!`].
pub fn get_registered_commands() -> &'static [&'static str] {
    REGISTERED_COMMANDS
        .get()
        .map(|v| v.as_slice())
        .unwrap_or(&[])
}

/// Drop-in replacement for [`tauri::generate_handler!`] that also registers
/// command names with the fuzz harness plugin for runtime discovery.
///
/// # Example
/// ```rust,ignore
/// .invoke_handler(tauri_plugin_fuzz_harness::generate_handler![
///     read_file, list_directory, fetch_url, process_data,
/// ])
/// ```
#[macro_export]
macro_rules! generate_handler {
    ($($cmd:path),* $(,)?) => {{
        $crate::register_commands(vec![$(stringify!($cmd)),*]);
        tauri::generate_handler![$($cmd),*]
    }};
}

// ---------------------------------------------------------------------------
// Plugin entry point
// ---------------------------------------------------------------------------

pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("fuzz-harness")
        .setup(|app_handle, _api| {
            let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));

            // --- Event listener ---
            // The injected JavaScript emits 'fuzz-result' events back to the
            // Rust backend after each invoke() call completes (or errors).
            let pending_for_listener = pending.clone();
            app_handle.listen("fuzz-result", move |event| {
                if let Ok(result) = serde_json::from_str::<FuzzResult>(event.payload()) {
                    let mut map = pending_for_listener.lock().unwrap();
                    if let Some(sender) = map.remove(&result.id) {
                        let _ = sender.send(result);
                    }
                } else {
                    eprintln!("[!] Failed to parse fuzz-result event: {}", event.payload());
                }
            });

            // --- WebSocket server ---
            let handle = app_handle.clone();
            tauri::async_runtime::spawn(async move {
                if let Err(e) = run_websocket_server(handle, pending).await {
                    eprintln!("[!] Fuzzing harness server error: {}", e);
                }
            });

            Ok(())
        })
        .build()
}

// ---------------------------------------------------------------------------
// WebSocket server
// ---------------------------------------------------------------------------

async fn run_websocket_server<R: Runtime>(
    app_handle: tauri::AppHandle<R>,
    pending: PendingMap,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(LISTEN_ADDR).await?;
    println!(
        "[*] Fuzz harness WebSocket server listening on ws://{}",
        LISTEN_ADDR
    );

    loop {
        let (stream, addr) = listener.accept().await?;
        println!("[*] Fuzzer connected from {}", addr);

        let handle = app_handle.clone();
        let pending = pending.clone();

        tokio::spawn(async move {
            let ws_stream = match tokio_tungstenite::accept_async(stream).await {
                Ok(ws) => ws,
                Err(e) => {
                    eprintln!("[!] WebSocket handshake failed from {}: {}", addr, e);
                    return;
                }
            };

            let (mut ws_write, mut ws_read) = ws_stream.split();

            while let Some(msg) = ws_read.next().await {
                let msg = match msg {
                    Ok(Message::Text(text)) => text,
                    Ok(Message::Close(_)) => {
                        println!("[*] Fuzzer {} sent close frame", addr);
                        break;
                    }
                    Err(e) => {
                        eprintln!("[!] WebSocket read error from {}: {}", addr, e);
                        break;
                    }
                    _ => continue, // Ignore ping/pong/binary
                };

                let response_json = dispatch_message(&handle, &pending, &msg).await;
                if ws_write
                    .send(Message::Text(response_json.into()))
                    .await
                    .is_err()
                {
                    eprintln!("[!] WebSocket write failed for {}", addr);
                    break;
                }
            }

            println!("[*] Fuzzer disconnected from {}", addr);
        });
    }
}

// ---------------------------------------------------------------------------
// Message dispatch: routes incoming WebSocket messages to the right handler
// ---------------------------------------------------------------------------

async fn dispatch_message<R: Runtime>(
    app_handle: &tauri::AppHandle<R>,
    pending: &PendingMap,
    msg: &str,
) -> String {
    // Parse as generic JSON first so we can inspect the shape.
    let parsed: serde_json::Value = match serde_json::from_str(msg) {
        Ok(v) => v,
        Err(e) => {
            return serde_json::to_string(&FuzzResult {
                id: "unknown".into(),
                status: "error".into(),
                command: "unknown".into(),
                result: None,
                error: Some(format!("Invalid JSON: {}", e)),
            })
            .unwrap();
        }
    };

    // Control messages use a "type" field to identify themselves.
    if let Some(msg_type) = parsed.get("type").and_then(|v| v.as_str()) {
        return match msg_type {
            "list_commands" => {
                let commands = get_registered_commands();
                serde_json::json!({
                    "type": "list_commands",
                    "commands": commands,
                })
                .to_string()
            }
            other => serde_json::json!({
                "type": "error",
                "error": format!("Unknown message type: {}", other),
            })
            .to_string(),
        };
    }

    // No "type" field → treat as a fuzz request (backward-compatible).
    let response = match serde_json::from_value::<FuzzRequest>(parsed) {
        Ok(request) => handle_fuzz_request(app_handle, pending, request).await,
        Err(e) => FuzzResult {
            id: "unknown".into(),
            status: "error".into(),
            command: "unknown".into(),
            result: None,
            error: Some(format!("Invalid request JSON: {}", e)),
        },
    };

    serde_json::to_string(&response).unwrap()
}

// ---------------------------------------------------------------------------
// Request handler: inject JS into the webview and wait for the result event
// ---------------------------------------------------------------------------

async fn handle_fuzz_request<R: Runtime>(
    app_handle: &tauri::AppHandle<R>,
    pending: &PendingMap,
    request: FuzzRequest,
) -> FuzzResult {
    let id = request.id.clone();
    let command = request.command.clone();

    // Create a oneshot channel so the event listener can deliver the result.
    let (tx, rx) = oneshot::channel();
    {
        let mut map = pending.lock().unwrap();
        map.insert(id.clone(), tx);
    }

    // Build the JavaScript that will invoke the command through the real IPC
    // layer and emit the result back as a Tauri event.
    let js = build_invoke_js(&request.id, &request.command, &request.args);

    // Inject into the main webview window.
    let window = match app_handle.get_webview_window("main") {
        Some(w) => w,
        None => {
            pending.lock().unwrap().remove(&id);
            return FuzzResult {
                id,
                status: "error".into(),
                command,
                result: None,
                error: Some("Main webview window not found".into()),
            };
        }
    };

    if let Err(e) = window.eval(&js) {
        pending.lock().unwrap().remove(&id);
        return FuzzResult {
            id,
            status: "error".into(),
            command,
            result: None,
            error: Some(format!("Failed to inject JS: {}", e)),
        };
    }

    // Wait for the event listener to deliver the result, with a timeout.
    match tokio::time::timeout(Duration::from_secs(RESPONSE_TIMEOUT_SECS), rx).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => {
            // oneshot sender was dropped without sending — should not happen
            pending.lock().unwrap().remove(&id);
            FuzzResult {
                id,
                status: "error".into(),
                command,
                result: None,
                error: Some("Internal error: response channel dropped".into()),
            }
        }
        Err(_) => {
            // Timeout — the command may have panicked and crashed the handler,
            // or is simply taking too long.
            pending.lock().unwrap().remove(&id);
            FuzzResult {
                id,
                status: "timeout".into(),
                command,
                result: None,
                error: Some(format!(
                    "No response within {}s — possible panic or hang in command handler",
                    RESPONSE_TIMEOUT_SECS
                )),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// JavaScript builder
// ---------------------------------------------------------------------------
// Constructs a self-executing async JS snippet that:
//   1. Calls window.__TAURI__.core.invoke() through the real IPC layer
//   2. Emits a 'fuzz-result' event back to the Rust backend with the outcome
//
// The args JSON is embedded via JSON.parse() with proper escaping to avoid
// injection issues from payload strings containing quotes or backslashes.

fn build_invoke_js(id: &str, command: &str, args: &serde_json::Value) -> String {
    let args_json = serde_json::to_string(args).unwrap_or_else(|_| "{}".to_string());

    // Escape for safe embedding inside a JS single-quoted string literal.
    let args_escaped = escape_for_js_string(&args_json);
    let id_escaped = escape_for_js_string(id);
    let cmd_escaped = escape_for_js_string(command);

    format!(
        r"(async () => {{
    const __id = '{id}';
    const __cmd = '{cmd}';
    try {{
        const __args = JSON.parse('{args}');
        const __result = await window.__TAURI__.core.invoke(__cmd, __args);
        await window.__TAURI__.event.emit('fuzz-result', {{
            id: __id, status: 'success', command: __cmd,
            result: __result, error: null
        }});
    }} catch (e) {{
        await window.__TAURI__.event.emit('fuzz-result', {{
            id: __id, status: 'error', command: __cmd,
            result: null, error: String(e)
        }});
    }}
}})();",
        id = id_escaped,
        cmd = cmd_escaped,
        args = args_escaped,
    )
}

/// Escape a string for safe embedding inside a JavaScript single-quoted
/// string literal (`'...'`).  Handles backslashes, quotes, newlines, and
/// Unicode line/paragraph separators (which are valid JSON but terminate
/// JS string literals in some engines).
fn escape_for_js_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 16);
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            other => out.push(other),
        }
    }
    out
}
