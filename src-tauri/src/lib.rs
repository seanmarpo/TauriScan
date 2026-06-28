use serde_json::Value;
use std::fs;
use std::path::PathBuf;

/// Hardcoded "safe" base directory for file operations.
/// In a real application this would be a sandboxed app-data directory.
const BASE_DIR: &str = "./safe_files/";

// ---------------------------------------------------------------------------
// Command: read_file
// ---------------------------------------------------------------------------
// VULNERABILITY: Path Traversal / Arbitrary Filesystem Read
//
// The user-supplied `path` is concatenated directly onto `BASE_DIR` without
// any canonicalization, sanitization, or traversal checks.  An attacker can
// supply a path such as `../../../../etc/passwd` to escape the base directory
// and read arbitrary files on the host filesystem.
//
// A secure implementation would:
//   1. Canonicalize the joined path.
//   2. Verify the canonical path still starts with the canonical base.
//   3. Reject any path containing `..` components.
// ---------------------------------------------------------------------------
#[tauri::command]
fn read_file(path: String) -> Result<String, String> {
    // VULNERABILITY: direct concatenation — no traversal guard
    let full_path = PathBuf::from(BASE_DIR).join(&path);

    fs::read_to_string(&full_path).map_err(|e| format!("Failed to read file: {}", e))
}

// ---------------------------------------------------------------------------
// Command: list_directory
// ---------------------------------------------------------------------------
// VULNERABILITY: Path Traversal / Arbitrary Directory Listing
//
// Same flaw as `read_file` — the caller controls the final path component and
// can use `..` sequences to list directories outside the intended base.
// ---------------------------------------------------------------------------
#[tauri::command]
fn list_directory(path: String) -> Result<Value, String> {
    // VULNERABILITY: direct concatenation — no traversal guard
    let full_path = PathBuf::from(BASE_DIR).join(&path);

    let entries =
        fs::read_dir(&full_path).map_err(|e| format!("Failed to list directory: {}", e))?;

    let mut names: Vec<String> = Vec::new();
    for entry in entries {
        if let Ok(entry) = entry {
            if let Some(name) = entry.file_name().to_str() {
                names.push(name.to_owned());
            }
        }
    }

    serde_json::to_value(names).map_err(|e| format!("Serialization error: {}", e))
}

// ---------------------------------------------------------------------------
// Command: fetch_url
// ---------------------------------------------------------------------------
// VULNERABILITY: Server-Side Request Forgery (SSRF) / Arbitrary URL Access
//
// The handler fetches whatever URL the frontend supplies with zero validation:
//   - No scheme allowlist (allows file://, ftp://, gopher://, etc.)
//   - No domain/IP allowlist (allows requests to 127.0.0.1, 169.254.169.254
//     metadata endpoints, internal network hosts, etc.)
//   - No response-size limit (potential for resource exhaustion)
//
// A secure implementation would:
//   1. Parse the URL and reject non-https schemes.
//   2. Resolve the hostname and reject private/loopback IPs.
//   3. Maintain an explicit domain allowlist.
//   4. Cap response body size.
// ---------------------------------------------------------------------------
#[tauri::command]
fn fetch_url(url: String) -> Result<String, String> {
    // VULNERABILITY: no scheme/domain/IP validation — full SSRF
    let client = reqwest::blocking::Client::new();

    let response = client
        .get(&url)
        .send()
        .map_err(|e| format!("Request failed: {}", e))?;

    response
        .text()
        .map_err(|e| format!("Failed to read response body: {}", e))
}

// ---------------------------------------------------------------------------
// Command: process_data
// ---------------------------------------------------------------------------
// VULNERABILITY: Type Confusion / Unsafe Deserialization
//
// The handler accepts an arbitrary `serde_json::Value` and blindly assumes a
// specific shape:
//   - `data["name"]` is assumed to be a string
//   - `data["age"]` is assumed to be a number (used in arithmetic)
//   - `data["admin"]` is assumed to be a boolean
//   - `data["metadata"]["role"]` is assumed to exist and be a string
//
// When the frontend sends unexpected types (e.g., a number where a string is
// expected, null values, or missing nested objects) the `.unwrap()` calls will
// panic, and the unchecked arithmetic can produce nonsensical results.
//
// A secure implementation would:
//   1. Deserialize into a strongly-typed struct with `serde::Deserialize`.
//   2. Validate every field before use.
//   3. Return clear errors for malformed input.
// ---------------------------------------------------------------------------
#[tauri::command]
fn process_data(data: Value) -> Result<String, String> {
    // VULNERABILITY: blindly unwrapping — panics on unexpected types
    let name = data["name"].as_str().unwrap();

    // VULNERABILITY: assumes numeric type, no bounds/overflow check
    let age = data["age"].as_f64().unwrap();
    let age_in_months = age * 12.0;

    // VULNERABILITY: blindly unwrapping nested field that may not exist
    let is_admin = data["admin"].as_bool().unwrap();

    // VULNERABILITY: deep nested access with no existence check — panics if
    // "metadata" is missing or is not an object
    let role = data["metadata"]["role"].as_str().unwrap();

    // VULNERABILITY: constructing output from unvalidated, unsanitized input
    let result = format!(
        "Processed: name={}, age_in_months={}, admin={}, role={}",
        name, age_in_months, is_admin, role
    );

    Ok(result)
}

// ---------------------------------------------------------------------------
// Application entry point (Tauri v2)
// ---------------------------------------------------------------------------
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_fuzz_harness::init())
        .invoke_handler(tauri_plugin_fuzz_harness::generate_handler![
            read_file,
            list_directory,
            fetch_url,
            process_data,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
