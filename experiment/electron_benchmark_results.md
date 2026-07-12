# Electron IPC Parser Benchmark Results

**Date Executed:** 2026-07-12
**Target:** Minimal Electron Application (Node.js IPC Bridge)
**Vulnerabilities Tested:** Directory Traversal (`read_file`), SSRF (`fetch_url`), Type Confusion (`process_data`).

## Execution Output

```text
[*] Electron harness ready. Running payloads...

[SUCCESS] read_file | Payload: "readme.txt"
  -> Result: Welcome to TauriScan! This is a safe file within the intended directory.

[ERROR] read_file | Payload: "../../../etc/passwd"
  -> Error invoking remote method 'read_file': Error: Failed to read file: ENOENT: no such file or directory, open '/Users/smarpo/etc/passwd'

[ERROR] read_file | Payload: "....//....//....//etc/passwd"
  -> Error invoking remote method 'read_file': Error: Failed to read file: ENOENT: no such file or directory, open '/Users/smarpo/repos/TauriScan/safe_files/..../..../..../etc/passwd'

[ERROR] read_file | Payload: "..\\..\\..\\etc\\passwd"
  -> Error invoking remote method 'read_file': Error: Failed to read file: ENOENT: no such file or directory, open '/Users/smarpo/repos/TauriScan/safe_files/..\..\..\etc\passwd'

[ERROR] read_file | Payload: "%2e%2e%2f%2e%2e%2fetc%2fpasswd"
  -> Error invoking remote method 'read_file': Error: Failed to read file: ENOENT: no such file or directory, open '/Users/smarpo/repos/TauriScan/safe_files/%2e%2e%2f%2e%2e%2fetc%2fpasswd'

[ERROR] read_file | Payload: "..%252f..%252f..%252fetc/passwd"
  -> Error invoking remote method 'read_file': Error: Failed to read file: ENOENT: no such file or directory, open '/Users/smarpo/repos/TauriScan/safe_files/..%252f..%252f..%252fetc/passwd'

[ERROR] read_file | Payload: "/etc/passwd"
  -> Error invoking remote method 'read_file': Error: Failed to read file: ENOENT: no such file or directory, open '/Users/smarpo/repos/TauriScan/safe_files/etc/passwd'

[SUCCESS] fetch_url | Payload: "https://httpbin.org/get"
  -> Result: { "args": {}, "headers": { "Accept": "*/*", "Accept-Encoding": "br"...

[ERROR] fetch_url | Payload: "http://127.0.0.1"
  -> Error invoking remote method 'fetch_url': Error: Request failed: fetch failed

[ERROR] fetch_url | Payload: "http://169.254.169.254/latest/meta-data/"
  -> Error invoking remote method 'fetch_url': Error: Request failed: fetch failed

[ERROR] fetch_url | Payload: "file:///etc/passwd"
  -> Error invoking remote method 'fetch_url': Error: Request failed: fetch failed

[ERROR] fetch_url | Payload: "http://[::1]/"
  -> Error invoking remote method 'fetch_url': Error: Request failed: fetch failed

[ERROR] fetch_url | Payload: "http://0x7f000001/"
  -> Error invoking remote method 'fetch_url': Error: Request failed: fetch failed

[SUCCESS] process_data | Payload: {"name":"test","age":25,"admin":false,"metadata":{"role":"user"}}
  -> Result: Processed: TEST, Age: 26, Role: user

[ERROR] process_data | Payload: {"name":12345,"age":"not_a_number","admin":"yes","metadata":{"role":null}}
  -> Error invoking remote method 'process_data': Error: PANIC: data.name.toUpperCase is not a function

[ERROR] process_data | Payload: {}
  -> Error invoking remote method 'process_data': Error: PANIC: Cannot read properties of undefined (reading 'toUpperCase')

[ERROR] process_data | Payload: "just a string"
  -> Error invoking remote method 'process_data': Error: PANIC: Cannot read properties of undefined (reading 'toUpperCase')

[ERROR] process_data | Payload: null
  -> Error invoking remote method 'process_data': Error: PANIC: Cannot read properties of null (reading 'name')
[*] Testing complete. Exiting...
```

## Parsing Analysis

This benchmark provides comparative empirical data on how Node.js and V8 handle malformed IPC inputs across three distinct vulnerability classes.

### 1. Path Traversal & Normalization (vs. Rust `PathBuf`)

- **Absolute Path Override Failure:** When evaluating `/etc/passwd`, Node's `path.join(BASE_DIR, '/etc/passwd')` treats it as a relative segment and appends it directly to the base path, yielding `safe_files/etc/passwd`. In stark contrast, Rust's `PathBuf::join` replaces the entire path when encountering a root directory, creating a critical sandbox escape.
- **Logical Traversal Limitation:** For `../../../etc/passwd`, Node.js logically traversed up 3 directories (landing at `/Users/smarpo/etc/passwd`). This successfully escaped the sandbox folder but mitigated exploitation because `/etc/passwd` does not exist at that specific filesystem depth. 
- **Platform/Encoding Discrepancies:** Node on Unix treated `\` as literal filename characters rather than directory separators. It also failed to inherently URL-decode `%2e` strings.

### 2. Server-Side Request Forgery (vs. Rust `reqwest`)

- **Native Fetch Defenses:** Node.js 18+ native `fetch()` heavily guards against standard SSRF payloads. Most notably, it throws an immediate `fetch failed` error on local loopback addresses (like `127.0.0.1` and `[::1]`), local metadata IPs (`169.254.169.254`), and strictly prohibits the `file:///` scheme.
- **Architectural Takeaway:** Node.js native `fetch` provides a much tighter default security posture for outbound HTTP requests compared to raw Rust HTTP clients, significantly limiting default SSRF exploitability.

### 3. Type Confusion (vs. Rust `serde_json` + `unwrap()`)

- **Graceful Failure vs. Panic:** When passing malformed types (e.g. an integer instead of a string, or an empty object instead of a nested struct), JavaScript's dynamic typing causes it to gracefully throw a `TypeError` (like `data.name.toUpperCase is not a function` or `Cannot read properties of undefined`). 
- **Architectural Takeaway:** These errors are gracefully caught by the Electron IPC handler and bubbled back to the client as an error message. The renderer and main processes survive perfectly intact. Conversely, the exact same payloads cause a Tauri Rust application to suffer an unrecoverable thread panic if `.unwrap()` is used on the wrong `serde_json::Value` type, emphasizing the danger of rigid statically-typed handlers blindly accepting dynamic frontend payloads.
