# Tauri vs. Electron IPC Experiment

This directory contains a comparative security experiment between Tauri and Electron IPC boundary implementations.

## Overview

We have implemented an intentionally vulnerable minimal Electron application (`main.js`) that directly mirrors the vulnerable Tauri implementation found in our main app. It exposes three IPC handlers designed to test three distinct vulnerability classes:
1. **Directory Traversal** (`read_file`): Blindly concatenates user input with a base directory.
2. **Server-Side Request Forgery** (`fetch_url`): Blindly fetches user-supplied URLs.
3. **Type Confusion** (`process_data`): Blindly expects specific, rigid JSON structures without validation.

## How It Works

1. The Electron app spins up a `BrowserWindow`.
2. It reads a list of predefined payloads from `payloads.json` encompassing path traversals, internal/loopback IPs, and malformed data structures.
3. For each payload, the harness injects JavaScript into the renderer process using `mainWindow.webContents.executeJavaScript`, which subsequently invokes the appropriate IPC handler.
4. The responses (or errors) are logged to the console to analyze how the Node.js/V8 backend handled the maliciously crafted IPC messages.

## Benchmark Results & Evaluation

By comparing the results of identically formulated payloads in this Electron testbed against our Tauri testbed, we can definitively analyze how differences in IPC deserialization, typing, and bridging impact exploitability. 

View the full execution outputs and detailed parsing analysis here:
- 📄 [Electron Benchmark Results](./electron_benchmark_results.md)
- 📄 [Tauri Benchmark Results](./tauri_benchmark_results.md)

### Key Architectural Findings

1. **Path Parsing (Rust vs. Node.js):**
   Rust's `std::path::PathBuf::join` replaces the entire base path when presented with an absolute path payload (e.g., `/etc/passwd`), creating a critical sandbox escape. Node.js `path.join` treats absolute payload segments as relative when appended, naturally mitigating this specific attack vector.
2. **SSRF Guardrails (`reqwest` vs Native `fetch`):**
   Node.js 18+ native `fetch` provides robust default security, explicitly rejecting requests to loopback addresses (`127.0.0.1`), metadata servers (`169.254.169.254`), and the `file:///` scheme. Conversely, standard Rust HTTP clients like `reqwest` blindly follow these protocols and internal routes unless deliberately restricted by the developer.
3. **Type Confusion (Dynamic V8 vs. Strict Rust `serde_json`):**
   V8's dynamic typing allows malformed JSON payloads (like unexpected arrays or missing fields) to gracefully fail with a catchable `TypeError`. In a Tauri application, rigid static typing combined with careless `.unwrap()` deserialization causes these exact same payloads to trigger an unrecoverable thread panic, completely crashing the backend process and severing the IPC connection.
