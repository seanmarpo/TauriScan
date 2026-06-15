# TauriFuzz — Intentionally Vulnerable Tauri Application

> ⚠️ **WARNING**: This application is intentionally vulnerable. Do not deploy in production or on untrusted networks.

A deliberately insecure Tauri v2 application built as a testbed for IPC fuzzing and security research. This is part of a Georgia Tech CS-6727 capstone project investigating parser discrepancies and security flaws in the Tauri Inter-Process Communication (IPC) boundary.

## Summary

This repository contains an intentionally vulnerable Tauri v2 application, a Tauri plugin for IPC-based fuzzing, and a fuzzing orchestrator.

## Vulnerabilities

| # | Handler | Vulnerability | Description |
|---|---------|--------------|-------------|
| 1 | `read_file` | Path Traversal | Concatenates user input to base path without canonicalization |
| 2 | `list_directory` | Path Traversal | Same path concatenation flaw for directory listing |
| 3 | `fetch_url` | SSRF | Fetches any URL without scheme/domain allowlisting |
| 4 | `process_data` | Type Confusion | Blindly trusts JSON structure, panics on unexpected types |

## Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) (latest stable)
- [Node.js](https://nodejs.org/) via nvm (LTS version)
- [Tauri CLI v2](https://v2.tauri.app/start/create-project/)

## Setup

```bash
# Use correct Node version
nvm use

# Install npm dependencies
npm install

# Run in development mode
cargo tauri dev

# Build for production
cargo tauri build
```

## Project Structure

- [`ui/`](ui/) — Intentionally vulnerable app frontend (vanilla HTML/JS)
- [`src-tauri/`](src-tauri/) — Intentionally vulnerable Tauri app backend
- [`safe_files/`](safe_files/) — Intended file access sandbox directory
- [`orchestrator/`](orchestrator/) — Python fuzzing orchestrator
- [`src-tauri/tauri-plugin-fuzz-harness/`](src-tauri/tauri-plugin-fuzz-harness/) — Tauri plugin that enables IPC-based fuzzing

## License

This project is for educational and research purposes only.
