# TauriScan — Tauri IPC Security Scanner & Research Project

> ⚠️ **WARNING**: This repository contains intentionally vulnerable code used as a ground-truth testbed. Do not deploy any applications from this repository in production or on untrusted networks.

TauriScan is a security research project and automated Dynamic Application Security Testing (DAST) suite created as part of a Georgia Tech CS-6727 capstone project. 

The primary goal of this project is to investigate and prove that parser discrepancies, path confusion, and deserialization flaws at the Inter-Process Communication (IPC) boundary of zero-egress desktop applications (like Tauri) can be systematically discovered via automated dynamic testing.

While desktop frameworks like Tauri provide memory safety via Rust, they are still vulnerable to logic flaws when frontend JavaScript security filters and backend native execution engines disagree on the structural intent of a payload. TauriScan systematically injects malicious payloads into the real IPC bridge to uncover Path Traversal, Server-Side Request Forgery (SSRF), and Type Confusion vulnerabilities.

## Repository Structure

This repository is structured into several interconnected components. For detailed information on any specific component, please refer to its dedicated README:

- **[TauriScan Orchestrator (`/orchestrator`)](orchestrator/README.md)**
  A Python-based fuzzing client that manages payload generation, dispatching, and response analysis to detect security vulnerabilities.

- **[Tauri Fuzz Harness Plugin (`/src-tauri/tauri-plugin-fuzz-harness`)](src-tauri/tauri-plugin-fuzz-harness/README.md)**
  A drop-in Tauri v2 plugin that enables dynamic IPC fuzzing by opening a WebSocket and injecting payloads directly into the WebView's JavaScript context.

- **[Tauri Secure Utils (`/src-tauri/tauri-secure-utils`)](src-tauri/tauri-secure-utils/README.md)**
  A library of drop-in secure Rust macros and functions (e.g., path canonicalization, SSRF prevention) that developers can implement to secure custom `invoke` handlers against parser confusion.

- **[Tauri vs. Electron IPC Experiment (`/experiment`)](experiment/README.md)**
  A comparative testbed containing a minimal Electron application to evaluate whether Tauri's architectural advantages extend to parser logic vulnerabilities when compared to Node.js / Electron.

- **Intentionally Vulnerable Tauri App (`/src-tauri` & `/ui`)**
  The root of this project serves as a "ground truth" testbed application containing known IPC security flaws used to prove the efficacy of the TauriScan orchestrator.

## Getting Started (Vulnerable Testbed)

To run the intentionally vulnerable testbed application locally:

### Prerequisites
- [Rust](https://www.rust-lang.org/tools/install) (latest stable)
- [Node.js](https://nodejs.org/) via nvm (LTS version)
- [Tauri CLI v2](https://v2.tauri.app/start/create-project/)

### Setup
```bash
# Use correct Node version
nvm use

# Install npm dependencies
npm install

# Run in development mode
cargo tauri dev
```

Once the testbed is running, refer to the **[Orchestrator README](orchestrator/README.md)** to begin scanning the application for vulnerabilities.

## License
This project is for educational and security research purposes only.

## AI Usage Disclaimer
Google Gemini 3.1 Pro was utilized during the development of this project to assist in code generation, refactoring, and testing the code changes delivered. All AI-generated suggestions were thoroughly reviewed, verified, and adapted by the author to ensure accuracy and original intent.
