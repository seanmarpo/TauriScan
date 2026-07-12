# TauriScan Orchestrator

The orchestrator is a Python-based fuzzing client that connects to the TauriScan plugin (running inside the target application) via WebSockets. It is responsible for payload generation, dispatching, and analyzing responses to detect security vulnerabilities (like Path Traversal, SSRF, or Type Confusion).

## Prerequisites
We recommend running the orchestrator using `uv`, which handles dependency installation automatically.

## Usage

### 1. Setup Mode
First, run the orchestrator in `--setup` mode while the target application is running. 
This connects to the app, discovers available commands, automatically probes for argument names, and writes a configuration template to `fuzz_config.json`.

```bash
uv run --with websockets scanner.py --setup
```

### 2. Configuration
Open the generated `fuzz_config.json`. For each discovered command, specify the `payload_type` you wish to use (e.g., `"path_traversal"`, `"ssrf"`, `"type_confusion"`, etc.).

### 3. Run the Scanner
Once configured, run the fuzzer by passing the config file:

```bash
uv run --with websockets scanner.py --config fuzz_config.json
```

### Other Flags
- **Custom Payloads**: Run with a raw JSON array of payloads:
  `uv run --with websockets scanner.py custom_payloads.json`
- **Built-in Smoke Test**: Run without arguments to use a hardcoded set of legacy test payloads:
  `uv run --with websockets scanner.py`
