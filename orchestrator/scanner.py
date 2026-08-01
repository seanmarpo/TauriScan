"""
Fuzzing orchestrator for Tauri plugin WebSocket listener.

Sends security-focused fuzzing payloads over WebSocket to a Tauri plugin
running at ws://127.0.0.1:31337, then analyzes the responses for potential
vulnerabilities including path traversal, SSRF, and type confusion issues.

Usage:
    python scanner.py                  # Run with built-in test payloads
    python scanner.py payloads.json    # Run with custom payload file
"""

import argparse
import asyncio
import json
import os
import re
import signal
import subprocess
import sys
import time
import uuid
from datetime import datetime
from dataclasses import dataclass, field
from pathlib import Path

import websockets
from websockets.exceptions import ConnectionClosed, InvalidURI, WebSocketException

WS_URI = "ws://127.0.0.1:31337"
DEFAULT_TIMEOUT = 15
DEFAULT_CONFIG_PATH = "scan_config.json"
RUN_ID = str(uuid.uuid4())[:8]

# ---------------------------------------------------------------------------
# Preset payload collections keyed by vulnerability category.
# Each list contains raw values that get injected into the target argument.
# ---------------------------------------------------------------------------
PAYLOAD_PRESETS: dict[str, list] = {
    "path_traversal": [
        "../../../tmp/fuzz_{UUID}",
        "....//....//....//tmp/fuzz_{UUID}",
        "..\\..\\..\\tmp\\fuzz_{UUID}",
        "%2e%2e%2f%2e%2e%2ftmp%2ffuzz_{UUID}",
        "..%252f..%252f..%252ftmp/fuzz_{UUID}",
        "/tmp/fuzz_{UUID}",
        "../../../..",
        "/etc",
    ],
    "ssrf": [
        "http://127.0.0.1:31337/{UUID}",
        "http://169.254.169.254/latest/meta-data/{UUID}",
        "file:///tmp/fuzz_{UUID}",
        "http://[::1]/{UUID}",
        "http://0x7f000001/{UUID}",
        "http://localhost/{UUID}",
    ],
    "type_confusion": [
        None,
        "",
        0,
        False,
        True,
        [],
        {},
        "unexpected string",
        12345,
        -1,
        [1, 2, 3],
        [None, None],
        {"unexpected": "structure"},
        {"a": {"b": {"c": {"d": {"e": "deep"}}}}},
    ],
    "string_injection": [
        "",
        " ",
        "A" * 100_000,
        "<script>alert('{UUID}')</script>",
        "'; DROP TABLE users; --",
        "${7*7}",
        "{{7*7}}",
        "%s%s%s%s%s",
        "\\",
        "\n\r\t",
    ],
    "numeric_boundary": [
        0,
        -1,
        1,
        1e308,
        -1e308,
        2_147_483_647,
        -2_147_483_648,
        2_147_483_648,
        9_007_199_254_740_992,
        1e-308,
        None,
    ],
    "oversized": [
        "A" * 100_000,
        "A" * 1_000_000,
        [0] * 10_000,
        {"a": {"a": {"a": {"a": {"a": {"a": {"a": {"a": {"a": {"a": "deep"}}}}}}}}}},
    ],
}

# Human-readable descriptions printed during --setup.
PAYLOAD_TYPE_DESCRIPTIONS: dict[str, str] = {
    "path_traversal": "Directory traversal via ../ sequences, absolute paths, encoded slashes",
    "ssrf": "Server-Side Request Forgery via internal IPs, metadata URLs, file:// scheme",
    "type_confusion": "Wrong types, missing fields, null values, nested object abuse",
    "string_injection": "Special characters, Unicode, control characters, format strings",
    "numeric_boundary": "Integer overflow, underflow, NaN, Infinity, negative values",
    "oversized": "Extremely large strings, deeply nested objects, huge arrays",
}



@dataclass
class Finding:
    """A single security finding from a fuzz run."""

    category: str
    severity: str
    payload: dict
    response: dict
    description: str


@dataclass
class CommandStats:
    """Statistics for a specific Tauri command/endpoint."""
    payloads_sent: int = 0
    timeout: int = 0
    disconnect: int = 0
    deadlock: int = 0
    vulnerabilities_found: set[str] = field(default_factory=set)

@dataclass
class FuzzStats:
    """Accumulated statistics for a fuzz run."""

    total: int = 0
    timeout: int = 0
    disconnect: int = 0
    deadlock: int = 0
    findings: list = field(default_factory=list)
    command_stats: dict[str, CommandStats] = field(default_factory=dict)
    total_endpoints_discovered: int = 0


def is_panic_finding(payload: dict, response: dict) -> Finding | None:
    """Check if the handler panicked."""
    if response.get("status") != "error":
        return None

    error_msg = response.get("error", "")
    if not isinstance(error_msg, str) or "panic" not in error_msg.lower():
        return None

    return Finding(
        category="Panic / Unhandled Type",
        severity="HIGH",
        payload=payload,
        response=response,
        description=f"Command '{payload.get('command')}' panicked: {error_msg}",
    )


def is_timeout_finding(payload: dict, response: dict) -> Finding | None:
    """Check if a timeout occurred, possibly indicating a crash or hang."""
    if response.get("status") != "timeout":
        return None

    return Finding(
        category="Timeout / Possible Crash",
        severity="MEDIUM",
        payload=payload,
        response=response,
        description=f"Command '{payload.get('command')}' timed out — possible crash or hang",
    )


def check_findings(payload: dict, response: dict) -> list[Finding]:
    """Run all finding detectors against a payload/response pair."""
    detectors = [
        is_panic_finding,
        is_timeout_finding,
    ]
    return [f for det in detectors if (f := det(payload, response)) is not None]


def truncate(text: str, max_len: int = 120) -> str:
    """Truncate a string for display."""
    s = str(text)
    return s if len(s) <= max_len else s[: max_len - 3] + "..."


async def send_payload(ws, payload: dict, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """
    Send a single fuzzing payload over the WebSocket and wait for a response.

    Args:
        ws: The open WebSocket connection.
        payload: A dict with 'command' and 'args' keys.
        timeout: Seconds to wait for a response before declaring a timeout.

    Returns:
        A response dict with at least an 'id', 'status', and 'command' field.
        On timeout the status is 'timeout'. On connection errors the status
        is 'disconnect'.
    """
    msg_id = str(uuid.uuid4())
    message = {
        "id": msg_id,
        "command": payload["command"],
        "args": payload.get("args", {}),
    }

    try:
        await ws.send(json.dumps(message))
    except ConnectionClosed:
        return {
            "id": msg_id,
            "status": "disconnect",
            "command": payload["command"],
            "result": None,
            "error": "WebSocket connection closed before send completed",
        }

    try:
        raw = await asyncio.wait_for(ws.recv(), timeout=timeout)
        response = json.loads(raw)
        return response
    except TimeoutError:
        return {
            "id": msg_id,
            "status": "deadlock",
            "command": payload["command"],
            "result": None,
            "error": f"No response within {timeout}s (Deadlock)",
        }
    except ConnectionClosed:
        return {
            "id": msg_id,
            "status": "disconnect",
            "command": payload["command"],
            "result": None,
            "error": "WebSocket connection closed while waiting for response",
        }


async def try_connect(uri: str, retries: int = 1, delay: float = 3.0):
    """
    Attempt to open a WebSocket connection, retrying on failure.

    Args:
        uri: The WebSocket URI to connect to.
        retries: Number of extra attempts after the first failure.
        delay: Seconds to wait between retries.

    Returns:
        An open WebSocket connection.

    Raises:
        Exception: If all connection attempts fail.
    """
    for attempt in range(1 + retries):
        try:
            ws = await websockets.connect(uri, max_size=10 * 1024 * 1024)
            return ws
        except (OSError, WebSocketException, InvalidURI) as exc:
            if attempt < retries:
                print(f"  ⏳ Connection failed ({exc}), retrying in {delay}s...")
                await asyncio.sleep(delay)
            else:
                raise


async def fetch_commands(uri: str) -> list[str]:
    """
    Connect to the fuzz harness WebSocket and request the list of registered
    Tauri commands via the ``list_commands`` control message.

    Returns:
        A list of command name strings.
    """
    print(f"📡 Connecting to {uri} ...")
    try:
        ws = await try_connect(uri)
    except Exception as exc:
        print(f"💥 Could not connect to {uri}: {exc}")
        print("   Is the Tauri app running with the fuzzing plugin loaded?")
        sys.exit(1)

    print("✅ Connected!")

    try:
        await ws.send(json.dumps({"type": "list_commands"}))
        raw = await asyncio.wait_for(ws.recv(), timeout=DEFAULT_TIMEOUT)
        response = json.loads(raw)
    except Exception as exc:
        print(f"💥 Failed to fetch command list: {exc}")
        sys.exit(1)
    finally:
        await ws.close()

    if response.get("type") != "list_commands":
        print(f"💥 Unexpected response from harness: {json.dumps(response)}")
        sys.exit(1)

    return response.get("commands", [])


def parse_args_from_error(error: str) -> list[str]:
    """Extract argument names from a Tauri command deserialization error.

    Tauri v2 typically formats these as::

        invalid args `name` for command `cmd` ...

    and serde errors may contain::

        missing field `name`
    """
    found: list[str] = []

    # Tauri v2: "invalid args `name` for command ..."
    for m in re.finditer(r"invalid args [`'\"](\w+)[`'\"]", error):
        if m.group(1) not in found:
            found.append(m.group(1))

    # serde: "missing field `name`"
    for m in re.finditer(r"missing field [`'\"](\w+)[`'\"]", error):
        if m.group(1) not in found:
            found.append(m.group(1))

    return found


async def probe_command_args(
    ws, command: str, timeout: int = DEFAULT_TIMEOUT
) -> list[str]:
    """Send a command with empty args and parse the error to discover
    argument names.  Returns a (possibly empty) list of names."""
    response = await send_payload(ws, {"command": command, "args": {}}, timeout)

    if response.get("status") == "success":
        # Command accepts no args (or all args are optional)
        return []

    error = response.get("error", "")
    return parse_args_from_error(error)


async def setup_mode(output_path: str, app_manager=None) -> None:
    """
    Connect to the Tauri app, discover available commands, and write a
    configuration file template for the user to fill in.

    The generated file lists every discovered command with empty ``arg``
    and ``payload_type`` fields.  The user sets each one, then runs the
    fuzzer with ``--config``.
    """
    if app_manager:
        await app_manager.start()

    commands = await fetch_commands(WS_URI)

    if not commands:
        print(
            "\n⚠️  No commands discovered. "
            "Is the app using tauri_plugin_fuzz_harness::generate_handler! ?"
        )
        if app_manager:
            await app_manager.stop()
        sys.exit(1)

    print(f"\n🔍 Discovered {len(commands)} command(s): {', '.join(commands)}\n")

    # --- Probe each command for argument names ---
    print("🔬 Probing commands for argument names...")
    try:
        ws = await try_connect(WS_URI)
    except Exception as exc:
        print(f"⚠️  Could not reconnect for probing ({exc}), skipping arg discovery")
        ws = None

    discovered: dict[str, list[str]] = {}
    if ws:
        max_cmd = max(len(c) for c in commands)
        for cmd in commands:
            args = await probe_command_args(ws, cmd)
            discovered[cmd] = args
            if args:
                print(f"  {cmd:<{max_cmd}}  → found: {', '.join(args)}")
            else:
                print(f"  {cmd:<{max_cmd}}  → (none detected)")
        await ws.close()

    print()

    # --- Build config with pre-filled arg names ---
    config = {
        "target": WS_URI,
        "commands": {
            cmd: {
                "arg": discovered.get(cmd, [""])[0] if discovered.get(cmd) else "",
                "payload_type": "",
            }
            for cmd in commands
        },
        "available_payload_types": sorted(PAYLOAD_PRESETS.keys()),
    }

    output = Path(output_path)
    output.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")

    print(f"📄 Configuration written to: {output_path}\n")

    # Show payload type reference so the user knows what to pick.
    print("Available payload types:")
    max_name = max(len(n) for n in PAYLOAD_TYPE_DESCRIPTIONS)
    for name, desc in PAYLOAD_TYPE_DESCRIPTIONS.items():
        print(f"  {name:<{max_name}}  — {desc}")

    print()
    print("Next steps:")
    print(f"  1. Open {output_path} in your editor")
    print("  2. Verify the 'arg' fields and pick a 'payload_type' for each command")
    print(f"  3. Run:  python scanner.py --config {output_path}")

    if app_manager:
        await app_manager.stop()


def load_config(path: str) -> list[dict]:
    """
    Load a fuzz configuration file (produced by ``--setup``) and expand it
    into a flat list of payload dicts suitable for :func:`run_fuzzer`.
    """
    p = Path(path)
    if not p.is_file():
        print(f"❌ Config file not found: {path}")
        sys.exit(1)

    try:
        config = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"❌ Invalid JSON in config file: {exc}")
        sys.exit(1)

    commands = config.get("commands", {})
    if not commands:
        print("❌ No commands defined in config file")
        sys.exit(1)

    payloads: list[dict] = []
    for cmd_name, cmd_config in commands.items():
        arg_name = cmd_config.get("arg", "")
        payload_type = cmd_config.get("payload_type", "")

        if not arg_name or not payload_type:
            print(f"⚠️  Skipping '{cmd_name}': 'arg' or 'payload_type' not set")
            continue

        if payload_type not in PAYLOAD_PRESETS:
            print(f"❌ Unknown payload type '{payload_type}' for command '{cmd_name}'")
            print(f"   Available: {', '.join(sorted(PAYLOAD_PRESETS.keys()))}")
            sys.exit(1)

        for value in PAYLOAD_PRESETS[payload_type]:
            payloads.append(
                {
                    "command": cmd_name,
                    "args": {arg_name: value},
                }
            )

    if not payloads:
        print(
            "❌ No payloads generated — set 'arg' and 'payload_type' for at least one command"
        )
        sys.exit(1)

    return payloads


class SystemMonitor:
    """
    OS-level monitor wrapper for macOS (fs_usage).
    Tracks underlying system calls made by the Tauri application to independently
    confirm successful vulnerability exploitation (e.g. unauthorized filesystem/network access).
    """
    def __init__(self, target_name: str = "tauriscan"):
        self.app_name = target_name
        self.proc: asyncio.subprocess.Process | None = None
        self.log_file = "/tmp/fuzz_fs.log"
        self.nettop_proc: asyncio.subprocess.Process | None = None
        self.nettop_log_file = "/tmp/fuzz_nettop.log"
        self.records = []

    async def start(self):
        print(f"  🛡️ SystemMonitor: Starting background OS monitor logging to {self.log_file} and {self.nettop_log_file}...")
        try:
            self.proc = await asyncio.create_subprocess_exec(
                "sudo", "-n", "fs_usage", "-w", "-f", "network", "-f", "filesys", self.app_name,
                stdout=open(self.log_file, "a"),
                stderr=asyncio.subprocess.DEVNULL,
                stdin=asyncio.subprocess.DEVNULL
            )
            self.nettop_proc = await asyncio.create_subprocess_exec(
                "nettop", "-p", self.app_name, "-n", "-x", "-l", "0",
                stdout=open(self.nettop_log_file, "a"),
                stderr=asyncio.subprocess.DEVNULL,
                stdin=asyncio.subprocess.DEVNULL
            )
            try:
                await asyncio.wait_for(self.proc.wait(), timeout=1.0)
                if self.proc.returncode is not None:
                    print("  ❌ SystemMonitor: 'sudo fs_usage' failed (did you forget to run `sudo -v` first?). Exiting.")
                    sys.exit(1)
            except TimeoutError:
                pass # Still running, good!
        except Exception as exc:
            print(f"  ❌ SystemMonitor: failed to start ({exc})")
            sys.exit(1)

    async def stop(self):
        if self.proc:
            try:
                self.proc.terminate()
            except OSError:
                pass
            subprocess.run(["sudo", "-n", "pkill", "-15", "fs_usage"], capture_output=True, check=False)

        if self.nettop_proc:
            try:
                self.nettop_proc.terminate()
            except OSError:
                pass
            subprocess.run(["pkill", "-15", "nettop"], capture_output=True, check=False)

        await asyncio.sleep(0.5)

    def correlate(self):
        print(f"\n🔬 SystemMonitor: Correlating OS-level syscalls from trace log...")
        if not os.path.exists(self.log_file):
            return

        with open(self.log_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                parts = line.split(maxsplit=1)
                if len(parts) < 2: continue
                ts_str = parts[0]
                content = parts[1]

                if RUN_ID in content:
                    match = re.search(f"fuzz_{RUN_ID}_(\\d+)", content)
                    idx = int(match.group(1)) if match else None
                    clean_line = re.sub(r'\\s+', ' ', content).strip()

                    for r in self.records:
                        if r.idx == idx or (idx is None and r.start_time and r.end_time):
                            r.syscalls.append(f"{ts_str} {clean_line}")
                            if idx is not None:
                                break

        if os.path.exists(self.nettop_log_file):
            ip_pattern = re.compile(r'(?:http|https)://([0-9\.]+|(?:\[[0-9a-fA-F:]+\])|localhost)')

            with open(self.nettop_log_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    for r in self.records:
                        url = str(r.payload.get("args", {}).get("url", ""))
                        if not url:
                            continue

                        match = ip_pattern.search(url)
                        if not match:
                            continue

                        ip = match.group(1).strip("[]")
                        if ip == "0x7f000001" or ip == "localhost":
                            ip = "127.0.0.1"

                        # Determine expected port (default to 80 for HTTP)
                        port = 80
                        try:
                            # e.g., http://127.0.0.1:8080/path -> 8080
                            host_part = url.split("://")[1].split("/")[0]
                            if ":" in host_part:
                                port = int(host_part.split(":")[1])
                        except Exception:
                            pass

                        # Look for exact IP:Port match in nettop output
                        target_str = f"{ip}:{port}"
                        if target_str in line:
                            # Verify timestamp constraint if start/end times exist
                            time_match = re.match(r'^(\d{2}:\d{2}:\d{2}\.\d+)', line)
                            if time_match and r.start_time and r.end_time:
                                try:
                                    # Parse nettop timestamp
                                    # Nettop only gives HH:MM:SS.frac, so we combine with today's date
                                    today_date = datetime.now().strftime("%Y-%m-%d")
                                    time_str = time_match.group(1)
                                    parts = time_str.split(".")
                                    frac = parts[1][:6].ljust(6, '0')
                                    line_time_str = f"{today_date} {parts[0]}.{frac}"
                                    log_time = datetime.strptime(line_time_str, "%Y-%m-%d %H:%M:%S.%f").timestamp()

                                    # r.start_time is float (from time.time())
                                    if not (r.start_time - 1.0 <= log_time <= r.end_time + 1.0):
                                        continue # skip if not within the payload window
                                except Exception:
                                    pass # fallback to append if parsing fails

                            clean_line = re.sub(r'\\s+', ' ', line).strip()
                            r.syscalls.append(f"[nettop] {clean_line}")


class FuzzPayloadRecord:
    def __init__(self, idx, payload):
        self.idx = idx
        self.payload = payload
        self.start_time = None
        self.end_time = None
        self.syscalls = []
        self.response = None


class AppManager:
    """
    Manages the lifecycle of the target Tauri application (spawning, monitoring, restarting).
    Grants the orchestrator full control over the fuzzing workflow.
    """
    def __init__(self, app_dir: str, app_name: str):
        self.app_dir = app_dir
        self.app_name = app_name
        self.proc: asyncio.subprocess.Process | None = None
        self.monitor: SystemMonitor | None = None

    async def start(self):
        print(f"📦 Launching target Tauri application in '{self.app_dir}'...")
        try:
            self.proc = await asyncio.create_subprocess_exec(
                "cargo", "tauri", "dev",
                cwd=self.app_dir,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )
            print(f"  🚀 Subprocess spawned (PID: {self.proc.pid}). Waiting for WebSocket server...")
            # Wait for app to warm up and open WebSocket
            for _ in range(15):
                try:
                    ws = await websockets.connect(WS_URI)
                    await ws.close()
                    print("  ✅ Tauri application is ready and listening!")
                    if self.monitor is None:
                        self.monitor = SystemMonitor(self.app_name)
                        open(self.monitor.log_file, "w").close() # Clear on first run
                        open(self.monitor.nettop_log_file, "w").close() # Clear nettop log
                    await self.monitor.start()
                    return
                except Exception:
                    await asyncio.sleep(2.0)
            print("  ⚠️ Timed out waiting for WebSocket server. Fuzzing may fail.")
        except Exception as exc:
            print(f"  ❌ Failed to spawn Tauri application: {exc}")

    async def restart(self):
        print("\n  🔄 AppManager: Restarting target Tauri application after crash...")
        await self.stop()
        await asyncio.sleep(1.0)
        await self.start()

    async def stop(self):
        if self.monitor:
            await self.monitor.stop()
        if self.proc:
            print("  🛑 AppManager: Terminating Tauri subprocess and all child processes...")
            try:
                os.killpg(self.proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(self.proc.wait(), timeout=2.0)
            except TimeoutError:
                pass
            self.proc = None


async def run_fuzzer(
    payloads: list[dict],
    app_manager: AppManager | None = None,
    total_endpoints: int = 0,
    json_report_path: str | None = None
) -> None:
    """
    Run the fuzzer: connect to the WebSocket server, send every payload,
    collect results, and print a final summary with findings.

    Args:
        payloads: A list of dicts, each with 'command' and 'args' keys.
        app_manager: Optional AppManager instance managing the Tauri subprocess.
        total_endpoints: Total number of IPC endpoints discovered.
        json_report_path: Optional path to save JSON metrics report.
    """
    stats = FuzzStats(total=len(payloads), total_endpoints_discovered=total_endpoints)

    print("=" * 70)
    print("🔧  TauriScan Orchestrator")
    print(f"    Target : {WS_URI}")
    print(f"    Payloads: {len(payloads)}")
    print("=" * 70)
    print()

    # --- connect ---
    print(f"📡 Connecting to {WS_URI} ...")
    try:
        ws = await try_connect(WS_URI)
    except Exception as exc:
        print(f"💥 Could not connect to {WS_URI}: {exc}")
        print("   Is the Tauri app running with the fuzzing plugin loaded?")
        return
    print("✅ Connected!\n")

    # --- send payloads ---
    for idx, payload in enumerate(payloads, start=1):
        payload_str = json.dumps(payload)
        if "{UUID}" in payload_str:
            payload_str = payload_str.replace("{UUID}", f"{RUN_ID}_{idx}")
            payload = json.loads(payload_str)

        cmd = payload.get("command", "?")
        args_preview = truncate(json.dumps(payload.get("args", {})))
        print(f"[{idx}/{len(payloads)}] 📤 {cmd}  {args_preview}")

        if cmd not in stats.command_stats:
            stats.command_stats[cmd] = CommandStats()
        stats.command_stats[cmd].payloads_sent += 1

        record = None
        if app_manager and app_manager.monitor:
            record = FuzzPayloadRecord(idx, payload)
            record.start_time = time.time()
            app_manager.monitor.records.append(record)

        response = await send_payload(ws, payload)

        if record:
            record.end_time = time.time()
            record.response = response

        # Handle disconnection or deadlock with automated recovery
        if response["status"] in ("disconnect", "deadlock"):
            if response["status"] == "deadlock":
                stats.deadlock += 1
                stats.command_stats[cmd].deadlock += 1
                stats.command_stats[cmd].vulnerabilities_found.add("Deadlock / Hard Hang")
                print(f"  💥 Deadlock! ({response.get('error', '')})")
                stats.findings.append(
                    Finding(
                        category="Deadlock / Hard Hang",
                        severity="HIGH",
                        payload=payload,
                        response=response,
                        description="No response within 15s — process completely deadlocked",
                    )
                )
            else:
                stats.disconnect += 1
                stats.command_stats[cmd].disconnect += 1
                stats.command_stats[cmd].vulnerabilities_found.add("Crash / Disconnect")
                print(f"  💥 Disconnected! ({response.get('error', '')})")
                stats.findings.append(
                    Finding(
                        category="Crash / Disconnect",
                        severity="HIGH",
                        payload=payload,
                        response=response,
                        description=f"Connection lost while processing '{cmd}' — possible crash",
                    )
                )

            if app_manager:
                print("  🔄 Crash/Deadlock detected! AppManager initiating automated recovery...")
                await app_manager.restart()
            else:
                print("  🔄 Attempting reconnect in 3s...")
                await asyncio.sleep(3.0)

            try:
                ws = await try_connect(WS_URI, retries=0)
                print("  ✅ Reconnected! Skipping the crashing payload and proceeding to the next.")
                # We do not re-send the payload that caused the disconnect, because if it's a hard panic/crash,
                # it will simply crash the app again in an infinite loop or break the run.
                print()
                continue
            except Exception as exc:
                print(f"  💥 Reconnect failed: {exc} — skipping remaining payloads")
                break

        # Tally status
        status = response.get("status", "unknown")
        if status == "success":
            result_preview = truncate(str(response.get("result", "")))
            print(f"  ✅ Success: {result_preview}")
        elif status == "timeout":
            stats.timeout += 1
            stats.command_stats[cmd].timeout += 1
            stats.command_stats[cmd].vulnerabilities_found.add("Timeout / Hang")
            print(f"  ⏱️  Timeout ({DEFAULT_TIMEOUT}s)")
        elif status == "error":
            err = truncate(str(response.get("error", "")))
            print(f"  ❌ Error: {err}")
        else:
            print(f"  ❓ Unknown status: {status}")

        # Check for findings
        new_findings = check_findings(payload, response)
        for finding in new_findings:
            stats.findings.append(finding)
            stats.command_stats[cmd].vulnerabilities_found.add(finding.category)
            print(
                f"  🚨 FINDING [{finding.severity}] {finding.category}: {finding.description}"
            )

        print()

    # --- close ---
    try:
        await ws.close()
    except websockets.exceptions.WebSocketException:
        pass



    if app_manager and app_manager.monitor:
        await app_manager.monitor.stop()
        app_manager.monitor.correlate()
        print("\n" + "=" * 70)
        print("🛡️  Correlated OS Monitor Syscalls")
        print("=" * 70)
        for r in app_manager.monitor.records:
            if r.syscalls:
                cmd = r.payload.get("command", "?")
                print(f"[{r.idx}] 📤 {cmd}:")
                for sys_log in r.syscalls:
                    print(f"  -> {sys_log}")

                # Register a finding for the correlated OS activity
                stats.findings.append(
                    Finding(
                        category="OS Monitor Trace",
                        severity="CRITICAL",
                        payload=r.payload,
                        response=r.response or {},
                        description=f"OS-level syscall trace confirmed execution: {r.syscalls[0]} ({len(r.syscalls)} total syscalls)"
                    )
                )
                if cmd in stats.command_stats:
                    stats.command_stats[cmd].vulnerabilities_found.add("OS Monitor Trace")
        print()

    # --- summary ---
    print("\n" + "=" * 70)
    print("📊  Evaluation Metrics Summary")
    print("=" * 70)

    exercised = len(stats.command_stats)
    coverage_pct = (exercised / stats.total_endpoints_discovered * 100) if stats.total_endpoints_discovered > 0 else 0
    print("Endpoint Coverage:")
    print(f"  Total IPC Endpoints Discovered : {stats.total_endpoints_discovered}")
    print(f"  Endpoints Exercised by Scanner : {exercised} / {stats.total_endpoints_discovered} ({coverage_pct:.0f}% Coverage)")
    print()

    print("Vulnerability Detection Results:")
    print(f"  {'Endpoint':<25}  {'Exploited?':<10}  {'Vulnerabilities Found':<30}  {'Stability':<15}")
    print(f"  {'-'*25}  {'-'*10}  {'-'*30}  {'-'*15}")

    for c, c_stats in stats.command_stats.items():
        exploited = "✅ YES" if c_stats.vulnerabilities_found else "❌ NO"
        vulns = ", ".join(sorted(c_stats.vulnerabilities_found)) if c_stats.vulnerabilities_found else "None"

        if c_stats.disconnect == 0 and c_stats.deadlock == 0 and c_stats.timeout == 0:
            stability = "100% stable"
        else:
            stability = f"C:{c_stats.disconnect} D:{c_stats.deadlock} T:{c_stats.timeout}"

        print(f"  {c:<25}  {exploited:<10}  {truncate(vulns, 30):<30}  {stability:<15}")

    print("=" * 70)

    if json_report_path:
        report = {
            "metrics": {
                "total_endpoints_discovered": stats.total_endpoints_discovered,
                "endpoints_exercised": exercised,
                "coverage_percentage": coverage_pct,
                "throughput": {
                    "total_payloads": stats.total,
                    "timeout": stats.timeout,
                    "deadlock": stats.deadlock,
                    "disconnect": stats.disconnect
                }
            },
            "endpoints": {}
        }
        for c, c_stats in stats.command_stats.items():
            report["endpoints"][c] = {
                "exploited": bool(c_stats.vulnerabilities_found),
                "vulnerabilities": sorted(c_stats.vulnerabilities_found),
                "payloads_sent": c_stats.payloads_sent,
                "crashes": c_stats.disconnect,
                "deadlocks": c_stats.deadlock,
                "timeouts": c_stats.timeout,
            }

        try:
            Path(json_report_path).write_text(json.dumps(report, indent=2), encoding="utf-8")
            print(f"\n📄 JSON report saved to: {json_report_path}")
        except Exception as e:
            print(f"\n⚠️ Failed to save JSON report: {e}")


def load_payloads(path: str) -> list[dict]:
    """
    Load payloads from a JSON file.

    The file must contain a JSON array of objects, each with at least
    a 'command' key and an optional 'args' key.

    Args:
        path: Path to the JSON payload file.

    Returns:
        A list of payload dicts.

    Raises:
        SystemExit: If the file cannot be read or parsed.
    """
    p = Path(path)
    if not p.is_file():
        print(f"❌ Payload file not found: {path}")
        sys.exit(1)

    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"❌ Invalid JSON in payload file: {exc}")
        sys.exit(1)

    if not isinstance(data, list):
        print("❌ Payload file must contain a JSON array")
        sys.exit(1)

    for i, entry in enumerate(data):
        if not isinstance(entry, dict) or "command" not in entry:
            print(f"❌ Payload at index {i} is missing required 'command' key")
            sys.exit(1)

    return data


async def async_main(args, payloads=None):
    app_manager = AppManager(args.spawn, app_name=args.app_name) if args.spawn is not None else None

    if args.setup:
        await setup_mode(args.output, app_manager=app_manager)
        return

    if app_manager:
        await app_manager.start()

    total_endpoints = 0
    try:
        commands = await fetch_commands(WS_URI)
        total_endpoints = len(commands)
    except Exception:
        pass

    try:
        await run_fuzzer(
            payloads,
            app_manager=app_manager,
            total_endpoints=total_endpoints,
            json_report_path=args.json_report
        )
    finally:
        if app_manager:
            await app_manager.stop()


def main() -> None:
    """Entry point: parse CLI arguments and launch the async fuzzer."""
    parser = argparse.ArgumentParser(
        description="TauriScan — Dynamic security scanner for Tauri applications",
    )

    # -- Modes ----------------------------------------------------------------
    parser.add_argument(
        "payload_file",
        nargs="?",
        default=None,
        help="Path to a JSON file with an array of {command, args} payloads. "
        "If omitted, built-in test payloads are used.",
    )
    parser.add_argument(
        "--setup",
        action="store_true",
        help="Connect to the Tauri app, discover commands, and generate a "
        "fuzz configuration template. The process exits after writing the file.",
    )
    parser.add_argument(
        "--config",
        default=None,
        metavar="FILE",
        help="Run the fuzzer using a configuration file produced by --setup.",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=DEFAULT_CONFIG_PATH,
        metavar="FILE",
        help=f"Output path for --setup mode (default: {DEFAULT_CONFIG_PATH}).",
    )
    parser.add_argument(
        "--spawn",
        nargs="?",
        const=".",
        default=None,
        help="Automatically launch the Tauri application via `cargo tauri dev` in the specified directory (default: current directory).",
    )
    parser.add_argument(
        "--app-name",
        default="tauriscan",
        help="Name of the target binary for OS monitoring (default: tauriscan).",
    )
    parser.add_argument(
        "--json-report",
        default=None,
        metavar="FILE",
        help="Path to save the JSON evaluation metrics report.",
    )

    args = parser.parse_args()

    if args.setup:
        payloads = None
    elif args.config:
        payloads = load_config(args.config)
        print(f"📂 Loaded config from {args.config} → {len(payloads)} payload(s)\n")
    elif args.payload_file:
        payloads = load_payloads(args.payload_file)
        print(f"📂 Loaded {len(payloads)} payloads from {args.payload_file}\n")
    else:
        print("❌ Please provide a payload file, use --config, or run --setup.")
        sys.exit(1)

    try:
        asyncio.run(async_main(args, payloads))
    except KeyboardInterrupt:
        print("\n\n⛔ Interrupted by user")
        sys.exit(130)


if __name__ == "__main__":
    main()
