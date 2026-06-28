#!/usr/bin/env python3
"""
Fuzzing orchestrator for Tauri plugin WebSocket listener.

Sends security-focused fuzzing payloads over WebSocket to a Tauri plugin
running at ws://127.0.0.1:31337, then analyzes the responses for potential
vulnerabilities including path traversal, SSRF, and type confusion issues.

Usage:
    python fuzzer.py                  # Run with built-in test payloads
    python fuzzer.py payloads.json    # Run with custom payload file
"""

import argparse
import asyncio
import json
import os
import re
import signal
import subprocess
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import websockets
from websockets.exceptions import ConnectionClosed, InvalidURI, WebSocketException

WS_URI = "ws://127.0.0.1:31337"
DEFAULT_TIMEOUT = 15
DEFAULT_CONFIG_PATH = "fuzz_config.json"

# ---------------------------------------------------------------------------
# Preset payload collections keyed by vulnerability category.
# Each list contains raw values that get injected into the target argument.
# ---------------------------------------------------------------------------
PAYLOAD_PRESETS: dict[str, list] = {
    "path_traversal": [
        ".",
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "..\\..\\..\\etc\\passwd",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc/passwd",
        "/etc/passwd",
        "/",
        "../../..",
        "/etc",
    ],
    "ssrf": [
        "https://httpbin.org/get",
        "http://127.0.0.1",
        "http://169.254.169.254/latest/meta-data/",
        "file:///etc/passwd",
        "http://[::1]/",
        "http://0x7f000001/",
        "http://localhost/",
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
        "<script>alert(1)</script>",
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

TEST_PAYLOADS = [
    # Path traversal — read_file
    {
        "command": "read_file",
        "args": {"path": "readme.txt"},
    },  # Baseline: should succeed
    {"command": "read_file", "args": {"path": "../../../etc/passwd"}},
    {"command": "read_file", "args": {"path": "....//....//....//etc/passwd"}},
    {"command": "read_file", "args": {"path": "..\\..\\..\\etc\\passwd"}},
    {"command": "read_file", "args": {"path": "%2e%2e%2f%2e%2e%2fetc%2fpasswd"}},
    {"command": "read_file", "args": {"path": "..%252f..%252f..%252fetc/passwd"}},
    {"command": "read_file", "args": {"path": "/etc/passwd"}},
    # Path traversal — list_directory
    {"command": "list_directory", "args": {"path": "."}},  # Baseline: should succeed
    {"command": "list_directory", "args": {"path": "../../.."}},
    {"command": "list_directory", "args": {"path": "/etc"}},
    {"command": "list_directory", "args": {"path": "/"}},
    # SSRF — fetch_url
    {"command": "fetch_url", "args": {"url": "https://httpbin.org/get"}},  # Baseline
    {"command": "fetch_url", "args": {"url": "http://127.0.0.1:31337"}},
    {
        "command": "fetch_url",
        "args": {"url": "http://169.254.169.254/latest/meta-data/"},
    },
    {"command": "fetch_url", "args": {"url": "file:///etc/passwd"}},
    {"command": "fetch_url", "args": {"url": "http://[::1]/"}},
    {"command": "fetch_url", "args": {"url": "http://0x7f000001/"}},
    # Type confusion — process_data
    # Valid baseline
    {
        "command": "process_data",
        "args": {
            "data": {
                "name": "test",
                "age": 25,
                "admin": False,
                "metadata": {"role": "user"},
            }
        },
    },
    # Wrong types
    {
        "command": "process_data",
        "args": {
            "data": {
                "name": 12345,
                "age": "not_a_number",
                "admin": "yes",
                "metadata": {"role": None},
            }
        },
    },
    # Missing fields
    {"command": "process_data", "args": {"data": {}}},
    {"command": "process_data", "args": {"data": {"name": "test"}}},
    # Wrong top-level type
    {"command": "process_data", "args": {"data": "just a string"}},
    {"command": "process_data", "args": {"data": [1, 2, 3]}},
    {"command": "process_data", "args": {"data": None}},
    # Deeply nested
    {
        "command": "process_data",
        "args": {
            "data": {
                "name": "test",
                "age": 25,
                "admin": False,
                "metadata": {
                    "role": "user",
                    "nested": {"a": {"b": {"c": {"d": "deep"}}}},
                },
            }
        },
    },
    # Oversized values
    {
        "command": "process_data",
        "args": {
            "data": {
                "name": "A" * 100000,
                "age": 1e308,
                "admin": False,
                "metadata": {"role": "user"},
            }
        },
    },
]

SSRF_INDICATORS = ["127.0.0.1", "169.254", "file://", "localhost", "[::1]", "0x7f"]


@dataclass
class Finding:
    """A single security finding from a fuzz run."""

    category: str
    severity: str
    payload: dict
    response: dict
    description: str


@dataclass
class FuzzStats:
    """Accumulated statistics for a fuzz run."""

    total: int = 0
    success: int = 0
    error: int = 0
    timeout: int = 0
    disconnect: int = 0
    findings: list = field(default_factory=list)


def is_path_traversal_finding(payload: dict, response: dict) -> Finding | None:
    """Check if a response indicates a successful path traversal."""
    cmd = payload.get("command", "")
    if cmd not in ("read_file", "list_directory"):
        return None
    if response.get("status") != "success":
        return None

    path_arg = payload.get("args", {}).get("path", "")
    if ".." in path_arg or path_arg.startswith("/"):
        return Finding(
            category="Path Traversal",
            severity="CRITICAL",
            payload=payload,
            response=response,
            description=f"{cmd} succeeded with path: {path_arg}",
        )
    return None


def is_ssrf_finding(payload: dict, response: dict) -> Finding | None:
    """Check if a response indicates a successful SSRF."""
    if payload.get("command") != "fetch_url":
        return None
    if response.get("status") != "success":
        return None

    url = payload.get("args", {}).get("url", "")
    for indicator in SSRF_INDICATORS:
        if indicator in url.lower():
            return Finding(
                category="SSRF",
                severity="HIGH",
                payload=payload,
                response=response,
                description=f"fetch_url succeeded with suspicious URL: {url}",
            )
    return None


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
        is_path_traversal_finding,
        is_ssrf_finding,
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
    except asyncio.TimeoutError:
        return {
            "id": msg_id,
            "status": "timeout",
            "command": payload["command"],
            "result": None,
            "error": f"No response within {timeout}s",
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
    print(f"  3. Run:  python fuzzer.py --config {output_path}")

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
    OS-level monitor wrapper for macOS (fs_usage / lsof).
    Tracks underlying system calls made by the Tauri application to independently
    confirm successful vulnerability exploitation (e.g. unauthorized filesystem/network access).
    """
    def __init__(self, pid: int | None = None):
        self.pid = pid
        self.proc: asyncio.subprocess.Process | None = None
        self.running = False
        self.alerts: list[str] = []

    async def start(self):
        self.running = True
        if not self.pid:
            print("  ⚠️ SystemMonitor: No target PID available for monitoring.")
            return

        print(f"  🛡️ SystemMonitor: Initializing OS-level monitoring for PID {self.pid}...")
        try:
            # Check if we can run fs_usage without password prompt
            test_proc = await asyncio.create_subprocess_exec(
                "sudo", "-n", "fs_usage", "-w", "-f", "filesys", str(self.pid),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            await asyncio.sleep(0.5)
            if test_proc.returncode is not None and test_proc.returncode != 0:
                print("  ⚠️ SystemMonitor: 'sudo fs_usage' requires root/password. Falling back to active lsof monitoring.")
                self.proc = None
                asyncio.create_task(self._poll_lsof())
            else:
                print(f"  🛡️ SystemMonitor: Successfully attached fs_usage to PID {self.pid}.")
                self.proc = test_proc
                asyncio.create_task(self._read_fs_usage())
        except Exception as exc:
            print(f"  ⚠️ SystemMonitor: Monitoring startup failed ({exc}).")

    async def _read_fs_usage(self):
        if not self.proc or not self.proc.stdout:
            return
        while self.running:
            line = await self.proc.stdout.readline()
            if not line:
                break
            text = line.decode(errors="ignore")
            if any(target in text for target in ["/etc/passwd", "169.254", "127.0.0.1", "httpbin"]):
                clean_line = text.strip()
                self.alerts.append(f"Syscall match: {clean_line}")

    async def _poll_lsof(self):
        while self.running:
            if not self.pid:
                break
            try:
                proc = await asyncio.create_subprocess_exec(
                    "lsof", "-p", str(self.pid),
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await proc.communicate()
                text = stdout.decode(errors="ignore")
                for line in text.splitlines():
                    if any(target in line for target in ["/etc/passwd", "169.254", "127.0.0.1", "httpbin"]):
                        self.alerts.append(f"lsof match: {line.strip()}")
            except Exception:
                pass
            await asyncio.sleep(1.0)

    async def stop(self):
        self.running = False
        if self.proc:
            try:
                self.proc.kill()
            except Exception:
                pass


class AppManager:
    """
    Manages the lifecycle of the target Tauri application (spawning, monitoring, restarting).
    Grants the orchestrator full control over the fuzzing workflow.
    """
    def __init__(self, app_dir: str, enable_monitor: bool = False):
        self.app_dir = app_dir
        self.enable_monitor = enable_monitor
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
                    if self.enable_monitor:
                        self.monitor = SystemMonitor(self.proc.pid)
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
            except Exception:
                pass
            try:
                subprocess.run(["pkill", "-9", "-f", "taurifuzz"], capture_output=True)
            except Exception:
                pass
            try:
                await asyncio.wait_for(self.proc.wait(), timeout=2.0)
            except asyncio.TimeoutError:
                pass
            self.proc = None


async def run_fuzzer(payloads: list[dict], app_manager: AppManager | None = None) -> None:
    """
    Run the fuzzer: connect to the WebSocket server, send every payload,
    collect results, and print a final summary with findings.

    Args:
        payloads: A list of dicts, each with 'command' and 'args' keys.
        app_manager: Optional AppManager instance managing the Tauri subprocess.
    """
    stats = FuzzStats(total=len(payloads))

    print("=" * 70)
    print("🔧  TauriFuzz Orchestrator")
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
        cmd = payload.get("command", "?")
        args_preview = truncate(json.dumps(payload.get("args", {})))
        print(f"[{idx}/{len(payloads)}] 📤 {cmd}  {args_preview}")

        response = await send_payload(ws, payload)

        # Handle disconnection with automated recovery or reconnect attempt
        if response["status"] == "disconnect":
            stats.disconnect += 1
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
                print("  🔄 Crash detected! AppManager initiating automated recovery...")
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
            stats.success += 1
            result_preview = truncate(str(response.get("result", "")))
            print(f"  ✅ Success: {result_preview}")
        elif status == "timeout":
            stats.timeout += 1
            print(f"  ⏱️  Timeout ({DEFAULT_TIMEOUT}s)")
        elif status == "error":
            stats.error += 1
            err = truncate(str(response.get("error", "")))
            print(f"  ❌ Error: {err}")
        else:
            stats.error += 1
            print(f"  ❓ Unknown status: {status}")

        # Check for findings
        new_findings = check_findings(payload, response)
        for finding in new_findings:
            stats.findings.append(finding)
            print(
                f"  🚨 FINDING [{finding.severity}] {finding.category}: {finding.description}"
            )

        # Check for OS-level monitor alerts
        if app_manager and app_manager.monitor and app_manager.monitor.alerts:
            for alert in app_manager.monitor.alerts:
                print(f"  🛡️ OS MONITOR ALERT: {alert}")
            app_manager.monitor.alerts.clear()

        print()

    # --- close ---
    try:
        await ws.close()
    except Exception:
        pass

    # --- summary ---
    print()
    print("=" * 70)
    print("📊  Summary")
    print("=" * 70)
    print(f"  Total payloads : {stats.total}")
    print(f"  ✅ Success      : {stats.success}")
    print(f"  ❌ Error        : {stats.error}")
    print(f"  ⏱️  Timeout      : {stats.timeout}")
    print(f"  💥 Disconnect   : {stats.disconnect}")
    print()

    if stats.findings:
        print(f"🚨 {len(stats.findings)} FINDING(S):")
        print("-" * 70)
        for i, f in enumerate(stats.findings, start=1):
            print(f"  {i}. [{f.severity}] {f.category}")
            print(f"     {f.description}")
            print(f"     Payload: {truncate(json.dumps(f.payload), 200)}")
            resp_preview = {k: truncate(str(v), 80) for k, v in f.response.items()}
            print(f"     Response: {truncate(json.dumps(resp_preview), 200)}")
            print()
    else:
        print("✅ No findings — all payloads handled safely.")

    print("=" * 70)


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
    app_manager = AppManager(args.spawn, enable_monitor=args.monitor) if args.spawn is not None else None

    if args.setup:
        await setup_mode(args.output, app_manager=app_manager)
        return

    if app_manager:
        await app_manager.start()

    try:
        await run_fuzzer(payloads, app_manager=app_manager)
    finally:
        if app_manager:
            await app_manager.stop()


def main() -> None:
    """Entry point: parse CLI arguments and launch the async fuzzer."""
    parser = argparse.ArgumentParser(
        description="TauriFuzz — WebSocket fuzzing orchestrator for Tauri plugins",
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
        "--monitor",
        action="store_true",
        help="Enable OS-level system monitoring (e.g. fs_usage/lsof on macOS) to confirm vulnerability exploitation at the syscall level.",
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
        payloads = TEST_PAYLOADS
        print(f"📦 Using {len(payloads)} built-in test payloads\n")

    try:
        asyncio.run(async_main(args, payloads))
    except KeyboardInterrupt:
        print("\n\n⛔ Interrupted by user")
        sys.exit(130)


if __name__ == "__main__":
    main()
