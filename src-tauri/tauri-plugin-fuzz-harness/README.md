# Tauri Fuzz Harness Plugin

This crate provides a drop-in Tauri v2 plugin that enables dynamic IPC (Inter-Process Communication) fuzzing for any Tauri application.

## How it Works

The harness injects payloads through the *real* Tauri IPC boundary by injecting JavaScript directly into the WebView. This ensures that every payload transverses the exact same serialization and dispatch layers an actual attacker would use.

When initialized, the plugin:
1. Populates a command registry.
2. Spawns a WebSocket server on `ws://127.0.0.1:31337`.
3. Listens for `fuzz-result` events emitted back from the WebView.

## Connecting and Sending Payloads

The plugin listens for WebSocket connections on **Port 31337**. You can connect to it generically using any WebSocket client.

### Payload Format (JSON)
```json
{
  "id": "123e4567-e89b-12d3-a456-426614174000",
  "command": "read_file",
  "args": { "path": "../../../etc/passwd" }
}
```

### Simple Python Example
```python
import asyncio
import websockets
import json

async def run_fuzz():
    uri = "ws://127.0.0.1:31337"
    async with websockets.connect(uri) as ws:
        payload = {
            "id": "test-1",
            "command": "read_file",
            "args": {"path": "../../../etc/passwd"}
        }
        await ws.send(json.dumps(payload))
        response = await ws.recv()
        print(f"Received: {response}")

asyncio.run(run_fuzz())
```
