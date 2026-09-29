"""No-op MCP stdio server for instrument calibration."""

from __future__ import annotations

import json
import sys


def _reply(msg_id: object, result: object) -> None:
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": result}) + "\n")
    sys.stdout.flush()


def _reply_error(msg_id: object, code: int, message: str) -> None:
    sys.stdout.write(
        json.dumps(
            {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}
        )
        + "\n"
    )
    sys.stdout.flush()


def main() -> None:
    for line in sys.stdin:
        trimmed = line.strip()
        if not trimmed:
            continue
        try:
            msg = json.loads(trimmed)
        except json.JSONDecodeError:
            continue
        method = msg.get("method")
        msg_id = msg.get("id")
        if method == "initialize":
            _reply(
                msg_id,
                {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "aos-bp-calibrate-pypi", "version": "0.0.1"},
                },
            )
        elif method in ("notifications/initialized", "initialized"):
            continue
        elif method == "tools/list":
            _reply(
                msg_id,
                {
                    "tools": [
                        {
                            "name": "noop",
                            "description": "calibration noop",
                            "inputSchema": {"type": "object", "properties": {}},
                        }
                    ]
                },
            )
        elif method == "tools/call":
            _reply(msg_id, {"content": [{"type": "text", "text": "ok"}]})
        elif msg_id is not None:
            _reply_error(msg_id, -32601, "Method not found")


if __name__ == "__main__":
    main()
