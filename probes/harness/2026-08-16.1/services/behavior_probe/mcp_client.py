"""JSON-RPC MCP session over stdio (no LLM)."""

from __future__ import annotations

import json
import os
import select
import time
from dataclasses import dataclass, field
from typing import Any, BinaryIO, TextIO

from services.behavior_probe.args_synth import SchemaError, synthesize_arguments
from services.behavior_probe.constants import JSONRPC_INVALID_PARAMS, TOOL_CALL_TIMEOUT_SEC


def _now_ts() -> str:
    # Match strace -ttt epoch seconds (no TZ); compare with container stamps via float.
    return f"{time.time():.6f}"


@dataclass
class ToolOutcome:
    name: str
    kind: str  # success | validation_error | domain_error | timeout | not_measured
    reason: str | None = None


@dataclass
class SessionResult:
    initialize_ok: bool = False
    tools: list[dict[str, Any]] = field(default_factory=list)
    tools_total: int = 0
    tools_called: int = 0
    tool_outcomes: dict[str, int] = field(
        default_factory=lambda: {
            "success": 0,
            "validation_error": 0,
            "domain_error": 0,
            "timeout": 0,
            "not_measured": 0,
        }
    )
    stage_marks: list[tuple[str, str]] = field(default_factory=list)
    error: str | None = None
    raw_log: list[str] = field(default_factory=list)


class McpStdioClient:
    def __init__(
        self,
        stdin: BinaryIO | TextIO,
        stdout: BinaryIO | TextIO,
        *,
        tool_timeout: float = TOOL_CALL_TIMEOUT_SEC,
    ) -> None:
        self._in = stdin
        self._out = stdout
        self._tool_timeout = tool_timeout
        self._next_id = 1
        self._buf = b""

    def _write(self, msg: dict[str, Any]) -> None:
        data = (json.dumps(msg, ensure_ascii=False) + "\n").encode("utf-8")
        raw = self._in
        if hasattr(raw, "buffer"):
            raw = raw.buffer  # type: ignore[assignment]
        raw.write(data)  # type: ignore[union-attr]
        raw.flush()  # type: ignore[union-attr]

    def _stdout_fd(self) -> int:
        """Raw fd for non-blocking-amount reads (never BufferedReader.read)."""
        out = self._out
        if hasattr(out, "buffer"):
            out = out.buffer  # type: ignore[assignment]
        return out.fileno()  # type: ignore[union-attr]

    def _read_message(self, timeout: float) -> dict[str, Any] | None:
        """Read one JSON line; return available bytes only (os.read, not BufferedReader).

        BufferedReader.read(n) waits for n bytes or EOF — a short MCP response
        (~150 B) makes select report readable then blocks forever while the
        server waits for the next request.
        """
        deadline = time.monotonic() + timeout
        fd = self._stdout_fd()
        while time.monotonic() < deadline:
            if b"\n" in self._buf:
                line, self._buf = self._buf.split(b"\n", 1)
                line = line.strip()
                if not line:
                    continue
                try:
                    return json.loads(line.decode("utf-8"))
                except json.JSONDecodeError:
                    continue
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            ready, _, _ = select.select([fd], [], [], min(remaining, 0.5))
            if not ready:
                continue
            # os.read returns whatever is available (may be < 4096); never
            # BufferedReader.read which blocks until size or EOF.
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            self._buf += chunk
        return None

    def request(self, method: str, params: dict[str, Any] | None, timeout: float) -> dict[str, Any] | None:
        req_id = self._next_id
        self._next_id += 1
        msg: dict[str, Any] = {"jsonrpc": "2.0", "id": req_id, "method": method}
        if params is not None:
            msg["params"] = params
        self._write(msg)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            resp = self._read_message(max(0.1, deadline - time.monotonic()))
            if resp is None:
                return None
            # Skip notifications / unmatched
            if resp.get("id") == req_id:
                return resp
        return None

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        msg: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self._write(msg)


def run_mcp_session(
    stdin: BinaryIO | TextIO,
    stdout: BinaryIO | TextIO,
    *,
    tool_timeout: float = TOOL_CALL_TIMEOUT_SEC,
    overall_deadline: float | None = None,
) -> SessionResult:
    """initialize → initialized → tools/list → tools/call for each tool."""
    client = McpStdioClient(stdin, stdout, tool_timeout=tool_timeout)
    result = SessionResult()
    result.stage_marks.append((_now_ts(), "startup"))

    init = client.request(
        "initialize",
        {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "aos-behavior-probe", "version": "0.1.0"},
        },
        timeout=30.0,
    )
    if init is None or "error" in (init or {}):
        result.error = "initialize_failed"
        return result
    result.initialize_ok = True
    client.notify("notifications/initialized")

    result.stage_marks.append((_now_ts(), "tools_list"))
    listed = client.request("tools/list", {}, timeout=30.0)
    if listed is None:
        result.error = "tools_list_failed"
        return result
    if "error" in listed:
        result.error = f"tools_list_error:{listed['error']}"
        return result
    tools = ((listed.get("result") or {}).get("tools")) or []
    if not isinstance(tools, list):
        result.error = "tools_list_malformed"
        return result
    result.tools = tools
    result.tools_total = len(tools)

    for tool in tools:
        if overall_deadline is not None and time.monotonic() > overall_deadline:
            result.error = "run_timeout"
            break
        name = str(tool.get("name") or "")
        if not name:
            result.tool_outcomes["not_measured"] += 1
            continue
        result.stage_marks.append((_now_ts(), f"tools_call:{name}"))
        schema = tool.get("inputSchema")
        try:
            args = synthesize_arguments(schema)
        except SchemaError as exc:
            result.tool_outcomes["not_measured"] += 1
            result.raw_log.append(f"schema_error:{name}:{exc}")
            continue

        resp = client.request(
            "tools/call",
            {"name": name, "arguments": args},
            timeout=tool_timeout,
        )
        result.tools_called += 1
        if resp is None:
            result.tool_outcomes["timeout"] += 1
            continue
        if "error" in resp:
            err = resp["error"] or {}
            code = err.get("code")
            if code == JSONRPC_INVALID_PARAMS or code == -32602:
                result.tool_outcomes["validation_error"] += 1
            else:
                # Treat other JSON-RPC errors as domain-ish for counting purposes.
                result.tool_outcomes["domain_error"] += 1
            continue
        body = resp.get("result") or {}
        if isinstance(body, dict) and body.get("isError") is True:
            result.tool_outcomes["domain_error"] += 1
        else:
            result.tool_outcomes["success"] += 1

    return result
