"""Run a built image under --network=none and collect strace + MCP outcomes."""

from __future__ import annotations

import json
import subprocess
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from services.behavior_probe.constants import (
    RUN_TIMEOUT_SEC,
    STDERR_CAPTURE_CAPTURED,
    STDERR_CAPTURE_EMPTY,
    STDERR_CAPTURE_UNAVAILABLE,
    STDERR_DRAIN_AFTER_EXIT_SEC,
    TOOL_CALL_TIMEOUT_SEC,
)
from services.behavior_probe.env import ResourceLimits, build_podman_run_base_args, resolve_resource_limits
from services.behavior_probe.mcp_client import SessionResult, run_mcp_session

WATCHDOG_REASON = "run_timeout_watchdog"


@dataclass
class RunResult:
    ok: bool
    reason: str | None
    strace_text: str
    session: SessionResult | None
    container_inspect: dict[str, Any] | None
    network_mode: str | None
    mounts: list[Any] | None
    resource_limits: dict[str, Any] | None = None
    podman_argv: list[str] | None = None
    dns_query_log: str = ""
    server_stderr: str = ""
    stderr_capture: str = STDERR_CAPTURE_UNAVAILABLE


def server_stderr_head(text: str, *, max_lines: int = 20, max_bytes: int = 2048) -> str:
    """First 20 lines or 2KB of server stderr (whichever is smaller)."""
    if not text:
        return ""
    clipped = text[:max_bytes]
    lines = clipped.splitlines()
    if len(lines) > max_lines:
        return "\n".join(lines[:max_lines])
    return clipped


@dataclass
class StderrDrain:
    """In-flight stderr reader. Join only after the child has exited."""

    thread: threading.Thread
    chunks: list[bytes]
    flags: dict[str, bool]


def start_stderr_drain(proc: subprocess.Popen[Any]) -> StderrDrain:
    """Read stderr concurrently so the PIPE cannot fill and drop output."""
    flags = {"eof": False, "error": False, "pipe_missing": False}
    chunks: list[bytes] = []

    def _reader() -> None:
        if proc.stderr is None:
            flags["pipe_missing"] = True
            return
        try:
            while True:
                chunk = proc.stderr.read(4096)
                if not chunk:
                    break
                chunks.append(chunk)
            flags["eof"] = True
        except Exception:  # noqa: BLE001 — best-effort capture
            flags["error"] = True

    t = threading.Thread(target=_reader, name="aos-bp-stderr-drain", daemon=True)
    t.start()
    return StderrDrain(thread=t, chunks=chunks, flags=flags)


def collect_stderr_after_exit(
    drain: StderrDrain,
    proc: subprocess.Popen[Any],
    *,
    timeout: float = STDERR_DRAIN_AFTER_EXIT_SEC,
) -> tuple[str, str]:
    """Drain to EOF after the process has exited. Returns (text, stderr_capture).

    Callers must not start container cleanup before this returns. A timeout
    yields ``unavailable`` and does not fail the measurement.
    """
    drain.thread.join(timeout=timeout)
    finished = not drain.thread.is_alive()
    text = b"".join(drain.chunks).decode("utf-8", errors="replace")
    if finished and drain.flags.get("eof") and not text and proc.stderr is not None:
        try:
            leftover = proc.stderr.read()
            if leftover:
                text = leftover.decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            drain.flags["error"] = True

    if (
        not finished
        or drain.flags.get("error")
        or drain.flags.get("pipe_missing")
    ):
        return text, STDERR_CAPTURE_UNAVAILABLE
    if text:
        return text, STDERR_CAPTURE_CAPTURED
    return "", STDERR_CAPTURE_EMPTY


def _run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, check=False, **kwargs)


def run_session_with_watchdog(
    proc: subprocess.Popen[Any],
    *,
    run_timeout: float,
    tool_timeout: float = TOOL_CALL_TIMEOUT_SEC,
    on_fire: Callable[[], None] | None = None,
) -> tuple[SessionResult, bool]:
    """Drive MCP over an already-started process; kill it if run_timeout elapses.

    The timer fires independently of whether ``_read_message`` is blocked.
    Returns ``(session, watchdog_fired)``.
    """
    watchdog_fired = threading.Event()

    def _fire() -> None:
        watchdog_fired.set()
        try:
            if proc.poll() is None:
                proc.kill()
        except OSError:
            pass
        if on_fire is not None:
            try:
                on_fire()
            except Exception:  # noqa: BLE001 — cleanup must not raise into timer
                pass

    timer = threading.Timer(run_timeout, _fire)
    timer.daemon = True
    timer.start()
    deadline = time.monotonic() + run_timeout
    try:
        assert proc.stdin is not None and proc.stdout is not None
        session = run_mcp_session(
            proc.stdin,
            proc.stdout,
            tool_timeout=tool_timeout,
            overall_deadline=deadline,
        )
    except Exception as exc:  # noqa: BLE001
        session = SessionResult(error=f"mcp_session_exception:{exc}")
    finally:
        timer.cancel()
        # If fire() raced with cancel(), keep the fired flag as truth.
    return session, watchdog_fired.is_set()


def run_probed_server(
    image_ref: str,
    *,
    limits: ResourceLimits | None = None,
    run_timeout: float = RUN_TIMEOUT_SEC,
    tool_timeout: float = TOOL_CALL_TIMEOUT_SEC,
) -> RunResult:
    """Start container with network=none, no mounts, no env; talk MCP; collect strace.

    Does NOT relax seccomp or capabilities. If strace fails under default seccomp,
    returns not_measured reason for the caller to stop and report.

    ``--cpus`` is included only when ``limits.cpus`` is set (cpu controller delegated).
    Outer ``run_timeout`` is enforced by a thread timer that kills the child and
    ``podman rm -f`` regardless of MCP read progress (calibration uses the same path).
    """
    resolved = limits if limits is not None else resolve_resource_limits()
    name = f"aos-bp-{uuid.uuid4().hex[:12]}"
    cmd = build_podman_run_base_args(resolved)
    # Insert --name after "podman run -i"
    # build_podman_run_base_args starts: podman run -i --network=none ...
    cmd = cmd[:3] + ["--name", name] + cmd[3:] + [image_ref]
    limits_record = resolved.as_record()

    inspect_data: dict[str, Any] | None = None
    network_mode: str | None = None
    mounts: list[Any] | None = None
    container_cleaned = False
    strace_from_watchdog = ""
    dns_from_watchdog = ""
    stderr_text = ""
    stderr_capture = STDERR_CAPTURE_UNAVAILABLE
    drain: StderrDrain | None = None

    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
        )
    except OSError as exc:
        return RunResult(
            False,
            f"podman_run_failed:{exc}",
            "",
            None,
            None,
            None,
            None,
            limits_record,
            cmd,
            "",
            "",
            STDERR_CAPTURE_UNAVAILABLE,
        )

    drain = start_stderr_drain(proc)

    # Brief settle so ENTRYPOINT/strace starts.
    time.sleep(0.5)
    if proc.poll() is not None:
        # Process already gone — finish the pipe before any container cleanup.
        stderr_text, stderr_capture = collect_stderr_after_exit(drain, proc)
        _cleanup_container(name)
        if "Operation not permitted" in stderr_text or "ptrace" in stderr_text.lower():
            return RunResult(
                False,
                "strace_blocked_under_default_seccomp_stop_and_report",
                stderr_text,
                None,
                None,
                None,
                None,
                limits_record,
                cmd,
                "",
                stderr_text,
                stderr_capture,
            )
        return RunResult(
            False,
            f"container_exited_early:{stderr_text[:500]}",
            stderr_text,
            None,
            None,
            None,
            None,
            limits_record,
            cmd,
            "",
            stderr_text,
            stderr_capture,
        )

    # Inspect while running.
    inspect_proc = _run(["podman", "inspect", name], timeout=30)
    if inspect_proc.returncode == 0 and inspect_proc.stdout:
        try:
            arr = json.loads(inspect_proc.stdout)
            inspect_data = arr[0] if isinstance(arr, list) and arr else {}
            hc = inspect_data.get("HostConfig") or {}
            network_mode = str(hc.get("NetworkMode") or "")
            mounts = list(inspect_data.get("Mounts") or [])
        except json.JSONDecodeError:
            inspect_data = None

    def _watchdog_collect() -> None:
        """Kill is done by the timer. Collect artifacts only — do not rm yet.

        stderr drain must finish (or hit its cap) before container cleanup.
        """
        nonlocal strace_from_watchdog, dns_from_watchdog
        try:
            strace_from_watchdog = _collect_strace(name)
        except Exception:  # noqa: BLE001
            strace_from_watchdog = ""
        try:
            dns_from_watchdog = _collect_dns_query_log(name)
        except Exception:  # noqa: BLE001
            dns_from_watchdog = ""

    session, watchdog_fired = run_session_with_watchdog(
        proc,
        run_timeout=run_timeout,
        tool_timeout=tool_timeout,
        on_fire=_watchdog_collect,
    )

    # Close stdin to signal EOF; wait for exit.
    try:
        if proc.stdin is not None:
            proc.stdin.close()
    except Exception:  # noqa: BLE001
        pass
    try:
        proc.wait(timeout=5.0)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass

    # Process is gone (or killed). Finish the pipe before any container cleanup.
    if drain is not None:
        stderr_text, stderr_capture = collect_stderr_after_exit(drain, proc)

    # Fallback when PIPE drained empty but the container still logged something.
    if stderr_capture == STDERR_CAPTURE_EMPTY and not container_cleaned:
        logs = _run(["podman", "logs", name], timeout=15)
        if logs.returncode == 0 and (logs.stderr or logs.stdout):
            # podman logs merges streams; prefer stderr field then stdout.
            stderr_text = (logs.stderr or "") + (logs.stdout or "")
            if stderr_text:
                stderr_capture = STDERR_CAPTURE_CAPTURED

    strace_text = strace_from_watchdog or _collect_strace(name)
    if not strace_text and stderr_text:
        strace_text = stderr_text
    dns_query_log = dns_from_watchdog or _collect_dns_query_log(name)
    _cleanup_container(name)
    container_cleaned = True

    if watchdog_fired:
        return RunResult(
            False,
            WATCHDOG_REASON,
            strace_text,
            session,
            inspect_data,
            network_mode,
            mounts,
            limits_record,
            cmd,
            dns_query_log,
            stderr_text,
            stderr_capture,
        )

    if network_mode and network_mode != "none":
        return RunResult(
            False,
            f"network_mode_not_none:{network_mode}",
            strace_text,
            session,
            inspect_data,
            network_mode,
            mounts,
            limits_record,
            cmd,
            dns_query_log,
            stderr_text,
            stderr_capture,
        )
    if mounts:
        return RunResult(
            False,
            "mounts_not_empty",
            strace_text,
            session,
            inspect_data,
            network_mode,
            mounts,
            limits_record,
            cmd,
            dns_query_log,
            stderr_text,
            stderr_capture,
        )

    if not session.initialize_ok:
        return RunResult(
            False,
            session.error or "initialize_failed",
            strace_text,
            session,
            inspect_data,
            network_mode,
            mounts,
            limits_record,
            cmd,
            dns_query_log,
            stderr_text,
            stderr_capture,
        )

    return RunResult(
        True,
        None,
        strace_text,
        session,
        inspect_data,
        network_mode,
        mounts,
        limits_record,
        cmd,
        dns_query_log,
        stderr_text,
        stderr_capture,
    )


def _collect_strace(container_name: str) -> str:
    with tempfile.TemporaryDirectory(prefix="aos-bp-strace-") as tmp:
        dest = Path(tmp) / "strace.log"
        cp = _run(["podman", "cp", f"{container_name}:/tmp/strace.log", str(dest)], timeout=30)
        if cp.returncode != 0 or not dest.is_file():
            return ""
        return dest.read_text(encoding="utf-8", errors="replace")


def _collect_dns_query_log(container_name: str) -> str:
    with tempfile.TemporaryDirectory(prefix="aos-bp-dns-") as tmp:
        dest = Path(tmp) / "dns_queries.log"
        cp = _run(
            ["podman", "cp", f"{container_name}:/tmp/dns_queries.log", str(dest)],
            timeout=30,
        )
        if cp.returncode != 0 or not dest.is_file():
            return ""
        return dest.read_text(encoding="utf-8", errors="replace")


def _cleanup_container(name: str) -> None:
    _run(["podman", "rm", "-f", name], timeout=60)
