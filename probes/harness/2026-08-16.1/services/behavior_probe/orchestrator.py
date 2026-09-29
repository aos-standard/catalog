"""Orchestrate build → run → judge for network_offline MCP servers."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from services.behavior_probe.build import build_image
from services.behavior_probe.calibrate import (
    CalibrationReport,
    InstrumentContaminatedError,
    run_instrument_calibration,
)
from services.behavior_probe.constants import (
    DNS_RECORDER_NOT_RECORDING,
    STDERR_CAPTURE_CAPTURED,
    STDERR_CAPTURE_UNAVAILABLE,
)
from services.behavior_probe.env import (
    ResourceLimits,
    require_podman_tools,
    resolve_resource_limits,
)
from services.behavior_probe.judge import judge
from services.behavior_probe.report import default_report_paths, write_probe_reports
from services.behavior_probe.run import run_probed_server, server_stderr_head
from services.behavior_probe.start_failure import classify_start_failure
from services.behavior_probe.strace_parse import (
    assign_stages,
    clock_skew_record,
    count_dns_queries_excluding_selftest,
    dns_log_has_selftest,
    merge_dns_queries,
    parse_strace_lines,
    partition_network_evidence,
    tools_name_description,
)
from services.behavior_probe.targets import ProbeTarget, collect_offline_targets, measured_targets


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _attach_stderr_head(base: dict[str, Any], reason: str | None, server_stderr: str) -> None:
    """Keep server stderr head on early-exit / initialize failures."""
    if not reason:
        return
    early = reason.startswith("container_exited_early") or reason.startswith(
        "initialize_failed"
    ) or ("initialize_failed" in reason)
    if not early:
        return
    head = server_stderr_head(server_stderr)
    if not head and reason.startswith("container_exited_early:"):
        # Fallback: early-exit reason embeds the first 500 chars of stderr.
        embedded = reason[len("container_exited_early:") :]
        head = server_stderr_head(embedded)
    if head:
        base["server_stderr_head"] = head


def _attach_stderr_capture(base: dict[str, Any], stderr_capture: str | None) -> None:
    """Record whether the process pipe was actually read."""
    if not stderr_capture:
        return
    base["stderr_capture"] = stderr_capture


def _attach_start_failed_reason(
    base: dict[str, Any],
    reason: str | None,
    *,
    stderr_capture: str | None = None,
) -> None:
    """Keep initialize_failed; add stderr-only subordinate taxonomy.

    Empty / unread pipes become start_failed_stderr_unavailable.
    start_failed_other is only for captured text that matches no known type.
    """
    if not reason:
        return
    if reason != "initialize_failed" and "initialize_failed" not in reason:
        return
    stderr = base.get("server_stderr_head")
    if not isinstance(stderr, str):
        stderr = ""
    capture = stderr_capture if isinstance(stderr_capture, str) else base.get("stderr_capture")
    if not isinstance(capture, str):
        capture = STDERR_CAPTURE_CAPTURED if stderr else STDERR_CAPTURE_UNAVAILABLE
    base["start_failed_reason"] = classify_start_failure(
        stderr,
        stderr_capture=capture,
    )


def _attach_network_partition(
    base: dict[str, Any],
    parsed: Any,
    tools: list[dict[str, Any]] | None = None,
) -> None:
    partitioned = partition_network_evidence(parsed, tools)
    base["unprompted_network"] = partitioned["unprompted_network"]
    base["tool_invoked_network"] = partitioned["tool_invoked_network"]
    base["tool_invoked_network_present"] = partitioned["tool_invoked_network_present"]


def apply_strace_observations(
    base: dict[str, Any],
    strace_text: str,
    stage_marks: list[tuple[str, str]] | None = None,
    *,
    dns_query_log: str | None = None,
    tools: list[dict[str, Any]] | None = None,
) -> None:
    """Attach strace observations even when verdict is not_measured."""
    if not strace_text and not dns_query_log:
        return
    parsed = parse_strace_lines(strace_text or "")
    parsed = merge_dns_queries(parsed, dns_query_log, exclude_selftest=True)
    if stage_marks:
        parsed = assign_stages(parsed, stage_marks)
    base["observations"] = parsed.by_stage()
    base["raw_socket_events"] = parsed.raw_socket_events
    base["strace_lines"] = len((strace_text or "").splitlines())
    base["dns_query_log_lines"] = count_dns_queries_excluding_selftest(dns_query_log)
    base["dns_recorder_selftest"] = dns_log_has_selftest(dns_query_log)
    _attach_network_partition(base, parsed, tools)
    init_ts = None
    if stage_marks:
        for ts, name in stage_marks:
            if name == "startup":
                init_ts = ts
                break
        if init_ts is None and stage_marks:
            init_ts = stage_marks[0][0]
    base["stage_clock"] = clock_skew_record(
        initialize_send_ts=init_ts,
        first_strace_ts=parsed.first_strace_ts,
    )


def _probe_one(target: ProbeTarget, limits: ResourceLimits) -> dict[str, Any]:
    started = _utc_now()
    limits_record = limits.as_record()
    base: dict[str, Any] = {
        "name": target.name,
        "package": {
            "registryType": target.registry_type,
            "identifier": target.identifier,
            "version": target.version,
            "transport": target.transport,
        },
        "claim": target.claim,
        "image_digest": None,
        "verdict": None,
        "observations": {},
        "tools_total": 0,
        "tools_called": 0,
        "tool_outcomes": {
            "success": 0,
            "validation_error": 0,
            "domain_error": 0,
            "timeout": 0,
            "not_measured": 0,
        },
        "not_measured_reason": None,
        "installed_versions": {},
        "artifact_sha256": {},
        "strace_lines": 0,
        "raw_socket_events": [],
        "dns_recorder_selftest": None,
        "started_at": started,
        "finished_at": None,
        "network_mode": None,
        "mounts": None,
        "resource_limits": limits_record,
    }

    if not target.measured:
        decision = judge(
            measured=False,
            not_measured_reason=target.not_measured_reason,
            parsed=None,
        )
        base["verdict"] = decision["verdict"]
        base["not_measured_reason"] = decision["not_measured_reason"]
        base["finished_at"] = _utc_now()
        return base

    built = build_image(target)
    if not built.ok or not built.image_ref:
        decision = judge(
            measured=False,
            not_measured_reason=built.reason or "build_failed",
            parsed=None,
        )
        base["verdict"] = decision["verdict"]
        base["not_measured_reason"] = decision["not_measured_reason"]
        base["build_log_tail"] = (built.build_log or "")[-2000:]
        base["finished_at"] = _utc_now()
        return base

    base["image_digest"] = built.image_digest
    base["installed_versions"] = dict(built.installed_versions or {})
    base["artifact_sha256"] = dict(built.artifact_sha256 or {})
    base["build_log_has_ignore_scripts"] = "--ignore-scripts" in (built.build_log or "")
    base["build_log_has_only_binary"] = "--only-binary=:all:" in (built.build_log or "")
    # Also true from Dockerfile content even if build log truncates:
    if target.registry_type == "npm":
        base["build_log_has_ignore_scripts"] = True
    if target.registry_type == "pypi":
        base["build_log_has_only_binary"] = True

    ran = run_probed_server(built.image_ref, limits=limits)
    base["network_mode"] = ran.network_mode
    base["mounts"] = ran.mounts
    _attach_stderr_capture(base, ran.stderr_capture)
    if ran.resource_limits is not None:
        base["resource_limits"] = ran.resource_limits

    selftest_ok = dns_log_has_selftest(ran.dns_query_log or "")
    base["dns_recorder_selftest"] = selftest_ok

    if not ran.ok or ran.session is None:
        # Keep startup observations even on initialize_failed / not_measured.
        stage_marks = None
        tools = None
        if ran.session is not None:
            if ran.session.stage_marks:
                stage_marks = ran.session.stage_marks
            tools = ran.session.tools
            base["tools"] = tools_name_description(tools)
        apply_strace_observations(
            base,
            ran.strace_text or "",
            stage_marks,
            dns_query_log=ran.dns_query_log or "",
            tools=tools,
        )
        _attach_stderr_capture(base, ran.stderr_capture)
        _attach_stderr_head(base, ran.reason, ran.server_stderr or "")
        _attach_start_failed_reason(base, ran.reason, stderr_capture=ran.stderr_capture)
        decision = judge(
            measured=False,
            not_measured_reason=ran.reason or "run_failed",
            parsed=None,
        )
        base["verdict"] = decision["verdict"]
        base["not_measured_reason"] = decision["not_measured_reason"]
        if not base.get("strace_lines") and ran.strace_text:
            base["strace_lines"] = len(ran.strace_text.splitlines())
        base["finished_at"] = _utc_now()
        return base

    # Session reached initialize — positive control must be present or row is
    # not_measured (cannot trust dns_query=0). Early-exit reasons above keep
    # their own not_measured_reason + server_stderr_head.
    if not selftest_ok:
        base["tools"] = tools_name_description(ran.session.tools)
        apply_strace_observations(
            base,
            ran.strace_text or "",
            ran.session.stage_marks,
            dns_query_log=ran.dns_query_log or "",
            tools=ran.session.tools,
        )
        decision = judge(
            measured=False,
            not_measured_reason=DNS_RECORDER_NOT_RECORDING,
            parsed=None,
        )
        base["verdict"] = decision["verdict"]
        base["not_measured_reason"] = decision["not_measured_reason"]
        base["tools_total"] = ran.session.tools_total
        base["tools_called"] = ran.session.tools_called
        base["tool_outcomes"] = dict(ran.session.tool_outcomes)
        base["finished_at"] = _utc_now()
        return base

    session = ran.session
    base["tools_total"] = session.tools_total
    base["tools_called"] = session.tools_called
    base["tool_outcomes"] = dict(session.tool_outcomes)
    base["tools"] = tools_name_description(session.tools)

    parsed = parse_strace_lines(ran.strace_text)
    parsed = merge_dns_queries(parsed, ran.dns_query_log or "", exclude_selftest=True)
    parsed = assign_stages(parsed, session.stage_marks)
    base["observations"] = parsed.by_stage()
    base["raw_socket_events"] = parsed.raw_socket_events
    base["strace_lines"] = len(ran.strace_text.splitlines()) if ran.strace_text else 0
    base["dns_query_log_lines"] = count_dns_queries_excluding_selftest(ran.dns_query_log or "")
    _attach_network_partition(base, parsed, session.tools)
    init_ts = None
    for ts, name in session.stage_marks:
        if name == "startup":
            init_ts = ts
            break
    if init_ts is None and session.stage_marks:
        init_ts = session.stage_marks[0][0]
    base["stage_clock"] = clock_skew_record(
        initialize_send_ts=init_ts,
        first_strace_ts=parsed.first_strace_ts,
    )

    decision = judge(
        measured=True,
        not_measured_reason=None,
        parsed=parsed,
        tools=session.tools,
    )
    base["verdict"] = decision["verdict"]
    base["not_measured_reason"] = decision["not_measured_reason"]
    # Prefer judge's partition (same as attach) so fields stay consistent.
    if "unprompted_network" in decision:
        base["unprompted_network"] = decision["unprompted_network"]
    if "tool_invoked_network" in decision:
        base["tool_invoked_network"] = decision["tool_invoked_network"]
    base["tool_invoked_network_present"] = bool(
        decision.get("tool_invoked_network_present")
    )
    base["finished_at"] = _utc_now()
    return base


def run_behavior_probe(
    tool_root: Path,
    *,
    limit: int | None = None,
    only: str | None = None,
    concurrency: int = 1,
    snapshot_path: Path | None = None,
    census_dir: Path | None = None,
    include_excluded: bool = True,
    measured_only: bool = False,
    run_tag: str | None = None,
    which: Any | None = None,
    controllers_text: str | None = None,
    skip_calibration: bool = False,
    calibration_fn: Any | None = None,
) -> dict[str, Any]:
    """Run phase-1 behavior probe and write reports under docs/reports/.

    Host gates (podman/conmon on PATH · memory/pids cgroup) run once up front.
    Instrument calibration (npm + pypi noop) runs next; contamination aborts with
    InstrumentContaminatedError and does not write production rows.
    On gate failure no report rows are written.
    """
    if concurrency < 1:
        raise ValueError("concurrency must be >= 1")

    require_podman_tools(which=which)
    limits = resolve_resource_limits(controllers_text=controllers_text)

    calibration: CalibrationReport | None = None
    if not skip_calibration:
        cal_runner = calibration_fn or run_instrument_calibration
        calibration = cal_runner(limits)
        if not calibration.ok:
            raise InstrumentContaminatedError(
                calibration.reason or "instrument_contaminated",
                report=calibration,
            )

    targets = collect_offline_targets(
        snapshot_path=snapshot_path, census_dir=census_dir
    )
    excluded = [(t.name, t.not_measured_reason or "") for t in targets if not t.measured]
    work = measured_targets(targets) if measured_only else list(targets)

    if only:
        work = [t for t in work if t.name == only or t.identifier == only]
        if not work:
            raise ValueError(f"no target matched --only {only!r}")

    if limit is not None:
        # Apply limit to measured servers primarily; keep excluded if include_excluded.
        measured = [t for t in work if t.measured]
        excluded_t = [t for t in work if not t.measured]
        measured = measured[:limit]
        work = measured + (excluded_t if include_excluded else [])

    rows: list[dict[str, Any]] = []
    if concurrency == 1:
        for t in work:
            rows.append(_probe_one(t, limits))
    else:
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            futures = {pool.submit(_probe_one, t, limits): t for t in work}
            for fut in as_completed(futures):
                rows.append(fut.result())
        rows.sort(key=lambda r: str(r.get("name") or ""))

    jsonl_path, md_path = default_report_paths(tool_root, run_tag=run_tag)
    write_probe_reports(
        jsonl_path,
        md_path,
        rows,
        excluded_reasons=excluded,
        run_label=jsonl_path.stem,
        calibration=calibration.as_dict() if calibration else None,
    )

    return {
        "jsonl": str(jsonl_path),
        "md": str(md_path),
        "rows": len(rows),
        "targets_total": len(targets),
        "measured": len(measured_targets(targets)),
        "resource_limits": limits.as_record(),
        "run_tag": run_tag,
        "calibration": calibration.as_dict() if calibration else None,
    }


def _row_has_network_attempt(row: dict[str, Any]) -> bool:
    obs = row.get("observations") or {}
    for _stage, kinds in obs.items():
        if kinds.get("network_attempt"):
            return True
    return False


def compare_probe_runs(
    rows_a: list[dict[str, Any]], rows_b: list[dict[str, Any]]
) -> dict[str, Any]:
    """Compare two runs: network_attempt presence and verdict per server."""
    by_a = {r["name"]: r for r in rows_a}
    by_b = {r["name"]: r for r in rows_b}
    names = sorted(set(by_a) | set(by_b))
    matches = 0
    mismatches: list[dict[str, Any]] = []
    for name in names:
        a = by_a.get(name)
        b = by_b.get(name)
        net_a = _row_has_network_attempt(a) if a else None
        net_b = _row_has_network_attempt(b) if b else None
        ver_a = (a or {}).get("verdict")
        ver_b = (b or {}).get("verdict")
        if net_a == net_b and ver_a == ver_b and a is not None and b is not None:
            matches += 1
        else:
            mismatches.append(
                {
                    "name": name,
                    "run1_network_attempt": net_a,
                    "run2_network_attempt": net_b,
                    "run1_verdict": ver_a,
                    "run2_verdict": ver_b,
                }
            )
    return {
        "matches": matches,
        "mismatches": mismatches,
        "mismatch_count": len(mismatches),
        "servers": len(names),
    }


def compare_network_attempt_presence(
    rows_a: list[dict[str, Any]], rows_b: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Return mismatches of network_attempt presence between two runs."""
    result = compare_probe_runs(rows_a, rows_b)
    out = []
    for m in result["mismatches"]:
        if m["run1_network_attempt"] != m["run2_network_attempt"]:
            out.append(
                {
                    "name": m["name"],
                    "run1": m["run1_network_attempt"],
                    "run2": m["run2_network_attempt"],
                }
            )
    return out


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows
