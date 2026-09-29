"""Parse strace lines into network/exec/write observations."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any

from services.behavior_probe.constants import DNS_SELFTEST_QNAME

# strace -f -o FILE -ttt (epoch seconds; preferred — no TZ skew):
#   "PID  1726300000.123456 body"
# legacy -tt / fixtures:
#   "PID  HH:MM:SS.ffffff body"
# stderr / older:
#   "[pid N] HH:MM:SS.ffffff body"
# no -f:
#   "SECONDS.ffffff body" or "HH:MM:SS.ffffff body"
_LINE_RE = re.compile(
    r"^(?:\[pid\s+(?P<bracket_pid>\d+)\]\s+|(?P<col_pid>\d+)\s+)?"
    r"(?P<ts>\d{10,}\.\d+|\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"(?P<body>.*)$"
)

_CONNECT_INET = re.compile(
    r"connect\([^,]+,\s*\{sa_family=(?P<fam>AF_INET6?),\s*"
    r"(?:sin_port=htons\((?P<port>\d+)\),\s*sin_addr=inet_addr\(\"(?P<v4>[^\"]+)\"\)"
    r"|sin6_port=htons\((?P<port6>\d+)\),\s*inet_pton\(AF_INET6,\s*\"(?P<v6>[^\"]+)\""
    r").*"
)

_SENDTO_INET = re.compile(
    r"sendto\([^,]+,\s*[^,]+,\s*[^,]+,\s*[^,]+,\s*\{sa_family=(?P<fam>AF_INET6?),\s*"
    r"(?:sin_port=htons\((?P<port>\d+)\),\s*sin_addr=inet_addr\(\"(?P<v4>[^\"]+)\"\)"
    r"|sin6_port=htons\((?P<port6>\d+)\),\s*inet_pton\(AF_INET6,\s*\"(?P<v6>[^\"]+)\""
    r").*"
)

_SOCKET_FAM = re.compile(r"socket\((?P<fam>AF_[A-Z0-9]+),")
_SENDTO_OTHER = re.compile(r"sendto\([^,]+,.*,\s*\{sa_family=(?P<fam>AF_[A-Z0-9]+)")
_CONNECT_OTHER = re.compile(r"connect\([^,]+,\s*\{sa_family=(?P<fam>AF_[A-Z0-9]+)")

_EXECVE = re.compile(
    r"""execve\("(?P<path>[^"]+)",(?P<rest>.*)"""
)
_EXEC_RET = re.compile(r"""=\s*(?P<ret>-?\d+)(?:\s+(?P<errno>[A-Z0-9]+))?""")

_OPENAT_WRITE = re.compile(
    r"""openat\([^,]+,\s*"(?P<path>[^"]+)",\s*(?P<flags>[^,]+)"""
)
_UNLINK = re.compile(
    r"""unlink(?:at)?\([^,]*,\s*"(?P<path>[^"]+)"|unlink\("(?P<path2>[^"]+)"\)"""
)
_RENAME = re.compile(r"""rename\("(?P<source>[^"]+)",\s*"(?P<dest>[^"]+)"\)""")

_DNS_LOG_LINE = re.compile(
    r"^(?:(?P<epoch>\d{10,}\.\d+)\s+)?(?P<name>\S+)\s+(?P<qtype>\S+)\s*$"
)

_OTHER_FAMILIES = frozenset({"AF_NETLINK", "AF_PACKET", "AF_ALG"})
UNPROMPTED_STAGES = frozenset({"startup", "tools_list"})


@dataclass
class Observation:
    kind: str  # network_attempt | dns_attempt | other_socket | exec | exec_attempt_failed | write_outside
    ts: str
    detail: dict[str, Any]
    stage: str = "startup"
    pid: int | None = None


@dataclass
class ParseResult:
    network_attempt: list[Observation] = field(default_factory=list)
    dns_attempt: list[Observation] = field(default_factory=list)
    other_socket: list[Observation] = field(default_factory=list)
    exec: list[Observation] = field(default_factory=list)
    exec_attempt_failed: list[Observation] = field(default_factory=list)
    write_outside: list[Observation] = field(default_factory=list)
    raw_socket_events: list[dict[str, Any]] = field(default_factory=list)
    first_strace_ts: str | None = None

    def by_stage(self) -> dict[str, dict[str, list[dict[str, Any]]]]:
        stages: dict[str, dict[str, list[dict[str, Any]]]] = {}
        for kind in (
            "network_attempt",
            "dns_attempt",
            "other_socket",
            "exec",
            "exec_attempt_failed",
            "write_outside",
        ):
            for obs in getattr(self, kind):
                bucket = stages.setdefault(obs.stage, {})
                entry: dict[str, Any] = {"ts": obs.ts, **obs.detail}
                if obs.pid is not None and "pid" not in entry:
                    entry["pid"] = obs.pid
                bucket.setdefault(kind, []).append(entry)
        return stages


def _is_loopback(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return bool(ip.is_loopback)


def _exclude_as_loopback(addr: str, port: int) -> bool:
    """Loopback is excluded except :53 (DNS recorder path)."""
    if not _is_loopback(addr):
        return False
    return port != 53


def _allowed_write(path: str) -> bool:
    allowed_prefixes = (
        "/tmp",
        "/var/tmp",
        "/usr/lib",
        "/usr/local",
        "/opt",
        "/home/",
        "/root/",
        "/app",
        "/proc",
        "/dev",
        "/etc",
        "/var/cache",
        "/var/lib",
        "/run",
    )
    if path.startswith(allowed_prefixes):
        return True
    if path.startswith("/home") or "/.cache" in path or "/.npm" in path or "/.local" in path:
        return True
    return False


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1] if path else path


def _parse_line_meta(line: str) -> tuple[str, str, int | None]:
    """Return (ts, body, pid). Unmatched → default ts and full line as body."""
    m = _LINE_RE.match(line)
    if not m:
        return "00:00:00.000000", line, None
    pid_s = m.group("bracket_pid") or m.group("col_pid")
    pid = int(pid_s) if pid_s else None
    return m.group("ts"), m.group("body"), pid


def normalize_dns_qname(name: str) -> str:
    return name.rstrip(".").lower()


def is_dns_selftest_name(name: str) -> bool:
    return normalize_dns_qname(name) == normalize_dns_qname(DNS_SELFTEST_QNAME)


def dns_log_has_selftest(dns_log: list[str] | str | None) -> bool:
    """True iff the recorder log contains the positive-control qname."""
    if not dns_log:
        return False
    lines = dns_log.splitlines() if isinstance(dns_log, str) else dns_log
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        m = _DNS_LOG_LINE.match(line)
        if m and is_dns_selftest_name(m.group("name")):
            return True
        # Also accept "_unparsed …" never matching; bare prefix form.
        first = line.split(None, 1)[0]
        if is_dns_selftest_name(first):
            return True
    return False


def count_dns_queries_excluding_selftest(dns_log: list[str] | str | None) -> int:
    """Count recorder log lines that are not the selftest qname (for reports / calibrate)."""
    if not dns_log:
        return 0
    lines = dns_log.splitlines() if isinstance(dns_log, str) else dns_log
    n = 0
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        m = _DNS_LOG_LINE.match(line)
        if not m:
            n += 1
            continue
        if is_dns_selftest_name(m.group("name")):
            continue
        n += 1
    return n


def parse_dns_query_log(
    lines: list[str] | str,
    *,
    exclude_selftest: bool = False,
) -> list[Observation]:
    """Parse recorder log lines into network_attempt (kind=dns_query).

    Preferred form: ``<epoch> <name> <qtype>`` (epoch = strace -ttt seconds).
    Legacy form without epoch is accepted (ts placeholder); stage stays startup
    when marks are epoch-based.

    ``_unparsed len=<n>`` lines become dns_query with name=_unparsed.
    When ``exclude_selftest`` is True, the positive-control qname is omitted
    (counts and verdicts only).
    """
    if isinstance(lines, str):
        lines = lines.splitlines()
    out: list[Observation] = []
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        m = _DNS_LOG_LINE.match(line)
        if not m:
            continue
        name = m.group("name")
        qtype = m.group("qtype")
        if exclude_selftest and is_dns_selftest_name(name):
            continue
        epoch = m.group("epoch")
        ts = epoch if epoch else "00:00:00.000000"
        out.append(
            Observation(
                "network_attempt",
                ts,
                {"kind": "dns_query", "name": name, "qtype": qtype},
            )
        )
    return out


def merge_dns_queries(
    parsed: ParseResult,
    dns_log: list[str] | str | None,
    *,
    exclude_selftest: bool = True,
) -> ParseResult:
    """Append dns_query observations from the recorder log into network_attempt.

    Default excludes the selftest qname so it never contaminates verdict /
    calibration counts.
    """
    if not dns_log:
        return parsed
    for obs in parse_dns_query_log(dns_log, exclude_selftest=exclude_selftest):
        parsed.network_attempt.append(obs)
    return parsed


def ts_to_epoch(ts: str | None) -> float | None:
    """Parse strace/driver timestamp to epoch seconds when possible.

    Accepts ``SECONDS.ffffff`` (-ttt / time.time). Wall-clock HH:MM:SS.ffffff
    returns None (not comparable across timezones).
    """
    if not ts:
        return None
    if re.fullmatch(r"\d{10,}\.\d+", ts):
        try:
            return float(ts)
        except ValueError:
            return None
    return None


def _flush_failed_exec_group(
    result: ParseResult,
    group: list[tuple[str, str, int | None, str]],
) -> None:
    """Collapse consecutive PATH-search ENOENT for the same argv0 into one obs."""
    if not group:
        return
    paths = [g[0] for g in group]
    ts = group[0][1]
    pid = group[0][2]
    errno = group[0][3]
    basename = _basename(paths[0])
    detail: dict[str, Any] = {
        "path": paths[0],
        "errno": errno,
        "basename": basename,
    }
    if len(paths) > 1:
        detail["searched_paths"] = paths
    if pid is not None:
        detail["pid"] = pid
    result.exec_attempt_failed.append(
        Observation("exec_attempt_failed", ts, detail, pid=pid)
    )


def parse_strace_lines(lines: list[str] | str, *, server_exec_path: str | None = None) -> ParseResult:
    if isinstance(lines, str):
        lines = lines.splitlines()
    result = ParseResult()
    first_exec_seen = False
    failed_group: list[tuple[str, str, int | None, str]] = []
    failed_group_basename: str | None = None

    for raw in lines:
        line = raw.rstrip("\n")
        if not line.strip():
            continue
        ts, body, pid = _parse_line_meta(line)
        if result.first_strace_ts is None:
            result.first_strace_ts = ts
        elif result.first_strace_ts == "00:00:00.000000" and ts != "00:00:00.000000":
            result.first_strace_ts = ts

        if "socket(" in body:
            sm = _SOCKET_FAM.search(body)
            if sm:
                fam = sm.group("fam")
                raw_ev: dict[str, Any] = {
                    "family": fam,
                    "syscall": "socket",
                    "line": body if pid is None else line,
                    "ts": ts,
                }
                if pid is not None:
                    raw_ev["pid"] = pid
                result.raw_socket_events.append(raw_ev)
                if fam in _OTHER_FAMILIES:
                    result.other_socket.append(
                        Observation(
                            "other_socket",
                            ts,
                            {"family": fam, "syscall": "socket", **({"pid": pid} if pid is not None else {})},
                            pid=pid,
                        )
                    )

        for regex, syscall in ((_CONNECT_INET, "connect"), (_SENDTO_INET, "sendto")):
            cm = regex.search(body)
            if not cm:
                continue
            fam = cm.group("fam")
            port_s = cm.group("port") or cm.group("port6") or "0"
            addr = cm.group("v4") or cm.group("v6") or ""
            port = int(port_s)
            raw_ev = {
                "family": fam,
                "addr": addr,
                "port": port,
                "syscall": syscall,
                "line": body if pid is None else line,
                "ts": ts,
            }
            if pid is not None:
                raw_ev["pid"] = pid
            result.raw_socket_events.append(raw_ev)
            if fam not in ("AF_INET", "AF_INET6"):
                continue
            if _exclude_as_loopback(addr, port):
                continue
            detail: dict[str, Any] = {
                "family": fam,
                "addr": addr,
                "port": port,
                "syscall": syscall,
            }
            if pid is not None:
                detail["pid"] = pid
            obs = Observation("network_attempt", ts, detail, pid=pid)
            result.network_attempt.append(obs)
            if port == 53:
                dns_detail = dict(detail)
                result.dns_attempt.append(
                    Observation("dns_attempt", ts, dns_detail, pid=pid)
                )

        if "connect(" in body and "AF_INET" not in body:
            om = _CONNECT_OTHER.search(body)
            if om and om.group("fam") in _OTHER_FAMILIES:
                detail = {"family": om.group("fam"), "syscall": "connect"}
                if pid is not None:
                    detail["pid"] = pid
                result.other_socket.append(
                    Observation("other_socket", ts, detail, pid=pid)
                )
                raw_ev = {
                    "family": om.group("fam"),
                    "syscall": "connect",
                    "line": body if pid is None else line,
                    "ts": ts,
                }
                if pid is not None:
                    raw_ev["pid"] = pid
                result.raw_socket_events.append(raw_ev)
        if "sendto(" in body and "AF_INET" not in body:
            om = _SENDTO_OTHER.search(body)
            if om and om.group("fam") in _OTHER_FAMILIES:
                detail = {"family": om.group("fam"), "syscall": "sendto"}
                if pid is not None:
                    detail["pid"] = pid
                result.other_socket.append(
                    Observation("other_socket", ts, detail, pid=pid)
                )
                raw_ev = {
                    "family": om.group("fam"),
                    "syscall": "sendto",
                    "line": body if pid is None else line,
                    "ts": ts,
                }
                if pid is not None:
                    raw_ev["pid"] = pid
                result.raw_socket_events.append(raw_ev)

        em = _EXECVE.search(body)
        if em:
            path = em.group("path")
            ret_m = _EXEC_RET.search(body)
            ret_code = int(ret_m.group("ret")) if ret_m else 0
            errno = (ret_m.group("errno") if ret_m else None) or None
            failed = ret_code < 0
            if failed:
                basen = _basename(path)
                # Coalesce consecutive PATH searches for the same argv0.
                if (
                    failed_group
                    and failed_group_basename == basen
                    and (pid is None or failed_group[0][2] is None or failed_group[0][2] == pid)
                ):
                    failed_group.append((path, ts, pid, errno or "UNKNOWN"))
                else:
                    _flush_failed_exec_group(result, failed_group)
                    failed_group = [(path, ts, pid, errno or "UNKNOWN")]
                    failed_group_basename = basen
            else:
                _flush_failed_exec_group(result, failed_group)
                failed_group = []
                failed_group_basename = None
                if not first_exec_seen:
                    first_exec_seen = True
                    if server_exec_path is None or path == server_exec_path:
                        continue
                if server_exec_path and path == server_exec_path and not result.exec:
                    continue
                detail = {"path": path}
                if pid is not None:
                    detail["pid"] = pid
                result.exec.append(Observation("exec", ts, detail, pid=pid))

        om = _OPENAT_WRITE.search(body)
        if om:
            flags = om.group("flags")
            path = om.group("path")
            if "O_WRONLY" in flags or "O_RDWR" in flags or "O_CREAT" in flags or "O_TRUNC" in flags:
                if not _allowed_write(path):
                    detail = {"path": path, "op": "openat"}
                    if pid is not None:
                        detail["pid"] = pid
                    result.write_outside.append(
                        Observation("write_outside", ts, detail, pid=pid)
                    )

        um = _UNLINK.search(body)
        if um:
            path = um.group("path") or um.group("path2") or ""
            if path and not _allowed_write(path):
                detail = {"path": path, "op": "unlink"}
                if pid is not None:
                    detail["pid"] = pid
                result.write_outside.append(
                    Observation("write_outside", ts, detail, pid=pid)
                )

        rm = _RENAME.search(body)
        if rm:
            dest = rm.group("dest")
            if not _allowed_write(dest):
                detail = {"path": dest, "source": rm.group("source"), "op": "rename"}
                if pid is not None:
                    detail["pid"] = pid
                result.write_outside.append(
                    Observation("write_outside", ts, detail, pid=pid)
                )

    _flush_failed_exec_group(result, failed_group)
    return result


def clock_skew_record(
    *,
    initialize_send_ts: str | None,
    first_strace_ts: str | None,
) -> dict[str, Any]:
    """Record initialize send vs first strace stamp as epoch seconds + delta.

    Prefer -ttt / time.time() epoch strings. Do not rely on TZ env.
    """
    init_epoch = ts_to_epoch(initialize_send_ts)
    first_epoch = ts_to_epoch(first_strace_ts)
    delta: float | None = None
    if init_epoch is not None and first_epoch is not None:
        delta = init_epoch - first_epoch
    return {
        "initialize_send_ts": initialize_send_ts,
        "first_strace_ts": first_strace_ts,
        "initialize_send_epoch": init_epoch,
        "first_strace_epoch": first_epoch,
        "delta_seconds": delta,
        "note": (
            "stage assignment compares epoch seconds from driver time.time() "
            "against strace -ttt; TZ env is not used"
        ),
    }


def assign_stages(
    parsed: ParseResult,
    stage_marks: list[tuple[str, str]],
) -> ParseResult:
    """Assign each observation to startup / tools_list / tools_call:<name>.

    stage_marks: list of (timestamp_str, stage_name) in chronological order,
    marking when that stage *began* (JSON-RPC send time as epoch via time.time()).
    Comparison uses epoch floats when both sides are -ttt / time.time() form;
    otherwise falls back to lexicographic string compare (legacy -tt fixtures).
    """
    if not stage_marks:
        return parsed

    mark_epochs: list[tuple[float | None, str, str]] = [
        (ts_to_epoch(mark_ts), mark_ts, name) for mark_ts, name in stage_marks
    ]
    use_epoch = all(e is not None for e, _ts, _n in mark_epochs)

    def stage_for(ts: str) -> str:
        current = stage_marks[0][1]
        obs_epoch = ts_to_epoch(ts) if use_epoch else None
        if use_epoch and obs_epoch is not None:
            for mark_epoch, _mark_ts, name in mark_epochs:
                assert mark_epoch is not None
                if obs_epoch >= mark_epoch:
                    current = name
                else:
                    break
            return current
        for mark_ts, name in stage_marks:
            if ts >= mark_ts:
                current = name
            else:
                break
        return current

    for kind in (
        "network_attempt",
        "dns_attempt",
        "other_socket",
        "exec",
        "exec_attempt_failed",
        "write_outside",
    ):
        for obs in getattr(parsed, kind):
            obs.stage = stage_for(obs.ts)
    return parsed


def _obs_as_entry(obs: Observation) -> dict[str, Any]:
    entry: dict[str, Any] = {"ts": obs.ts, **obs.detail}
    if obs.pid is not None and "pid" not in entry:
        entry["pid"] = obs.pid
    entry["stage"] = obs.stage
    return entry


def partition_network_evidence(
    parsed: ParseResult,
    tools: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Split network_attempt into unprompted vs tool-invoked.

    unprompted = stages ``startup`` / ``tools_list``.
    tool_invoked = stages ``tools_call:<name>``, grouped per tool with description.
    """
    desc_by_name: dict[str, str] = {}
    for tool in tools or []:
        name = str(tool.get("name") or "")
        if name:
            desc_by_name[name] = str(tool.get("description") or "")

    unprompted_attempts: list[dict[str, Any]] = []
    unprompted_dns: list[str] = []
    by_tool: dict[str, dict[str, Any]] = {}

    for obs in parsed.network_attempt:
        entry = _obs_as_entry(obs)
        stage = obs.stage or "startup"
        if stage in UNPROMPTED_STAGES:
            unprompted_attempts.append(entry)
            if entry.get("kind") == "dns_query":
                qname = str(entry.get("name") or "")
                if qname and qname not in unprompted_dns:
                    unprompted_dns.append(qname)
            continue
        if stage.startswith("tools_call:"):
            tool_name = stage[len("tools_call:") :]
            bucket = by_tool.get(tool_name)
            if bucket is None:
                bucket = {
                    "tool": tool_name,
                    "description": desc_by_name.get(tool_name, ""),
                    "attempts": [],
                    "dns_names": [],
                }
                by_tool[tool_name] = bucket
            bucket["attempts"].append(entry)
            if entry.get("kind") == "dns_query":
                qname = str(entry.get("name") or "")
                if qname and qname not in bucket["dns_names"]:
                    bucket["dns_names"].append(qname)
            continue
        # Unknown stage: treat as unprompted (fail closed for verdict).
        unprompted_attempts.append(entry)
        if entry.get("kind") == "dns_query":
            qname = str(entry.get("name") or "")
            if qname and qname not in unprompted_dns:
                unprompted_dns.append(qname)

    tool_invoked = list(by_tool.values())
    return {
        "unprompted_network": {
            "attempts": unprompted_attempts,
            "dns_names": unprompted_dns,
        },
        "tool_invoked_network": tool_invoked,
        "tool_invoked_network_present": bool(tool_invoked),
        "unprompted_count": len(unprompted_attempts),
    }


def tools_name_description(tools: list[dict[str, Any]] | None) -> list[dict[str, str]]:
    """Persist tools/list name + description (verbatim) on the row."""
    out: list[dict[str, str]] = []
    for tool in tools or []:
        name = str(tool.get("name") or "")
        if not name:
            continue
        out.append(
            {
                "name": name,
                "description": str(tool.get("description") or ""),
            }
        )
    return out
