"""Write BEHAVIOR_PROBE_<YYYYMMDD>[_TAG].jsonl and .md reports (internal only)."""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

from services.behavior_probe.constants import (
    EXPECTED_BY_REGISTRY,
    EXPECTED_OFFLINE_TOTAL,
    FORBIDDEN_OUTPUT_WORDS,
    VERDICT_CLAIM_CONTRADICTED,
    VERDICT_NOT_CONTRADICTED,
    VERDICT_NOT_MEASURED,
)
from services.behavior_probe.targets import CountMismatchError

# Third-party verbatim columns — republished as-is; not filtered (census note).
# Nested: tools[].description · tool_invoked_network[].description · *.dns_names ·
# network attempt name (DNS qname) · raw_socket_events lines.
THIRD_PARTY_ROW_KEYS = frozenset(
    {
        "claim",
        "server_stderr_head",
        "build_log_tail",
        "raw_socket_events",
        "tools",
        "tool_invoked_network",
        "unprompted_network",
    }
)

# Authored string fields we do scan on each jsonl row.
OUR_ROW_STRING_FIELDS = (
    "verdict",
    "not_measured_reason",
    "start_failed_reason",
    "stderr_capture",
)

_WORD_PATTERNS: dict[str, re.Pattern[str]] = {
    word: re.compile(rf"\b{re.escape(word)}\b", re.IGNORECASE)
    for word in FORBIDDEN_OUTPUT_WORDS
}

_THIRD_PARTY_NOTE = "Third-party text republished verbatim; not filtered."


@dataclass(frozen=True)
class ForbiddenHit:
    word: str
    field: str
    row_name: str | None = None

    def format(self) -> str:
        loc = f"row={self.row_name!r} field={self.field}" if self.row_name else f"field={self.field}"
        return f"{loc} word={self.word!r}"


class ForbiddenOutputError(ValueError):
    """Raised after rejected artifacts are written (results are not discarded)."""

    def __init__(
        self,
        hits: list[ForbiddenHit],
        *,
        rejected_jsonl: Path | None = None,
        rejected_md: Path | None = None,
    ) -> None:
        self.hits = hits
        self.rejected_jsonl = rejected_jsonl
        self.rejected_md = rejected_md
        detail = "; ".join(h.format() for h in hits) if hits else "unknown"
        saved: list[str] = []
        if rejected_jsonl is not None:
            saved.append(str(rejected_jsonl))
        if rejected_md is not None:
            saved.append(str(rejected_md))
        suffix = f" (saved: {', '.join(saved)})" if saved else ""
        # Keep a short lead token for log grepping; detail follows.
        super().__init__(f"forbidden output word present: {detail}{suffix}")


def default_report_paths(
    tool_root: Path,
    day: date | None = None,
    *,
    run_tag: str | None = None,
) -> tuple[Path, Path]:
    day = day or date.today()
    stamp = day.strftime("%Y%m%d")
    if run_tag:
        stamp = f"{stamp}_{run_tag}"
    reports = tool_root / "docs" / "reports"
    return (
        reports / f"BEHAVIOR_PROBE_{stamp}.jsonl",
        reports / f"BEHAVIOR_PROBE_{stamp}.md",
    )


def rejected_sibling(path: Path) -> Path:
    """BEHAVIOR_PROBE_<stamp>.jsonl → BEHAVIOR_PROBE_<stamp>_rejected.jsonl."""
    return path.with_name(f"{path.stem}_rejected{path.suffix}")


def find_forbidden_word(text: str) -> str | None:
    """Return the first forbidden word matched on word boundaries, else None."""
    for word, pattern in _WORD_PATTERNS.items():
        if pattern.search(text):
            return word
    return None


def assert_no_forbidden_words(text: str) -> None:
    """Word-boundary check for authored text (not third-party verbatim)."""
    word = find_forbidden_word(text)
    if word is not None:
        raise ValueError(f"forbidden output word present: {word}")


def scan_row_our_text(row: dict[str, Any]) -> list[ForbiddenHit]:
    """Scan only fields we author; skip THIRD_PARTY_ROW_KEYS and nested third-party."""
    hits: list[ForbiddenHit] = []
    row_name = str(row.get("name") or "") or None

    for key in OUR_ROW_STRING_FIELDS:
        val = row.get(key)
        if isinstance(val, str):
            word = find_forbidden_word(val)
            if word is not None:
                hits.append(ForbiddenHit(word=word, field=key, row_name=row_name))

    rl = row.get("resource_limits")
    if isinstance(rl, dict):
        reason = rl.get("cpus_not_applied_reason")
        if isinstance(reason, str):
            word = find_forbidden_word(reason)
            if word is not None:
                hits.append(
                    ForbiddenHit(
                        word=word,
                        field="resource_limits.cpus_not_applied_reason",
                        row_name=row_name,
                    )
                )

    # Defensive: any other top-level string we might author later, except third-party keys
    # and opaque structural/id fields that are not prose.
    skip_also = THIRD_PARTY_ROW_KEYS | frozenset(
        {
            "name",
            "package",
            "image_digest",
            "observations",
            "tool_outcomes",
            "started_at",
            "finished_at",
            "network_mode",
            "mounts",
            "resource_limits",
            "stage_clock",
            "dns_recorder_selftest",
            "tool_invoked_network_present",
            "build_log_has_ignore_scripts",
            "build_log_has_only_binary",
            "installed_versions",
            "artifact_sha256",
            "stderr_capture",
            "census_snapshot_sha256",
            "method_version",
            "base_image_digest",
            "built_image_digest",
        }
    )
    for key, val in row.items():
        if key in skip_also or key in OUR_ROW_STRING_FIELDS:
            continue
        if isinstance(val, str):
            word = find_forbidden_word(val)
            if word is not None:
                hits.append(ForbiddenHit(word=word, field=key, row_name=row_name))

    return hits


def scan_rows_our_text(rows: list[dict[str, Any]]) -> list[ForbiddenHit]:
    hits: list[ForbiddenHit] = []
    for row in rows:
        hits.extend(scan_row_our_text(row))
    return hits


def _quote_block(text: str, *, indent: str = "    ") -> list[str]:
    lines = text.splitlines() or [""]
    return [f"{indent}> {line}" for line in lines]


def _row_registry_type(row: dict[str, Any]) -> str:
    pkg = row.get("package") or {}
    if isinstance(pkg, dict):
        return str(pkg.get("registryType") or "")
    return ""


def _categorize_registry_row(row: dict[str, Any]) -> str:
    """Return one of: measured | start_failed | excluded | sdist | other."""
    verdict = str(row.get("verdict") or "")
    reason = str(row.get("not_measured_reason") or "")
    if verdict in (VERDICT_CLAIM_CONTRADICTED, VERDICT_NOT_CONTRADICTED):
        return "measured"
    if reason == "initialize_failed" or reason.startswith("initialize_failed"):
        return "start_failed"
    if reason == "pypi_sdist_only_or_no_binary":
        return "sdist"
    if "phase1_excluded_registry_type:" in reason or "unsupported_registry_type:" in reason:
        return "excluded"
    if verdict == VERDICT_NOT_MEASURED:
        # Excluded registries always land here via phase1_excluded_*; keep a bucket
        # for other not_measured so strict checks can still detect drift.
        return "other"
    return "other"


def registry_coverage_table(
    rows: list[dict[str, Any]],
    *,
    strict: bool | None = None,
) -> list[dict[str, int | str]]:
    """Build per-registry coverage rows. Denominator from EXPECTED_BY_REGISTRY.

    When strict (default: True iff len(rows)==EXPECTED_OFFLINE_TOTAL), raises
    CountMismatchError if per-registry category sums diverge from the denominator
    or if denominators do not total EXPECTED_OFFLINE_TOTAL.
    """
    denom_total = sum(EXPECTED_BY_REGISTRY.values())
    if denom_total != EXPECTED_OFFLINE_TOTAL:
        raise CountMismatchError(
            f"EXPECTED_BY_REGISTRY sum {denom_total} != {EXPECTED_OFFLINE_TOTAL}"
        )

    if strict is None:
        strict = len(rows) == EXPECTED_OFFLINE_TOTAL

    counts: dict[str, Counter[str]] = {
        reg: Counter() for reg in EXPECTED_BY_REGISTRY
    }
    for row in rows:
        reg = _row_registry_type(row)
        if reg not in counts:
            continue
        counts[reg][_categorize_registry_row(row)] += 1

    table: list[dict[str, int | str]] = []
    for reg, expected in EXPECTED_BY_REGISTRY.items():
        c = counts[reg]
        measured = int(c.get("measured", 0))
        start_failed = int(c.get("start_failed", 0))
        excluded = int(c.get("excluded", 0))
        sdist = int(c.get("sdist", 0))
        other = int(c.get("other", 0))
        categorized = measured + start_failed + excluded + sdist + other
        if strict and categorized != expected:
            raise CountMismatchError(
                f"registryType {reg}: categorized {categorized} "
                f"(measured={measured} start_failed={start_failed} "
                f"excluded={excluded} sdist={sdist} other={other}) "
                f"!= expected {expected}"
            )
        if strict and other:
            raise CountMismatchError(
                f"registryType {reg}: unexpected not_measured other={other}"
            )
        table.append(
            {
                "registry": reg,
                "in_scope": expected,
                "measured": measured,
                "start_failed": start_failed,
                "excluded": excluded,
                "sdist_only": sdist,
            }
        )

    if strict:
        observed = sum(int(r["in_scope"]) for r in table)
        if observed != EXPECTED_OFFLINE_TOTAL:
            raise CountMismatchError(
                f"registry coverage in_scope sum {observed} != {EXPECTED_OFFLINE_TOTAL}"
            )

    return table


def _dump_jsonl_body(rows: list[dict[str, Any]]) -> str:
    lines = [json.dumps(row, ensure_ascii=False, sort_keys=True) for row in rows]
    return "\n".join(lines) + ("\n" if lines else "")


def _write_text(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    hits = scan_rows_our_text(rows)
    body = _dump_jsonl_body(rows)
    if hits:
        rejected = rejected_sibling(path)
        _write_text(rejected, body)
        raise ForbiddenOutputError(hits, rejected_jsonl=rejected)
    _write_text(path, body)


def _build_markdown(
    rows: list[dict[str, Any]],
    *,
    excluded_reasons: list[tuple[str, str]],
    run_label: str,
    calibration: dict[str, Any] | None = None,
) -> tuple[str, str]:
    """Return (full_body, our_text_for_scan). Third-party lines go only into full_body."""
    verdicts = Counter(str(r.get("verdict")) for r in rows)
    outcomes = Counter()
    tools_called_total = 0
    validation_errors = 0
    cpus_not_applied = 0
    for r in rows:
        to = r.get("tool_outcomes") or {}
        for k, v in to.items():
            outcomes[k] += int(v)
        tools_called_total += int(r.get("tools_called") or 0)
        validation_errors += int(to.get("validation_error") or 0)
        rl = r.get("resource_limits") or {}
        if rl.get("cpus") is None and rl.get("cpus_not_applied_reason"):
            cpus_not_applied += 1

    trigger = False
    if tools_called_total > 0:
        trigger = (validation_errors / tools_called_total) > 0.5

    our: list[str] = []
    full: list[str] = []

    def add_our(line: str = "") -> None:
        our.append(line)
        full.append(line)

    def add_full_only(line: str = "") -> None:
        full.append(line)

    add_our(f"# Behavior probe report — {run_label}")
    add_our("")
    add_our("## Instrument calibration")
    add_our("")
    if calibration is None:
        add_our("- (not run)")
    else:
        add_our(f"- overall_ok: {calibration.get('ok')}")
        if calibration.get("reason"):
            add_our(f"- reason: `{calibration.get('reason')}`")
        for ch in calibration.get("channels") or []:
            add_our(
                f"- `{ch.get('registry_type')}`: network_attempt={ch.get('network_attempt_count')} · "
                f"dns_query={ch.get('dns_query_count', 0)} · "
                f"selftest={ch.get('dns_recorder_selftest')} · "
                f"ok={ch.get('ok')}"
                + (f" · reason=`{ch.get('reason')}`" if ch.get("reason") else "")
            )
    add_our("")
    add_our(f"- CPU limit not applied (servers): {cpus_not_applied}")
    add_our("")
    add_our("## Verdict counts")
    add_our("")
    add_our("| verdict | count |")
    add_our("|---|---|")
    for key in (
        "claim_contradicted",
        "not_contradicted_within_coverage",
        "not_measured",
    ):
        add_our(f"| {key} | {verdicts.get(key, 0)} |")
    add_our("")
    add_our("## Registry coverage")
    add_our("")
    add_our("| registry | in_scope | measured | start_failed | excluded | sdist_only |")
    add_our("|---|---|---|---|---|---|")
    for cov in registry_coverage_table(rows):
        add_our(
            f"| {cov['registry']} | {cov['in_scope']} | {cov['measured']} | "
            f"{cov['start_failed']} | {cov['excluded']} | {cov['sdist_only']} |"
        )
    add_our("")
    add_our("## Excluded registry types (phase 1)")
    add_our("")
    for name, reason in excluded_reasons:
        add_our(f"- `{name}`: {reason}")

    add_our("")
    add_our("## tool_outcomes (all servers)")
    add_our("")
    add_our("| outcome | count |")
    add_our("|---|---|")
    for key in ("success", "validation_error", "domain_error", "timeout", "not_measured"):
        add_our(f"| {key} | {outcomes.get(key, 0)} |")
    add_our("")
    add_our(f"- tools_called total: {tools_called_total}")
    add_our(f"- validation_error: {validation_errors}")
    add_our(
        f"- phase2_llm_arg_trigger (>50% validation_error): {'YES' if trigger else 'NO'}"
    )
    add_our("")
    add_our("## claim_contradicted summaries")
    add_our("")
    contradicted = [r for r in rows if r.get("verdict") == "claim_contradicted"]
    if not contradicted:
        add_our("(none)")
    else:
        for r in contradicted:
            unp = r.get("unprompted_network") or {}
            dns_names = unp.get("dns_names") if isinstance(unp, dict) else None
            if dns_names:
                add_our(f"- `{r.get('name')}` — unprompted dns (third-party):")
                add_full_only(f"  {_THIRD_PARTY_NOTE}")
                for q in dns_names:
                    for qline in _quote_block(str(q), indent="  "):
                        add_full_only(qline)
                continue
            obs = r.get("observations") or {}
            net = []
            for stage, kinds in obs.items():
                if stage not in ("startup", "tools_list"):
                    continue
                for item in kinds.get("network_attempt") or []:
                    net.append(f"{stage}:{item.get('addr')}:{item.get('port')}")
            add_our(
                f"- `{r.get('name')}` — attempts: {', '.join(net) if net else '(see jsonl)'}"
            )

    add_our("")
    add_our("## tool_invoked_network (human review — does not change verdict)")
    add_our("")
    invoked_rows = [r for r in rows if r.get("tool_invoked_network_present")]
    if not invoked_rows:
        add_our("(none)")
    else:
        add_full_only(f"({_THIRD_PARTY_NOTE})")
        add_full_only("")
        for r in invoked_rows:
            add_our(f"### `{r.get('name')}`")
            add_our("")
            for item in r.get("tool_invoked_network") or []:
                tool = item.get("tool")
                desc = item.get("description") or ""
                dns = item.get("dns_names") or []
                attempts = item.get("attempts") or []
                add_our(f"- tool: `{tool}`")
                add_our("  - description (third-party verbatim):")
                for qline in _quote_block(str(desc)):
                    add_full_only(qline)
                add_our("  - dns_names (third-party):")
                if dns:
                    for name in dns:
                        for qline in _quote_block(str(name)):
                            add_full_only(qline)
                else:
                    add_our("    (none)")
                add_our(f"  - attempts: {len(attempts)}")
            add_our("")

    full_body = "\n".join(full) + "\n"
    our_body = "\n".join(our) + "\n"
    return full_body, our_body


def _rejected_markdown(hits: list[ForbiddenHit], would_be: str) -> str:
    lines = [
        "# Behavior probe report — REJECTED",
        "",
        "## Forbidden-word hits",
        "",
    ]
    for hit in hits:
        lines.append(f"- {hit.format()}")
    lines.extend(["", "## Would-be report", "", would_be])
    return "\n".join(lines) if would_be.endswith("\n") else "\n".join(lines) + "\n"


def write_markdown(
    path: Path,
    rows: list[dict[str, Any]],
    *,
    excluded_reasons: list[tuple[str, str]],
    run_label: str,
    calibration: dict[str, Any] | None = None,
) -> None:
    full_body, our_body = _build_markdown(
        rows,
        excluded_reasons=excluded_reasons,
        run_label=run_label,
        calibration=calibration,
    )
    hits = scan_rows_our_text(rows)
    word = find_forbidden_word(our_body)
    if word is not None:
        hits.append(ForbiddenHit(word=word, field="markdown", row_name=None))
    if hits:
        rejected = rejected_sibling(path)
        _write_text(rejected, _rejected_markdown(hits, full_body))
        raise ForbiddenOutputError(hits, rejected_md=rejected)
    _write_text(path, full_body)


def write_probe_reports(
    jsonl_path: Path,
    md_path: Path,
    rows: list[dict[str, Any]],
    *,
    excluded_reasons: list[tuple[str, str]],
    run_label: str,
    calibration: dict[str, Any] | None = None,
) -> None:
    """Write jsonl+md together; on forbidden-word hits, save *_rejected.* then raise."""
    full_body, our_body = _build_markdown(
        rows,
        excluded_reasons=excluded_reasons,
        run_label=run_label,
        calibration=calibration,
    )
    hits = scan_rows_our_text(rows)
    word = find_forbidden_word(our_body)
    if word is not None:
        hits.append(ForbiddenHit(word=word, field="markdown", row_name=None))
    if hits:
        rejected_jsonl = rejected_sibling(jsonl_path)
        rejected_md = rejected_sibling(md_path)
        _write_text(rejected_jsonl, _dump_jsonl_body(rows))
        _write_text(rejected_md, _rejected_markdown(hits, full_body))
        raise ForbiddenOutputError(
            hits,
            rejected_jsonl=rejected_jsonl,
            rejected_md=rejected_md,
        )
    _write_text(jsonl_path, _dump_jsonl_body(rows))
    _write_text(md_path, full_body)
