"""Instrument calibration — noop MCP servers via the same build→run path.

If calibration sees any non-loopback network_attempt (excluding the DNS
selftest qname), production must not run (reason:
instrument_contaminated). Missing selftest → dns_recorder_not_recording.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from services.behavior_probe.build import build_local_image
from services.behavior_probe.constants import DNS_RECORDER_NOT_RECORDING
from services.behavior_probe.env import ResourceLimits
from services.behavior_probe.run import run_probed_server
from services.behavior_probe.strace_parse import (
    count_dns_queries_excluding_selftest,
    dns_log_has_selftest,
    merge_dns_queries,
    parse_strace_lines,
)

CALIBRATE_FIXTURE_NAMES: tuple[str, ...] = ("calibrate_npm", "calibrate_pypi")
_IN_TREE_FIXTURES = Path("tests") / "fixtures" / "behavior_probe"


class CalibrationFixturesNotFoundError(FileNotFoundError):
    """Walk-up found neither bundled nor in-tree calibration fixtures."""


def _fixtures_complete(root: Path) -> bool:
    return root.is_dir() and all(
        (root / name).is_dir() for name in CALIBRATE_FIXTURE_NAMES
    )


def default_fixtures_root(
    start: Path | None = None,
    *,
    stop_at: Path | None = None,
) -> Path:
    """Prefer fixtures bundled next to this package; else walk up to the tool root.

    Search order:
    1. ``<start>/fixtures`` with both calibrate_npm and calibrate_pypi
    2. Each ancestor's ``tests/fixtures/behavior_probe``
    3. Each ancestor's ``fixtures`` (bundled harness layout)
    Raises CalibrationFixturesNotFoundError if none exist. Never returns a
    missing path. ``stop_at`` clips the walk (tests); production omits it.
    """
    here = (start or Path(__file__)).resolve()
    if here.is_file():
        here = here.parent
    limit = stop_at.resolve() if stop_at is not None else None

    bundled = here / "fixtures"
    if _fixtures_complete(bundled):
        return bundled

    for parent in (here, *here.parents):
        in_tree = parent / _IN_TREE_FIXTURES
        if _fixtures_complete(in_tree):
            return in_tree
        ancestor_bundled = parent / "fixtures"
        if _fixtures_complete(ancestor_bundled):
            return ancestor_bundled
        if limit is not None and parent == limit:
            break

    raise CalibrationFixturesNotFoundError(
        "calibration fixtures not found: expected tests/fixtures/behavior_probe "
        f"or a bundled fixtures/ with {', '.join(CALIBRATE_FIXTURE_NAMES)} "
        f"(search started at {here})"
    )


FIXTURES_ROOT = default_fixtures_root()
CALIBRATE_NPM_DIR = FIXTURES_ROOT / "calibrate_npm"
CALIBRATE_PYPI_DIR = FIXTURES_ROOT / "calibrate_pypi"

CALIBRATE_NPM_IDENT = "aos-bp-calibrate-npm"
CALIBRATE_PYPI_IDENT = "aos-bp-calibrate-pypi"


class InstrumentContaminatedError(RuntimeError):
    """Calibration observed network_attempt — stop before production."""

    def __init__(self, message: str, *, report: "CalibrationReport") -> None:
        super().__init__(message)
        self.report = report


@dataclass
class CalibrationChannel:
    registry_type: str
    ok: bool
    network_attempt_count: int
    reason: str | None = None
    strace_lines: int = 0
    image_digest: str | None = None
    dns_query_count: int = 0
    dns_recorder_selftest: bool = False


@dataclass
class CalibrationReport:
    ok: bool
    channels: list[CalibrationChannel] = field(default_factory=list)
    reason: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "reason": self.reason,
            "channels": [
                {
                    "registry_type": c.registry_type,
                    "ok": c.ok,
                    "network_attempt_count": c.network_attempt_count,
                    "dns_query_count": c.dns_query_count,
                    "dns_recorder_selftest": c.dns_recorder_selftest,
                    "reason": c.reason,
                    "strace_lines": c.strace_lines,
                    "image_digest": c.image_digest,
                }
                for c in self.channels
            ],
        }


def evaluate_calibration_strace(
    strace_text: str,
    *,
    dns_query_log: str | None = None,
) -> tuple[bool, int]:
    """Return (clean, network_attempt_count). Clean iff count == 0.

    DNS recorder queries count as network_attempt (kind=dns_query), except the
    positive-control selftest qname. Any other query during calibration →
    instrument_contaminated.
    """
    parsed = parse_strace_lines(strace_text)
    parsed = merge_dns_queries(parsed, dns_query_log, exclude_selftest=True)
    count = len(parsed.network_attempt)
    return count == 0, count


def assert_calibration_straces_clean(
    straces: dict[str, str],
    *,
    dns_logs: dict[str, str] | None = None,
    require_selftest: bool = False,
) -> CalibrationReport:
    """Unit-testable gate: contaminated fixture → InstrumentContaminatedError.

    When ``require_selftest`` is True (production calibrate path), a missing
    selftest qname aborts with dns_recorder_not_recording.
    """
    channels: list[CalibrationChannel] = []
    contaminated = False
    recorder_dead = False
    dns_logs = dns_logs or {}
    for registry_type, text in straces.items():
        dns_text = dns_logs.get(registry_type, "")
        selftest_ok = dns_log_has_selftest(dns_text)
        if require_selftest and not selftest_ok:
            recorder_dead = True
            channels.append(
                CalibrationChannel(
                    registry_type=registry_type,
                    ok=False,
                    network_attempt_count=0,
                    reason=DNS_RECORDER_NOT_RECORDING,
                    strace_lines=len(text.splitlines()) if text else 0,
                    dns_query_count=count_dns_queries_excluding_selftest(dns_text),
                    dns_recorder_selftest=False,
                )
            )
            continue
        clean, count = evaluate_calibration_strace(text, dns_query_log=dns_text)
        dns_count = count_dns_queries_excluding_selftest(dns_text)
        channels.append(
            CalibrationChannel(
                registry_type=registry_type,
                ok=clean,
                network_attempt_count=count,
                reason=None if clean else "instrument_contaminated",
                strace_lines=len(text.splitlines()) if text else 0,
                dns_query_count=dns_count,
                dns_recorder_selftest=selftest_ok,
            )
        )
        if not clean:
            contaminated = True
    if recorder_dead:
        report = CalibrationReport(
            ok=False,
            channels=channels,
            reason=DNS_RECORDER_NOT_RECORDING,
        )
        raise InstrumentContaminatedError(
            f"{DNS_RECORDER_NOT_RECORDING}: calibration selftest missing",
            report=report,
        )
    report = CalibrationReport(
        ok=not contaminated,
        channels=channels,
        reason="instrument_contaminated" if contaminated else None,
    )
    if contaminated:
        raise InstrumentContaminatedError(
            "instrument_contaminated: calibration network_attempt >= 1",
            report=report,
        )
    return report


def run_instrument_calibration(
    limits: ResourceLimits,
    *,
    fixtures_root: Path | None = None,
    build_fn: Callable[..., Any] | None = None,
    run_fn: Callable[..., Any] | None = None,
) -> CalibrationReport:
    """Build+run npm and pypi noop fixtures; abort if either shows network_attempt."""
    root = fixtures_root or FIXTURES_ROOT
    npm_dir = root / "calibrate_npm"
    pypi_dir = root / "calibrate_pypi"
    _build = build_fn or build_local_image
    _run = run_fn or run_probed_server

    channels: list[CalibrationChannel] = []
    for registry_type, fixture_dir, ident, tag in (
        ("npm", npm_dir, CALIBRATE_NPM_IDENT, "localhost/aos-behavior-probe/calibrate-npm:local"),
        ("pypi", pypi_dir, CALIBRATE_PYPI_IDENT, "localhost/aos-behavior-probe/calibrate-pypi:local"),
    ):
        if not fixture_dir.is_dir():
            ch = CalibrationChannel(
                registry_type=registry_type,
                ok=False,
                network_attempt_count=0,
                reason=f"calibration_fixture_missing:{fixture_dir}",
            )
            channels.append(ch)
            report = CalibrationReport(ok=False, channels=channels, reason=ch.reason)
            raise InstrumentContaminatedError(str(ch.reason), report=report)

        built = _build(
            registry_type=registry_type,
            identifier=ident,
            fixture_dir=fixture_dir,
            image_tag=tag,
        )
        if not built.ok or not built.image_ref:
            ch = CalibrationChannel(
                registry_type=registry_type,
                ok=False,
                network_attempt_count=0,
                reason=built.reason or "calibration_build_failed",
            )
            channels.append(ch)
            report = CalibrationReport(ok=False, channels=channels, reason=ch.reason)
            raise InstrumentContaminatedError(
                f"calibration build failed ({registry_type}): {ch.reason}",
                report=report,
            )

        ran = _run(built.image_ref, limits=limits)
        dns_text = getattr(ran, "dns_query_log", "") or ""
        selftest_ok = dns_log_has_selftest(dns_text)
        if not selftest_ok:
            ch = CalibrationChannel(
                registry_type=registry_type,
                ok=False,
                network_attempt_count=0,
                reason=DNS_RECORDER_NOT_RECORDING,
                strace_lines=len((ran.strace_text or "").splitlines()),
                image_digest=built.image_digest,
                dns_query_count=count_dns_queries_excluding_selftest(dns_text),
                dns_recorder_selftest=False,
            )
            channels.append(ch)
            report = CalibrationReport(
                ok=False, channels=channels, reason=DNS_RECORDER_NOT_RECORDING
            )
            raise InstrumentContaminatedError(
                f"{DNS_RECORDER_NOT_RECORDING}: calibration selftest missing ({registry_type})",
                report=report,
            )

        clean, count = evaluate_calibration_strace(
            ran.strace_text or "",
            dns_query_log=dns_text,
        )
        dns_count = count_dns_queries_excluding_selftest(dns_text)
        ch = CalibrationChannel(
            registry_type=registry_type,
            ok=clean and bool(ran.ok),
            network_attempt_count=count,
            reason=(
                None
                if clean and ran.ok
                else ("instrument_contaminated" if not clean else (ran.reason or "calibration_run_failed"))
            ),
            strace_lines=len((ran.strace_text or "").splitlines()),
            image_digest=built.image_digest,
            dns_query_count=dns_count,
            dns_recorder_selftest=True,
        )
        channels.append(ch)
        if not clean:
            report = CalibrationReport(
                ok=False, channels=channels, reason="instrument_contaminated"
            )
            raise InstrumentContaminatedError(
                "instrument_contaminated: calibration network_attempt >= 1",
                report=report,
            )
        if not ran.ok:
            report = CalibrationReport(ok=False, channels=channels, reason=ch.reason)
            raise InstrumentContaminatedError(
                f"calibration run failed ({registry_type}): {ch.reason}",
                report=report,
            )

    return CalibrationReport(ok=True, channels=channels, reason=None)
