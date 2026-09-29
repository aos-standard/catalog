"""Recompute network_offline targets from the public census snapshot.

Does not hand-copy the 27 names. Stops with CountMismatchError if totals diverge.
"""

from __future__ import annotations

import importlib.util
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from services.behavior_probe.constants import (
    EXPECTED_BY_REGISTRY,
    EXPECTED_OFFLINE_TOTAL,
    EXCLUDED_REGISTRY_TYPES,
    MEASURED_REGISTRY_TYPES,
    METHOD_VERSION,
)


class CountMismatchError(RuntimeError):
    """Observed offline counts do not match the census invariant."""


@dataclass(frozen=True)
class ProbeTarget:
    name: str
    claim: str
    registry_type: str
    identifier: str
    version: str
    transport: str
    package: dict[str, Any]
    measured: bool
    not_measured_reason: str | None = None


def _census_marker(directory: Path) -> bool:
    return (directory / "registry_capability_census.py").is_file()


def _is_workspace_root(parent: Path) -> bool:
    return (parent / ".git").exists() or (parent / "CLAUDE.md").is_file()


def _census_candidates(parent: Path) -> list[Path]:
    """Public-tree layouts. Does not name a repository-internal tree."""
    out = [
        parent / "census",
        parent / "public_catalog_export" / "census",
    ]
    if _is_workspace_root(parent):
        try:
            children = list(parent.iterdir())
        except OSError:
            children = []
        for child in children:
            if not child.is_dir():
                continue
            out.append(child / "census")
            out.append(child / "public_catalog_export" / "census")
    return out


def _default_census_dir() -> Path:
    """Locate census/ that ships the census module and the pinned snapshot.

    Walks parents of this file and of the current working directory. Accepts
    ``<root>/census`` or ``<root>/public_catalog_export/census``. At a workspace
    root, also looks one directory deeper. Raises FileNotFoundError when none
    is found.
    """
    seen: set[Path] = set()
    starts = [Path(__file__).resolve().parent, Path.cwd().resolve()]
    for start in starts:
        for parent in (start, *start.parents):
            if parent in seen:
                continue
            seen.add(parent)
            for candidate in _census_candidates(parent):
                if _census_marker(candidate):
                    return candidate
    raise FileNotFoundError(
        "census directory with registry_capability_census.py not found "
        "(walked parents of the harness and the current working directory)"
    )


def _load_census_module(census_dir: Path) -> Any:
    path = census_dir / "registry_capability_census.py"
    spec = importlib.util.spec_from_file_location("registry_capability_census", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load census module from {path}")
    mod = importlib.util.module_from_spec(spec)
    # Ensure relative Path lookups inside census still work if needed.
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _primary_package(server: dict[str, Any]) -> dict[str, Any] | None:
    """Match census recalc: packages[0] drives registryType breakdown."""
    pkgs = list(server.get("packages") or [])
    return pkgs[0] if pkgs else None


def _transport_type(pkg: dict[str, Any]) -> str:
    transport = pkg.get("transport") or {}
    if isinstance(transport, dict):
        return str(transport.get("type") or "stdio")
    if isinstance(transport, str) and transport:
        return transport
    return "stdio"


def collect_offline_targets(
    snapshot_path: Path | None = None,
    census_dir: Path | None = None,
) -> list[ProbeTarget]:
    """Return the 27 network_offline targets (measured + excluded rows)."""
    census_dir = census_dir or _default_census_dir()
    census = _load_census_module(census_dir)
    snapshot = snapshot_path or (census_dir / "registry_2026-08-16.jsonl.gz")
    if not snapshot.is_file():
        raise FileNotFoundError(f"registry snapshot missing: {snapshot}")

    method_spec = census.METHOD_VERSIONS[METHOD_VERSION]
    compiled = census._compile_method_spec(method_spec)
    records = census._load_records(snapshot)
    _stats, scannable = census._collect_scannable(records, compiled)
    process_claims, _data = census._split_process(scannable, compiled)
    offline_claims = [
        c
        for c in process_claims
        if any(p.search(c["claim"]) for p in compiled["network_offline"])
    ]

    # Latest active server object per name (same dedup as census).
    latest: dict[str, dict[str, Any]] = {}
    for row in records:
        meta = (row.get("_meta") or {}).get("io.modelcontextprotocol.registry/official") or {}
        if meta.get("status") != "active":
            continue
        srv = row.get("server") or {}
        name = srv.get("name")
        if name:
            latest[name] = srv

    by_type: Counter[str] = Counter()
    targets: list[ProbeTarget] = []
    for claim_row in offline_claims:
        name = claim_row["name"]
        srv = latest.get(name) or {}
        pkg = _primary_package(srv) or {}
        registry_type = str(pkg.get("registryType") or pkg.get("registry_name") or "unknown")
        identifier = str(pkg.get("identifier") or "")
        version = str(pkg.get("version") or "")
        transport = _transport_type(pkg) if pkg else "unknown"
        by_type[registry_type] += 1

        # Phase 1 measures npm+pypi stdio only.
        is_measured = (
            registry_type in MEASURED_REGISTRY_TYPES
            and transport == "stdio"
            and bool(identifier)
        )
        if is_measured:
            targets.append(
                ProbeTarget(
                    name=name,
                    claim=str(claim_row.get("claim") or ""),
                    registry_type=registry_type,
                    identifier=identifier,
                    version=version,
                    transport=transport,
                    package=dict(pkg),
                    measured=True,
                )
            )
        else:
            reason = _exclusion_reason(registry_type, transport)
            targets.append(
                ProbeTarget(
                    name=name,
                    claim=str(claim_row.get("claim") or ""),
                    registry_type=registry_type,
                    identifier=identifier,
                    version=version,
                    transport=transport,
                    package=dict(pkg),
                    measured=False,
                    not_measured_reason=reason,
                )
            )

    _assert_expected_counts(len(offline_claims), by_type)
    # Stable order: measured npm/pypi first by name, then excluded.
    targets.sort(key=lambda t: (0 if t.measured else 1, t.registry_type, t.name))
    return targets


def _exclusion_reason(registry_type: str, transport: str) -> str:
    if registry_type in EXCLUDED_REGISTRY_TYPES:
        return (
            f"phase1_excluded_registry_type:{registry_type} "
            "(mcpb/nuget/cargo not measured in phase 1)"
        )
    if transport != "stdio":
        return f"non_stdio_transport:{transport}"
    return f"unsupported_registry_type:{registry_type}"


def _assert_expected_counts(total: int, by_type: Counter[str]) -> None:
    if total != EXPECTED_OFFLINE_TOTAL:
        raise CountMismatchError(
            f"network_offline total {total} != {EXPECTED_OFFLINE_TOTAL}; stop without adapting"
        )
    for reg, expected in EXPECTED_BY_REGISTRY.items():
        got = int(by_type.get(reg, 0))
        if got != expected:
            raise CountMismatchError(
                f"registryType {reg}: got {got} != expected {expected}; "
                f"full breakdown={dict(by_type)}; stop without adapting"
            )


def measured_targets(targets: list[ProbeTarget]) -> list[ProbeTarget]:
    return [t for t in targets if t.measured]
