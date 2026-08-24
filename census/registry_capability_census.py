#!/usr/bin/env python3
"""Registry capability census — phrase match, scannability triage, stage-2 split.

Everything an attacker needs to break this number is in this file: phrase list,
axis mapping, dedup rule, scannability rule, and stage-2 locality heuristic.
Re-runnable against a fresh snapshot; the number is expected to move.
"""
from __future__ import annotations

import argparse
import copy
import gzip
import hashlib
import io
import json
import re
import sys
from collections import Counter
from datetime import date
from pathlib import Path
from typing import Any

# Report-only scan vocabulary (matches 0012 public_export.FORBIDDEN_WORDS).
FORBIDDEN_WORDS: tuple[str, ...] = (
    "Imperial",
    "帝國",
    "帝国",
    "Tetsuroh",
    "判例",
    "Phase",
    "T-2",
    "EMV",
    "precedent",
    "02_Production",
    "A0000",
    "A1000",
)
JAPANESE_RE = re.compile(r"[ぁ-んァ-ヶ一-龯]")

CURRENT_METHOD_VERSION = "2026-08-16.1"

AXES: dict[str, list[str]] = {
    "filesystem": [
        r"read[-\s]?only",
        r"does ?n[o']?t write",
        r"never writes",
        r"no file writes?",
        r"without (?:writing|modifying)",
        r"never modif(?:y|ies)",
    ],
    "network": [
        r"no network",
        r"does ?n[o']?t (?:make|use) .{0,20}network",
        r"no phone[-\s]?home",
        r"no telemetry",
        r"does ?n[o']?t (?:send|transmit|upload)",
        r"never leaves your (?:machine|device|computer)",
        r"local[-\s]only",
        r"fully offline",
        r"works offline",
        r"air[-\s]?gapped",
    ],
    "subprocess": [
        r"no (?:subprocess|shell|shell out|command execution)",
        r"does ?n[o']?t (?:execute|spawn|run) .{0,20}(?:command|shell|process)",
        r"sandbox(?:ed)?",
    ],
    "env": [
        r"no (?:data )?collection",
        r"does ?n[o']?t (?:collect|read) .{0,20}(?:credential|secret|env)",
        r"no credentials? (?:are )?(?:stored|read)",
    ],
}

LOCALITY_PATTERNS = [
    r"\blocal(?:ly|-only|-first)?\b",
    r"\boffline\b",
    r"never leaves your (?:machine|device|computer)",
    r"\bon[-\s]device\b",
    r"\bair[-\s]?gapped\b",
    r"your (?:machine|device|disk|computer)",
    r"\bno network\b",
    r"\bno telemetry\b",
    r"\bphone[-\s]?home\b",
    r"\bno account\b",
    r"\bfilesystem\b",
    r"\bto disk\b",
    r"\bfiles?\b",
    r"\bsandbox",
    r"\bsubprocess\b",
    r"\bnever writes\b",
    r"does ?n[o']?t write",
    r"writes? are opt-in",
    r"\bdry[-\s]?run\b",
    r"\bno credentials?\b",
    r"\bnever receives keys\b",
    r"\bno data collection\b",
]

NETWORK_OFFLINE_PHRASES: tuple[str, ...] = (
    r"no network",
    r"fully offline",
    r"works offline",
    r"air[-\s]?gapped",
    r"local[-\s]only",
    r"never leaves your (?:machine|device|computer)",
)

METHOD_VERSIONS: dict[str, dict[str, Any]] = {
    CURRENT_METHOD_VERSION: {
        "axes": copy.deepcopy(AXES),
        "locality_patterns": list(LOCALITY_PATTERNS),
        "network_offline_phrases": list(NETWORK_OFFLINE_PHRASES),
        "dedup": "one row per server name among active records; latest row wins",
        "scannable": "packages non-empty AND repository URL contains github.com",
        "excluded_phrases": ["secure", "safe", "privacy-first", "trusted"],
    },
}


def _compile_method_spec(spec: dict[str, Any]) -> dict[str, Any]:
    offline_phrases = list(spec.get("network_offline_phrases") or [])
    return {
        "axes": {
            axis: [re.compile(p, re.I) for p in patterns]
            for axis, patterns in spec["axes"].items()
        },
        "locality": [re.compile(p, re.I) for p in spec["locality_patterns"]],
        "network_offline": [re.compile(p, re.I) for p in offline_phrases],
        "dedup": spec["dedup"],
        "scannable": spec["scannable"],
        "excluded_phrases": list(spec.get("excluded_phrases") or []),
        "network_offline_phrases": offline_phrases,
    }


def _load_records(path: Path) -> list[dict[str, Any]]:
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            return [json.loads(line) for line in handle if line.strip()]
    raw = path.read_bytes()
    data = json.loads(raw)
    if isinstance(data, list):
        return data
    raise ValueError(f"unsupported snapshot shape: {path}")


def snapshot_content_sha256(path: Path) -> str:
    """Hash the snapshot *content*, not the gzip container.

    For ``*.gz`` / ``*.jsonl.gz``, hash decompressed bytes. Container hashes drift
    with ``mtime`` even when the payload is identical.
    """
    raw = path.read_bytes()
    name = path.name
    if name.endswith(".gz"):
        return hashlib.sha256(gzip.decompress(raw)).hexdigest()
    return hashlib.sha256(raw).hexdigest()


def records_to_jsonl_gz(records: list[dict[str, Any]], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    buf = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buf, mtime=0, compresslevel=9) as gz:
        for row in records:
            line = json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n"
            gz.write(line.encode("utf-8"))
    out_path.write_bytes(buf.getvalue())


def build_reduced_servers_jsonl(records: list[dict[str, Any]]) -> bytes:
    seen: dict[str, dict[str, Any]] = {}
    for row in records:
        srv = row.get("server") or {}
        name = srv.get("name")
        if not name:
            continue
        meta = (row.get("_meta") or {}).get("io.modelcontextprotocol.registry/official") or {}
        seen[name] = {
            "name": name,
            "status": meta.get("status"),
            "title": srv.get("title"),
            "description": srv.get("description"),
            "repository": ((srv.get("repository") or {}).get("url")) or "",
            "packages": [
                p.get("registryType") or p.get("registry_name")
                for p in (srv.get("packages") or [])
            ],
            "has_remotes": bool(srv.get("remotes")),
        }
    lines = [json.dumps(seen[key], ensure_ascii=False) + "\n" for key in sorted(seen)]
    return "".join(lines).encode("utf-8")


def scan_third_party_vocabulary_collisions(reduced_jsonl: bytes) -> dict[str, Any]:
    """Report-only disclosure scan — never raises."""
    breakdown: Counter[str] = Counter()
    forbidden_rows = 0
    japanese_rows = 0
    for line in reduced_jsonl.splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        text = " ".join(
            str(row.get(key) or "")
            for key in ("name", "title", "description", "repository")
        )
        matched_words = [word for word in FORBIDDEN_WORDS if word in text]
        if matched_words:
            forbidden_rows += 1
            breakdown[matched_words[0]] += 1
        if JAPANESE_RE.search(text):
            japanese_rows += 1
    return {
        "scope": "rows of the reduced per-server JSONL",
        "forbidden_word_rows": forbidden_rows,
        "forbidden_word_breakdown": dict(sorted(breakdown.items())),
        "japanese_character_rows": japanese_rows,
        "note": "Third-party text republished verbatim; not filtered.",
    }


def _match_axes(text: str, compiled_axes: dict[str, list[re.Pattern[str]]]) -> list[str]:
    return sorted(
        axis for axis, patterns in compiled_axes.items() if any(p.search(text) for p in patterns)
    )


def _aggregate_counts(records: list[dict[str, Any]], compiled: dict[str, Any]) -> dict[str, int]:
    seen: dict[str, dict[str, Any]] = {}
    stats: Counter[str] = Counter()
    scannable: list[dict[str, Any]] = []

    for row in records:
        meta = (row.get("_meta") or {}).get("io.modelcontextprotocol.registry/official") or {}
        if meta.get("status") != "active":
            stats["skipped_inactive"] += 1
            continue
        srv = row.get("server") or {}
        name = srv.get("name")
        if not name:
            continue
        if name in seen:
            stats["dup_versions"] += 1
        seen[name] = srv

    stats["unique_active"] = len(seen)
    dup_versions = stats["dup_versions"]
    for srv in seen.values():
        text = " ".join(filter(None, [srv.get("title"), srv.get("description")]))
        axes = _match_axes(text, compiled["axes"])
        if not axes:
            continue
        stats["boundary_claim"] += 1
        pkgs = srv.get("packages") or []
        remotes = srv.get("remotes") or []
        repo = ((srv.get("repository") or {}).get("url")) or ""
        scannable_flag = bool(pkgs) and "github.com" in repo
        if scannable_flag:
            stats["scannable"] += 1
            scannable.append({"claim": text[:300]})
        elif remotes and not pkgs:
            stats["remote_only"] += 1
        else:
            stats["unscannable_other"] += 1

    process_claims = [c for c in scannable if any(p.search(c["claim"]) for p in compiled["locality"])]
    data_domain = [c for c in scannable if c not in process_claims]
    network_offline = sum(
        1 for c in process_claims if any(p.search(c["claim"]) for p in compiled["network_offline"])
    )
    return {
        "unique_active_servers": stats["unique_active"],
        "duplicate_version_rows_removed": dup_versions,
        "boundary_claim_mappable": stats["boundary_claim"],
        "remote_only": stats["remote_only"],
        "unscannable_other": stats["unscannable_other"],
        "scannable_package_and_github": stats["scannable"],
        "process_capability_claims": len(process_claims),
        "data_domain_claims_excluded": len(data_domain),
        "network_offline_approx": network_offline,
    }


def build_series_block(records: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    series: dict[str, dict[str, int]] = {}
    for version in sorted(METHOD_VERSIONS):
        compiled = _compile_method_spec(METHOD_VERSIONS[version])
        series[version] = _aggregate_counts(records, compiled)
    return series


def compute_results(
    records: list[dict[str, Any]],
    *,
    snapshot_sha256: str,
    snapshot_date: str,
    reduced_jsonl: bytes,
    method_version: str = CURRENT_METHOD_VERSION,
) -> dict[str, Any]:
    if method_version not in METHOD_VERSIONS:
        raise ValueError(f"unknown method_version: {method_version}")
    compiled = _compile_method_spec(METHOD_VERSIONS[method_version])
    counts = _aggregate_counts(records, compiled)
    spec = METHOD_VERSIONS[method_version]
    series = build_series_block(records)
    return {
        "snapshot_date": snapshot_date,
        "snapshot_sha256": snapshot_sha256,
        "method_version": method_version,
        "records_all_versions": len(records),
        **counts,
        "series": series,
        "third_party_vocabulary_collisions": scan_third_party_vocabulary_collisions(reduced_jsonl),
        "method": {
            "axes": list(spec["axes"].keys()),
            "dedup": spec["dedup"],
            "scannable": spec["scannable"],
            "stage2": "process vs data-domain split via locality heuristic in LOCALITY_PATTERNS",
            "excluded_phrases": list(spec["excluded_phrases"]),
            "network_offline_phrases": list(spec["network_offline_phrases"]),
            "network_offline_scope": (
                "Counted only within process_capability_claims, "
                "not within data_domain_claims_excluded"
            ),
        },
    }


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _static_digest_targets() -> tuple[str, ...]:
    return (
        "README.md",
        "fetch_registry_snapshot.py",
        "registry_capability_census.py",
        "SERIES.md",
        "RUNS.jsonl",
    )


def discover_runs(census_dir: Path) -> dict[str, dict[str, str]]:
    runs: dict[str, dict[str, str]] = {}
    for results_path in sorted(census_dir.glob("results_*.json")):
        run_date = results_path.name.removeprefix("results_").removesuffix(".json")
        servers = census_dir / f"servers_{run_date}.jsonl"
        if not servers.is_file():
            continue
        entry: dict[str, str] = {
            "servers": servers.name,
            "results": results_path.name,
        }
        registry_gz = census_dir / f"registry_{run_date}.jsonl.gz"
        if registry_gz.is_file():
            entry["registry_gz"] = registry_gz.name
        runs[run_date] = entry
    return runs


def write_digests(census_dir: Path) -> None:
    static_files = {
        name: _sha256_file(census_dir / name)
        for name in _static_digest_targets()
        if (census_dir / name).is_file()
    }
    run_entries: dict[str, Any] = {}
    for run_date, paths in discover_runs(census_dir).items():
        run_entries[run_date] = {
            "paths": paths,
            "sha256": {
                key: _sha256_file(census_dir / rel) for key, rel in paths.items()
            },
        }
    payload = {
        "schema": "aos-census-digests.v2",
        "static_files": static_files,
        "runs": run_entries,
    }
    (census_dir / "DIGESTS.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def write_series_md(census_dir: Path) -> None:
    rows: list[list[str]] = []
    for results_path in sorted(census_dir.glob("results_*.json")):
        run_date = results_path.name.removeprefix("results_").removesuffix(".json")
        payload = json.loads(results_path.read_text(encoding="utf-8"))
        sha = str(payload.get("snapshot_sha256") or "")
        version = str(payload.get("method_version") or "?")
        missing = "no" if results_path.is_file() else "yes"
        rows.append(
            [
                run_date,
                version,
                str(payload.get("unique_active_servers", "?")),
                str(payload.get("boundary_claim_mappable", "?")),
                str(payload.get("scannable_package_and_github", "?")),
                str(payload.get("process_capability_claims", "?")),
                str(payload.get("network_offline_approx", "?")),
                sha[:12] if sha else "?",
                missing,
            ]
        )
    lines = [
        "# Registry capability census — series",
        "",
        "Counts only. No interpretation of deltas.",
        "",
        "| run_date | method_version | unique_active | claims | scannable | process | network_offline | snapshot_sha256 | gap |",
        "|---|---|---:|---:|---:|---:|---:|---|---|",
    ]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    lines.append("")
    (census_dir / "SERIES.md").write_text("\n".join(lines), encoding="utf-8")


def _snapshot_source_for_run(census_dir: Path, run_paths: dict[str, str]) -> Path:
    if "registry_gz" in run_paths:
        return census_dir / run_paths["registry_gz"]
    raise ValueError(f"no snapshot source for run: {run_paths}")


def _results_match(stored: dict[str, Any], recomputed: dict[str, Any]) -> None:
    keys = (
        "unique_active_servers",
        "boundary_claim_mappable",
        "remote_only",
        "unscannable_other",
        "scannable_package_and_github",
        "process_capability_claims",
        "data_domain_claims_excluded",
        "network_offline_approx",
        "method_version",
        "series",
        "third_party_vocabulary_collisions",
    )
    for key in keys:
        if stored.get(key) != recomputed.get(key):
            raise ValueError(f"results mismatch on {key}")


def _load_digests_doc(census_dir: Path) -> dict[str, Any]:
    digests_path = census_dir / "DIGESTS.json"
    if not digests_path.is_file():
        raise ValueError(f"missing DIGESTS.json in {census_dir}")
    return json.loads(digests_path.read_text(encoding="utf-8"))


def verify_artifacts(census_dir: Path) -> None:
    """Validate run data and recomputed results. Does not check RUNS.jsonl or DIGESTS hashes."""
    for run_date, rel_map in discover_runs(census_dir).items():
        servers_path = census_dir / rel_map["servers"]
        results_path = census_dir / rel_map["results"]
        source = _snapshot_source_for_run(census_dir, rel_map)
        records = _load_records(source)
        expected_servers = build_reduced_servers_jsonl(records)
        actual_servers = servers_path.read_bytes()
        if actual_servers != expected_servers:
            raise ValueError(f"servers byte mismatch for {run_date}")
        stored = json.loads(results_path.read_text(encoding="utf-8"))
        stored_sha = stored.get("snapshot_sha256")
        if not isinstance(stored_sha, str) or not stored_sha:
            raise ValueError(f"results missing snapshot_sha256 for {run_date}")
        derived_sha = snapshot_content_sha256(source)
        if stored_sha != derived_sha:
            raise ValueError(
                f"snapshot_sha256 mismatch for {run_date}: "
                f"stored={stored_sha} derived={derived_sha}"
            )
        recomputed = compute_results(
            records,
            snapshot_sha256=derived_sha,
            snapshot_date=run_date,
            reduced_jsonl=actual_servers,
            method_version=str(stored.get("method_version") or CURRENT_METHOD_VERSION),
        )
        _results_match(stored, recomputed)


def verify_digests(census_dir: Path) -> None:
    """Validate DIGESTS.json hashes against on-disk files (includes RUNS.jsonl)."""
    digest_doc = _load_digests_doc(census_dir)
    if digest_doc.get("schema") == "aos-census-digests.v2":
        static_files = digest_doc.get("static_files") or {}
        runs_meta = digest_doc.get("runs") or {}
    else:
        static_files = digest_doc.get("files") or {}
        runs_meta = {
            run_date: {
                "paths": paths,
                "sha256": {key: _sha256_file(census_dir / rel) for key, rel in paths.items()},
            }
            for run_date, paths in discover_runs(census_dir).items()
        }

    for rel, expected in static_files.items():
        path = census_dir / rel
        if not path.is_file():
            raise ValueError(f"missing digest static target: {rel}")
        if _sha256_file(path) != expected:
            raise ValueError(f"DIGESTS static mismatch for {rel}")

    for run_date, run_doc in runs_meta.items():
        rel_map = run_doc.get("paths") or run_doc
        if not isinstance(rel_map, dict) or "servers" not in rel_map:
            rel_map = discover_runs(census_dir).get(run_date, {})
        if not rel_map:
            raise ValueError(f"unknown run in DIGESTS: {run_date}")
        sha_map = run_doc.get("sha256") if isinstance(run_doc, dict) else {}
        for key, rel in rel_map.items():
            expected = sha_map.get(key)
            if expected and _sha256_file(census_dir / rel) != expected:
                raise ValueError(f"DIGESTS run mismatch for {run_date}/{key}")


def verify_census_dir(census_dir: Path) -> None:
    verify_artifacts(census_dir)
    verify_digests(census_dir)


def main() -> int:
    parser = argparse.ArgumentParser(description="Registry capability census utilities.")
    sub = parser.add_subparsers(dest="command", required=True)

    pack = sub.add_parser("pack-gz", help="Write registry JSON array to jsonl.gz")
    pack.add_argument("snapshot", type=Path)
    pack.add_argument("-o", "--output", type=Path, required=True)

    reduced = sub.add_parser("write-reduced", help="Write reduced servers JSONL bytes")
    reduced.add_argument("snapshot", type=Path)
    reduced.add_argument("-o", "--output", type=Path, required=True)

    results = sub.add_parser("write-results", help="Write results JSON")
    results.add_argument("snapshot", type=Path)
    results.add_argument("-o", "--output", type=Path, required=True)
    results.add_argument("--run-date", default=None)

    verify = sub.add_parser("verify", help="Provenance lint for census directory")
    verify.add_argument("census_dir", type=Path)

    refresh = sub.add_parser("refresh-metadata", help="Rewrite DIGESTS.json and SERIES.md")
    refresh.add_argument("census_dir", type=Path)

    args = parser.parse_args()
    if args.command == "verify":
        verify_census_dir(args.census_dir)
        print(f"OK provenance {args.census_dir}")
        return 0
    if args.command == "refresh-metadata":
        write_series_md(args.census_dir)
        write_digests(args.census_dir)
        print(f"OK metadata {args.census_dir}")
        return 0
    records = _load_records(args.snapshot)
    if args.command == "pack-gz":
        records_to_jsonl_gz(records, args.output)
        print(f"wrote {args.output} lines={len(records)}")
        return 0
    if args.command == "write-reduced":
        payload = build_reduced_servers_jsonl(records)
        args.output.write_bytes(payload)
        print(f"wrote {args.output} bytes={len(payload)}")
        return 0
    if args.command == "write-results":
        sha = snapshot_content_sha256(args.snapshot)
        run_date = args.run_date or date.today().isoformat()
        reduced = build_reduced_servers_jsonl(records)
        payload = compute_results(
            records,
            snapshot_sha256=sha,
            snapshot_date=run_date,
            reduced_jsonl=reduced,
        )
        args.output.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"wrote {args.output}")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
