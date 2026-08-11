#!/usr/bin/env python3
"""Reproduce the T2 self-attack constructions against a local ANCHORS.jsonl.

Standard library only. No network. Input is the tag-bundled ANCHORS.jsonl
(same directory by default). Each construction regenerates its digest sidecar
(attacker-holds-sidecar threat model). Writes eleven streams + MANIFEST.json.

Count correction: a public comment said "nine constructions"; the set that was
actually run is ten mutations plus baseline (eleven artifacts). See
T2_CONSTRUCTIONS.md.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


CONSTRUCTION_IDS = (
    "baseline",
    "A2",
    "A3",
    "B",
    "C",
    "D2",
    "D3",
    "E",
    "F",
    "G",
    "H",
)

# Expected outcomes from the 2026-08-11 self-attack (anchors-verify-v0.5).
EXPECTED: dict[str, dict[str, Any]] = {
    "baseline": {
        "exit_code": 3,
        "verdict": "VERIFY PARTIAL",
        "rejection_class": None,
        "note": "unmodified stream; attested_prefix_lines=18",
    },
    "A2": {
        "exit_code": 1,
        "verdict": "VERIFY FAILED",
        "rejection_class": "fork or insertion detected",
        "note": "duplicate genuine record inserted inside attested prefix",
    },
    "A3": {
        "exit_code": 1,
        "verdict": "VERIFY FAILED",
        "rejection_class": "fork or insertion detected",
        "note": "altered genuine record inserted inside attested prefix",
    },
    "B": {
        "exit_code": 1,
        "verdict": "VERIFY FAILED",
        "rejection_class": "fork or insertion detected",
        "note": "one record deleted inside attested prefix",
    },
    "C": {
        "exit_code": 1,
        "verdict": "VERIFY FAILED",
        "rejection_class": "fork or insertion detected",
        "note": "one byte flipped inside attested prefix",
    },
    "D2": {
        "exit_code": 3,
        "verdict": "VERIFY PARTIAL",
        "rejection_class": None,
        "note": "duplicate genuine record in unattested tip (documented out of scope)",
    },
    "D3": {
        "exit_code": 3,
        "verdict": "VERIFY PARTIAL",
        "rejection_class": None,
        "note": "altered tip row (documented out of scope)",
    },
    "E": {
        "exit_code": 1,
        "verdict": "VERIFY FAILED",
        "rejection_class": "truncation vector 2",
        "note": "binding row removed (line count shrinks)",
    },
    "F": {
        "exit_code": 1,
        "verdict": "VERIFY FAILED",
        "rejection_class": "truncation vector 2",
        "note": "stream truncated to 10 lines",
    },
    "G": {
        "exit_code": 1,
        "verdict": "VERIFY FAILED",
        "rejection_class": "has fewer than",
        "note": "extra binding claiming line_count=24; witness commit lacks 24 lines",
    },
    "H": {
        "exit_code": 1,
        "verdict": "VERIFY FAILED",
        "rejection_class": "missing witness after introduction",
        "note": "binding row replaced by a record row (line count preserved)",
    },
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def bytes_to_lines(content: bytes) -> list[bytes]:
    """Split on b'\\n' only; each line includes its trailing newline byte."""
    if not content:
        return []
    parts = content.split(b"\n")
    lines: list[bytes] = []
    for index, part in enumerate(parts):
        is_last = index == len(parts) - 1
        if is_last and part == b"" and content.endswith(b"\n"):
            continue
        if is_last and not content.endswith(b"\n"):
            lines.append(part + b"\n")
        else:
            lines.append(part + b"\n")
    return lines


def sidecar_bytes(lines: list[bytes]) -> bytes:
    """Regenerate digest sidecar (compact JSON, no trailing newline)."""
    digests = [sha256_bytes(line) for line in lines]
    return json.dumps(
        {"version": "1.0.0", "line_sha256": digests},
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _alter_first_string_field(line: bytes) -> bytes:
    row = json.loads(line)
    for key, value in list(row.items()):
        if isinstance(value, str) and key != "event":
            row[key] = value + "X"
            break
    return (
        json.dumps(row, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"
    )


def _flip_first_digit(line: bytes) -> bytes:
    row = bytearray(line)
    for index, byte in enumerate(row):
        char = chr(byte)
        if char.isdigit():
            row[index] = ord("9") if char != "9" else ord("8")
            break
    return bytes(row)


def build_constructions(base_lines: list[bytes]) -> dict[str, list[bytes]]:
    """Deterministic mutations matching the 2026-08-11 self-attack scripts."""
    if len(base_lines) < 22:
        raise SystemExit(
            f"ANCHORS.jsonl too short for T2 constructions: {len(base_lines)} lines"
        )

    constructions: dict[str, list[bytes]] = {}

    constructions["baseline"] = list(base_lines)

    # A2: duplicate genuine record (line index 2) into attested prefix at index 4
    a2 = list(base_lines)
    a2.insert(4, base_lines[2])
    constructions["A2"] = a2

    # A3: altered genuine record inserted at the same position
    a3 = list(base_lines)
    a3.insert(4, _alter_first_string_field(base_lines[2]))
    constructions["A3"] = a3

    # B: delete one record inside attested prefix
    b = list(base_lines)
    del b[4]
    constructions["B"] = b

    # C: flip one digit byte inside attested prefix
    c = list(base_lines)
    c[4] = _flip_first_digit(c[4])
    constructions["C"] = c

    # D2: replace a tip row with a copy of another tip row
    d2 = list(base_lines)
    d2[21] = base_lines[20]
    constructions["D2"] = d2

    # D3: alter one tip row field
    d3 = list(base_lines)
    d3[21] = _alter_first_string_field(base_lines[21])
    constructions["D3"] = d3

    # E: strip binding event (line count shrinks)
    constructions["E"] = [ln for ln in base_lines if b"position_binding_introduced" not in ln]

    # F: truncate to 10 lines
    constructions["F"] = list(base_lines[:10])

    # G: insert a second binding claiming line_count=24 (byte_length/sha256 left as-is)
    g = list(base_lines)
    for index, line in enumerate(g):
        if b"position_binding_introduced" in line:
            row = json.loads(line)
            row["attestation"]["prefix"]["line_count"] = 24
            g.insert(
                index + 1,
                json.dumps(row, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
                + b"\n",
            )
            break
    constructions["G"] = g

    # H: replace binding row with a genuine record (same total line count)
    h = list(base_lines)
    for index, line in enumerate(h):
        if b"position_binding_introduced" in line:
            h[index] = base_lines[2]
            break
    constructions["H"] = h

    return constructions


def write_construction(
    out_dir: Path,
    construction_id: str,
    lines: list[bytes],
) -> dict[str, Any]:
    anchors_path = out_dir / f"{construction_id}.jsonl"
    digests_path = out_dir / f"{construction_id}.jsonl.digests.json"
    anchors_content = b"".join(lines)
    digests_content = sidecar_bytes(lines)
    anchors_path.write_bytes(anchors_content)
    digests_path.write_bytes(digests_content)
    expected = EXPECTED[construction_id]
    return {
        "id": construction_id,
        "anchors_file": anchors_path.name,
        "digests_file": digests_path.name,
        "line_count": len(lines),
        "sha256_anchors": sha256_bytes(anchors_content),
        "sha256_digests": sha256_bytes(digests_content),
        "expected_exit_code": expected["exit_code"],
        "expected_verdict": expected["verdict"],
        "expected_rejection_class": expected["rejection_class"],
        "note": expected["note"],
        "sidecar_regenerated": True,
    }


def generate(
    anchors_path: Path,
    out_dir: Path,
) -> dict[str, Any]:
    content = anchors_path.read_bytes()
    base_lines = bytes_to_lines(content)
    constructions = build_constructions(base_lines)
    out_dir.mkdir(parents=True, exist_ok=True)

    records: list[dict[str, Any]] = []
    for construction_id in CONSTRUCTION_IDS:
        records.append(
            write_construction(out_dir, construction_id, constructions[construction_id])
        )

    manifest: dict[str, Any] = {
        "schema": "aos-t2-constructions.v1",
        "count_correction": (
            "A public comment said 'nine constructions'. The set that was "
            "actually run is ten mutations plus baseline (eleven artifacts). "
            "That miscount is ours; it is not hidden."
        ),
        "input": {
            "anchors_path": str(anchors_path.resolve()),
            "anchors_sha256": sha256_bytes(content),
            "anchors_line_count": len(base_lines),
        },
        "threat_model": {
            "this_set": "sidecar_regenerated",
            "external_separator_receipt": "sidecar_unmodified",
            "stricter": "external_separator_receipt",
        },
        "constructions": records,
    }
    manifest_path = out_dir / "MANIFEST.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Generate the eleven T2 constructions (ten mutations + baseline) "
            "from a local ANCHORS.jsonl. Stdlib only; no network."
        )
    )
    here = Path(__file__).resolve().parent
    parser.add_argument(
        "--anchors",
        type=Path,
        default=here / "ANCHORS.jsonl",
        help="Path to tag-bundled ANCHORS.jsonl (default: beside this script)",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=here / "t2_constructions",
        help="Output directory for .jsonl, sidecars, and MANIFEST.json",
    )
    args = parser.parse_args(argv)

    if not args.anchors.is_file():
        print(f"ERROR: anchors not found: {args.anchors}", file=sys.stderr)
        return 2

    manifest = generate(args.anchors, args.out_dir)
    print(
        f"Wrote {len(manifest['constructions'])} constructions + MANIFEST.json -> "
        f"{args.out_dir}",
        file=sys.stderr,
    )
    for record in manifest["constructions"]:
        rejection = record["expected_rejection_class"] or "-"
        print(
            f"  {record['id']:9s}  sha256={record['sha256_anchors'][:16]}…  "
            f"exit={record['expected_exit_code']}  "
            f"{record['expected_verdict']}  ({rejection})",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
