#!/usr/bin/env python3
"""Regenerate unterminated.jsonl from terminated.jsonl; print sha256 and sizes."""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

CASE_DIR = Path(__file__).resolve().parent
TERMINATED = CASE_DIR / "terminated.jsonl"
UNTERMINATED = CASE_DIR / "unterminated.jsonl"
SIDECAR = CASE_DIR / "sidecar.json"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def report_file(label: str, path: Path) -> None:
    data = path.read_bytes()
    print(f"{label}\tsize_bytes={len(data)}\tsha256={sha256_bytes(data)}")


def regenerate_unterminated() -> None:
    term = TERMINATED.read_bytes()
    if not term.endswith(b"\n"):
        raise SystemExit("terminated.jsonl must end with 0x0a for this case")
    unterm = term[:-1]
    UNTERMINATED.write_bytes(unterm)
    if term != unterm + b"\n":
        raise SystemExit("assert failed: terminated == unterminated + b'\\n'")


def main() -> int:
    for path in (TERMINATED, SIDECAR):
        if not path.is_file():
            raise SystemExit(f"missing {path.name}")
    regenerate_unterminated()
    report_file("terminated.jsonl", TERMINATED)
    report_file("unterminated.jsonl", UNTERMINATED)
    report_file("sidecar.json", SIDECAR)
    term = TERMINATED.read_bytes()
    unterm = UNTERMINATED.read_bytes()
    print(f"terminated == unterminated + newline: {term == unterm + b'\n'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
