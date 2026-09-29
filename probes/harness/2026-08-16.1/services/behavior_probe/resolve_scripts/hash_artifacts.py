#!/usr/bin/env python3
"""Hash already-downloaded install artifacts. Never fails the build.

Usage: python3 hash_artifacts.py <artifact-dir> <output-json>
Missing dir / unreadable files → write {}.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import sys

DEFAULT_SRC = pathlib.Path("/tmp/aos-bp-artifacts")
DEFAULT_DEST = pathlib.Path("/app/aos-bp-artifact-sha256.json")


def hash_artifact_dir(src: pathlib.Path) -> dict[str, str]:
    """Return {filename: sha256} for regular files in src. Empty if unreadable."""
    out: dict[str, str] = {}
    try:
        if not src.is_dir():
            return {}
        for path in sorted(src.iterdir()):
            if not path.is_file():
                continue
            try:
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
            except OSError:
                continue
            out[path.name] = digest
    except OSError:
        return {}
    return out


def write_artifact_sha256(src: pathlib.Path, dest: pathlib.Path) -> dict[str, str]:
    """Write hashes (or {}) to dest. Never raises to the caller."""
    try:
        payload = hash_artifact_dir(src)
    except Exception:  # noqa: BLE001 — measurement must proceed with {}
        payload = {}
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(
            json.dumps(payload, ensure_ascii=False, sort_keys=True),
            encoding="utf-8",
        )
    except OSError:
        return {}
    return payload


def main() -> int:
    src = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_SRC
    dest = pathlib.Path(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_DEST
    write_artifact_sha256(src, dest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
