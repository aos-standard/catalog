#!/usr/bin/env python3
"""Build the monthly timestamp manifest of the public catalog (aos-standard/catalog).

One line per file: `<sha256>  <path>`, sorted by path, over every file TRACKED at the given commit under:
  CONDUCT.jsonl, ANCHORS.jsonl, ANCHORS.jsonl.digests.json, docs/runs/**, docs/evidence/**
plus one line for the maintainer's private ledger (VERIFICATION_CONDUCT_LEDGER.jsonl), whose public subset is
CONDUCT.jsonl; a reader cannot recompute that line, the maintainer can.

Bytes are read from the git object store at the commit (`git show <commit>:<path>`), never from the work tree, so the
manifest describes exactly that commit. The manifest's own sha256 is what gets stamped with OpenTimestamps.

Usage: python3 build_manifest.py <shelf repo> <commit> <private ledger path> <out manifest>
"""
from __future__ import annotations

import hashlib
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

INCLUDE_FILES = ("CONDUCT.jsonl", "ANCHORS.jsonl", "ANCHORS.jsonl.digests.json")
INCLUDE_DIRS = ("docs/runs/", "docs/evidence/")


def git(repo: Path, *args: str) -> bytes:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True).stdout


def main() -> int:
    repo, commit, private, out = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3]), Path(sys.argv[4])
    full = git(repo, "rev-parse", commit).decode().strip()
    paths = [p for p in git(repo, "ls-tree", "-r", "--name-only", full).decode().splitlines()
             if p in INCLUDE_FILES or p.startswith(INCLUDE_DIRS)]
    lines = []
    for p in sorted(paths):
        blob = git(repo, "show", f"{full}:{p}")
        lines.append(f"{hashlib.sha256(blob).hexdigest()}  {p}")
    dev_repo = Path(git(private.parent, "rev-parse", "--show-toplevel").decode().strip())  # the maintainer's repository
    dev_full = git(dev_repo, "rev-parse", "HEAD").decode().strip()
    rel = private.relative_to(dev_repo).as_posix()
    priv = git(dev_repo, "show", f"{dev_full}:{rel}")
    lines.append(f"{hashlib.sha256(priv).hexdigest()}  [private] VERIFICATION_CONDUCT_LEDGER.jsonl ({len(priv.splitlines())} rows; public subset = CONDUCT.jsonl)")
    header = [
        "# aos-standard/catalog — timestamp manifest",
        f"# commit: {full}",
        f"# private_ledger_commit: {dev_full} (maintainer's repository, not public; the [private] line is recomputable by the maintainer only)",
        f"# built_at: {datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')}",
        f"# files: {len(paths)} public + 1 private",
        "# format: sha256 of the file's bytes at that commit, two spaces, path; sorted by path",
        "",
    ]
    out.write_text("\n".join(header + lines) + "\n", encoding="utf-8")
    print(f"commit {full[:12]} files {len(paths)} manifest sha256 {hashlib.sha256(out.read_bytes()).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
