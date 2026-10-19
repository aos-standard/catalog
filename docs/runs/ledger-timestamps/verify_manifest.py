#!/usr/bin/env python3
"""Recompute a timestamp manifest of aos-standard/catalog from a clone — no OpenTimestamps client needed.

Step 1 of the two-step check (step 2 is `ots verify MANIFEST.txt.ots`). For every public line `<sha256>  <path>`
of MANIFEST.txt, read the file's bytes at the manifest's commit from the clone's object store and compare.
Lines marked [private] are reported as not recomputable here.

Usage: python3 verify_manifest.py <clone of aos-standard/catalog> <MANIFEST.txt>
Exit 0 iff every public line matches and the commit exists in the clone.
"""
from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path


def main() -> int:
    repo, manifest = Path(sys.argv[1]), Path(sys.argv[2])
    text = manifest.read_text(encoding="utf-8")
    commit = next(l.split(":", 1)[1].strip() for l in text.splitlines() if l.startswith("# commit:"))
    print(f"manifest sha256 {hashlib.sha256(manifest.read_bytes()).hexdigest()}  (this is the value the .ots proof commits to)")
    print(f"commit {commit}")
    ok = bad = private = 0
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        digest, path = line.split("  ", 1)
        if path.startswith("[private]"):
            private += 1
            continue
        r = subprocess.run(["git", "-C", str(repo), "show", f"{commit}:{path}"], capture_output=True)
        if r.returncode != 0:
            print(f"MISSING {path}")
            bad += 1
            continue
        if hashlib.sha256(r.stdout).hexdigest() == digest:
            ok += 1
        else:
            print(f"DIFFERS {path}")
            bad += 1
    print(f"{ok} match, {bad} differ or missing, {private} private (not recomputable here)")
    return 0 if bad == 0 and ok > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
