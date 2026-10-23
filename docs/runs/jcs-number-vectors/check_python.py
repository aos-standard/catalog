#!/usr/bin/env python3
"""Score a Python JSON canonicalizer on jcs-number-vectors.tsv.

Usage: python3 check_python.py <module> <callable>
The callable takes a Python value and returns str or bytes (for example `rfc8785 dumps`).
Each vector's `json` literal is parsed with the standard library, passed to the callable, and compared with `expected`.
"""
import importlib
import json
import sys
from pathlib import Path


def main() -> int:
    mod, attr = sys.argv[1], sys.argv[2]
    fn = getattr(importlib.import_module(mod), attr)
    rows = [
        line.split("	")
        for line in (Path(__file__).resolve().parent / "jcs-number-vectors.tsv").read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    ]
    head, body = rows[0], rows[1:]
    vectors = [dict(zip(head, r)) for r in body]
    bad = []
    for v in vectors:
        try:
            got = fn(json.loads(v["json"]))
            got = got.decode() if isinstance(got, bytes) else got
        except Exception as exc:  # report, do not stop
            got = f"raised {type(exc).__name__}"
        if got != v["expected"]:
            bad.append((v["json"], v["expected"], got, v["why"]))
    print(f"{len(vectors) - len(bad)}/{len(vectors)}")
    for b in bad[:20]:
        print("  json %s  expected %s  got %s  (%s)" % b)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
