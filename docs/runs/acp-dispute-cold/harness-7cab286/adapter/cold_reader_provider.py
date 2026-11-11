#!/usr/bin/env python3
"""Adapter: one case `input` on stdin -> the cold reader's decision as JSON on stdout.

The reader is acp_dispute_check.py from the cold read (aos-standard/catalog docs/runs/acp-dispute-cold/),
pass the reader file as the first argument. Output keys follow the case file's `expect`:
eligible, not_eligible, approval_bound, per_line, and det_ok / det_problems when the input has a determination."""
import json, sys
from pathlib import Path

import importlib.util
_spec = importlib.util.spec_from_file_location("reader", Path(sys.argv[1]).resolve())
_reader = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(_reader)
check_determination, decide = _reader.check_determination, _reader.decide

inp = json.load(sys.stdin)
d = decide(inp["record"], complete_digest=inp.get("complete_digest"), opened_at=inp.get("opened_at"),
           as_of=inp.get("as_of"), window_days=inp.get("window_days"))
out = {"eligible": d["eligible"], "not_eligible": d["not_eligible"], "approval_bound": d["approval_bound"],
       "per_line": d["per_line"]}
if "determination" in inp:
    t = check_determination(inp["determination"], inp["record"], d)
    out.update(det_ok=t["ok"], det_problems=t["problems"])
json.dump(out, sys.stdout)
