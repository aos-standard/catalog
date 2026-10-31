#!/usr/bin/env python3
"""Score a reader on cases.json. Compares only the keys each case's `expect` names.
Usage: python3 -I run_cases_089d8f9.py <reader.py> <case_dir>   (prints JSON: reader_sha256, n, agree, rows)"""
import hashlib, importlib.util, json, sys
from pathlib import Path
reader = Path(sys.argv[1]).resolve()
spec = importlib.util.spec_from_file_location("reader", reader); mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
root = Path(sys.argv[2]); meta = json.load(open(root / "cases.json", encoding="utf-8"))
rows = []
for c in meta["cases"]:
    raw = (root / "cases" / f"{c['id']}.json").read_bytes(); case = json.loads(raw)
    d = mod.decide(case["record"], complete_digest=case.get("complete_digest"), opened_at=case.get("opened_at"),
                   as_of=case.get("as_of"), window_days=case.get("window_days"))
    got = {"eligible": d["eligible"], "not_eligible": d["not_eligible"], "approval_bound": d["approval_bound"], "per_line": d["per_line"]}
    if "determination" in case:
        t = mod.check_determination(case["determination"], case["record"], d)
        got.update(det_ok=t["ok"], det_problems=t["problems"], det_warnings=t["warnings"])
    diffs = {k: {"expected": v, "got": got.get(k)} for k, v in c["expect"].items() if got.get(k) != v}
    rows.append({"id": c["id"], "agree": not diffs, "diffs": diffs, "spec_open": c["spec_open"], "input_sha256": hashlib.sha256(raw).hexdigest()})
print(json.dumps({"reader": reader.name, "reader_sha256": hashlib.sha256(reader.read_bytes()).hexdigest(), "n": len(rows),
                  "agree": sum(r["agree"] for r in rows), "rows": rows}, indent=1, ensure_ascii=False))
