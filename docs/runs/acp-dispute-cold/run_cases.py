#!/usr/bin/env python3
"""Score acp_dispute_check.py on cases.json. Compares only the keys each case's `expect` names.
Usage: python3 -I run_cases.py <case_dir>   (prints JSON: n, agree, rows)"""
import hashlib, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from acp_dispute_check import check_determination, decide  # noqa: E402

root = Path(sys.argv[1]); meta = json.load(open(root / "cases.json", encoding="utf-8"))
rows = []
for c in meta["cases"]:
    raw = (root / "cases" / f"{c['id']}.json").read_bytes(); case = json.loads(raw)
    d = decide(case["record"], complete_digest=case.get("complete_digest"), opened_at=case.get("opened_at"),
               as_of=case.get("as_of"), window_days=case.get("window_days"))
    got = {"eligible": d["eligible"], "not_eligible": d["not_eligible"], "approval_bound": d["approval_bound"], "per_line": d["per_line"]}
    if "determination" in case:
        t = check_determination(case["determination"], case["record"], d)
        got.update(det_ok=t["ok"], det_problems=t["problems"], det_warnings=t["warnings"])
    diffs = {k: {"expected": v, "got": got.get(k)} for k, v in c["expect"].items() if got.get(k) != v}
    rows.append({"id": c["id"], "agree": not diffs, "diffs": diffs, "spec_open": c["spec_open"],
                 "input_sha256": hashlib.sha256(raw).hexdigest()})
print(json.dumps({"reader_sha256": hashlib.sha256((Path(__file__).resolve().parent / "acp_dispute_check.py").read_bytes()).hexdigest(),
                  "n": len(rows), "agree": sum(r["agree"] for r in rows), "rows": rows}, indent=1, ensure_ascii=False))
