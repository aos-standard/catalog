#!/usr/bin/env python3
"""Run ap2_cold_verifier over spec/vectors/ap2 and compare the normative block (and report).

Usage: python3 -I run_conformance.py <ap2-evidence-pack clone> <out.json>
Exit 0 only when every vector agrees (SKIP counts as not-agreed and is listed).
"""
from __future__ import annotations

import hashlib
import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ap2_cold_verifier import NORMATIVE, verify_pack  # noqa: E402

repo, out_path = Path(sys.argv[1]), Path(sys.argv[2])
vdir = repo / "spec/vectors/ap2"
rows, agree, skipped = [], 0, 0
for exp_path in sorted(vdir.glob("*.expected.json")):
    name = exp_path.name[: -len(".expected.json")]
    pack_path = vdir / f"{name}.json"
    exp = json.loads(exp_path.read_text(encoding="utf-8"))
    req = exp.get("requires") or []
    if any(shutil.which(tool) is None for tool in req):
        rows.append({"vector": name, "status": "SKIP", "requires": req})
        skipped += 1
        continue
    got = verify_pack(pack_path, exp.get("policy") or {})
    diffs = {}
    for k in NORMATIVE:
        if got.get(k) != exp["normative"].get(k):
            diffs[k] = {"expected": exp["normative"].get(k), "got": got.get(k)}
    rep = exp.get("report") or {}
    if "ignored" in rep:
        got_ign = [a["ignored"] for a in got.get("artifacts", [])]
        if got_ign != rep["ignored"]:
            diffs["report.ignored"] = {"expected": rep["ignored"], "got": got_ign}
    if "refused" in rep:
        if got.get("refused") != rep["refused"]:
            diffs["report.refused"] = {"expected": rep["refused"], "got": got.get("refused")}
    ok = not diffs
    agree += ok
    rows.append({"vector": name, "status": "AGREE" if ok else "DISAGREE", "input_sha256": hashlib.sha256(pack_path.read_bytes()).hexdigest(),
                 "diffs": diffs, "refused": got.get("refused"), "artifact_errors": [a["error"] for a in got.get("artifacts", []) if a.get("error")]})
report = {"n": len(rows), "agree": agree, "skip": skipped, "rows": rows}
out_path.write_text(json.dumps(report, indent=1, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
print(f"{agree}/{len(rows)} agree, {skipped} skip")
for r in rows:
    if r["status"] != "AGREE":
        print(" ", r["vector"], r["status"], json.dumps(r.get("diffs"), ensure_ascii=False)[:400], "| errors:", r.get("artifact_errors"), "| refused:", r.get("refused"))
sys.exit(0 if agree == len(rows) else 1)
