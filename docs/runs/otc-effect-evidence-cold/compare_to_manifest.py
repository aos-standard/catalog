#!/usr/bin/env python3
"""Compare an edge-result-v1 file with the manifest's expectations (our own comparison; runner/edge_check.py was not fetched).
Positives expect ESTABLISHED; negatives expect manifest expected_verdict. Also reports whether claim_id matches the
manifest's claim_id for negatives (stricter than the README's scoring rule, which counts the verdict only)."""
import json, sys
m = json.load(open(sys.argv[1])); r = json.load(open(sys.argv[2]))
exp = {c["case_id"]: c for c in m["cases"]}
got = {v["case_id"]: v for v in r["verdicts"]}
pos = neg = pos_ok = neg_ok = claim_ok = 0; rows = []
for cid, c in exp.items():
    v = got.get(cid)
    want = "ESTABLISHED" if c["kind"] == "positive" else c["expected_verdict"]
    ok = v is not None and v["verdict"] == want
    if c["kind"] == "positive": pos += 1; pos_ok += ok
    else:
        neg += 1; neg_ok += ok
        if ok and v.get("claim_id") == c["claim_id"]: claim_ok += 1
    rows.append((cid, c["kind"], c.get("fault") or "-", want, v["verdict"] if v else "MISSING", v.get("claim_id","-") if v else "-", "ok" if ok else "DIFF"))
print(f"{'case':60} {'kind':8} {'fault':26} {'expected':16} {'got':16} {'claim_id':26} ")
for row in rows: print(f"{row[0][:60]:60} {row[1]:8} {row[2]:26} {row[3]:16} {row[4]:16} {row[5]:26} {row[6]}")
print(f"\npositives {pos_ok}/{pos} established; negatives {neg_ok}/{neg} caught; claim_id matches manifest on {claim_ok}/{neg} negatives")
print("unanswered:", [c for c in exp if c not in got]); print("extra:", [c for c in got if c not in exp])
sys.exit(0 if pos_ok == pos and neg_ok == neg else 1)
