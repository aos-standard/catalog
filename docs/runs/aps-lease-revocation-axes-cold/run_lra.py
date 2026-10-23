#!/usr/bin/env python3
"""Score lra_cold_model.py against revision-2/vectors.json (every call, both modes, both endpoints, every field).

Usage: python3 -I run_lra.py <vectors.json> <out.json>
Also checks that the model's ledger truth equals each call's `truth` input (an input-consistency check, not a score).
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lra_cold_model import ENDPOINTS, MODES, run_case  # noqa: E402

FIELDS = ("evidence_binding", "evidence_freshness", "observation", "authority_answer", "current_validity",
          "verification_accepted", "action_decision", "downstream_reached", "observation_differs_from_truth")


def main() -> int:
    raw = Path(sys.argv[1]).read_bytes()
    d = json.loads(raw)
    rows, cmp_total, cmp_agree, truth_mismatch = [], 0, 0, []
    for case in d["cases"]:
        calls = {e["id"]: e for e in case["timeline"] if e["event"] == "call"}
        for mode in MODES:
            for ep in ENDPOINTS:
                got = run_case(d["profile"], case, mode, ep)
                for cid, call in calls.items():
                    exp = call["expected"]["by_mode"][mode][ep]
                    g = got[cid]
                    if g["_truth_model"] != call["truth"]:
                        truth_mismatch.append(cid)
                    diffs = {f: {"expected": exp.get(f), "got": g.get(f)} for f in FIELDS if exp.get(f) != g.get(f)}
                    extra = sorted(set(exp) - set(FIELDS))
                    cmp_total += len(FIELDS)
                    cmp_agree += len(FIELDS) - len(diffs)
                    rows.append({"case": case["id"], "call": cid, "mode": mode, "endpoint": ep,
                                 "agree": not diffs, "diffs": diffs, "unscored_expected_keys": extra})
    agree = sum(r["agree"] for r in rows)
    out = {"source_sha256": hashlib.sha256(raw).hexdigest(), "calls_x_profiles": len(rows), "agree": agree,
           "field_comparisons": cmp_total, "field_agree": cmp_agree, "truth_input_mismatch": sorted(set(truth_mismatch)),
           "rows": rows}
    Path(sys.argv[2]).write_text(json.dumps(out, indent=1, sort_keys=True) + "\n")
    print(f"{agree}/{len(rows)} call-profiles agree; fields {cmp_agree}/{cmp_total}; truth input mismatches {len(set(truth_mismatch))}")
    for r in rows:
        if not r["agree"]:
            print(" ", r["call"], r["mode"], r["endpoint"], json.dumps(r["diffs"])[:260])
    return 0 if agree == len(rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
