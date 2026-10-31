#!/usr/bin/env python3
"""Case set for the rerun at ddc2871: the 34 cases of ../089d8f9/ unchanged (same bytes), plus U3, the example pair
as published at ddc2871. Expectation for U3 written from the ddc2871 text before any scored run (FROZEN.txt).
Usage: python3 -I gen_cases_ddc2871.py <../089d8f9 case dir> <examples.dispute_resolution.json @ddc2871> <out_dir>"""
import hashlib, json, shutil, sys
from pathlib import Path
src = Path(sys.argv[1]); exf = sys.argv[2]; out = Path(sys.argv[3]); (out / "cases").mkdir(parents=True, exist_ok=True)
ex = json.load(open(exf, encoding="utf-8"))
meta = json.load(open(src / "cases.json", encoding="utf-8"))
for c in meta["cases"]:
    shutil.copyfile(src / "cases" / f"{c['id']}.json", out / "cases" / f"{c['id']}.json")
u3 = {"record": ex["dispute_record"], "determination": ex["dispute_determination"], "opened_at": ex["dispute_determination"]["opened_at"]}
(out / "cases" / "U3.json").write_text(json.dumps(u3, indent=1, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
meta["cases"].append({"id": "U3",
    "expect": {"eligible": True, "not_eligible": None,
               "per_line": [{"line_id": "line_item_123", "outcome": "overturn", "amount": 330, "rule": "3_canceled", "finding": None}],
               "det_ok": True, "det_problems": []},
    "spec_open": [],
    "note": "the ddc2871 example pair as published: line_item_123 now carries subtotal 330 (§7.5 eligible, no line_amount_missing); "
            "merchant canceled with no completed refund/credit/price_adjustment, which §7.4 rule 3 now states ('of a type counted in rule 1'): "
            "overturn 330, as dispute_determination says; opened_at 2026-11-12 in window; five factors present"})
meta["source_examples_sha256_ddc2871"] = hashlib.sha256(open(exf, "rb").read()).hexdigest()
(out / "cases.json").write_text(json.dumps(meta, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
print(len(meta["cases"]), "cases")
