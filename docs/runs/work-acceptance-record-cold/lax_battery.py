#!/usr/bin/env python3
"""Mutation battery: which README checks do the eleven vectors actually exercise?

Each mutation removes or weakens one check in war_cold_verifier.py by editing its source text,
loads the mutated module, and runs all vectors against `expected`. A mutation that still scores
11/11 marks a check no vector pins.

Usage: python3 -I lax_battery.py <repo clone> <out.json> [extra vectors dir ...]
"""
from __future__ import annotations

import json
import sys
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = (HERE / "war_cold_verifier.py").read_text(encoding="utf-8")

MUTATIONS = [
    ("M01 skip signature verification", "sig_ok = False\n    if key is not None", "sig_ok = True\n    if False and key is not None"),
    ("M02 drop CHECKER_NOT_SIGNER", 'problems.add("CHECKER_NOT_SIGNER")', "pass"),
    ("M03 drop PRODUCER_UNDECLARED", 'warnings.add("PRODUCER_UNDECLARED")', "pass"),
    ("M04 drop KEY_COLLISION", 'problems.add("KEY_COLLISION")', "pass"),
    ("M05 drop INDEPENDENCE_INCONSISTENT", 'problems.add("INDEPENDENCE_INCONSISTENT")', "pass"),
    ("M06 drop SELF_CHECKED warning", 'warnings.add("SELF_CHECKED")', "pass"),
    ("M07 drop criteria hash check", 'if hashlib.sha256(cbytes).hexdigest() == criteria.get("sha256"):', "if True:"),
    ("M08 drop CRITERIA_RESULTS_MISMATCH", 'problems.add("CRITERIA_RESULTS_MISMATCH")', "pass"),
    ("M09 drop receipt token imprint check", 'if rt["imprint_alg_oid"] == SHA256_OID_HEX and rt["imprint_hex"] == canonical_sha:', "if True:"),
    ("M10 use a mismatching receipt token's time anyway", 'out["receipt_timestamp"] = "imprint_mismatch"  # never used as evidence of time', 'out["receipt_timestamp"] = "imprint_mismatch"; receipt_time = gen_time_to_dt(rt["gen_time"])'),
    ("M11 drop criteria token imprint check", 'if ct["imprint_alg_oid"] == SHA256_OID_HEX and ct["imprint_hex"] == criteria.get("sha256"):', "if True:"),
    ("M12 drop CRITERIA_TIME_MISMATCH", 'problems.add("CRITERIA_TIME_MISMATCH")', "pass"),
    ("M13 drop CRITERIA_COMMITMENT_UNVERIFIED", 'warnings.add("CRITERIA_COMMITMENT_UNVERIFIED")', "pass"),
    ("M14 committed-before uses <= instead of <", "if commitment_time is not None and commitment_time < reference:", "if commitment_time is not None and commitment_time <= reference:"),
    ("M15 commitment compares committed_at, ignores token time", "commitment_time = gen_time_to_dt(ct[\"gen_time\"])", "commitment_time = committed_at"),
    ("M16 drop RESULT_VOCABULARY", 'problems.add("RESULT_VOCABULARY")', "pass"),
    ("M17 drop VERDICT_MISMATCH", 'problems.add("VERDICT_MISMATCH")', "pass"),
    ("M18 required fail no longer wins", "if any(r.get(\"result\") == \"fail\" for r in required):\n        return \"fail\", vocab_ok", "if False:\n        return \"fail\", vocab_ok"),
    ("M19 treat every criterion as required", 'required = [r for r in results if r.get("required") is True]', "required = list(results)"),
    ("M20 drop schema/suite refusal", 'return {"refused": "unknown schema, canonicalization or suite"}', "pass"),
    ("M21 sign over non-canonical JSON (indent)", "canonical = jcs(receipt)", 'canonical = json.dumps(receipt, sort_keys=True, indent=1).encode()'),
    ("M22 ignore imprint algorithm OID", 'rt["imprint_alg_oid"] == SHA256_OID_HEX and ', ""),
]

KEYS = ("signature_valid", "independence", "criteria_hash", "criteria_committed_before_check", "receipt_timestamp", "verdict_recomputed", "verdict_stated")
SET_KEYS = ("problem_codes", "warning_codes")


def load(src: str):
    mod = types.ModuleType("mutant")
    exec(compile(src, "<mutant>", "exec"), mod.__dict__)
    return mod


def score(mod, repo: Path, extra=()):
    agree, n = 0, 0
    paths = sorted((repo / "vectors").glob("*.json")) + [q for d in extra for q in sorted(Path(d).glob("*.json"))]
    for path in paths:
        vec = json.loads(path.read_text(encoding="utf-8"))
        n += 1
        try:
            got = mod.verify(vec)
        except Exception:  # noqa: BLE001 — a crash is a disagreement
            continue
        exp = vec["expected"]
        if exp.get("refused"):
            agree += bool(got.get("refused")); continue
        ok = all(got.get(k) == exp.get(k) for k in KEYS if k in exp) and all(
            set(got.get(k, [])) == set(exp.get(k, [])) for k in SET_KEYS
        )
        agree += ok
    return agree, n


def main() -> int:
    repo, out = Path(sys.argv[1]), Path(sys.argv[2])
    extra = sys.argv[3:]
    base = score(load(SRC), repo, extra)
    rows = []
    for name, old, new in MUTATIONS:
        if old not in SRC:
            rows.append({"mutation": name, "applied": False})
            continue
        agree, n = score(load(SRC.replace(old, new, 1)), repo, extra)
        rows.append({"mutation": name, "applied": True, "agree": agree, "n": n, "caught": agree < n})
    survivors = [r["mutation"] for r in rows if r.get("applied") and not r["caught"]]
    doc = {"baseline": {"agree": base[0], "n": base[1]}, "mutations": rows, "survivors": survivors}
    out.write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
    print(f"baseline {base[0]}/{base[1]}; mutations {len(rows)}; survivors {len(survivors)}")
    for r in rows:
        print(("  survived " if r.get("applied") and not r["caught"] else ("  caught   " if r.get("applied") else "  n/a      ")) + r["mutation"] + (f" ({r['agree']}/{r['n']})" if r.get("applied") else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
