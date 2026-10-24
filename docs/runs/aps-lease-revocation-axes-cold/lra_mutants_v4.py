#!/usr/bin/env python3
"""Third reading of the declared defective variants: each written from its one-sentence rule in the family README at
bccef3e (README sha256 5d799f91…1ad8), not from harness.ts. fabricated-live-read is left out: its rule says the
answers are hardcoded from the call id, grant and time without giving them, so it cannot be written from the text.
Usage: python3 -I lra_mutants_v3.py <vectors.json> <out.json>
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_lra import FIELDS  # noqa: E402

NONE = object()


def run_case_v3(profile, case, mode, endpoint, mut):
    evidence = {e["id"]: e for e in profile["initial_evidence"]}
    by_grant = {e["grant"]: e for e in profile["initial_evidence"]}
    revoked, available = set(), True
    last_call_at: dict[tuple, int] = {}      # (worker, evidence id) -> previous call time, for sliding-lease
    no_answer_seen: set[str] = set()         # workers whose source read got no answer, for sticky-unavailable
    first_result: dict[tuple, object] = {}   # (worker, grant) -> first source result, for first-read reuse
    out = {}
    for ev in case["timeline"]:
        if ev["event"] == "revoke":
            revoked.add(ev["grant"]); continue
        if ev["event"] == "availability":
            available = bool(ev["available"]); continue
        t, grant, w = ev["at_ms"], ev["grant"], ev["worker"]
        reads = [0]
        evd = evidence[ev["evidence_id"]] if "evidence_id" in ev else by_grant[grant]
        lease = evd["expires_at_ms"] - evd["issued_at_ms"]
        matched = evd["grant"] == grant or mut == "ignore-evidence-binding"

        def read():
            reads[0] += 1
            return {"status": "revoked" if grant in revoked else "active", "as_of_ms": t, "retrieved_at_ms": t} if available else None

        expires = evd["expires_at_ms"]
        if mut == "sliding-lease" and (w, evd["id"]) in last_call_at:
            expires = last_call_at[(w, evd["id"])] + lease
        if mut == "sliding-lease":
            last_call_at[(w, evd["id"])] = t
        fresh = not ((t >= expires) if endpoint == "exclusive" else (t > expires))
        fresh_orig = not ((t >= evd["expires_at_ms"]) if endpoint == "exclusive" else (t > evd["expires_at_ms"]))
        live = mode == "live_standing_read"
        if mut == "lease-ignores-expiry":
            fresh = True
        obs = None
        live = mode == "live_standing_read"
        if live and mut == "retrieval-renews-evidence" and matched:
            obs = read()
            if obs is not None:
                fresh = t < obs["retrieved_at_ms"] + lease
            if not fresh:
                obs = None
        elif matched and fresh:
            if not live:
                obs = {"status": evd["status"], "as_of_ms": evd["issued_at_ms"], "retrieved_at_ms": evd["issued_at_ms"]}
            elif mut == "sticky-unavailable" and w in no_answer_seen:
                obs = None
            elif mut in ("live-first-read-only", "second-worker-stale") and (mut == "live-first-read-only" or w == "w2"):
                key = (w, grant)
                if key not in first_result:
                    first_result[key] = read()
                obs = first_result[key]
            else:
                obs = read()
                if obs is None and mut == "sticky-unavailable":
                    no_answer_seen.add(w)
                if obs is None and mut == "live-fail-open":
                    obs = {"status": "active", "as_of_ms": t, "retrieved_at_ms": t}
        answer = "not_established" if obs is None else ("valid" if obs["status"] == "active" else "revoked")
        current = obs is not None and obs["as_of_ms"] == t
        accepted = matched and fresh and answer == "valid"
        permit = accepted and current and obs["status"] == "active" and ev["operation"] in evd["allowed_operations"]
        if mut == "deny-everything":
            permit = False
        decision = "permit" if permit else ("not_supported" if mut == "selective-not-supported" else "deny")
        truth = "revoked" if grant in revoked else "active"
        must_read = live and matched and fresh_orig
        rc_fail = must_read and reads[0] != 1
        out[ev["id"]] = {"_rc_fail": rc_fail, "_must_read": must_read,"evidence_binding": "matched" if matched else "mismatch",
                         "evidence_freshness": "fresh" if fresh else "expired", "observation": obs,
                         "authority_answer": answer, "current_validity": answer if current else "not_established",
                         "verification_accepted": accepted, "action_decision": decision,
                         "downstream_reached": permit or mut == "deny-but-dispatch",
                         "observation_differs_from_truth": obs is not None and obs["status"] != truth}
    return out


def main() -> int:
    d = json.loads(Path(sys.argv[1]).read_text())
    rows = []
    for name, m in d["mutants"].items():
        failed = []; ans_failed=set(); rc_failed=set()
        for case in d["cases"]:
            got = run_case_v3(d["profile"], case, m["mode"], m["boundary"], None if name == "fabricated-live-read" else name)
            if name == "fabricated-live-read":  # answers as expected (README 86e5e7a), zero reads on fresh matched live calls
                for k in got:
                    if got[k]["_must_read"]: got[k]["_rc_fail"] = True
            for e in case["timeline"]:
                if e["event"] == "call" and any(e["expected"]["by_mode"][m["mode"]][m["boundary"]].get(f) != got[e["id"]].get(f) for f in FIELDS):
                    ans_failed.add(case["id"])
                if e["event"] == "call" and got[e["id"]]["_rc_fail"]:
                    rc_failed.add(case["id"])
            if case["id"] in ans_failed | rc_failed:
                failed.append(case["id"])
        declared = sorted(m["expected_failed_cases"])
        st = "match" if sorted(failed) == declared else "differ"
        rows.append({"mutant": name, "declared": declared, "this_reading": sorted(failed), "status": st,
                     "only_declared": sorted(set(declared) - set(failed)), "only_here": sorted(set(failed) - set(declared))})
        rows[-1]["answers_only"]=sorted(ans_failed); rows[-1]["read_check_only"]=sorted(rc_failed-ans_failed)
        print(f"{st:6} {name:28} only_declared={rows[-1]['only_declared']} only_here={rows[-1]['only_here']} read_check_only={rows[-1]['read_check_only']}")
    Path(sys.argv[2]).write_text(json.dumps({"readme": "86e5e7a", "rows": rows}, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
