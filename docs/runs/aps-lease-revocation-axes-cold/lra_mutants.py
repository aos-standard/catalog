#!/usr/bin/env python3
"""Re-derive the twelve declared defective variants of lease-revocation-axes revision 2 in this catalog's own model, and
compare the cases each one fails with the family's declared `expected_failed_cases`.

Each mutant is written from its name and the README's one-line description only (not from the family's harness).
The model has no source-read audit, so a mutant that returns the right values without the right reads cannot fail
here; such mutants are reported as `audit_only` rather than as agreement or disagreement.

Usage: python3 -I lra_mutants.py <vectors.json> <out.json>
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_lra import FIELDS  # noqa: E402

# Per the README: the read audit catches these; their values can be right.
AUDIT_ONLY = {"fabricated-live-read", "selective-not-supported"}


def run_case_mut(profile, case, mode, endpoint, mut):
    evidence = {e["id"]: e for e in profile["initial_evidence"]}
    by_grant = {e["grant"]: e for e in profile["initial_evidence"]}
    revoked, available, sticky_down = set(), True, False
    expires_override: dict[str, int] = {}
    first_obs: dict[tuple, dict] = {}
    out = {}
    for ev in case["timeline"]:
        if ev["event"] == "revoke":
            revoked.add(ev["grant"]); continue
        if ev["event"] == "availability":
            available = bool(ev["available"])
            if not available:
                sticky_down = True
            continue
        t, grant = ev["at_ms"], ev["grant"]
        evd = evidence[ev["evidence_id"]] if "evidence_id" in ev else by_grant[grant]
        bound = evd["grant"] == grant or mut == "ignore-evidence-binding"
        exp_at = expires_override.get(evd["id"], evd["expires_at_ms"])
        expired = (t >= exp_at) if endpoint == "exclusive" else (t > exp_at)
        if mut == "lease-ignores-expiry":
            expired = False
        fresh = not expired
        src_up = available and not (mut == "sticky-unavailable" and sticky_down)
        obs = None
        if bound and fresh:
            if mode == "cached_lease":
                obs = {"status": evd["status"], "as_of_ms": evd["issued_at_ms"], "retrieved_at_ms": evd["issued_at_ms"]}
                if mut == "sliding-lease":
                    expires_override[evd["id"]] = t + profile["lease_ms"]
            else:
                key = (ev["worker"], grant)
                if mut == "live-first-read-only" and key in first_obs:
                    obs = first_obs[key]
                elif mut == "second-worker-stale" and ev["worker"] == "w2" and key in first_obs:
                    obs = first_obs[key]
                elif src_up:
                    obs = {"status": "revoked" if grant in revoked else "active", "as_of_ms": t, "retrieved_at_ms": t}
                elif mut == "live-fail-open":
                    obs = {"status": "active", "as_of_ms": t, "retrieved_at_ms": t}
                if obs is not None and key not in first_obs:
                    first_obs[key] = obs
                if obs is not None and mut == "retrieval-renews-evidence":
                    expires_override[evd["id"]] = t + profile["lease_ms"]
        answer = "not_established" if obs is None else ("valid" if obs["status"] == "active" else "revoked")
        current = obs is not None and obs["as_of_ms"] == t
        validity = answer if current else "not_established"
        accepted = bound and fresh and answer == "valid"
        permit = accepted and current and obs["status"] == "active" and ev["operation"] in evd["allowed_operations"]
        if mut == "deny-everything":
            permit = False
        reached = permit or mut == "deny-but-dispatch"
        truth = "revoked" if grant in revoked else "active"
        out[ev["id"]] = {"evidence_binding": "matched" if (evd["grant"] == grant or mut == "ignore-evidence-binding") else "mismatch",
                         "evidence_freshness": "fresh" if fresh else "expired", "observation": obs,
                         "authority_answer": answer, "current_validity": validity, "verification_accepted": accepted,
                         "action_decision": "permit" if permit else "deny", "downstream_reached": reached,
                         "observation_differs_from_truth": obs is not None and obs["status"] != truth}
    return out


def main() -> int:
    d = json.loads(Path(sys.argv[1]).read_text())
    rows = []
    for name, m in d["mutants"].items():
        failed = []
        for case in d["cases"]:
            got = run_case_mut(d["profile"], case, m["mode"], m["boundary"], name)
            for e in case["timeline"]:
                if e["event"] != "call":
                    continue
                exp = e["expected"]["by_mode"][m["mode"]][m["boundary"]]
                if any(exp.get(f) != got[e["id"]].get(f) for f in FIELDS):
                    failed.append(case["id"]); break
        declared = sorted(m["expected_failed_cases"])
        status = "audit_only" if (name in AUDIT_ONLY and not failed) else ("match" if sorted(failed) == declared else "differ")
        rows.append({"mutant": name, "mode": m["mode"], "boundary": m["boundary"], "declared": declared,
                     "this_model": sorted(failed), "status": status,
                     "only_declared": sorted(set(declared) - set(failed)), "only_here": sorted(set(failed) - set(declared))})
    Path(sys.argv[2]).write_text(json.dumps({"rows": rows}, indent=1) + "\n")
    for r in rows:
        print(f"{r['status']:10} {r['mutant']:28} declared={len(r['declared'])} here={len(r['this_model'])} "
              f"only_declared={r['only_declared']} only_here={r['only_here']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
