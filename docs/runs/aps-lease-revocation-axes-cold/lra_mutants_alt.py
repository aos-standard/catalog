#!/usr/bin/env python3
"""Second reading of four mutants, written AFTER lra_mutants.py's first run showed them differing (post-hoc; not a
blind result). Each change is one alternative reading of the README's one-line description:
 sliding-lease              the use renews the lease before freshness is judged (expires := T + lease_ms)
 retrieval-renews-evidence  a bound call reads whenever the source is up, the read renews, then freshness is judged
 sticky-unavailable         after the first outage the worker never re-reads and keeps its last observation
 live-first-read-only       the first attempt per worker and grant, even a failed one, is the only read
Usage: python3 -I lra_mutants_alt.py <vectors.json> <out.json>
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_lra import FIELDS  # noqa: E402

ALT = ("sliding-lease", "retrieval-renews-evidence", "sticky-unavailable", "live-first-read-only")
_UNSET = object()


def run_case_alt(profile, case, mode, endpoint, mut):
    evidence = {e["id"]: e for e in profile["initial_evidence"]}
    by_grant = {e["grant"]: e for e in profile["initial_evidence"]}
    revoked, available, sticky_down = set(), True, False
    expires: dict[str, int] = {e["id"]: e["expires_at_ms"] for e in profile["initial_evidence"]}
    last: dict[tuple, object] = {}
    out = {}
    for ev in case["timeline"]:
        if ev["event"] == "revoke":
            revoked.add(ev["grant"]); continue
        if ev["event"] == "availability":
            available = bool(ev["available"]); sticky_down = sticky_down or not available; continue
        t, grant = ev["at_ms"], ev["grant"]
        evd = evidence[ev["evidence_id"]] if "evidence_id" in ev else by_grant[grant]
        bound = evd["grant"] == grant
        key = (ev["worker"], grant)
        if mut == "sliding-lease":
            expires[evd["id"]] = t + profile["lease_ms"]
        live = lambda: {"status": "revoked" if grant in revoked else "active", "as_of_ms": t, "retrieved_at_ms": t}
        obs, pre_read = None, False
        if mut == "retrieval-renews-evidence" and mode != "cached_lease" and bound and available:
            obs, pre_read = live(), True
            expires[evd["id"]] = t + profile["lease_ms"]
        exp_at = expires[evd["id"]]
        fresh = not ((t >= exp_at) if endpoint == "exclusive" else (t > exp_at))
        if bound and fresh and not pre_read:
            if mode == "cached_lease":
                obs = {"status": evd["status"], "as_of_ms": evd["issued_at_ms"], "retrieved_at_ms": evd["issued_at_ms"]}
            elif mut == "sticky-unavailable" and sticky_down:
                obs = last.get(key)
            elif mut == "live-first-read-only" and last.get(key, _UNSET) is not _UNSET:
                obs = last[key]
            else:
                obs = live() if available else None
                if mut == "live-first-read-only":
                    last.setdefault(key, obs)
            if mut == "sticky-unavailable" and obs is not None:
                last[key] = obs
        if not (bound and fresh):
            obs = None if not pre_read else obs
        answer = "not_established" if obs is None else ("valid" if obs["status"] == "active" else "revoked")
        current = obs is not None and obs["as_of_ms"] == t
        accepted = bound and fresh and answer == "valid"
        permit = accepted and current and obs["status"] == "active" and ev["operation"] in evd["allowed_operations"]
        truth = "revoked" if grant in revoked else "active"
        out[ev["id"]] = {"evidence_binding": "matched" if bound else "mismatch",
                         "evidence_freshness": "fresh" if fresh else "expired", "observation": obs,
                         "authority_answer": answer, "current_validity": answer if current else "not_established",
                         "verification_accepted": accepted, "action_decision": "permit" if permit else "deny",
                         "downstream_reached": permit,
                         "observation_differs_from_truth": obs is not None and obs["status"] != truth}
    return out


def main() -> int:
    d = json.loads(Path(sys.argv[1]).read_text())
    rows = []
    for name in ALT:
        m = d["mutants"][name]
        failed = []
        for case in d["cases"]:
            got = run_case_alt(d["profile"], case, m["mode"], m["boundary"], name)
            for e in case["timeline"]:
                if e["event"] == "call" and any(e["expected"]["by_mode"][m["mode"]][m["boundary"]].get(f) != got[e["id"]].get(f) for f in FIELDS):
                    failed.append(case["id"]); break
        declared = sorted(m["expected_failed_cases"])
        rows.append({"mutant": name, "declared": declared, "this_reading": sorted(failed),
                     "status": "match" if sorted(failed) == declared else "differ"})
        print(f"{rows[-1]['status']:6} {name:28} declared={declared} here={sorted(failed)}")
    Path(sys.argv[2]).write_text(json.dumps({"post_hoc": True, "rows": rows}, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
