#!/usr/bin/env python3
"""Clean-room model of the APS conformance suite's lease-revocation-axes family, revision 2 (candidate).

Written 2026-10-24 from fixtures/lease-revocation-axes/README.md and ORACLE.md of
Agent-Authority-Conformance/aps-conformance-suite PR #180 at b745d25, and the input shape of revision-2/vectors.json.
Not opened: harness.ts, verify.ts, generate.py, sdk-bridge.mjs, mutation.test.mjs, the records/ and revision-2 model
records. Answer-exposed: each call's `expected` block was on screen while the input shape was read.

Readings (each a choice the text leaves to the reader, fixed before the first scored run):
 R1 evidence for a call: the one named by `evidence_id`, else the evidence whose grant is the call's grant.
 R2 binding: matched iff that evidence names the requested grant.
 R3 freshness: exclusive expires at T >= expires_at; inclusive at T > expires_at. Nothing renews it.
 R4 cached_lease: no source read; the observation is the original active one (as_of = retrieved_at = issued_at)
    while the evidence is unexpired and bound; otherwise there is no observation (default path makes no diagnostic).
 R5 live_standing_read: one atomic source read at T for every unexpired, correctly bound call; if the source is
    unavailable the read returns nothing. Expired or mismatched calls make no read (default path, no diagnostic).
 R6 authority answer: from the observation — active -> valid, revoked -> revoked, none -> not_established.
 R7 current validity: the answer if the observation is current (age 0 at T: as_of == T), else not_established.
 R8 verification accepted (composite): bound and fresh and the authority answer is valid.
 R9 P1-current-observation: permit iff accepted, the observation is current (age 0) and active, and the operation is
    in the evidence's allowed operations; otherwise deny. downstream reached iff permit.
 R10 observation differs from truth: an observation exists and its status differs from the ledger truth at T.
"""
from __future__ import annotations

MODES = ("cached_lease", "live_standing_read")
ENDPOINTS = ("exclusive", "inclusive")


def _expired(t: int, expires: int, endpoint: str) -> bool:
    return t >= expires if endpoint == "exclusive" else t > expires


def run_case(profile: dict, case: dict, mode: str, endpoint: str) -> dict[str, dict]:
    evidence = {e["id"]: e for e in profile["initial_evidence"]}
    by_grant = {e["grant"]: e for e in profile["initial_evidence"]}
    revoked: set[str] = set()
    available = True
    out: dict[str, dict] = {}
    for ev in sorted(case["timeline"], key=lambda e: e["at_ms"]) if False else case["timeline"]:
        kind = ev["event"]
        if kind == "revoke":
            revoked.add(ev["grant"])
            continue
        if kind == "availability":
            available = bool(ev["available"])
            continue
        if kind != "call":
            raise ValueError(f"unknown event {kind}")
        t = ev["at_ms"]
        grant = ev["grant"]
        evd = evidence[ev["evidence_id"]] if "evidence_id" in ev else by_grant[grant]
        bound = evd["grant"] == grant                                   # R2
        fresh = not _expired(t, evd["expires_at_ms"], endpoint)        # R3
        observation = None
        if bound and fresh:
            if mode == "cached_lease":                                  # R4
                observation = {"status": evd["status"], "as_of_ms": evd["issued_at_ms"],
                               "retrieved_at_ms": evd["issued_at_ms"]}
            elif available:                                             # R5
                st = "revoked" if grant in revoked else "active"
                observation = {"status": st, "as_of_ms": t, "retrieved_at_ms": t}
        answer = "not_established" if observation is None else (
            "valid" if observation["status"] == "active" else "revoked")  # R6
        current = observation is not None and observation["as_of_ms"] == t
        validity = answer if current else "not_established"             # R7
        accepted = bound and fresh and answer == "valid"               # R8
        permit = (accepted and current and observation["status"] == "active"
                  and ev["operation"] in evd["allowed_operations"])     # R9
        truth = "revoked" if grant in revoked else "active"
        out[ev["id"]] = {
            "evidence_binding": "matched" if bound else "mismatch",
            "evidence_freshness": "fresh" if fresh else "expired",
            "observation": observation,
            "authority_answer": answer,
            "current_validity": validity,
            "verification_accepted": accepted,
            "action_decision": "permit" if permit else "deny",
            "downstream_reached": permit,
            "observation_differs_from_truth": observation is not None and observation["status"] != truth,  # R10
            "_truth_model": truth,
        }
    return out
