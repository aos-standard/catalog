#!/usr/bin/env python3
"""Clean-room reader for darklordVirtual/autonomous-ot-control federation fixtures (effect_evidence boundary).

Written from docs/federation/README.md ("Claims", "Digest rules", "The fixtures"),
contracts/federation-case-v1.schema.json and contracts/edge-result-v1.schema.json at 3b7b7e8,
and the case files themselves. federation/edges/_template/adapter.py and runner/ were not fetched.
Standard library only. CC0.

Usage: otc_effect_evidence_cold.py run --fixtures <dir> --out <result.json>
  <dir> holds manifest.json and cases/. The manifest seal (per-file sha256, package digest) is
  checked first; a broken seal stops the run (exit 2) and writes nothing.

Per case, six claims are read; the case verdict is CONTRADICTED if any claim is contradicted,
else NOT_ESTABLISHED if any claim could not be established, else ESTABLISHED. claim_id names the
first claim in the order below that is not established; reason says why.

  decision_correspondence  executed=true requires decision.approved=true and the decision to be
                           "accept", or "verify"/"escalate" with reviewer.approved=true; the
                           envelope's request_id and the evidence's proposal_id must be the claim's
                           proposal_id (bound to the proposal). executed=false together with a twin
                           record of status APPLIED or a non-null observation is a trail that
                           disagrees with itself: CONTRADICTED (schema, "execution").
  single_dispatch          execution.executions must be present (int); 1 establishes, any other
                           value contradicts, absent is NOT_ESTABLISHED (never assumed to be 1).
  call_binding             twin_operation.operation_id must equal the claim's proposal_id; null twin
                           record is NOT_ESTABLISHED; a different id contradicts.
  declared_effect_observed twin_operation.status must be APPLIED for the claim's zone_id with
                           new_setpoint_c equal to the claim's setpoint_c, and
                           observation.observed_setpoint_c must equal it; a null observation or an
                           absent observed_setpoint_c is NOT_ESTABLISHED; a different value, zone or
                           status contradicts.
  observation_after_dispatch execution.dispatched_at_sim_s (absent or null -> NOT_ESTABLISHED) and
                           observation.observed_at_sim_s (absent -> NOT_ESTABLISHED, never assumed
                           equal to the dispatch time); observed < dispatched contradicts.
  evidence_digest_integrity evidence_sha256 must equal sha256 over the UTF-8 bytes of
                           json.dumps(remora_evidence, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False); a digest that is not 64 lowercase hex is
                           NOT_ESTABLISHED, a different digest contradicts.

A case whose shape is not the schema's (wrong types, missing required members) is answered
NOT_ESTABLISHED with reason "malformed", never ESTABLISHED, and never raises.
"""
import argparse, hashlib, json, os, re, sys

CLAIMS = ["decision_correspondence", "single_dispatch", "call_binding",
          "declared_effect_observed", "observation_after_dispatch", "evidence_digest_integrity"]
HEX64 = re.compile(r"^[0-9a-f]{64}$")
APPROVED_DECISIONS = {"accept", "verify", "escalate"}
NEEDS_REVIEWER = {"verify", "escalate"}


def canonical_sha256(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False).encode("utf-8")).hexdigest()


def check_seal(fixtures):
    """Per-file sha256 and the package digest, as the README's 'The fixtures' states them."""
    raw = open(os.path.join(fixtures, "manifest.json"), "rb").read()
    manifest = json.loads(raw)
    files = manifest["files"]
    bad = []
    for f in files:
        p = os.path.join(fixtures, f["path"])
        h = hashlib.sha256(open(p, "rb").read()).hexdigest() if os.path.isfile(p) else None
        if h != f["sha256"]:
            bad.append(f["path"])
    lines = "".join(f"{f['path']} {f['sha256']}\n" for f in sorted(files, key=lambda x: x["path"]))
    pkg = "sha256:" + hashlib.sha256(lines.encode("utf-8")).hexdigest()
    return manifest, hashlib.sha256(raw).hexdigest(), bad, pkg == manifest.get("package_digest")


def is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def is_num(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def shape_ok(c):
    if not isinstance(c, dict) or c.get("schema") != "ot-federation-case/v1":
        return False
    for k in ("case_id", "kind", "claim", "decision", "execution", "twin_operation",
              "observation", "remora_evidence", "evidence_sha256"):
        if k not in c:
            return False
    cl, d, e = c["claim"], c["decision"], c["execution"]
    if not (isinstance(cl, dict) and isinstance(d, dict) and isinstance(e, dict)):
        return False
    if not all(k in cl for k in ("proposal_id", "tool", "zone_id", "setpoint_c", "claimed_effect")):
        return False
    if not (isinstance(cl["proposal_id"], str) and isinstance(cl["zone_id"], str) and is_num(cl["setpoint_c"])):
        return False
    if not (isinstance(d.get("decision"), str) and isinstance(d.get("approved"), bool)):
        return False
    if d.get("reviewer") is not None and not isinstance(d["reviewer"], dict):
        return False
    if not isinstance(e.get("executed"), bool):
        return False
    if "dispatched_at_sim_s" in e and e["dispatched_at_sim_s"] is not None and not is_int(e["dispatched_at_sim_s"]):
        return False
    if "executions" in e and not is_int(e["executions"]):
        return False
    if c["twin_operation"] is not None and not isinstance(c["twin_operation"], dict):
        return False
    if c["observation"] is not None and not isinstance(c["observation"], dict):
        return False
    if not isinstance(c["evidence_sha256"], str):
        return False
    return True


def read_claims(c):
    """Return {claim_id: (status, detail)} with status in ESTABLISHED/CONTRADICTED/NOT_ESTABLISHED."""
    out = {}
    cl, d, e = c["claim"], c["decision"], c["execution"]
    pid = cl["proposal_id"]
    twin = c["twin_operation"]
    obs = c["observation"]
    twin_applied = isinstance(twin, dict) and twin.get("status") == "APPLIED"

    # decision_correspondence
    if e["executed"]:
        dec = d["decision"]
        rev = d.get("reviewer")
        if not d["approved"]:
            out[CLAIMS[0]] = ("CONTRADICTED", "executed but decision.approved is false")
        elif dec not in APPROVED_DECISIONS:
            out[CLAIMS[0]] = ("CONTRADICTED", f"executed on decision {dec!r}, not an ACCEPT or an approved VERIFY/ESCALATE")
        elif dec in NEEDS_REVIEWER and not (isinstance(rev, dict) and rev.get("approved") is True):
            out[CLAIMS[0]] = ("CONTRADICTED", f"executed on {dec} without an approving reviewer")
        else:
            env_rid = (c.get("remora_envelope") or {}).get("request", {}) if isinstance(c.get("remora_envelope"), dict) else {}
            env_rid = env_rid.get("request_id") if isinstance(env_rid, dict) else None
            ev = c["remora_evidence"]
            ev_pid = ev.get("proposal", {}).get("proposal_id") if isinstance(ev, dict) and isinstance(ev.get("proposal"), dict) else None
            if env_rid is not None and env_rid != pid:
                out[CLAIMS[0]] = ("CONTRADICTED", "envelope request_id is not the proposal")
            elif ev_pid is not None and ev_pid != pid:
                out[CLAIMS[0]] = ("CONTRADICTED", "evidence proposal_id is not the proposal")
            elif env_rid is None and ev_pid is None:
                out[CLAIMS[0]] = ("NOT_ESTABLISHED", "neither envelope nor evidence names the proposal")
            else:
                out[CLAIMS[0]] = ("ESTABLISHED", "approved decision bound to the proposal")
    else:
        if twin_applied or obs is not None:
            out[CLAIMS[0]] = ("CONTRADICTED", "executed is false but the twin recorded APPLIED or an effect was observed")
        else:
            out[CLAIMS[0]] = ("NOT_ESTABLISHED", "nothing executed; no dispatch to attest")

    # single_dispatch
    if "executions" not in e:
        out[CLAIMS[1]] = ("NOT_ESTABLISHED", "execution.executions absent")
    elif e["executions"] == 1:
        out[CLAIMS[1]] = ("ESTABLISHED", "executions = 1")
    else:
        out[CLAIMS[1]] = ("CONTRADICTED", f"executions = {e['executions']}")

    # call_binding
    if twin is None:
        out[CLAIMS[2]] = ("NOT_ESTABLISHED", "no twin operation record")
    elif twin.get("operation_id") != pid:
        out[CLAIMS[2]] = ("CONTRADICTED", "twin operation_id is another proposal")
    else:
        out[CLAIMS[2]] = ("ESTABLISHED", "twin operation_id = proposal_id")

    # declared_effect_observed
    if twin is None:
        out[CLAIMS[3]] = ("NOT_ESTABLISHED", "no twin operation record")
    elif not twin_applied:
        out[CLAIMS[3]] = ("CONTRADICTED", f"twin status {twin.get('status')!r}, not APPLIED")
    elif twin.get("zone_id") != cl["zone_id"]:
        out[CLAIMS[3]] = ("CONTRADICTED", "twin zone differs from the claimed zone")
    elif not (is_num(twin.get("new_setpoint_c")) and twin["new_setpoint_c"] == cl["setpoint_c"]):
        out[CLAIMS[3]] = ("CONTRADICTED", f"twin applied {twin.get('new_setpoint_c')!r}, claim says {cl['setpoint_c']!r}")
    elif obs is None:
        out[CLAIMS[3]] = ("NOT_ESTABLISHED", "effect not observed")
    elif "observed_setpoint_c" not in obs or not is_num(obs["observed_setpoint_c"]):
        out[CLAIMS[3]] = ("NOT_ESTABLISHED", "observation has no observed_setpoint_c")
    elif obs["observed_setpoint_c"] != cl["setpoint_c"]:
        out[CLAIMS[3]] = ("CONTRADICTED", f"observed {obs['observed_setpoint_c']!r}, claim says {cl['setpoint_c']!r}")
    else:
        out[CLAIMS[3]] = ("ESTABLISHED", "twin APPLIED and observation show the claimed value")

    # observation_after_dispatch
    disp = e.get("dispatched_at_sim_s")
    if disp is None:
        out[CLAIMS[4]] = ("NOT_ESTABLISHED", "dispatched_at_sim_s absent or null")
    elif obs is None or "observed_at_sim_s" not in obs or not is_int(obs["observed_at_sim_s"]):
        out[CLAIMS[4]] = ("NOT_ESTABLISHED", "observed_at_sim_s absent")
    elif obs["observed_at_sim_s"] < disp:
        out[CLAIMS[4]] = ("CONTRADICTED", f"observed at {obs['observed_at_sim_s']} before dispatch at {disp}")
    else:
        out[CLAIMS[4]] = ("ESTABLISHED", "observed at or after dispatch")

    # evidence_digest_integrity
    want = c["evidence_sha256"]
    if not HEX64.match(want):
        out[CLAIMS[5]] = ("NOT_ESTABLISHED", "evidence_sha256 is not a 64-hex digest")
    elif canonical_sha256(c["remora_evidence"]) != want:
        out[CLAIMS[5]] = ("CONTRADICTED", "evidence_sha256 is not the canonical SHA-256 of remora_evidence")
    else:
        out[CLAIMS[5]] = ("ESTABLISHED", "evidence digest matches")
    return out


def verdict_for(case):
    try:
        if not shape_ok(case):
            return {"verdict": "NOT_ESTABLISHED", "reason": "malformed: not an ot-federation-case/v1 of the schema's shape"}
        claims = read_claims(case)
        for status in ("CONTRADICTED", "NOT_ESTABLISHED"):
            for cid in CLAIMS:
                if claims[cid][0] == status:
                    return {"verdict": status, "reason": f"{cid}: {claims[cid][1]}", "claim_id": cid, "_claims": claims}
        return {"verdict": "ESTABLISHED", "reason": "all six claims established", "_claims": claims}
    except Exception as exc:  # a stranger's input must never crash the reader
        return {"verdict": "NOT_ESTABLISHED", "reason": f"malformed: reader could not read the case ({type(exc).__name__})"}


def run(fixtures, out_path, edge_id="aos-catalog-cold-reader", with_claims=False):
    manifest, fixtures_sha, bad, pkg_ok = check_seal(fixtures)
    if bad or not pkg_ok:
        sys.stderr.write(f"seal broken: {len(bad)} file(s) differ, package_digest_ok={pkg_ok}\n")
        return 2
    verdicts = []
    for f in sorted(manifest["files"], key=lambda x: x["path"]):
        p = os.path.join(fixtures, f["path"])
        try:
            case = json.load(open(p, encoding="utf-8"))
        except Exception as exc:
            case = None
        case_id = case.get("case_id") if isinstance(case, dict) and isinstance(case.get("case_id"), str) else os.path.splitext(os.path.basename(f["path"]))[0]
        v = verdict_for(case) if case is not None else {"verdict": "NOT_ESTABLISHED", "reason": "malformed: not JSON"}
        row = {"case_id": case_id, "verdict": v["verdict"], "reason": v["reason"]}
        if "claim_id" in v:
            row["claim_id"] = v["claim_id"]
        if with_claims and "_claims" in v:
            row["claims"] = {k: s for k, (s, _) in v["_claims"].items()}
        verdicts.append(row)
    result = {"schema": "ot-edge-result/v1", "edge_id": edge_id, "fixtures_sha256": fixtures_sha, "verdicts": verdicts}
    if os.path.exists(out_path):
        sys.stderr.write("refusing to overwrite an existing result\n")
        return 3
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--fixtures", required=True)
    r.add_argument("--out", required=True)
    r.add_argument("--edge-id", default="aos-catalog-cold-reader")
    r.add_argument("--with-claims", action="store_true", help="also list per-claim status (not part of edge-result-v1)")
    a = ap.parse_args(argv)
    return run(a.fixtures, a.out, a.edge_id, a.with_claims)


if __name__ == "__main__":
    sys.exit(main())
