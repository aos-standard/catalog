#!/usr/bin/env python3
"""Score ac_receipt_check.py on the four vector files of agent-custody (packages/receipts/vectors/ at bd57844).
Usage: python3 -I run_vectors.py <vectors_dir> <out.json>
receipts.json: compare the set of failing check names with expected.failing; also classify each case by whether every
expected name is one the page names (PAGE_NAMED) or one the vectors name only (VECTOR_NAMED)."""
import hashlib, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import ac_receipt_check as R  # noqa: E402

PAGE_NAMED = {"approval consistent with execution", "approval payload binding", "approval signatures (human keys)",
 "approval valid at forward time", "delegation binds principal and agent", "delegation signature (principal key)",
 "delegation valid at receipt time", "executed tool within delegated scope", "execution result digest",
 "gateway receipt carries a delegation", "gateway receipt carries a policy decision", "issuer keyid matches signer",
 "issuer kind is known", "log file root matches tree head", "log inclusion proof", "newer log extends older log",
 "no policy errors on an allow", "older is not larger than newer", "policy decision consistent with execution",
 "principal is claimed, not attested", "receipt payload type", "receipt signature (issuer key)", "request args digest",
 "structural parts in clear", "tree head matches inclusion proof size", "tree head signature",
 "upstream signature (provider secret)", "upstream signature (upstream key)", "upstream signature not checked"}
def page_named(name): return name in PAGE_NAMED or name.startswith("withheld ") or name.startswith("fact ")

vd = Path(sys.argv[1]); out = {"reader_sha256": hashlib.sha256((Path(__file__).parent / "ac_receipt_check.py").read_bytes()).hexdigest(), "files": {}}
for f in ("canonical.json", "merkle.json", "audit.json", "receipts.json"):
    out["files"][f] = hashlib.sha256((vd / f).read_bytes()).hexdigest()

# canonical.json
c = json.load(open(vd / "canonical.json", encoding="utf-8")); rows = []
for v in c["values"]:
    rows.append({"kind": "value", "canonical_ok": R.canonical(v["value"]) == v["canonical"], "digest_ok": R.digest(v["value"]) == v["digest"], "value": json.dumps(v["value"], ensure_ascii=False)[:60]})
rows.append({"kind": "keyid", "ok": R.keyid_of_pem(c["keyid"]["publicKeyPem"]) == c["keyid"]["keyid"]})
d = c["dsse"]; env = d["envelope"]; kid = R.keyid_of_pem(d["publicKeyPem"])
pae_ok = ("pae" not in d) or (R.pae(env["payloadType"], R.b64decode_strict(env["payload"])).decode() == d["pae"])
rows.append({"kind": "dsse", "pae_ok": pae_ok, "pae_given": "pae" in d, "signature_ok": R.verified_signers(env, {kid: R.load_key(d["publicKeyPem"])}) == [kid], "keyid_matches": env["signatures"][0]["keyid"] == kid})
out["canonical"] = {"rows": rows, "all_ok": all(all(v for k, v in r.items() if k.endswith("ok")) for r in rows)}

# merkle.json
m = json.load(open(vd / "merkle.json", encoding="utf-8"))
leaves = [l.encode("utf-8") for l in m["leaves"]]; lh = [R.leaf_hash(l) for l in leaves]
mk = {"leafHashes_ok": [h.hex() for h in lh] == m["leafHashes"]}
roots = m["roots"]; mk["roots_ok"] = all(R.mth(lh[:n]).hex() == (roots[str(n)] if isinstance(roots, dict) else roots[n]) for n in range(len(leaves) + 1)) if isinstance(roots, (list, dict)) else None
inc_rows = []
for p in m["inclusion"]:
    root = R.root_from_inclusion(lh[p["leafIndex"]], p["leafIndex"], p["treeSize"], [bytes.fromhex(h) for h in p["hashes"]])
    inc_rows.append({"leafIndex": p["leafIndex"], "treeSize": p["treeSize"], "ok": root is not None and root.hex() == p["root"]})
mk["inclusion"] = inc_rows
con_rows = []
for p in m["consistency"]:
    got = R.consistency_ok(p["oldSize"], p["newSize"], bytes.fromhex(p["oldRoot"]), bytes.fromhex(p["newRoot"]), [bytes.fromhex(h) for h in p["hashes"]])
    con_rows.append({"oldSize": p["oldSize"], "newSize": p["newSize"], "expected": p.get("expected", True), "got": got, "ok": got == p.get("expected", True), "note": p.get("note") or p.get("name")})
mk["consistency"] = con_rows
mk["all_ok"] = bool(mk["leafHashes_ok"] and mk["roots_ok"] and all(r["ok"] for r in inc_rows) and all(r["ok"] for r in con_rows))
out["merkle"] = mk

# audit.json
a = json.load(open(vd / "audit.json", encoding="utf-8")); rows = []
rk = json.load(open(vd / "receipts.json", encoding="utf-8"))["keys"]
for case in a["cases"]:
    keys = {rk[n]["keyid"]: rk[n]["publicKeyPem"] for n in case["keys"]} if all(isinstance(k, str) for k in case["keys"]) else {k["keyid"]: k["publicKeyPem"] for k in case["keys"]}
    res = R.audit_extends(case["older"], case["newer"], case["proof"], keys)
    rows.append({"name": case["name"], "expected": sorted(case["expected"]["failing"]), "got": res["failing"], "agree": sorted(case["expected"]["failing"]) == res["failing"]})
out["audit"] = {"rows": rows, "agree": sum(r["agree"] for r in rows), "n": len(rows)}

# receipts.json
rows = []
for case in rk and json.load(open(vd / "receipts.json", encoding="utf-8"))["cases"]:
    def km(names): return {rk[n]["keyid"]: rk[n]["publicKeyPem"] for n in (names or [])}
    keys = {"issuer": km(case.get("issuerKeys")), "principal": km(case.get("principalKeys")), "log": km(case.get("logKeys")),
            "approval": km(case.get("approvalKeys")), "upstream": km(case.get("upstreamKeys"))}
    opts = {k: case[k] for k in ("requireStrict", "logId", "providerSecrets") if k in case}
    if case.get("log") is not None: opts["log"] = case["log"]
    try:
        res = R.verify_bundle(case["bundle"], keys, opts)
        got = res["failing"]; err = None
    except Exception as e:  # a verifier that raises has failed on its own terms
        got, err = ["<raised %s>" % type(e).__name__], repr(e)[:200]
    exp = sorted(case["expected"]["failing"])
    cls = "PAGE_NAMED" if all(page_named(n) for n in exp) else "VECTOR_NAMED"
    rows.append({"name": case["name"], "class": cls, "expected": exp, "got": got, "agree": exp == got,
                 "verdict_agree": (not exp) == (not got), "missing": sorted(set(exp) - set(got)), "extra": sorted(set(got) - set(exp)), "raised": err})
n = len(rows)
out["receipts"] = {"n": n, "agree": sum(r["agree"] for r in rows), "verdict_agree": sum(r["verdict_agree"] for r in rows),
                   "by_class": {c: {"n": sum(r["class"] == c for r in rows), "agree": sum(r["agree"] for r in rows if r["class"] == c)} for c in ("PAGE_NAMED", "VECTOR_NAMED")},
                   "raised": sum(1 for r in rows if r["raised"]), "rows": rows}
json.dump(out, open(sys.argv[2], "w"), indent=1, ensure_ascii=False)
print("canonical all_ok", out["canonical"]["all_ok"]); print("merkle all_ok", mk["all_ok"], {k: v for k, v in mk.items() if k in ("leafHashes_ok", "roots_ok")}, "inclusion", sum(r["ok"] for r in inc_rows), "/", len(inc_rows), "consistency", sum(r["ok"] for r in con_rows), "/", len(con_rows))
print("audit", out["audit"]["agree"], "/", out["audit"]["n"]); print("receipts exact", out["receipts"]["agree"], "/", n, "verdict", out["receipts"]["verdict_agree"], "/", n, "by class", out["receipts"]["by_class"], "raised", out["receipts"]["raised"])
for r in rows:
    if not r["agree"]: print(f"  {r['name']:58} {r['class']:12} missing={r['missing']} extra={r['extra']}" + (f" RAISED {r['raised']}" if r["raised"] else ""))
