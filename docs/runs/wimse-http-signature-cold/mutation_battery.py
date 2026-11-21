"""Turn off one check of the frozen reader at a time; rerun the judged set (P-01..P-06, 17 message negatives).
A mutant is caught when any judged case changes outcome."""
import os as _os_, tempfile as _tf_
_HERE = _os_.path.dirname(_os_.path.abspath(__file__))
_SCR = _os_.environ.get("WIMSE_TMP", _tf_.gettempdir())
import os, sys, json, subprocess, shutil, tempfile
SRC = (_HERE + "/reader/wimse_cold_reader.py")
HERE = _HERE
M = {
 "M01 WIT issuer signature not checked": [('    if not verify_with_jwk(issuer_jwk, alg, f"{h64}.{p64}".encode(), b64u_dec(s64)):\n        raise Reject("wit_signature")', '    pass')],
 "M02 WIT typ not checked": [('        raise Reject("wit_typ")', '        pass')],
 "M03 WIT exp not checked": [('    if now >= exp:\n        raise Reject("wit_expired")', '    pass')],
 "M04 cnf.jwk.alg policy/consistency not checked": [('    if not jwk_alg_ok(jwk):\n        raise Reject("wit_cnf_alg")', '    pass')],
 "M05 WIT sub not checked": [('        raise Reject("wit_sub")', '        pass')],
 "M06 created in the future accepted": [('if now < created or now > expires:', 'if now > expires:')],
 "M07 expires treated as exclusive": [('if now < created or now > expires:', 'if now < created or now >= expires:')],
 "M08 expires not checked": [('if now < created or now > expires:', 'if now < created:')],
 "M09 nonce not required": [('for p in ("created", "expires", "nonce", "tag"):', 'for p in ("created", "expires", "tag"):'), ('or pd["nonce"][0] != "string"', '')],
 "M10 created not required": [('for p in ("created", "expires", "nonce", "tag"):', 'for p in ("expires", "nonce", "tag"):'), ('created, expires = int(pd["created"][1]), int(pd["expires"][1])', 'created, expires = int(pd.get("created", ("int", 0))[1]), int(pd["expires"][1])'), ('if pd["created"][0] != "int" or', 'if')],
 "M11 keyid allowed": [('FORBIDDEN_PARAMS = ["keyid", "alg"]', 'FORBIDDEN_PARAMS = ["alg"]')],
 "M12 alg allowed": [('FORBIDDEN_PARAMS = ["keyid", "alg"]', 'FORBIDDEN_PARAMS = ["keyid"]')],
 "M13 @method coverage not required (request)": [('        if not has("@method"):\n            raise Reject("coverage_missing_@method")', '        pass')],
 "M14 @path/@query coverage not required": [('            for n in ("@path", "@query"):\n                if not has(n):', '            for n in ():\n                if not has(n):')],
 "M15 only @query coverage required (not @path)": [('            for n in ("@path", "@query"):\n                if not has(n):', '            for n in ("@query",):\n                if not has(n):')],
 "M16 Authorization coverage not required": [('REQ_HEADERS_IF_PRESENT = ["content-type", "content-digest", "authorization",', 'REQ_HEADERS_IF_PRESENT = ["content-type", "content-digest",')],
 "M17 Workload-Identity-Token coverage not required (request)": [('                          "txn-token", "workload-identity-token"]', '                          "txn-token"]')],
 "M18 Content-Type coverage not required (request)": [('REQ_HEADERS_IF_PRESENT = ["content-type", ', 'REQ_HEADERS_IF_PRESENT = [')],
 "M19 Content-Digest coverage not required (request)": [('REQ_HEADERS_IF_PRESENT = ["content-type", "content-digest", ', 'REQ_HEADERS_IF_PRESENT = ["content-type", ')],
 "M20 Content-Digest presence not required": [('    if body and cd is None:\n        raise Reject("content_digest_missing")', '    if body and cd is None:\n        return')],
 "M21 Content-Digest value not compared": [('            if mem[1][1] != known[alg](body).digest():\n                raise Reject("content_digest_mismatch")', '            pass')],
 "M22 CONNECT may cover @path/@query": [('            if has("@path") or has("@query"):\n                raise Reject("connect_covers_path_or_query")', '            pass')],
 "M23 CONNECT @authority not required": [('            if not has("@authority"):\n                raise Reject("coverage_missing_@authority")', '            pass')],
 "M24 wimse-aud not required": [('        if "wimse-aud" not in pd:\n            raise Reject("param_missing_wimse-aud")', '        if "wimse-aud" not in pd:\n            pd["wimse-aud"] = ("string", "https://svcb.example.com")')],
 "M25 wimse-aud compared after URI normalization": [('        if pd["wimse-aud"][1] not in trusted_aud:', '        if pd["wimse-aud"][1].rstrip("/") not in {a.rstrip("/") for a in trusted_aud}:')],
 "M26 wimse-aud not compared": [('        if pd["wimse-aud"][1] not in trusted_aud:\n            raise Reject("audience_mismatch")', '        pass')],
 "M27 more than one WIMSE signature: first one used": [('    if len(found) > 1:\n        raise Reject("multiple_wimse_signatures")', '    pass')],
 "M28 signature chosen by label (first), not by tag": [('        if ps.get("tag") == ("string", TAG):\n            found.append((label, mem))', '        found.append((label, mem))\n        break')],
 "M29 response: wimse-req-nonce not required": [('        if "wimse-req-nonce" not in pd:\n            raise Reject("param_missing_wimse-req-nonce")', '        if "wimse-req-nonce" not in pd:\n            pd["wimse-req-nonce"] = ("string", req_nonce_hint)'), ('    claims, jwk = validate_wit(', '    req_nonce_hint = dict(find_wimse_signature(req)[2])["nonce"][1] if req is not None else ""\n    claims, jwk = validate_wit(')],
 "M30 response: wimse-req-nonce not compared": [('        if pd["wimse-req-nonce"][1] != req_nonce:\n            raise Reject("req_nonce_mismatch")', '        pass')],
 "M31 response: unsigned accepted even when required": [('            if required:\n                raise Reject("signed_response_required")', '            pass')],
 "M32 response: @status / @method;req not required": [('        if not has("@status") or not has("@method", True):\n            raise Reject("coverage_missing_response_core")', '        pass')],
 "M33 response: @path;req/@query;req not required": [('            for n in ("@path", "@query"):\n                if not has(n, True):', '            for n in ():\n                if not has(n, True):')],
 "M34 response: CONNECT may cover @path;req": [('            if has("@path", True) or has("@query", True):\n                raise Reject("connect_response_covers_path_or_query")', '            pass')],
 "M35 response: Workload-Identity-Token coverage not required": [('        if not has("workload-identity-token"):\n            raise Reject("coverage_missing_workload-identity-token")', '        pass')],
 "M36 response: Content-Type/Digest coverage not required": [('RESP_HEADERS_IF_PRESENT = ["content-type", "content-digest"]', 'RESP_HEADERS_IF_PRESENT = []')],
 "M37 signature verified with any known key type (not cnf.jwk.alg)": [('    if not verify_with_jwk(jwk, jwk["alg"], base.encode(), sig):', '    if not (verify_with_jwk(jwk, jwk["alg"], base.encode(), sig) or verify_with_jwk(_svcC, "ES256", base.encode(), sig)):'), ('TAG = "wimse-workload-to-workload"', 'TAG = "wimse-workload-to-workload"\n_svcC = {"kty":"EC","crv":"P-256","x":"jZjfUBQgD1l9R_lm4nzo1rP82pGVDBxHD6YmOo_xoCo","y":"CBGv9b8hB-l0mov9rlu223g-vNE_SquCC2IhPi2IweE"}')],
 "M39 expires not required": [('for p in ("created", "expires", "nonce", "tag"):', 'for p in ("created", "nonce", "tag"):'), ('if pd["created"][0] != "int" or pd["expires"][0] != "int" or', 'if pd["created"][0] != "int" or'), ('created, expires = int(pd["created"][1]), int(pd["expires"][1])', 'created, expires = int(pd["created"][1]), int(pd.get("expires", ("int", 10**12))[1])')],
 "M38 message signature not checked": [('    if not verify_with_jwk(jwk, jwk["alg"], base.encode(), sig):\n        raise Reject("signature_invalid")', '    pass')],
}
JUDGED_NEG = ["N-01","N-02","N-03","N-04","N-05","N-06","N-07","N-08","N-09","N-09b@T0+301","N-10","N-11","N-12","N-13","N-14","N-15","N-21"]
def run(reader_dir, tag):
    env = dict(os.environ, P06_RESTORE="1", READER_DIR=reader_dir, NEG_OUT=f"{_SCR}/neg_{tag}.json",
               POS_PREFIX=f"{_SCR}/pos_{tag}_")
    for s in ("run_positives.py", "run_negatives.py"):
        r = subprocess.run(["/usr/bin/python3", "-I", "-B", f"{HERE}/{s}"], env=env, capture_output=True, text=True, cwd=HERE)
        if r.returncode:
            return {"error": r.stderr.strip().splitlines()[-1]}
    pos = json.load(open(env["POS_PREFIX"] + "expanded.json"))
    neg = json.load(open(env["NEG_OUT"]))
    out = {k: v["outcome"] for k, v in pos.items()}
    out["N-09b@T0+300"] = neg["N-09b@T0+300"][0]
    out.update({k: neg[k][0] for k in JUDGED_NEG})
    return out
expected = {**{f"P-0{i}": "accept" for i in range(1, 7)}, "N-09b@T0+300": "accept", **{k: "reject" for k in JUDGED_NEG}}
if __name__ == "__main__":
    results = {}
    for name, patches in M.items():
        t = open(SRC).read()
        for a, b in patches:
            assert t.count(a) == 1, (name, a[:60])
            t = t.replace(a, b)
        d = tempfile.mkdtemp(dir=_SCR)
        open(f"{d}/wimse_cold_reader.py", "w").write(t)
        got = run(d, name.split()[0])
        if "error" in got:
            results[name] = {"caught_by": ["<harness error> " + got["error"]]}
        else:
            results[name] = {"caught_by": [k for k in expected if got.get(k) != expected[k]]}
        print(f"{name:66s} {'CAUGHT by ' + ','.join(results[name]['caught_by']) if results[name]['caught_by'] else 'SURVIVES'}")
    json.dump(results, open(f"{HERE}/runs/mutation_battery.json", "w"), indent=1)
