#!/usr/bin/env python3
"""Turn off one check of the frozen verifier at a time and see which of the 20 vectors and 71 scenarios notice.
A mutant is killed when at least one outcome stops agreeing with its expected outcome. Scenario messages are signed
once by scenario_harness.py with the frozen code; only the verification runs under the mutant."""
import json, glob, os, sys, types
W = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(W, "reader", "wba_cold_verifier.py"), encoding="utf-8").read()
MUTANTS = {
 "M01 nonce optional": [('            raise Refusal("nonce-missing")', '            return'), ('    if state.seen(origin, params["nonce"], now):\n        raise Refusal("nonce-replayed")\n    state.record(origin, params["nonce"], params["expires"])', '    if "nonce" in params and state.seen(origin, params["nonce"], now):\n        raise Refusal("nonce-replayed")\n    if "nonce" in params:\n        state.record(origin, params["nonce"], params["expires"])')],
 "M02 no replay state": ('        return exp is not None and now <= exp + SKEW', '        return False'),
 "M03 Signature-Agent coverage not checked": ('        raise Refusal("signature-agent-not-covered")', '        pass'),
 "M04 key looked up by keyid alone": ('    d = dirs.get(origin)\n', '    d = next((x for x in dirs.values() if any(k.get("kid") == kid for k in json.loads(body_bytes(x["body"]))["keys"])), dirs.get(origin))\n    origin = next((o for o, x in dirs.items() if x is d), origin)\n'),
 "M05 two web-bot-auth signatures allowed (first wins)": [('    if len(labels) > 1:\n        raise Refusal("multiple-signatures")', '    if False:\n        pass'), ('    if len(tagged) > 1 or sum(', '    if False and len(tagged) > 1 or sum(')],
 "M06 response binding not required": ('        raise Refusal("response-not-bound")', '        pass'),
 "M07 Content-Digest not compared with body": ('    if sha[0][1] != hashlib.sha256(body).digest():\n        raise Refusal("content-digest")', '    pass'),
 "M08 authority not checked": ('        raise Refusal("authority")\n    check_params', '        pass\n    check_params'),
 "M09 created in the future accepted": ('        raise Refusal("created-in-future")', '        pass'),
 "M10 expired accepted": ('        raise Refusal("expired")', '        pass'),
 "M11 lifetime over 300 s accepted": ('        raise Refusal("lifetime")', '        pass'),
 "M12 alg not checked": ('    if params.get("alg") != "ed25519":\n        raise Refusal("alg")', '    pass'),
 "M13 required request components not checked": ('    for name, want in need:\n        if not covers(items, name, **want):\n            raise Refusal("components")\n    key = resolve_key(op, origin, params["keyid"], now)\n    if any(v == "content-digest" for v, _ in items):\n        check_digest(headers, body)\n    r = prepare_request(req, op["authority"])', '    key = resolve_key(op, origin, params["keyid"], now)\n    if any(v == "content-digest" for v, _ in items):\n        check_digest(headers, body)\n    r = prepare_request(req, op["authority"])'),
 "M14 any https Signature-Agent value accepted": ('    m = re.match(r"^https://([^/?#@:]+)(/\\.well-known/http-message-signatures-directory)?$", value)', '    m = re.match(r"^https://([^/?#@:]+)(/.*)?$", value)'),
 "M15 response signer origin not checked": ('        raise Refusal("origin-mismatch")', '        pass'),
 "M16 directory signatures not verified": ('        if not ed25519_verify(ed[kid]["x"], sigs[lab], base):\n            raise Refusal("directory-signature")', '        pass'),
 "M17 directory media type not checked": ('        raise Refusal("directory-media-type")', '        pass'),
 "M18 directory Content-Digest not checked": ('    if len(sha) != 1 or not isinstance(sha[0][1], (bytes, bytearray)) or sha[0][1] != hashlib.sha256(body).digest():\n        raise Refusal("directory-content-digest")', '    pass'),
 "M19 directory window not checked": ('        if created > now + SKEW or now > expires:\n            raise Refusal("directory-window")', '        pass'),
 "M20 target URI as written (no normalization)": ('    path = _remove_dots(_enc(path or "/", "`{}"))', '    path = path or "/"'),
 "M21 Signature-Agent member parameters not ignored": ('    with_params = [lab for lab, m in sa if m[2]]\n    plain = [(lab, m) for lab, m in sa if not m[2]]', '    with_params = []\n    plain = list(sa)'),
 "M22 two Signature-Agent members allowed": ('        raise Refusal("multiple-signature-agents")', '        pass'),
 "M23 nonce form not checked": ('        if not nonce_ok(n):\n            raise Refusal("nonce-invalid")', '        pass'),
 "M24 directory kid not checked against thumbprint": ('                raise Refusal("directory-kid")', '                pass'),
 "M25 lenient Signature-Agent parse (bare string accepted)": ('        sa = parse_dict(sa_raw) if sa_raw is not None else []', '        sa = parse_dict(sa_raw) if sa_raw is not None and not sa_raw.startswith(\'"\') else ([("sig1", ("item", sa_raw.strip(\'"\'), []))] if sa_raw else [])'),
 "M26 directory key without its own signature accepted": ('        if len(got) != 1:\n            raise Refusal("directory-one-signature-per-key")', '        if len(got) != 1:\n            continue'),
 "M27 directory signature components not checked": ('            raise Refusal("directory-components")', '            pass'),
 "M28 directory signature tag not checked": ('            raise Refusal("directory-tag")', '            pass'),
 "M29 response @status not required": ('    need = [("@status", {}), ("@method", {"req": True})', '    need = [("@method", {"req": True})'),
}
def load(src):
    m = types.ModuleType("v"); exec(compile(src, "v", "exec"), m.__dict__); return m
sys.path.insert(0, os.path.join(W, "reader"))
import scenario_harness as H
SC_ANS = json.load(open(os.path.join(W, "answers", "scenarios_answers.json")))
SC_OPS = {}
for _g, _fn in (("request_scenarios", H.request_op), ("directory_scenarios", H.directory_op), ("response_scenarios", H.response_op), ("target_uris", H.target_op)):
    for _sc in H.S[_g]:
        _exp = next(x for x in SC_ANS[_g] if x["id"] == _sc["id"]).get("expected", {"ok": True})
        SC_OPS[_sc["id"]] = (_fn(_sc, H.NOW), _exp)
def grade(mod):
    res = {}
    for c, (op, a) in SC_OPS.items():
        try: g = mod.run(op)
        except Exception as e: g = {"crash": type(e).__name__ + ": " + str(e)}
        if a["ok"]: same = g.get("ok") is True and (a.get("identity") is None or g.get("identity") == a.get("identity"))
        else: same = g.get("ok") is False and g.get("status") == a["status"] and g.get("rule") == a["rule"]
        res[c] = (same, g)
    for f in sorted(glob.glob(os.path.join(W, "inputs", "[pn][oe][sg]-*.json"))):
        c = os.path.basename(f)[:-5]
        a = json.load(open(os.path.join(W, "answers", c + ".json")))["expected"]
        try: g = mod.run(json.load(open(f))["operation"])
        except Exception as e: g = {"crash": type(e).__name__ + ": " + str(e)}
        if a["ok"]: same = g.get("ok") is True and g.get("identity") == a.get("identity")
        else: same = g.get("ok") is False and g.get("status") == a["status"] and g.get("rule") == a["rule"]
        res[c] = (same, g)
    return res
base = grade(load(SRC)); assert all(s for s, _ in base.values()), "frozen verifier must agree on all 91"
out = {"frozen_sha256": __import__("hashlib").sha256(SRC.encode()).hexdigest(), "mutants": []}
for name, patches in MUTANTS.items():
    if isinstance(patches, tuple): patches = [patches]
    src, bad = SRC, None
    for old, new in patches:
        if src.count(old) != 1: bad = f"patch matched {src.count(old)} times"; break
        src = src.replace(old, new)
    if bad: out["mutants"].append({"mutant": name, "error": bad}); continue
    r = grade(load(src))
    killers = {c: g for c, (s, g) in r.items() if not s}
    out["mutants"].append({"mutant": name, "killed": bool(killers), "killed_by": sorted(killers), "outcomes": killers})
json.dump(out, sys.stdout, indent=1, sort_keys=True)
