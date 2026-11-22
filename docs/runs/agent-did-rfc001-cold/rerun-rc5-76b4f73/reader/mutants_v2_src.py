#!/usr/bin/env python3
"""Source-level mutants of frozen reader v2 (each a textual change of one rule). Same scoring as mutants_v2.py."""
import json, sys, types
rd, hin, hexp, out = sys.argv[1:5]
H = json.load(open(hin)); E = {e["n"]: e for e in json.load(open(hexp))}
SRC = open(rd + "/agent_did_http_v2.py").read()
def mod(src):
    m = types.ModuleType("r"); exec(compile(src, "mut", "exec"), m.__dict__); return m
def run(r):
    res = r.Resolver({H["did"]: {"vms": {k["id"]: (k["publicKeyMultibase"], k["relationships"]) for k in H["keys"].values()}}}); got = {}
    for v in H["vectors"]:
        now = v.get("now", H["clock"]); skew = v.get("maxCreatedSkewSeconds", 300); q = v["request"]; store = {}
        def one():
            try: return r.verify_request(q["method"], q["url"], q["body"], v["headers"], res, now, skew, 300, store)["ok"]
            except Exception: return False
        got[v["n"]] = [one() for _ in range(v["repeat"])] if "repeat" in v else one()
    return got
exp = lambda n: E[n]["expectedSequence"] if "expectedSequence" in E[n] else E[n]["expected"]
M = [
 ("Content-Digest: a dictionary is accepted when its sha-256 member matches",
  "        if cd is None or cd != content_digest(body):",
  "        if cd is None or (cd != content_digest(body) and dict(parse_dictionary(cd)).get('sha-256', (0, b''))[1] != hashlib.sha256(body.encode()).digest()):"),
 ("Agent-DID member accepted when it is a Token or carries parameters",
  "    elif mem[0] != \"item\" or not isinstance(mem[1], str) or isinstance(mem[1], Token) or mem[2]:",
  "    elif mem[0] != \"item\" or not isinstance(mem[1], str):"),
 ("(keyid, nonce) recorded before the signature is checked",
  "    if mb is None or not _verify(ed25519_from_multibase(mb), sig_value, base.encode(\"utf-8\")):\n        return False, \"signature_invalid\", base\n    if rules.get(\"replay\", True) and \"nonce\" in p:\n        k = keyid + \" \" + p[\"nonce\"]\n        if k in store and store[k] >= now:\n            return False, \"nonce_replayed\", base\n        store[k] = p[\"expires\"]",
  "    if rules.get(\"replay\", True) and \"nonce\" in p:\n        k = keyid + \" \" + p[\"nonce\"]\n        if k in store and store[k] >= now:\n            return False, \"nonce_replayed\", base\n        store[k] = p[\"expires\"]\n    if mb is None or not _verify(ed25519_from_multibase(mb), sig_value, base.encode(\"utf-8\")):\n        return False, \"signature_invalid\", base"),
 ("replay window ends before expires (store kept until expires - 1)", "if k in store and store[k] >= now:", "if k in store and store[k] > now:"),
 ("nonce grammar allows space", "NONCE_RE = re.compile(r\"[A-Za-z0-9._~+/=\\-]{1,256}\")", "NONCE_RE = re.compile(r\"[A-Za-z0-9._~+/= \\-]{1,256}\")"),
 ("nonce up to 255 characters only", "{1,256}\")", "{1,255}\")"),
 ("lifetime cap exclusive (expires - created < cap)", "p[\"expires\"] - p[\"created\"] > max_lifetime", "p[\"expires\"] - p[\"created\"] >= max_lifetime"),
 ("now < expires (exclusive)", "now > p[\"expires\"]", "now >= p[\"expires\"]"),
 ("skew compared exclusive", "abs(now - p[\"created\"]) > max_skew", "abs(now - p[\"created\"]) >= max_skew"),
 ("skew one-sided (only created in the past checked)", "abs(now - p[\"created\"]) > max_skew", "(now - p[\"created\"]) > max_skew"),
 ("empty query '?' allowed", "        if query == \"?\":\n            return False", "        if False:\n            return False"),
 ("leading-zero port allowed", "(len(port) > 1 and port[0] == \"0\")", "False"),
 ("apostrophe allowed in query", "SUBDELIM.replace(\"'\", \"\")", "SUBDELIM"),
 ("IPv6 not required in RFC 5952 form", "        if a.compressed != host[1:-1]:\n            return False", "        if False:\n            return False"),
 ("@signature-params taken from the received text instead of re-serialized", "    lines.append('\"@signature-params\": ' + ser_inner(items, params))", "    lines.append('\"@signature-params\": ' + RAW_PARAMS.get('v', ser_inner(items, params)))"),
]
results = []
base = run(mod(SRC)); assert all(base[n] == exp(n) for n in base)
for name, a, b in M:
    assert SRC.count(a) >= 1, name
    src = SRC.replace(a, b, 1)
    if name.startswith("@signature-params"):
        src = "RAW_PARAMS = {}\n" + src.replace("    labels = [(l, m)", "    import re as _re\n    _m = _re.search(r'=(\\(.*)$', sig_in)\n    RAW_PARAMS['v'] = _m.group(1) if _m else None\n    labels = [(l, m)", 1)
    got = run(mod(src)); caught = [E[n]["id"] for n in got if got[n] != exp(n)]
    results.append({"mutant": name, "caught_by": caught, "caught": bool(caught)})
json.dump(results, open(out, "w"), indent=1, ensure_ascii=False)
for x in results: print("CAUGHT " if x["caught"] else "SURVIVE", x["mutant"], ("<- " + ", ".join(x["caught_by"][:3])) if x["caught"] else "")
print(sum(x["caught"] for x in results), "of", len(results), "caught")
