#!/usr/bin/env python3
"""One rule of the frozen reader changed at a time; each mutant is rerun on the blind inputs and scored.
Usage: mutants.py <reader.py> <inputs.json> <expected_SEALED.json> <now>"""
import importlib.util, json, os, subprocess, sys, tempfile
reader, inputs, sealed, now = sys.argv[1:5]
here = os.path.dirname(os.path.abspath(__file__))
src = open(reader).read()
M = [
 ("J1 sort keys by code point, not UTF-16", "keys = sorted(v, key=_utf16_key)", "keys = sorted(v)"),
 ("J2 escape non-ASCII as \\u", "        else:\n            out.append(ch)\n    out.append('\"')", "        elif o > 0x7e:\n            out.append('\\\\u%04x' % o)\n        else:\n            out.append(ch)\n    out.append('\"')"),
 ("J3 numbers as Python repr", "        return es_number(float(v))", "        return repr(float(v)) if float(v) != int(float(v)) else str(int(float(v)))"),
 ("J4 exponent without '+'", 'es = ("+" if e >= 0 else "-") + str(abs(e))', 'es = ("" if e >= 0 else "-") + str(abs(e))'),
 ("J5 -0 kept as -0", '        return "0"  # -0', '        return "-0" if str(x).startswith("-") else "0"  # -0'),
 ("J6 exponent form from 1e21 changed to 1e22", "if k <= n <= 21:", "if k <= n <= 22:"),
 ("J7 small numbers: exponent from 1e-6", "elif -6 < n <= 0:", "elif -5 < n <= 0:"),
 ("J8 duplicate names accepted", '            raise JcsError("duplicate property name")', "            pass"),
 ("J9 control characters other than the named ones kept raw", '        elif o < 0x20:\n            out.append("\\\\u%04x" % o)', '        elif False:\n            pass'),
 ("D1 timestamps normalized before hashing (+00:00 -> Z)", "def document_ref(doc: dict) -> str:\n", "def document_ref(doc: dict) -> str:\n    doc = {k: (v.replace('+00:00', 'Z') if isinstance(v, str) else v) for k, v in doc.items()}\n"),
 ("D2 non-canonical JSON (sorted, Python separators)", 'return "hash://sha256/" + hashlib.sha256(jcs(doc).encode("utf-8")).hexdigest()', 'return "hash://sha256/" + hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()'),
 ("C1 salt read as UTF-8 text, not hex", "    return bytes.fromhex(salt)", "    return salt.encode('utf-8')"),
 ("C2 HMAC key and message swapped", "hmac.new(salt_bytes(salt), value.encode(\"utf-8\"), hashlib.sha256)", "hmac.new(value.encode(\"utf-8\"), salt_bytes(salt), hashlib.sha256)"),
 ("H1 tag not checked", ' or p["tag"] != "agent-did":', ":"),
 ("H2 alg not checked", ' or p["alg"] != "ed25519" or', " or"),
 ("H3 expiry not checked", ' or now > p["expires"]:', ":"),
 ("H4 created skew not checked", 'if abs(now - p["created"]) > max_skew:', "if False:"),
 ("H5 expires >= created not checked", 'if p["expires"] < p["created"] or', "if"),
 ("H6 keyid need not be under Signature-Agent", 'not p["keyid"].startswith(agent + "#")', "False"),
 ("H7 Content-Digest not checked against the body", 'if not _digest_matches(_header(headers, "content-digest"), body):', "if False:"),
 ("H8 components in any order", "if comps[: len(PROFILE)] != PROFILE:", "if not set(PROFILE) <= set(comps):"),
 ("H9 signature-agent component optional", 'PROFILE = ["@method", "@authority", "@path", "@query", "content-digest", "date", "signature-agent"]', 'PROFILE = ["@method", "@authority", "@path", "@query", "content-digest", "date"]'),
 ("H10 nonce optional", 'REQUIRED_PARAMS = {"created", "expires", "nonce", "keyid", "alg", "tag"}', 'REQUIRED_PARAMS = {"created", "expires", "keyid", "alg", "tag"}'),
 ("H11 replay not checked", "            if key in seen:", "            if False:"),
 ("H12 @query empty string when there is no query", '        return "?" + u.query', '        return ("?" + u.query) if u.query else ""'),
 ("H13 @authority keeps the default port", 'port != default else "")', 'True else "")'),
 ("H14 @signature-params copied from the header, not re-serialized", "    lines.append('\"@signature-params\": ' + serialize_inner(items, params))", "    lines.append('\"@signature-params\": ' + _RAW_SIG_PARAMS[0])"),
 ("H15 Date header not required", ' or _header(headers, "date") is None \\\n', " \\\n"),
 ("S1 message signed over SHA-256 of the payload", 'bytes.fromhex(signature_hex), payload.encode("utf-8"))', 'bytes.fromhex(signature_hex), hashlib.sha256(payload.encode("utf-8")).digest())'),
]
results = []
for name, a, b in M:
    s = src
    assert s.count(a) >= 1, name
    s = s.replace(a, b)
    if name.startswith("H14"):
        s = s.replace("def signature_base(", "_RAW_SIG_PARAMS = ['']\ndef signature_base(", 1)
        s = s.replace("    inputs, sigs = parse_dictionary(sig_in), parse_dictionary(sig)",
                      "    inputs, sigs = parse_dictionary(sig_in), parse_dictionary(sig)\n    _RAW_SIG_PARAMS[0] = sig_in.split('=', 1)[1]", 1)
    with tempfile.TemporaryDirectory() as td:
        rp = os.path.join(td, "m.py"); open(rp, "w").write(s)
        run = os.path.join(td, "run.json")
        subprocess.run([sys.executable, "-I", "-B", os.path.join(here, "run_blind.py"), rp, inputs, run, now], check=True, capture_output=True)
        sc = json.loads(subprocess.run([sys.executable, "-I", "-B", os.path.join(here, "score.py"), run, sealed], check=True, capture_output=True, text=True).stdout)
    caught = [m["group"] + ":" + str(m["case"]) for m in sc["mismatches"]]
    results.append({"mutant": name, "caught": bool(caught), "by": caught[:6]})
    print(("CAUGHT  " if caught else "SURVIVES") + "  " + name + ("  <- " + ", ".join(caught[:3]) if caught else ""))
json.dump(results, open(os.path.join(os.path.dirname(here), "runs", "mutants_37a3190_v1.json"), "w"), indent=1, ensure_ascii=False)
print("caught %d of %d" % (sum(r["caught"] for r in results), len(results)))
