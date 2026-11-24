#!/usr/bin/env python3
"""Proposed sample tokens / validations for gaps the samples leave open. Built from samples/current files with the
samples' own root key; Ed25519 is deterministic, so the output is byte-reproducible.
usage: build_proposed.py samples_dir samples.json inputs.json out_dir"""
import json, sys, os, importlib.util
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
sd, sj, inp, out = sys.argv[1:5]; os.makedirs(out, exist_ok=True)
here = os.path.dirname(os.path.abspath(__file__))
s = importlib.util.spec_from_file_location("r", here + "/biscuit_reader_v1.py"); r = importlib.util.module_from_spec(s); s.loader.exec_module(r)
S = json.load(open(sj)); I = json.load(open(inp))
root_sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(S["root_private_key"]))
def enc_varint(n):
    o = b""
    while True:
        c = n & 0x7F; n >>= 7
        o += bytes([c | (0x80 if n else 0)])
        if not n: return o
def enc_field(fn, wt, v):
    return enc_varint(fn << 3 | wt) + (enc_varint(v) if wt == 0 else enc_varint(len(v)) + v)
def split_fields(b):
    """raw field list preserving order: [(fn, wt, value_bytes_or_int)]"""
    out, i = [], 0
    while i < len(b):
        key, i = r._varint(b, i); fn, wt = key >> 3, key & 7
        if wt == 0: v, i = r._varint(b, i)
        else:
            n, i = r._varint(b, i); v, i = b[i:i + n], i + n
        out.append((fn, wt, v))
    return out
def join(fields): return b"".join(enc_field(fn, wt, v) for fn, wt, v in fields)
def authz(fname):
    for c in I["cases"]:
        if c["filename"] == fname: return c["authorizer_code"]
P = []
base = open(sd + "/test012_authority_caveats.bc", "rb").read()
base_auth = authz("test012_authority_caveats.bc")
# G1 deny policy: authorizer-side only
P.append({"id": "proposed_deny_policy", "filename": "test012_authority_caveats.bc", "token_bytes": None,
          "authorizer_code": "deny if true;\n" + base_auth, "expect": ("err", "deny", 0),
          "expected_samples_json": {"Err": {"FailedLogic": {"Unauthorized": {"policy": {"Deny": 0}, "checks": []}}}},
          "mutant": "deny policy treated as allow", "note": "No sample has a deny policy that matches."})
# G2 superset semantics of set.contains(set): authorizer-side only
P.append({"id": "proposed_set_contains_is_superset", "filename": "test012_authority_caveats.bc", "token_bytes": None,
          "authorizer_code": "check if !{1, 2}.contains({1, 3});\n" + base_auth, "expect": ("ok", 0),
          "expected_samples_json": {"Ok": 0}, "mutant": "set contains set = intersection non-empty",
          "note": "Between two sets, contains is a superset test. No sample compares overlapping, non-nested sets."})
# G3 wrong proof secret
f = split_fields(base)
f2 = [(fn, wt, (join([(1, 2, bytes(range(1, 33)))]) if fn == 4 else v)) for fn, wt, v in f]
P.append({"id": "proposed_wrong_proof_secret", "filename": None, "token_bytes": join(f2), "authorizer_code": base_auth,
          "expect": ("err", "format"), "expected_samples_json": {"Err": {"Format": "<proof secret does not match the last public key>"}},
          "mutant": "proof secret not checked against the last key", "note": "test012 with nextSecret replaced by an unrelated 32-byte secret."})
# G4 sealed token with a corrupted final signature
sealed = open(sd + "/test020_sealed.bc", "rb").read()
fs = split_fields(sealed)
def corrupt_final(v):
    pf = split_fields(v); fn, wt, sig = pf[0]
    return join([(fn, wt, sig[:-1] + bytes([sig[-1] ^ 1]))])
fs2 = [(fn, wt, corrupt_final(v) if fn == 4 else v) for fn, wt, v in fs]
P.append({"id": "proposed_sealed_bad_final_signature", "filename": None, "token_bytes": join(fs2), "authorizer_code": authz("test020_sealed.bc"),
          "expect": ("err", "format"), "expected_samples_json": {"Err": {"Format": "<invalid final signature>"}},
          "mutant": "sealed final signature not checked", "note": "test020 with the last bit of finalSignature flipped."})
# G5/G6 datalog version out of range: re-sign the authority block with the samples' root key
def with_version(ver):
    fields = split_fields(base)
    auth = split_fields(fields[[i for i, x in enumerate(fields) if x[0] == 2][0]][2])
    data = [v for fn, wt, v in auth if fn == 1][0]
    nk = [v for fn, wt, v in auth if fn == 2][0]
    sver = [v for fn, wt, v in auth if fn == 5]
    bf = split_fields(data)
    bf = [(fn, wt, (ver if fn == 3 else v)) for fn, wt, v in bf]
    ndata = join(bf)
    npk = r.decode_public_key(nk)
    msg = r.payload_v0(ndata, None, npk) if not sver or sver[0] == 0 else r.payload_v1(ndata, npk, None, None, sver[0])
    sig = root_sk.sign(msg)
    nauth = join([(fn, wt, (ndata if fn == 1 else sig if fn == 3 else v)) for fn, wt, v in auth])
    return join([(fn, wt, (nauth if fn == 2 else v)) for fn, wt, v in fields])
for ver, label in ((7, "above"), (2, "below")):
    P.append({"id": "proposed_datalog_version_%s_range" % label, "filename": None, "token_bytes": with_version(ver), "authorizer_code": base_auth,
              "expect": ("err", "format"), "expected_samples_json": {"Err": {"Format": "<unsupported datalog version %d>" % ver}},
              "mutant": "datalog version not checked", "note": "test012 with the authority block's version set to %d, re-signed with the samples' root key." % ver})
meta = []
for p in P:
    fn = p["filename"]
    if p["token_bytes"] is not None:
        fn = p["id"] + ".bc"; open(out + "/" + fn, "wb").write(p["token_bytes"])
    meta.append({k: v for k, v in p.items() if k != "token_bytes"} | {"token_file": fn})
json.dump({"root_public_key": S["root_public_key"], "based_on": "eclipse-biscuit/biscuit samples/current at b3d3fe2", "cases": meta},
          open(out + "/proposed.json", "w"), indent=1)
print(len(meta), "proposed")
