"""Build N-xx message vectors from the prose of draft-miao-...-00 Section 5 and run the frozen reader.
Regenerated signatures use the test private keys from Section 3 and the reader's own base builder
(the base builder agreed with all six given positive bases)."""
import os as _os_, tempfile as _tf_
_HERE = _os_.path.dirname(_os_.path.abspath(__file__))
_SCR = _os_.environ.get("WIMSE_TMP", _tf_.gettempdir())
import sys, re, json, base64
sys.path.insert(0, _HERE)
import os
sys.path.insert(0, os.environ.get("READER_DIR", (_HERE + "/reader")))
import run_positives as P, wimse_cold_reader as R
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

def priv(label):
    s = P.V.index(label); seg = P.V[s:s+700]
    return re.search(r"Private d: (\S+)", seg).group(1)
D = {"A": priv("*svcA, Ed25519"), "B": priv("*svcB, Ed25519"), "C": priv("*svcC, ES256"), "O": priv("*other (decoy")}
def sign(who, data):
    d = R.b64u_dec(D[who])
    if who == "C":
        k = ec.derive_private_key(int.from_bytes(d, "big"), ec.SECP256R1())
        r, s = decode_dss_signature(k.sign(data, ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return Ed25519PrivateKey.from_private_bytes(d).sign(data)

def set_header(txt, name, value):
    head, sep, body = txt.partition("\n\n")
    out, done = [], False
    for l in head.split("\n"):
        if l.lower().startswith(name.lower() + ":"):
            if value is not None and not done:
                out.append(f"{name}: {value}"); done = True
            continue
        out.append(l)
    if value is not None and not done:
        out.append(f"{name}: {value}")
    return "\n".join(out) + sep + body

def get_header(txt, name):
    for l in txt.split("\n\n")[0].split("\n"):
        if l.lower().startswith(name.lower() + ":"):
            return l.split(":", 1)[1].strip()

def resign(txt, who, label="sig1", req=None, connect_path=False):
    # connect_path: signer-side only, gives CONNECT an @path of "/" as N-02 states ("its value would be /")
    orig = R.split_target
    if connect_path:
        R.split_target = lambda m: ("/", None, m["target"]) if m["method"] == "CONNECT" else orig(m)
    try:
        return _resign(txt, who, label, req)
    finally:
        R.split_target = orig

def _resign(txt, who, label="sig1", req=None):
    msg = R.parse_http(txt)
    si = dict(R.SFParser(R.header(msg, "signature-input")).dictionary())
    items, ps = si[label][1], si[label][2]
    base = R.signature_base(items, ps, msg, R.parse_http(req) if req else None)
    sig = base64.b64encode(sign(who, base.encode())).decode()
    sg = R.SFParser(R.header(msg, "signature")).dictionary()
    parts = [f"{k}=:{sig}:" if k == label else f"{k}={R.ser_bare(v[1])}" for k, v in sg]
    return set_header(txt, "Signature", ", ".join(parts))

def si_edit(txt, fn):
    return set_header(txt, "Signature-Input", fn(get_header(txt, "Signature-Input")))

P01, P02, P03, P04, P06 = (P.message(v) for v in ("P-01", "P-02", "P-03", "P-04", "P-06"))
P06 = P06.replace('"@query""workload-identity-token"', '"@query" "workload-identity-token"')
NOW = P.NOW
def req(t, now=NOW): return R.verify_request(t, now=now, trusted_aud=P.AUD, issuer_jwk=P.ISSUER)
def resp(t, rq=P01, now=NOW): return R.verify_response(t, request=rq, now=now, issuer_jwk=P.ISSUER)

cases = {}
# N-01: @query removed, signature carried over
cases["N-01"] = req(si_edit(P01, lambda s: s.replace(' "@query"', "")))
# N-02: CONNECT covering @path, regenerated
cases["N-02"] = req(resign(si_edit(P04, lambda s: s.replace('("@method" "@authority"', '("@method" "@authority" "@path"')), "A", connect_path=True))
# N-03: Content-Digest header and coverage removed, carried over
cases["N-03"] = req(set_header(si_edit(P03, lambda s: s.replace(' "content-digest"', "")), "Content-Digest", None))
# N-04: body replaced, digest unchanged, carried over
cases["N-04"] = req(P03.replace('{"flavor":"vanilla","amount":1}', '{"flavor":"chocolate","amount":1}'))
# N-05: expires removed, carried over
cases["N-05"] = req(si_edit(P01, lambda s: re.sub(r";expires=\d+", "", s)))
# N-06 / N-07: keyid / alg added, regenerated (appended at the end of the parameter set)
cases["N-06"] = req(resign(si_edit(P01, lambda s: s + ';keyid="vec-a-key"'), "A"))
cases["N-07"] = req(resign(si_edit(P01, lambda s: s + ';alg="ed25519"'), "A"))
# N-08: decoy sig1 retagged to the WIMSE tag, coverage and signature regenerated
def n08(s):
    return s.replace('sig1=("@method" "@path");created=1795000000;keyid="other-key";tag="example-other"',
                     'sig1=("@method" "@path" "@query" "workload-identity-token");created=1795000000;expires=1795000300;nonce="0123456789abcdef0123456789abcdef";tag="wimse-workload-to-workload";wimse-aud="https://svcb.example.com/gimme-ice-cream"')
n08m = si_edit(P06, n08); assert n08m != P06
cases["N-08"] = req(resign(n08m, "O", "sig1"))
# N-09: verification time T0+3600
cases["N-09"] = req(P01, now=P.T0 + 3600)
# N-09b: T0+300 accept, T0+301 reject
cases["N-09b@T0+300"] = req(P01, now=P.T0 + 300)
cases["N-09b@T0+301"] = req(P01, now=P.T0 + 301)
# N-10: trailing slash on wimse-aud, regenerated
cases["N-10"] = req(resign(si_edit(P01, lambda s: s.replace('gimme-ice-cream"', 'gimme-ice-cream/"')), "A"))
# N-11: wimse-aud removed, regenerated
cases["N-11"] = req(resign(si_edit(P01, lambda s: re.sub(r';wimse-aud="[^"]*"', "", s)), "A"))
# N-12: response without wimse-req-nonce, regenerated
cases["N-12"] = resp(resign(si_edit(P02, lambda s: re.sub(r';wimse-req-nonce="[^"]*"', "", s)), "B", req=P01))
# N-13: wimse-req-nonce = 32 zeros, regenerated
cases["N-13"] = resp(resign(si_edit(P02, lambda s: re.sub(r'wimse-req-nonce="[^"]*"', 'wimse-req-nonce="00000000000000000000000000000000"', s)), "B", req=P01))
# N-14: status line and body of P-02, no Signature / Signature-Input
n14 = set_header(set_header(P02, "Signature", None), "Signature-Input", None)
cases["N-14"] = resp(n14)
# N-15: literal Signature-Input / Signature in the entry, rest of P-01's form
sec = P.V[P.V.index("5.16.  N-15", P.V.index("\n5.  Negative")):]
blk = sec.split("Message and signature:\n\n", 1)[1].split("\n\n   *Expected", 1)[0]
lit = P.unfold(blk)
n15 = set_header(set_header(P01, "Signature-Input", lit[0].split(":", 1)[1].strip()), "Signature", lit[1].split(":", 1)[1].strip())
cases["N-15"] = req(n15)
# information: the N-15 signature verifies under svcC's key?
m15 = R.parse_http(n15); lab, it, ps, sg = R.find_wimse_signature(m15)
b15 = R.signature_base(it, ps, m15, None)
n15_info = R.verify_with_jwk(P.jwk_line("*svcC, ES256"), "ES256", b15.encode(), sg)
# N-20 probe: WIT expired, message signature valid. Time after WIT exp with a re-dated signature.
n20 = resign(si_edit(P01, lambda s: s.replace("created=1795000000;expires=1795000300", "created=1795003600;expires=1795003900")), "A")
cases["N-20 probe"] = req(n20, now=P.T0 + 3700)
# N-21: CONNECT exchange, response covers @path;req. Request = P-04; response = P-02 form.
n21 = si_edit(P02, lambda s: s.replace('"@method";req "@path";req "@query";req', '"@method";req "@authority";req "@path";req')
              .replace('wimse-req-nonce="7f3a9c1e5b284d06a1f4e8c2b6d50937"', 'wimse-req-nonce="9a0b1c2d3e4f5061728394a5b6c7d8e9"'))
cases["N-21"] = resp(resign(n21, "B", req=P04, connect_path=True), rq=P04)
# N-21 contrast: same response without "@path";req should pass the CONNECT branch
n21ok = si_edit(P02, lambda s: s.replace('"@method";req "@path";req "@query";req', '"@method";req "@authority";req')
                .replace('wimse-req-nonce="7f3a9c1e5b284d06a1f4e8c2b6d50937"', 'wimse-req-nonce="9a0b1c2d3e4f5061728394a5b6c7d8e9"'))
cases["N-21 contrast (no @path;req)"] = resp(resign(n21ok, "B", req=P04), rq=P04)

for k, v in cases.items():
    print(f"{k:32s} {v[0]:7s} {v[1] or ''}")
print("N-15 signature verifies under svcC ES256 key:", n15_info)
json.dump({k: [v[0], v[1]] for k, v in cases.items()} | {"N-15_sig_valid_under_svcC": n15_info},
          open(os.environ.get("NEG_OUT", (_HERE + "/runs/negatives.json")), "w"), indent=1)
