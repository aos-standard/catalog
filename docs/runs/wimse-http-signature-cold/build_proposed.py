"""Build proposed negative vectors X01-X10 for the gaps found by mutation_battery.py.
Each is signed with the draft's published test keys (Ed25519, deterministic) at the draft's clock."""
import os as _os_, tempfile as _tf_
_HERE = _os_.path.dirname(_os_.path.abspath(__file__))
_SCR = _os_.environ.get("WIMSE_TMP", _tf_.gettempdir())
import sys, os, json, re, base64, hashlib
sys.path.insert(0, _HERE)
import run_negatives as N, run_positives as P
R = N.R
OUT = (_HERE + "/proposed")
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
ISS_D = N.priv("*Issuer (WIT issuer)")

def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def reissue(wit, hdr_patch=None, claim_patch=None, corrupt=False):
    h64, p64, s64 = wit.split(".")
    hdr = json.loads(R.b64u_dec(h64)); cl = json.loads(R.b64u_dec(p64))
    hdr.update(hdr_patch or {}); cl.update(claim_patch or {})
    h = b64u(json.dumps(hdr, separators=(",", ":")).encode()); p = b64u(json.dumps(cl, separators=(",", ":")).encode())
    sig = Ed25519PrivateKey.from_private_bytes(R.b64u_dec(ISS_D)).sign(f"{h}.{p}".encode())
    if corrupt:
        sig = sig[:-1] + bytes([sig[-1] ^ 1])
    return f"{h}.{p}.{b64u(sig)}"

P01, P02, P04, P06 = N.P01, N.P02, N.P04, N.P06
WA = P.WITS["A"]; WB = P.WITS["B"]
vec = {}
def add(vid, title, kind, msg, now, requirement, rule_off, request=None):
    vec[vid] = {"id": vid, "title": title, "kind": kind, "verification_time": now, "message": msg,
                "request": request, "expected": "reject", "requirement": requirement, "isolates": rule_off}

add("X01", "N-01 with the signature regenerated: @query not covered", "request",
    N.resign(N.si_edit(P01, lambda s: s.replace(' "@query"', "")), "A"), P.NOW,
    "Section 3: @method, @path and @query MUST be signed", "M14")
add("X02", "N-03 with the signature regenerated: body without Content-Digest", "request",
    N.resign(N.set_header(N.si_edit(N.P03, lambda s: s.replace(' "content-digest"', "")), "Content-Digest", None), "C"), P.NOW,
    "Section 3: a message with a body MUST carry Content-Digest", "M20")
add("X03", "N-05 with the signature regenerated: expires missing", "request",
    N.resign(N.si_edit(P01, lambda s: re.sub(r";expires=\d+", "", s)), "A"), P.NOW,
    "Section 3: created, expires, nonce and tag MUST be included", "M39")
add("X04", "WIT issuer signature invalid (one bit flipped); message re-signed over the changed WIT", "request",
    N.resign(N.set_header(P01, "Workload-Identity-Token", reissue(WA, corrupt=True)), "A"), P.NOW,
    "Section 3: the WIT MUST be validated (workload-creds-03 5.1.3: the JWS signature is valid under the trust anchors)", "M01")
add("X05", "WIT typ is JWT instead of wit+jwt; otherwise identical, validly issued", "request",
    N.resign(N.set_header(P01, "Workload-Identity-Token", reissue(WA, hdr_patch={"typ": "JWT"})), "A"), P.NOW,
    "workload-creds-03 5.1.3: the typ JOSE header parameter conveys a media type of wit+jwt", "M02")
add("X06", "WIT expired (exp = T0+30) while the signature window is valid (verified at T0+60)", "request",
    N.resign(N.set_header(P01, "Workload-Identity-Token", reissue(WA, claim_patch={"exp": P.T0 + 30})), "A"), P.NOW,
    "Section 3 / workload-creds: an expired WIT fails validation; this isolates exp from the signature window (N-09 does not)", "M03")
add("X07", "Request does not cover Workload-Identity-Token; signature regenerated", "request",
    N.resign(N.si_edit(P01, lambda s: s.replace(' "workload-identity-token"', "")), "A"), P.NOW,
    "Section 3: Workload-Identity-Token MUST be signed when it exists", "M17")
add("X08", "Signed response does not cover Workload-Identity-Token; signature regenerated", "response",
    N.resign(N.si_edit(P02, lambda s: s.replace(' "workload-identity-token"', "")), "B", req=P01), P.NOW,
    "Section 3: a signed response MUST cover Workload-Identity-Token", "M35", request=P01)
add("X09", "created in the future: created = T0+120, expires = T0+420, verified at T0+60", "request",
    N.resign(N.si_edit(P01, lambda s: s.replace("created=1795000000;expires=1795000300", "created=1795000120;expires=1795000420")), "A"), P.NOW,
    "Section 3: recipients MUST reject signatures outside their validity window [created, expires]", "M06")
n08 = N.si_edit(P06, N.n08)
add("X10", "N-08 with both WIMSE-tagged signatures made by vec-a-key (the WIT's key)", "request",
    N.resign(n08, "A", "sig1"), P.NOW,
    "Section 3: if more than one signature has the WIMSE tag, the recipient MUST reject; here each one alone verifies", "M27")

json.dump(vec, open(f"{OUT}/proposed_vectors.json", "w"), indent=1, ensure_ascii=True)
print("built", len(vec))
