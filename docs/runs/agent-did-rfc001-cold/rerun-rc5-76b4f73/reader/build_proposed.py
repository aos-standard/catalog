#!/usr/bin/env python3
"""Build proposed vectors for gaps the rc.5 HTTP vectors leave open, with the fixture's own keys, DID and clock.
usage: build_proposed.py upstream/fixtures/http-verification-vectors.json READER_DIR out.json"""
import json, sys, base64, importlib.util
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
src, rd, out = sys.argv[1:4]
F = json.load(open(src)); V = {v["id"]: v for v in F["vectors"]}
s = importlib.util.spec_from_file_location("r", rd + "/agent_did_http_v2.py"); r = importlib.util.module_from_spec(s); s.loader.exec_module(r)
sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(F["keys"]["key-1"]["seedHex"]))
KID = F["keys"]["key-1"]["id"]; DID = F["did"]; CLOCK = F["clock"]
valid = V["valid"]
def build(url, created, expires, nonce, sign=True, literal=True, sig_override=None, method=None):
    method = method or valid["request"]["method"]; body = valid["request"]["body"]
    items = [(x, []) for x in ["@method", "@authority", "@path", "@query", "content-digest", "date"]] + [("agent-did", [("key", "sig1")])]
    params = [("created", created), ("expires", expires), ("nonce", nonce), ("keyid", KID), ("alg", "ed25519"), ("tag", "agent-did")]
    h = {"Agent-DID": 'sig1="%s"' % DID, "Date": valid["headers"]["Date"], "Content-Digest": r.content_digest(body)}
    base = r.signature_base(method, url, h, items, params, r.parse_dictionary(h["Agent-DID"]))  # literal components
    sig = sig_override if sig_override is not None else sk.sign(base.encode())
    h["Signature-Input"] = "sig1=" + r.ser_inner(items, params); h["Signature"] = "sig1=:" + base64.b64encode(sig).decode() + ":"
    return {"request": {"method": method, "url": url, "body": body}, "headers": h, "signatureBase": base}
P = []
u0 = valid["request"]["url"]
# G1: a forged request must not consume the nonce (RFC-001 6.5 item 6, second sentence)
forged = build(u0, CLOCK - 10, CLOCK + 50, "g1nonce", sig_override=b"\x00" * 64)
good = build(u0, CLOCK - 10, CLOCK + 50, "g1nonce")
P.append({"id": "proposed-forged-does-not-consume-nonce", "rule": "6.5 item 6: record the pair only after the signature verified",
          "description": "Two different requests with one nonce store: first a request whose signature does not verify, then the valid request with the same keyid and nonce. A verifier that records the pair before checking the signature rejects the second.",
          "steps": [forged, good], "expectedSequence": [False, True], "expectedReasons": ["signature_invalid", None]})
# G2: the pair is kept through expires inclusive (Anti-Replay guide, NonceStore contract)
g2 = build(u0, CLOCK - 60, CLOCK, "g2nonce")
P.append({"id": "proposed-replay-in-last-second", "rule": "6.5 item 6: record until expires (inclusive)", "now": CLOCK,
          "description": "now == expires. The same request verified twice with one nonce store. The second must be rejected: the pair is kept through second `expires`.",
          **{k: g2[k] for k in ("request", "headers", "signatureBase")}, "expectedSequence": [True, False], "expectedReasons": [None, "nonce_replayed"]})
# G3: URL rules signed over the literal components, so a verifier that reads the URL as written cannot reject on the signature
for vid, url in [("reject-url-apostrophe-in-query", "https://api.example.com/v1/verify?mode='fixture'"),
                 ("reject-url-non-canonical-ipv6", "https://[2001:db8:0:0::1]/v1/verify?mode=fixture"),
                 ("reject-url-dot-segment", "https://api.example.com/v1/../v1/verify?mode=fixture"),
                 ("reject-url-encoded-dot-segment", "https://api.example.com/v1/%2e%2E/v1/verify?mode=fixture"),
                 ("reject-url-space-in-query", "https://api.example.com/v1/verify?mode=hello world")]:  # IPv4 left out: the text as written lets 0x5d.0xb8.0xd8.0x22 through (README point 2)
    g = build(url, CLOCK - 10, CLOCK + 50, "g3" + vid.split("reject-url-")[1].replace("-", ""))
    P.append({"id": "proposed-" + vid[len("reject-"):] + "-literal", "rule": "6.5 item 4: url_not_normalized",
              "description": "As `%s`, but signed over the components read from the URL as written (RFC 3986 split, no normalization). The existing vector is signed over the normalized components, so a verifier whose URL parser does not normalize rejects it on the signature even without the rule." % vid,
              **{k: g[k] for k in ("request", "headers", "signatureBase")}, "expected": False, "reason": "url_not_normalized"})
json.dump({"basedOn": "edisonduran/agent-did fixtures/http-verification-vectors.json at v1.0.0-rc.5 (76b4f73): same keys, DID, clock, Date and body",
           "note": "steps[] is a new field: several requests verified in order with ONE nonce store.", "vectors": P}, open(out, "w"), indent=1, ensure_ascii=False)
print(len(P), "proposed")
