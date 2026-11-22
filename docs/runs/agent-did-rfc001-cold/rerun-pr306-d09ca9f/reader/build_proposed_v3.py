#!/usr/bin/env python3
"""One proposed vector: an ACCEPTED request whose host is a bracketed IPv6 address in RFC 5952 form.
Signed over "@authority": [2001:db8::1] (brackets kept, RFC 9421 2.2.3 / RFC 9110 host). Fixture keys, DID, clock, Date, body.
usage: build_proposed_v3.py upstream/fixtures/http-verification-vectors.json out.json"""
import json, sys, base64, hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
src, out = sys.argv[1:3]
F = json.load(open(src)); V = {v["id"]: v for v in F["vectors"]}; valid = V["valid"]
sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(F["keys"]["key-1"]["seedHex"]))
KID = F["keys"]["key-1"]["id"]; DID = F["did"]; CLOCK = F["clock"]; body = valid["request"]["body"]
url = "https://[2001:db8::1]/v1/verify?mode=fixture"
cd = "sha-256=:" + base64.b64encode(hashlib.sha256(body.encode()).digest()).decode() + ":"
comps = '("@method" "@authority" "@path" "@query" "content-digest" "date" "agent-did";key="sig1")'
params = comps + ';created=%d;expires=%d;nonce="v3ipv6host";keyid="%s";alg="ed25519";tag="agent-did"' % (CLOCK - 10, CLOCK + 50, KID)
base = "\n".join(['"@method": ' + valid["request"]["method"], '"@authority": [2001:db8::1]', '"@path": /v1/verify', '"@query": ?mode=fixture',
                  '"content-digest": ' + cd, '"date": ' + valid["headers"]["Date"], '"agent-did";key="sig1": "%s"' % DID, '"@signature-params": ' + params])
h = {"Agent-DID": 'sig1="%s"' % DID, "Date": valid["headers"]["Date"], "Content-Digest": cd, "Signature-Input": "sig1=" + params,
     "Signature": "sig1=:" + base64.b64encode(sk.sign(base.encode())).decode() + ":"}
json.dump({"basedOn": "edisonduran/agent-did fixtures/http-verification-vectors.json at d09ca9f (#306 merged): same keys, DID, clock, Date and body",
           "vectors": [{"id": "proposed-accept-ipv6-host", "rule": "6.5 item 4 and RFC 9421 2.2.3: @authority of a bracketed IPv6 host keeps the brackets",
                        "description": "An accepted request whose URL host is a bracketed IPv6 address in RFC 5952 form. The 95 vectors have no accepted IPv6 host, so a verifier that drops the brackets from @authority passes them all.",
                        "request": {"method": valid["request"]["method"], "url": url, "body": body}, "headers": h, "signatureBase": base, "expected": True}]},
          open(out, "w"), indent=1, ensure_ascii=False)
print("1 proposed")
