#!/usr/bin/env python3
"""Candidate cases for rules the published vectors do not reach, in the vectors' own layout.
Each is one change from an example in http.md. Expectations are this author's reading of http.md, the vectors
README and the RFCs it cites; they are candidates, not agreed vectors. Usage: make_candidates.py <inputs.json> <out.json>"""
import base64, json, sys
inp = {c["id"]: c for c in json.load(open(sys.argv[1]))["decode"]}
ex = inp["spec-payment-response-success"]["value"]          # http.md's PAYMENT-RESPONSE success example
raw = base64.b64decode(ex)
H3 = ["PAYMENT-REQUIRED", "PAYMENT-SIGNATURE", "PAYMENT-RESPONSE"]
def b(x): return base64.b64encode(x).decode()
c = []
c.append({"id": "pad-extra", "note": "The PAYMENT-RESPONSE success example, which fills its last quantum, with '==' appended. RFC 4648 3.2 puts pad characters only at the end of data that does not fill a quantum.", "headers": ["PAYMENT-RESPONSE"], "value": ex + "==", "expect": {"reject": True}})
mid = (len(ex) // 8) * 4
c.append({"id": "pad-inside", "note": "Two encodings concatenated: the example split at a quantum boundary, the first half re-encoded with padding. '=' inside the data is not in the alphabet (RFC 4648 3.3).", "headers": ["PAYMENT-RESPONSE"], "value": b(base64.b64decode(ex[:mid])[:-1]) + b(base64.b64decode(ex[:mid])[-1:] + base64.b64decode(ex[mid:])), "expect": {"reject": True}})
c.append({"id": "line-break", "note": "The example with CRLF after character 76, as MIME (RFC 2045) would write it. RFC 4648 3.1: no line feeds unless the referring specification says so.", "headers": ["PAYMENT-RESPONSE"], "value": ex[:76] + "\r\n" + ex[76:], "expect": {"reject": True}})
c.append({"id": "utf16-json", "note": "The example's JSON encoded as UTF-16LE with a BOM. The README's Scope decodes UTF-8; a parser that sniffs the encoding from bytes (RFC 4627 section 3) would accept it.", "headers": H3, "value": b(raw.decode("utf-8").encode("utf-16")), "expect": {"reject": True}})
c.append({"id": "json-nan", "note": "An object whose member value is NaN. NaN is not a JSON value (RFC 8259 section 6), though several parsers accept it by default.", "headers": H3, "value": b(b'{"x402Version":NaN}'), "expect": {"reject": True}})
c.append({"id": "json-trailing", "note": "The example's JSON followed by ' {}'. RFC 8259: a JSON text is one value.", "headers": ["PAYMENT-RESPONSE"], "value": b(raw + b" {}"), "expect": {"reject": True}})
ex2 = inp["spec-payment-signature"]["value"]                 # http.md's PAYMENT-SIGNATURE example, one '=' of padding
last = ex2.rstrip("=")
alt = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
pad = len(ex2) - len(last)
nz = last[:-1] + alt[alt.index(last[-1]) | (0b1111 if pad == 2 else 0b11)] + "=" * pad
c.append({"id": "pad-bits-nonzero", "note": "The PAYMENT-SIGNATURE example with the two unused bits of its last character set. RFC 4648 3.5 lets a decoder reject this; the spec does not say whether an x402 decoder must. No expectation is proposed: the spec could choose one.", "headers": ["PAYMENT-SIGNATURE"], "value": nz, "expect": None})
json.dump({"candidate_for": "specs/transports-v2/vectors/http_headers.json (x402 PR #4066 at c3e23c9)", "decode": c}, open(sys.argv[2], "w"), indent=1, ensure_ascii=False)
print(len(c), "pad", pad)
