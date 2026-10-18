#!/usr/bin/env python3
"""Proposed vector 22: a criteria token whose imprint is SHA-1 over the right bytes (wrong algorithm).

Pins the one mutation the eleven plus 12-21 leave open (lax_battery M22: "ignore the imprint
algorithm OID"). The token's DER lengths differ from vector 01's, so this file encodes the
TimeStampResp itself with a minimal DER builder instead of substituting bytes.

Usage: python3 -I build_vector22.py <repo clone> <out dir>
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parent))
from war_cold_verifier import jcs, parse_tsr, verify  # noqa: E402

repo, out = Path(sys.argv[1]), Path(sys.argv[2])
base = json.loads((repo / "vectors/01-valid.json").read_text(encoding="utf-8"))
keyfile = json.loads((out.parent / "TEST_KEY.json").read_text(encoding="utf-8"))
k1 = keyfile["keys"][0]
priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(k1["private_seed_hex"]))


# ---- minimal DER
def tlv(tag: int, body: bytes) -> bytes:
    n = len(body)
    if n < 0x80:
        ln = bytes([n])
    else:
        nb = (n.bit_length() + 7) // 8
        ln = bytes([0x80 | nb]) + n.to_bytes(nb, "big")
    return bytes([tag]) + ln + body


def seq(*parts: bytes) -> bytes:
    return tlv(0x30, b"".join(parts))


def integer(v: int) -> bytes:
    b = v.to_bytes((v.bit_length() + 8) // 8 or 1, "big", signed=True)
    return tlv(0x02, b)


def oid(dotted: str) -> bytes:
    arcs = [int(x) for x in dotted.split(".")]
    body = bytes([40 * arcs[0] + arcs[1]])
    for a in arcs[2:]:
        enc = [a & 0x7F]
        a >>= 7
        while a:
            enc.append(0x80 | (a & 0x7F))
            a >>= 7
        body += bytes(reversed(enc))
    return tlv(0x06, body)


def octets(b: bytes) -> bytes:
    return tlv(0x04, b)


def explicit0(body: bytes) -> bytes:
    return tlv(0xA0, body)


def gentime(s: str) -> bytes:
    return tlv(0x18, s.encode("ascii"))


def tsr(imprint_alg: str, imprint: bytes, gen: str, serial: int = 7) -> bytes:
    """TimeStampResp{ status{0}, ContentInfo{ id-signedData, [0] SignedData{3, {}, EncapContentInfo{ id-ct-TSTInfo, [0] OCTET STRING(TSTInfo) } } } }."""
    alg_id = seq(oid(imprint_alg), tlv(0x05, b""))  # AlgorithmIdentifier with NULL params
    tst_info = seq(integer(1), oid("1.2.3.4"), seq(alg_id, octets(imprint)), integer(serial), gentime(gen))
    eci = seq(oid("1.2.840.113549.1.9.16.1.4"), explicit0(octets(tst_info)))
    signed_data = seq(integer(3), tlv(0x31, b""), eci)
    content_info = seq(oid("1.2.840.113549.1.7.2"), explicit0(signed_data))
    return seq(seq(integer(0)), content_info)


# sanity: our encoder reproduces vector 01's criteria token when given the same fields
t01 = parse_tsr(base64.b64decode(base["inputs"]["criteria_tsr_base64"]))
ours = tsr("2.16.840.1.101.3.4.2.1", bytes.fromhex(t01["imprint_hex"]), t01["gen_time"])
same_fields = parse_tsr(ours)
assert same_fields["imprint_hex"] == t01["imprint_hex"] and same_fields["gen_time"] == t01["gen_time"]
print("encoder round-trip on vector 01 fields: ok; byte-identical to upstream token:", ours == base64.b64decode(base["inputs"]["criteria_tsr_base64"]))

vec = copy.deepcopy(base)
inp = vec["inputs"]
r = inp["receipt"]["receipt"]
r["key_id"] = k1["key_id"]
r["parties"]["checker"]["key_id"] = k1["key_id"]
inp["keys"] = {"issuer": "cold verifier (proposed test vectors)", "keys": [{"alg": "Ed25519", "key_id": k1["key_id"], "public_key_base64": k1["public_key_base64"], "status": "test"}]}
inp["receipt_tsr_base64"] = None
inp["receipt"]["timestamp"] = None
criteria_bytes = base64.b64decode(inp["criteria_file_base64"])
sha1 = hashlib.sha1(criteria_bytes).digest()
inp["criteria_tsr_base64"] = base64.b64encode(tsr("1.3.14.3.2.26", sha1, "20260301000000Z")).decode()
inp["receipt"]["signature"] = {"alg": "Ed25519", "key_id": k1["key_id"], "value": base64.b64encode(priv.sign(jcs(r))).decode()}
vec.update({
    "vector": "22-criteria-token-sha1-imprint",
    "title": "Criteria token imprint is SHA-1 over the right bytes",
    "description": "A structurally valid token whose messageImprint algorithm is SHA-1 (1.3.14.3.2.26) and whose 20-byte imprint is SHA-1 of the committed criteria document. A verifier that compares only the digest bytes to criteria.sha256 fails on length; one that ignores the algorithm and recomputes with the token's own algorithm accepts it. Step 5 says the imprint must equal criteria.sha256, which is a SHA-256 value, so the algorithm must be SHA-256.",
    "pins": "imprint algorithm OID (lax_battery M22)",
    "contributed_by": "proposed by the maintainer of aos-standard/catalog from the cold verifier in docs/runs/work-acceptance-record-cold (CC0)",
    "license": "CC0-1.0",
})
got = verify(vec)
vec["expected"] = {k: got[k] for k in ("criteria_committed_before_check", "criteria_hash", "independence", "problem_codes", "receipt_timestamp", "signature_valid", "verdict_recomputed", "verdict_stated", "warning_codes")}
(out / "22-criteria-token-sha1-imprint.json").write_text(json.dumps(vec, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print(json.dumps(vec["expected"]))
