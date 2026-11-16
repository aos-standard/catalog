#!/usr/bin/env python3
"""Clean-room reader for the did:atp DID method (W3C ATP Community Group draft, specs/did-atp/index.html).

Written from the specification text only: "Method-Specific Identifier Syntax", "The pq1_ Post-Quantum Binding
Fingerprint", the did:wba e1_ rule it adopts (RFC 7638 thumbprint of the Ed25519 OKP JWK), "The p_ Pseudonym Path
Segment" and "Recommended Derivation". The generator (scripts/gen-did-atp-vectors.ts), the proof directory and the
ATP SDK were not opened. Python standard library, `cryptography` for Ed25519, and the local
`openssl` (3.5 or later) for ML-DSA-65 key generation from a seed.

Choices the text leaves open, fixed before any expected value was read:
- HKDF salt: none given in the vectors' inputs, so the RFC 5869 default (HashLen zero bytes).
- domain-name: lowercase labels of a-z, 0-9 and "-", not starting or ending with "-", separated by dots, with an
  optional "%3A" port (the did:web convention did:wba keeps). The text does not define it.
- A path-type DID needs at least one path segment before e1_ and pq1_; any other shape is not a did:atp.
"""
import base64
import hashlib
import hmac
import json
import re
import subprocess
import sys
import tempfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

MLDSA65_PUB = 1952


def b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def thumbprint(jwk, members):
    canon = json.dumps({k: jwk[k] for k in sorted(members)}, separators=(",", ":"), ensure_ascii=False)
    return b64url(hashlib.sha256(canon.encode("utf-8")).digest())


def ed25519_jwk(pub):
    assert len(pub) == 32
    return {"crv": "Ed25519", "kty": "OKP", "x": b64url(pub)}


def mldsa65_jwk(pub):
    assert len(pub) == MLDSA65_PUB
    return {"alg": "ML-DSA-65", "kty": "AKP", "pub": b64url(pub)}


def e1(pub):
    return "e1_" + thumbprint(ed25519_jwk(pub), ("crv", "kty", "x"))


def pq1(pub):
    return "pq1_" + thumbprint(mldsa65_jwk(pub), ("alg", "kty", "pub"))


def path_did(domain, path, ed_pub, pq_pub):
    return "did:atp:" + domain + "".join(":" + s for s in path) + ":" + e1(ed_pub) + ":" + pq1(pq_pub)


# ------------------------------------------------------------- pairwise (RFC 5869 HKDF-SHA256)


def hkdf(ikm, info, length, salt=b""):
    prk = hmac.new(salt or b"\x00" * 32, ikm, hashlib.sha256).digest()
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


def info(label, peer):
    return ("atp-pairwise:v1:" + label + ":" + peer).encode("utf-8")


def ed25519_pub_from_seed(seed):
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def mldsa65_pub_from_seed(seed):
    with tempfile.TemporaryDirectory() as td:
        key = td + "/k.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ML-DSA-65", "-pkeyopt", "hexseed:" + seed.hex(), "-out", key],
                       check=True, capture_output=True)
        der = subprocess.run(["openssl", "pkey", "-in", key, "-pubout", "-outform", "DER"], check=True, capture_output=True).stdout
    return der[-MLDSA65_PUB:]


def pairwise(domain, master, peer, salt=b""):
    if len(master) < 32:
        raise ValueError("master secret shorter than 32 bytes")
    ed_seed = hkdf(master, info("ed25519", peer), 32, salt)
    pq_seed = hkdf(master, info("ml-dsa-65", peer), 32, salt)
    pseud = hkdf(master, info("path", peer), 16, salt)
    seg = "p_" + pseud.hex()
    return {"peerSegment": seg, "did": path_did(domain, [seg], ed25519_pub_from_seed(ed_seed), mldsa65_pub_from_seed(pq_seed))}


# ------------------------------------------------------------- syntax

LABEL = r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
DOMAIN = rf"{LABEL}(?:\.{LABEL})*(?:%3A[0-9]+)?"
SEG = r"[A-Za-z0-9_.-]+"
B64 = r"[A-Za-z0-9_-]{43}"
ROOT_RE = re.compile(rf"did:atp:({DOMAIN})")
PATH_RE = re.compile(rf"did:atp:({DOMAIN})((?::{SEG})+):e1_({B64}):pq1_({B64})")


def parse(value):
    """Return ("root", domain) or ("path", domain, [segments], e1, pq1); raise ValueError otherwise."""
    m = ROOT_RE.fullmatch(value)
    if m:
        return ("root", m.group(1))
    m = PATH_RE.fullmatch(value)
    if m:
        segs = m.group(2)[1:].split(":")
        if any(s.startswith("e1_") or s.startswith("pq1_") for s in segs):
            raise ValueError("binding segment in the path")
        return ("path", m.group(1), segs, "e1_" + m.group(3), "pq1_" + m.group(4))
    raise ValueError("not a did:atp identifier")


def run(given):
    out = {"rootIdentifiers": [], "pathIdentifiers": [], "pairwiseIdentifiers": [], "invalidIdentifiers": []}
    for v in given["rootIdentifiers"]:
        did = "did:atp:" + v["domain"]
        try:
            parse(did)
            out["rootIdentifiers"].append({"i": v["i"], "did": did})
        except ValueError as e:
            out["rootIdentifiers"].append({"i": v["i"], "error": str(e)})
    for v in given["pathIdentifiers"]:
        ed, pq = bytes.fromhex(v["ed25519PublicKeyHex"]), bytes.fromhex(v["mlDsa65PublicKeyHex"])
        did = path_did(v["domain"], v["path"], ed, pq)
        parse(did)
        out["pathIdentifiers"].append({"i": v["i"], "ed25519Jwk": ed25519_jwk(ed), "mlDsa65Jwk": mldsa65_jwk(pq),
                                       "e1": e1(ed), "pq1": pq1(pq), "did": did})
    for v in given["pairwiseIdentifiers"]:
        r = pairwise(v["domain"], bytes.fromhex(v["masterSecretHex"]), v["peerId"])
        parse(r["did"])
        out["pairwiseIdentifiers"].append({"i": v["i"], **r})
    for v in given["invalidIdentifiers"]:
        try:
            p = parse(v["value"])
            out["invalidIdentifiers"].append({"i": v["i"], "valid": True, "parsed": list(p[:2])})
        except ValueError as e:
            out["invalidIdentifiers"].append({"i": v["i"], "valid": False, "reason": str(e)})
    return out


if __name__ == "__main__":
    print(json.dumps(run(json.load(open(sys.argv[1]))), indent=1, sort_keys=True))
