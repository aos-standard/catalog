#!/usr/bin/env python3
"""Build two proposed JWS vectors for the offer-receipt set of x402-foundation/x402#3207, under its published test key
(seed 0x42 * 32), and run the frozen verifier on them.

 P1 offer_unknown_kid    a valid offer, signed by the test key, whose header names a kid the verifier does not hold
 P2 offer_extra_field    a valid offer with one member outside §4.2 (`note`), correctly signed
`expect` is left for the set's author. This catalog's verifier rejects both (R3, R5); the author's verifier
returns `key_unavailable` for P1 and accepts P2 (x402-foundation/x402#3207, 2026-10-25).
Ed25519 signing is RFC 8032 5.1.6, written here; each signature is checked by OpenSSL after building.
Usage: python3 -I -B build_proposed.py <offer-receipt-vectors.json> <out proposed.json>
"""
from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import x402_offer_receipt as v  # noqa: E402


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def ed25519_sign(seed: bytes, msg: bytes) -> tuple[bytes, bytes]:
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    A = v._ed_mul(a, v._ED_G)

    def enc(p):
        zi = pow(p[2], v._P - 2, v._P)
        x, y = p[0] * zi % v._P, p[1] * zi % v._P
        return (y | ((x & 1) << 255)).to_bytes(32, "little")

    pub = enc(A)
    r = int.from_bytes(hashlib.sha512(h[32:] + msg).digest(), "little") % v._L
    R = enc(v._ed_mul(r, v._ED_G))
    k = int.from_bytes(hashlib.sha512(R + pub + msg).digest(), "little") % v._L
    s = (r + k * a) % v._L
    return pub, R + s.to_bytes(32, "little")


def openssl_ok(pub: bytes, msg: bytes, sig: bytes) -> bool:
    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        der = bytes.fromhex("302a300506032b6570032100") + pub
        (p / "k.pem").write_bytes(b"-----BEGIN PUBLIC KEY-----\n" + base64.encodebytes(der) + b"-----END PUBLIC KEY-----\n")
        (p / "m").write_bytes(msg); (p / "s").write_bytes(sig)
        r = subprocess.run(["openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", str(p / "k.pem"),
                            "-in", str(p / "m"), "-sigfile", str(p / "s")], capture_output=True, text=True)
        return "Signature Verified Successfully" in r.stdout


def main() -> int:
    src = json.loads(Path(sys.argv[1]).read_text())
    sg = src["signing"]
    seed = bytes.fromhex(sg["test_seed_hex"])
    base_payload = next(x for x in src["valid"] if x["name"] == "offer_valid")["payload"]
    cases = [
        ("offer_unknown_kid", {"alg": "EdDSA", "kid": "did:web:scvd.store#not-a-published-key"}, dict(base_payload),
         "Signed by the test key, but the header names a kid the verifier holds no key for."),
        ("offer_extra_field", {"alg": "EdDSA", "kid": sg["kid"]}, dict(base_payload, note="one member outside §4.2"),
         "Correctly signed by the test key; the payload carries one member that §4.2 does not define."),
    ]
    keys = {sg["kid"]: {"alg": "EdDSA", "public_key": bytes.fromhex(sg["public_key_hex"]), "authorized": True}}
    out, ok_all = [], True
    for name, header, payload, note in cases:
        h, p = b64u(json.dumps(header, separators=(",", ":")).encode()), b64u(json.dumps(payload, separators=(",", ":")).encode())
        pub, sig = ed25519_sign(seed, (h + "." + p).encode())
        assert pub.hex() == sg["public_key_hex"], "seed does not give the published key"
        ossl = openssl_ok(pub, (h + "." + p).encode(), sig)
        got = v.verify_jws("offer", h + "." + p + "." + b64u(sig), keys, None)
        ok_all &= ossl
        out.append({"name": name, "expect": None, "note": note, "payload": payload, "jws": h + "." + p + "." + b64u(sig),
                    "signature_verifies_openssl": ossl, "this_catalog_verifier": {"accept": got["accept"], "stage": got["stage"], "detail": got["detail"]}})
        print(f"{name:20} openssl={'ok' if ossl else 'FAIL'} this_verifier={'accept' if got['accept'] else 'reject'}@{got['stage']} {got['detail']}")
    Path(sys.argv[2]).write_text(json.dumps({"proposed_for": "x402-foundation/x402#3207", "license": "CC0-1.0",
                                             "signing": {"kid_of_published_key": sg["kid"], "public_key_hex": sg["public_key_hex"]},
                                             "vectors": out}, indent=1, ensure_ascii=False) + "\n")
    return 0 if ok_all else 1


if __name__ == "__main__":
    raise SystemExit(main())
