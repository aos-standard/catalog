#!/usr/bin/env python3
"""Clean-room verifier for the x402 Offer and Receipt extension (offers and receipts, `jws` and `eip712`).

Written 2026-10-25 from `specs/extensions/extension-offer-and-receipt.md` at x402-foundation/x402 4241d56
(sha256 51151bd2…6ae9, version 0.6) and the input shape of two vector files: the JWS set of PR #3207
(head 96f7a71) and the EIP-712 set of issue #3533. Not opened: `@x402/extensions` (the reference), the PR's
`offer-receipt-vectors.test.ts`, and any generator. Answer-exposed: both files carry `expect` and
`reject_at` next to the inputs, and they were on screen while the input shape was read.
Standard library only. Keccak-256 and Ed25519 are this catalog's own code (from its evm-log and E6 runs);
secp256k1 recovery, ES256K, EIP-712 encoding and EIP-55 are written here.

Readings, fixed before the first scored run (R7 and R9 after the vectors' expectations were seen; see RUN.md):
 R1 JWS compact: three base64url segments without padding; header and payload decode to JSON objects.
 R2 JWS `alg` must be the algorithm of the configured key for that `kid` (EdDSA for Ed25519, ES256K for
    secp256k1). The header's `alg` never selects the algorithm (§3.3 names examples, not a choice for the sender).
 R3 JWS `kid` is required (§3.3) and is looked up in the verifier's configured keys; an unknown kid is rejected.
    Resolving a DID is outside this reader: the keys are an input.
 R4 Signature input is ASCII(header segment "." payload segment) as transmitted; the payload is not
    re-canonicalised (§10's JCS rule binds the signer).
 R5 Payload schema (§4.2, §5.2): every required field present with its JSON type, `version` = 1 (the only
    version defined), integers for `version`, `validUntil`, `issuedAt`. Unknown payload fields are rejected
    (§2: treat unknown fields as unsupported).
 R6 EIP-712: domain {name: "x402 offer" | "x402 receipt", version: "1", chainId: 1}; types and primaryType from
    §4.3/§5.3 only. A transmitted `types` or `primaryType` is rejected (§3.2.1 MUST NOT be included).
 R7 EIP-712 payload must carry every field of the fixed type, the optional ones at their empty value
    (§4.3 "MUST set unused fields to 0", §5.3 likewise); an omitted optional field is a schema failure.
    (§6's JSON schemas list them as not required; this reader follows §4.3/§5.3.)
 R8 EIP-712 `signature`: "0x" + 130 hex digits, v in {27, 28, 0, 1}, r and s in [1, n-1]; high s is accepted
    (the extension says nothing about malleability).
 R9 Authorization (§4.5.1): the recovered address, or the JWS key, must be one the verifier configured as
    authorized for the artifact. With ECDSA recovery an altered payload and an unauthorized key both surface
    as "recovered signer is not the configured one"; this reader reports `signer_not_authorized` for both.
 R10 Expiry (§4.6) and `issuedAt` policy (§5.5 step 6) are reported, not enforced: an expired offer still verifies.
 R11 EIP-712 `network` must be `eip155:<chainId>`; offer `payTo` must be an EVM address (40 hex digits, and if
    mixed-case, valid EIP-55).

Public entry points: `verify_jws(kind, compact, keys, now)` and `verify_eip712(kind, artifact, authorized, now)`,
each -> {"accept": bool, "stage": str | None, "detail": str, ...}. Stages: parse, alg, kid, signature, schema,
authorization.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re

# --------------------------------------------------------------------------- Keccak-256 (Ethereum padding)
_RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B,
       0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088,
       0x0000000080008009, 0x000000008000000A, 0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
       0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
       0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_M64 = (1 << 64) - 1


def _rot(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & _M64 if n else x


def _keccak_f(a):
    for rc in _RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rot(c[(x + 1) % 5], 1) for x in range(5)]
        a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rot(a[x][y], _ROT[x][y])
        a = [[b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
        a[0][0] ^= rc
    return a


def keccak256(msg: bytes) -> bytes:
    r = 136
    m = bytearray(msg) + b"\x01"
    m += b"\x00" * ((-len(m)) % r)
    m[-1] |= 0x80
    a = [[0] * 5 for _ in range(5)]
    for i in range(0, len(m), r):
        for j in range(r // 8):
            a[j % 5][j // 5] ^= int.from_bytes(m[i + 8 * j:i + 8 * j + 8], "little")
        a = _keccak_f(a)
    return b"".join(a[j % 5][j // 5].to_bytes(8, "little") for j in range(4))


# --------------------------------------------------------------------------- Ed25519 verify (RFC 8032 5.1.7)
_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _ed_recover_x(y: int, sign: int):
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _I % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


def _ed_decode(b: bytes):
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _ed_recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _P)


def _ed_add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _ed_mul(s: int, p):
    q = (0, 1, 1, 0)
    while s:
        if s & 1:
            q = _ed_add(q, p)
        p = _ed_add(p, p)
        s >>= 1
    return q


def _ed_eq(p, q) -> bool:
    return (p[0] * q[2] - q[0] * p[2]) % _P == 0 and (p[1] * q[2] - q[1] * p[2]) % _P == 0


_ED_GY = 4 * pow(5, _P - 2, _P) % _P
_ED_G = (_ed_recover_x(_ED_GY, 0), _ED_GY, 1, _ed_recover_x(_ED_GY, 0) * _ED_GY % _P)


def ed25519_verify(pub: bytes, msg: bytes, sig: bytes) -> bool:
    if len(pub) != 32 or len(sig) != 64:
        return False
    a, r = _ed_decode(pub), _ed_decode(sig[:32])
    if a is None or r is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _L:
        return False
    k = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(), "little") % _L
    return _ed_eq(_ed_mul(s, _ED_G), _ed_add(r, _ed_mul(k, a)))


# --------------------------------------------------------------------------- secp256k1 (recovery, ES256K)
_SP = 2 ** 256 - 2 ** 32 - 977
_SN = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_SG = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
       0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _sk_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % _SP == 0:
        return None
    if p == q:
        lam = 3 * p[0] * p[0] * pow(2 * p[1], _SP - 2, _SP) % _SP
    else:
        lam = (q[1] - p[1]) * pow(q[0] - p[0], _SP - 2, _SP) % _SP
    x = (lam * lam - p[0] - q[0]) % _SP
    return (x, (lam * (p[0] - x) - p[1]) % _SP)


def _sk_mul(k: int, p):
    r = None
    while k:
        if k & 1:
            r = _sk_add(r, p)
        p = _sk_add(p, p)
        k >>= 1
    return r


def secp256k1_recover(digest: bytes, r: int, s: int, recid: int):
    """Public key point for (r, s, recovery id), or None."""
    if not (1 <= r < _SN and 1 <= s < _SN) or recid not in (0, 1):
        return None
    x = r
    y2 = (pow(x, 3, _SP) + 7) % _SP
    y = pow(y2, (_SP + 1) // 4, _SP)
    if y * y % _SP != y2:
        return None
    if y % 2 != recid:
        y = _SP - y
    e = int.from_bytes(digest, "big") % _SN
    rinv = pow(r, _SN - 2, _SN)
    q = _sk_mul(rinv, _sk_add(_sk_mul(s, (x, y)), _sk_mul((-e) % _SN, _SG)))
    return q


def eth_address(point) -> str:
    raw = point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big")
    return "0x" + keccak256(raw)[12:].hex()


def es256k_verify(pub: bytes, msg: bytes, sig: bytes) -> bool:
    """ECDSA over secp256k1 with SHA-256 (RFC 8812), raw r||s; pub is 65-byte uncompressed."""
    if len(sig) != 64 or len(pub) != 65 or pub[0] != 4:
        return False
    q = (int.from_bytes(pub[1:33], "big"), int.from_bytes(pub[33:], "big"))
    if (q[1] * q[1] - pow(q[0], 3, _SP) - 7) % _SP:
        return False
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if not (1 <= r < _SN and 1 <= s < _SN):
        return False
    e = int.from_bytes(hashlib.sha256(msg).digest(), "big") % _SN
    w = pow(s, _SN - 2, _SN)
    pt = _sk_add(_sk_mul(e * w % _SN, _SG), _sk_mul(r * w % _SN, q))
    return pt is not None and pt[0] % _SN == r


# --------------------------------------------------------------------------- payload schema (§4.2, §5.2)
FIELDS = {  # name -> (json type, required)
    "offer": {"version": ("int", True), "resourceUrl": ("str", True), "scheme": ("str", True),
              "network": ("str", True), "asset": ("str", True), "payTo": ("str", True),
              "amount": ("str", True), "validUntil": ("int", False)},
    "receipt": {"version": ("int", True), "network": ("str", True), "resourceUrl": ("str", True),
                "payer": ("str", True), "issuedAt": ("int", True), "transaction": ("str", False)},
}
EIP712_TYPES = {  # §4.3, §5.3 — order is normative
    "offer": [("version", "uint256"), ("resourceUrl", "string"), ("scheme", "string"), ("network", "string"),
              ("asset", "string"), ("payTo", "string"), ("amount", "string"), ("validUntil", "uint256")],
    "receipt": [("version", "uint256"), ("network", "string"), ("resourceUrl", "string"), ("payer", "string"),
                ("issuedAt", "uint256"), ("transaction", "string")],
}
PRIMARY = {"offer": "Offer", "receipt": "Receipt"}
DOMAIN_NAME = {"offer": "x402 offer", "receipt": "x402 receipt"}


def _is_int(v) -> bool:
    return type(v) is int and 0 <= v < 2 ** 256


def schema_problem(kind: str, payload: object, *, all_fields: bool = False) -> str | None:
    if not isinstance(payload, dict):
        return "payload is not an object"
    spec = FIELDS[kind]
    for k in payload:
        if k not in spec:
            return f"unknown field {k}"
    for name, (typ, required) in spec.items():
        if name not in payload:
            if required or all_fields:
                return f"missing {name}"
            continue
        v = payload[name]
        if (typ == "int" and not _is_int(v)) or (typ == "str" and not isinstance(v, str)):
            return f"{name} has the wrong type"
    if payload["version"] != 1:
        return "version is not 1"
    return None


def _expired(kind: str, payload: dict, now: int | None) -> bool | None:
    if kind != "offer" or now is None or not payload.get("validUntil"):
        return None
    return now > payload["validUntil"]


# --------------------------------------------------------------------------- JWS
def _b64url(s: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]*", s) or len(s) % 4 == 1:
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def verify_jws(kind: str, compact: object, keys: dict, now: int | None = None) -> dict:
    """keys: kid -> {"alg": "EdDSA" | "ES256K", "public_key": bytes, "authorized": bool}."""
    def no(stage, detail):
        return {"accept": False, "stage": stage, "detail": detail}

    if not isinstance(compact, str) or compact.count(".") != 2:
        return no("parse", "not three segments")
    h64, p64, s64 = compact.split(".")
    try:
        header, payload_bytes, sig = json.loads(_b64url(h64)), _b64url(p64), _b64url(s64)
        payload = json.loads(payload_bytes)
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return no("parse", "a segment does not decode")
    if not isinstance(header, dict):
        return no("parse", "header is not an object")
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        return no("kid", "no kid")
    key = keys.get(kid)
    if key is None:
        return no("kid", "kid not among the configured keys")
    if header.get("alg") != key["alg"]:
        return no("alg", f"alg {header.get('alg')!r} is not the key's {key['alg']}")
    signing_input = (h64 + "." + p64).encode("ascii")
    ok = (ed25519_verify(key["public_key"], signing_input, sig) if key["alg"] == "EdDSA"
          else es256k_verify(key["public_key"], signing_input, sig))
    if not ok:
        return no("signature", "signature does not verify")
    problem = schema_problem(kind, payload)
    if problem:
        return no("schema", problem)
    if not key.get("authorized", False):
        return no("authorization", "key is not authorized for this resource")
    return {"accept": True, "stage": None, "detail": "", "payload": payload, "expired": _expired(kind, payload, now)}


# --------------------------------------------------------------------------- EIP-712
def _type_string(kind: str) -> bytes:
    return f"{PRIMARY[kind]}({','.join(f'{t} {n}' for n, t in EIP712_TYPES[kind])})".encode()


def _enc(t: str, v) -> bytes:
    return keccak256(v.encode("utf-8")) if t == "string" else v.to_bytes(32, "big")


def type_hash(kind: str) -> bytes:
    return keccak256(_type_string(kind))


def domain_separator(kind: str) -> bytes:
    th = keccak256(b"EIP712Domain(string name,string version,uint256 chainId)")
    return keccak256(th + keccak256(DOMAIN_NAME[kind].encode()) + keccak256(b"1") + (1).to_bytes(32, "big"))


def struct_hash(kind: str, payload: dict) -> bytes:
    return keccak256(type_hash(kind) + b"".join(_enc(t, payload[n]) for n, t in EIP712_TYPES[kind]))


def _evm_address_ok(a: str) -> bool:
    if not re.fullmatch(r"0x[0-9a-fA-F]{40}", a):
        return False
    body = a[2:]
    if body == body.lower() or body == body.upper():
        return True
    h = keccak256(body.lower().encode()).hex()
    return all((c.upper() if int(h[i], 16) >= 8 else c.lower()) == c for i, c in enumerate(body))


def verify_eip712(kind: str, artifact: object, authorized: set, now: int | None = None) -> dict:
    """authorized: lowercase EVM addresses the verifier accepts as signers for this artifact."""
    def no(stage, detail, **kw):
        return dict({"accept": False, "stage": stage, "detail": detail}, **kw)

    if not isinstance(artifact, dict) or artifact.get("format") != "eip712":
        return no("parse", "format is not eip712")
    sig = artifact.get("signature")
    if not isinstance(sig, str) or not re.fullmatch(r"0x[0-9a-fA-F]{130}", sig):
        return no("parse", "signature is not 65 hex bytes")
    raw = bytes.fromhex(sig[2:])
    r, s, v = int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:64], "big"), raw[64]
    if v not in (27, 28, 0, 1):
        return no("parse", f"v byte {v} is not 27, 28, 0 or 1")
    if "types" in artifact or "primaryType" in artifact:
        return no("schema", "artifact transmits types or primaryType")
    payload = artifact.get("payload")
    problem = schema_problem(kind, payload, all_fields=True)
    if problem:
        return no("schema", problem)
    if not re.fullmatch(r"eip155:[0-9]+", payload["network"]):
        return no("schema", "network is not eip155:<chainId>")
    if kind == "offer" and not _evm_address_ok(payload["payTo"]):
        return no("schema", "payTo is not an EVM address")
    sh = struct_hash(kind, payload)
    digest = keccak256(b"\x19\x01" + domain_separator(kind) + sh)
    point = secp256k1_recover(digest, r, s, v - 27 if v >= 27 else v)
    if point is None:
        return no("signature", "no public key recovers", struct_hash="0x" + sh.hex())
    signer = eth_address(point)
    if signer not in authorized:
        return no("authorization", "recovered signer is not a configured signer", signer=signer,
                  struct_hash="0x" + sh.hex(), reading="R9: altered payload and unauthorized key look alike")
    return {"accept": True, "stage": None, "detail": "", "signer": signer, "struct_hash": "0x" + sh.hex(),
            "expired": _expired(kind, payload, now)}
