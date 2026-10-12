#!/usr/bin/env python3
"""Independent reader for the PriorSeal exact-call envelope matrix v1.

Written from INPUT-CONTRACT.md alone (sections 2.1, 2.2, 4, 5). It does not
import, read or port reader.mjs / verify.mjs or any PriorSeal source.
Standard library only, except Ed25519 verification (cryptography), which is
optional and reported as "not_checked" when unavailable.

Usage: python3 -I oel_exact_call_reader.py <matrix-dir>
Prints one JSON object. Never reads expected.json or report.json.
"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

# ---------------------------------------------------------------- keccak-256
_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
_ROT = [
    [0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56], [27, 20, 39, 8, 14],
]
_M = (1 << 64) - 1


def _rol(x: int, n: int) -> int:
    n %= 64
    return ((x << n) | (x >> (64 - n))) & _M if n else x


def _f1600(a: list[list[int]]) -> None:
    for rc in _RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                a[x][y] ^= d[x]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rol(a[x][y], _ROT[x][y])
        for x in range(5):
            for y in range(5):
                a[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y])
        a[0][0] ^= rc


def keccak256(data: bytes) -> bytes:
    rate = 136
    p = bytearray(data)
    p.append(0x01)
    while len(p) % rate:
        p.append(0)
    p[-1] |= 0x80
    a = [[0] * 5 for _ in range(5)]
    for off in range(0, len(p), rate):
        for i in range(rate // 8):
            a[i % 5][i // 5] ^= int.from_bytes(p[off + 8 * i: off + 8 * i + 8], "little")
        _f1600(a)
    return b"".join(a[i % 5][i // 5].to_bytes(8, "little") for i in range(4))


# ------------------------------------------------------- secp256k1 recovery
_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def _add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % _P == 0:
        return None
    if p == q:
        lam = 3 * p[0] * p[0] * pow(2 * p[1], -1, _P) % _P
    else:
        lam = (q[1] - p[1]) * pow(q[0] - p[0], -1, _P) % _P
    x = (lam * lam - p[0] - q[0]) % _P
    return x, (lam * (p[0] - x) - p[1]) % _P


def _mul(k: int, p):
    r = None
    while k:
        if k & 1:
            r = _add(r, p)
        p = _add(p, p)
        k >>= 1
    return r


def recover_address(digest: bytes, sig: bytes) -> str:
    if len(sig) != 65:
        raise ValueError("signature is not 65 bytes")
    r, s, v = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:64], "big"), sig[64]
    rec = v - 27 if v in (27, 28) else v
    if rec not in (0, 1) or not (0 < r < _N and 0 < s < _N):
        raise ValueError("signature out of range")
    y = pow((pow(r, 3, _P) + 7) % _P, (_P + 1) // 4, _P)
    if (y * y - pow(r, 3, _P) - 7) % _P:
        raise ValueError("r is not on the curve")
    if y % 2 != rec:
        y = _P - y
    z = int.from_bytes(digest, "big")
    rinv = pow(r, -1, _N)
    q = _add(_mul(s * rinv % _N, (r, y)), _mul((-z * rinv) % _N, _G))
    pub = q[0].to_bytes(32, "big") + q[1].to_bytes(32, "big")
    return "0x" + keccak256(pub)[-20:].hex()


# ------------------------------------------------------------------ EIP-712
_AUTH_FIELDS = [
    ("intentHash", "bytes32"), ("principalType", "string"), ("principalId", "string"),
    ("principalAccount", "address"), ("authorizerType", "string"), ("authorizer", "address"),
    ("agentId", "string"), ("executor", "address"), ("issuedAt", "uint256"),
    ("notBefore", "uint256"), ("expiresAt", "uint256"), ("authorizationNonce", "bytes32"),
    ("maxUses", "uint256"), ("audience", "string"), ("policyHash", "bytes32"),
]


def _enc(kind: str, value) -> bytes:
    if kind == "string":
        return keccak256(str(value).encode("utf-8"))
    if kind == "bytes32":
        h = value[2:] if value.startswith("0x") else value
        b = bytes.fromhex(h)
        if len(b) != 32:
            raise ValueError("bytes32 is not 32 bytes")
        return b
    if kind == "address":
        return bytes.fromhex(value[2:]).rjust(32, b"\x00")
    if kind == "uint256":
        return int(value).to_bytes(32, "big")
    raise ValueError(kind)


def eip712_digest(auth: dict) -> tuple[bytes, dict]:
    intent = auth["intent"]
    # The contract gives struct field names and types but not the JSON paths
    # they are read from. This mapping is the reader's inference.
    message = {
        "intentHash": intent["intentHash"],
        "principalType": auth["principal"]["type"],
        "principalId": auth["principal"]["id"],
        "principalAccount": auth["principal"]["account"],
        "authorizerType": auth["authorizer"]["type"],
        "authorizer": auth["authorizer"]["address"],
        "agentId": auth["delegate"]["agentId"],
        "executor": auth["delegate"]["executor"],
        "issuedAt": auth["issuedAt"],
        "notBefore": auth["notBefore"],
        "expiresAt": auth["expiresAt"],
        "authorizationNonce": auth["authorizationNonce"],
        "maxUses": auth["maxUses"],
        "audience": auth["audience"],
        "policyHash": auth["policyHash"],
    }
    type_str = "PriorSealAuthorization(" + ",".join(f"{t} {n}" for n, t in _AUTH_FIELDS) + ")"
    struct = keccak256(keccak256(type_str.encode()) + b"".join(_enc(t, message[n]) for n, t in _AUTH_FIELDS))
    dom_type = b"EIP712Domain(string name,string version,uint256 chainId)"
    domain = keccak256(
        keccak256(dom_type) + keccak256(b"PriorSeal") + keccak256(b"2")
        + int(intent["chainId"]).to_bytes(32, "big")
    )
    json_types = {k: type(auth[k]).__name__ for k in ("issuedAt", "notBefore", "expiresAt", "maxUses")}
    return keccak256(b"\x19\x01" + domain + struct), json_types


# --------------------------------------------------------- acceptance (2.2)
def check_acceptance(acceptance: dict, keys: dict) -> dict:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except Exception:  # pragma: no cover
        return {"status": "not_checked", "why": "no Ed25519 library"}
    issuer = keys.get("issuer", {})
    raw = used = None
    for name, v in issuer.items():
        if not isinstance(v, str) or "private" in name.lower() or "seed" in name.lower():
            continue
        for dec in (
            lambda s: bytes.fromhex(s[2:] if s.startswith("0x") else s),
            lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)),
        ):
            try:
                cand = dec(v)
            except Exception:
                continue
            if len(cand) == 32:
                raw, used = cand, name
                break
        if raw:
            break
    if raw is None:
        return {"status": "not_checked", "why": "no 32-byte Ed25519 public key field found", "issuerFields": sorted(issuer)}
    body = {k: v for k, v in acceptance.items() if k != "signature"}
    # "RFC 8785-style": sorted keys, no insignificant whitespace, UTF-8.
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    sig = base64.urlsafe_b64decode(acceptance["signature"] + "=" * (-len(acceptance["signature"]) % 4))
    try:
        Ed25519PublicKey.from_public_bytes(raw).verify(sig, canon)
        return {"status": "valid", "keyField": used}
    except Exception:
        return {"status": "invalid", "keyField": used}


# ------------------------------------------------------- sections 4 and 5
def _ci(a, b) -> bool:
    return str(a).lower() == str(b).lower()


def compare(intent: dict, obs: dict) -> list[str]:
    codes = []
    if intent.get("chainId") != obs.get("chainId") or type(intent.get("chainId")) is not type(obs.get("chainId")):
        codes.append("CHAIN_MISMATCH")
    if not _ci(intent.get("action"), obs.get("action")):
        codes.append("ACTION_MISMATCH")
    if not _ci(intent.get("sender"), obs.get("sender")):
        codes.append("SENDER_MISMATCH")
    if intent.get("nonce", "0") != obs.get("nonce", "0"):
        codes.append("NONCE_MISMATCH")
    if "callTarget" in intent and not _ci(intent["callTarget"], obs.get("target")):
        codes.append("CALL_TARGET_MISMATCH")
    if "calldataHash" in intent and not _ci(intent["calldataHash"], obs.get("calldataHash")):
        codes.append("CALLDATA_MISMATCH")
    if "transactionValue" in intent and intent["transactionValue"] != obs.get("nativeValue"):
        codes.append("TRANSACTION_VALUE_MISMATCH")
    when = obs.get("executedAt", obs.get("observedAt"))
    if when is not None and when > intent["validUntil"]:
        codes.append("OUTSIDE_TIME_WINDOW")
    return sorted(set(codes))


def main() -> int:
    root = Path(sys.argv[1])
    src = json.loads((root / "fixture/signed-authorization.json").read_text(encoding="utf-8"))
    keys = json.loads((root / "fixture/public-test-keys.json").read_text(encoding="utf-8"))
    auth = src["authorization"]
    digest, json_types = eip712_digest(auth)
    recovered = recover_address(digest, bytes.fromhex(auth["signature"][2:]))
    out = {
        "reader": "independent-python-stdlib",
        "eip712": {
            "digest": "0x" + digest.hex(),
            "recovered": recovered,
            "declaredAuthorizer": auth["authorizer"]["address"],
            "signerMatches": recovered.lower() == auth["authorizer"]["address"].lower(),
            "jsonTypesSeen": json_types,
        },
        "acceptance": check_acceptance(src["acceptance"], keys),
        "cases": {},
    }
    for path in sorted((root / "fixture/observed").glob("*.json")):
        obs = json.loads(path.read_text(encoding="utf-8"))
        binding = compare(auth["intent"], obs)
        unavailable = obs.get("executionDataAvailable") is False
        out["cases"][path.stem] = {
            "bindingReasonCodes": binding,
            "bound": not binding,
            "availabilityCode": "EXECUTION_UNAVAILABLE" if unavailable else None,
        }
    print(json.dumps(out, indent=1, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
