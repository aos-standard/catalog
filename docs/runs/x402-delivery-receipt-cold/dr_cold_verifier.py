#!/usr/bin/env python3
"""Clean-room verifier for the x402 `delivery-receipt` extension, draft v0.2.1.

Written 2026-10-19 from `specs/extensions/delivery-receipt.md` at PR x402-foundation/x402#3783 head
737243dc (sha256 7f95be44…) and the input shape of `delivery-receipt.vectors.json`. The TypeScript
reference implementation and its port were not opened. Python 3.10, stdlib plus `cryptography`
(Ed25519 equation, SHA-256 is stdlib) and the local `openssl` binary (ML-DSA-65 / ML-DSA-87 via
`pkeyutl -verify -rawin`). JCS, the §3 subset check, the SSE frame parser, the stream digest, the
directory root, the Ed25519 key/point checks and all level logic are this file's own.

Public entry point: `verify(inputs, *, path, offline=False, skew=300, vector=None) -> dict`.
`inputs` follows Appendix A.7: receipt | reference+receiptDocument | eventStream (+reference/receiptDocument
inside the terminal event), directory, pinnedGovernanceKeys, now, settle, requirements, resourceUrl,
method, responseBody, responseStatus, paymentId (client-sent id, optional), offerReceipt (optional).
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import os
import re
import subprocess
import tempfile
from typing import Any
from urllib.parse import urlsplit

# --------------------------------------------------------------------------- constants (§3, §5.3, §5.6, §6, §7)
RECEIPT_DOMAIN = b"x402-delivery-receipt/1"
STREAM_DOMAIN = b"x402-delivery-stream/1"
DIR_SPEC = "x402-receipt-key-directory/1"
DIR_DOMAIN = b"x402-receipt-key-directory/1"
KEY_USE = "x402-delivery-receipt"
TERMINAL_EVENT = "x402-delivery-receipt"
ALGS = {  # alg -> (public key bytes, signature bytes)
    "ed25519": (32, 64),
    "ml-dsa-65": (1952, 3309),
    "ml-dsa-87": (2592, 4627),
}
ML_DSA_OID = {"ml-dsa-65": "2.16.840.1.101.3.4.3.18", "ml-dsa-87": "2.16.840.1.101.3.4.3.19"}
BASELINE = ("ed25519", "ml-dsa-65")
STATUSES = ("reserved", "active", "retiring", "retired", "revoked")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
KID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
CAIP2_RE = re.compile(r"^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$")
EVM_ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
SAFE_MAX = 2**53 - 1
LEVELS = ("integrity", "authentic", "trusted", "settlement", "delivery")

PAYLOAD_TYPES: dict[str, tuple] = {
    "version": (int,), "issuer": (str,), "resourceUrl": (str,), "method": (str,), "scheme": (str,),
    "network": (str,), "asset": (str,), "payTo": (str,), "amount": (str,), "payer": (str,),
    "transaction": (str,), "logIndex": (int, type(None)), "paymentId": (str, type(None)),
    "responseStatus": (int, type(None)), "responseContentType": (str, type(None)), "delivery": (dict,),
    "keyDirectoryEpoch": (int,), "keyDirectoryDigest": (str,), "issuedAt": (int,),
}
DIR_TYPES: dict[str, tuple] = {
    "spec": (str,), "issuer": (str,), "epoch": (int,), "prevRoot": (str,), "publishedAt": (int,),
    "governanceKeys": (list,), "keys": (list,), "root": (str,), "signatures": (list,),
}
KEY_TYPES: dict[str, tuple] = {
    "kid": (str,), "alg": (str,), "publicKey": (str,), "use": (str,), "status": (str,),
    "notBefore": (int, type(None)), "notAfter": (int, type(None)), "revokedAt": (int, type(None)),
}


class Fail(Exception):
    """A level fails with a code and a message."""

    def __init__(self, code: str, msg: str = ""):
        super().__init__(f"{code}: {msg}" if msg else code)
        self.code = code


# --------------------------------------------------------------------------- JSON: strict parse + JCS (§3, RFC 8785)
def _no_dup_pairs(pairs):
    out: dict = {}
    for k, v in pairs:
        if k in out:
            raise ValueError(f'duplicate member "{k}"')
        out[k] = v
    return out


def parse_strict(text: str | bytes) -> Any:
    """Parse JSON rejecting duplicate member names and non-finite numbers."""
    if isinstance(text, bytes):
        text = text.decode("utf-8")  # strict UTF-8; a lone surrogate cannot arrive this way
    def bad_const(c):
        raise ValueError(f"non-finite number {c}")
    return json.loads(text, object_pairs_hook=_no_dup_pairs, parse_constant=bad_const)


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def check_subset(v: Any, where: str = "$") -> None:
    """§3: only strings, booleans, null, arrays, objects and safe integers; valid Unicode strings."""
    if v is None or isinstance(v, bool):
        return
    if _is_int(v):
        if abs(v) > SAFE_MAX:
            raise Fail("JCS_SUBSET", f"{where}: integer outside the IEEE-754 safe range")
        return
    if isinstance(v, float):
        raise Fail("JCS_SUBSET", f"{where}: floating-point number")
    if isinstance(v, str):
        try:
            v.encode("utf-8")
        except UnicodeEncodeError:
            raise Fail("JCS_SUBSET", f"{where}: lone surrogate in string")
        return
    if isinstance(v, list):
        for i, x in enumerate(v):
            check_subset(x, f"{where}[{i}]")
        return
    if isinstance(v, dict):
        for k, x in v.items():
            if not isinstance(k, str):
                raise Fail("JCS_SUBSET", f"{where}: non-string member name")
            try:
                k.encode("utf-8")
            except UnicodeEncodeError:
                raise Fail("JCS_SUBSET", f"{where}: lone surrogate in member name")
            check_subset(x, f"{where}.{k}")
        return
    raise Fail("JCS_SUBSET", f"{where}: unsupported type {type(v).__name__}")


def _jcs_str(s: str) -> str:
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif o < 0x20:
            out.append(f"\\u{o:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def jcs(v: Any) -> str:
    """RFC 8785 serialization of a value inside the §3 subset (call check_subset first)."""
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if _is_int(v):
        return str(v)
    if isinstance(v, str):
        return _jcs_str(v)
    if isinstance(v, list):
        return "[" + ",".join(jcs(x) for x in v) + "]"
    if isinstance(v, dict):
        # RFC 8785 §3.2.3: sort by UTF-16 code units of the member name
        items = sorted(v.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(_jcs_str(k) + ":" + jcs(x) for k, x in items) + "}"
    raise Fail("JCS_SUBSET", f"cannot canonicalize {type(v).__name__}")


def jcs_bytes(v: Any) -> bytes:
    check_subset(v)
    return jcs(v).encode("utf-8")


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# --------------------------------------------------------------------------- base64, origins
def b64_canonical(s: str, where: str) -> bytes:
    if not isinstance(s, str) or not s or re.search(r"[^A-Za-z0-9+/=]", s) or s.count("=") > 2 or "=" in s.rstrip("="):
        raise Fail("BASE64", f"{where}: not canonical base64")
    try:
        raw = base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        raise Fail("BASE64", f"{where}: not canonical base64")
    if base64.b64encode(raw).decode("ascii") != s:
        raise Fail("BASE64", f"{where}: not canonical base64 (re-encoding differs)")
    return raw


def origin_of(url: str, where: str) -> str:
    """scheme://host[:port], host lower-cased, default port dropped. Raises on a non-absolute URL."""
    try:
        u = urlsplit(url)
    except ValueError:
        raise Fail("URL", f"{where}: unparsable URL")
    if u.scheme not in ("https", "http") or not u.hostname:
        raise Fail("URL", f"{where}: not an absolute http(s) URL")
    host = u.hostname.lower()
    port = u.port
    default = 443 if u.scheme == "https" else 80
    return f"{u.scheme}://{host}" + ("" if port in (None, default) else f":{port}")


def is_origin_string(s: str) -> bool:
    """§3 issuer: exactly scheme://host[:port], nothing else."""
    try:
        u = urlsplit(s)
    except ValueError:
        return False
    if u.scheme not in ("https", "http") or not u.hostname or u.path not in ("", ) or u.query or u.fragment or u.username or u.password:
        return False
    try:
        return origin_of(s, "issuer") == s or origin_of(s, "issuer") == s.lower()
    except Fail:
        return False


# --------------------------------------------------------------------------- Ed25519 (RFC 8032 strict) — own point checks + library equation
_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, -1, _P)) % _P
_ID = (0, 1, 1, 0)  # extended coordinates (X, Y, Z, T)


def _decode_point(b: bytes):
    """RFC 8032 §5.1.3 decoding; None if not a canonical encoding of a point on the curve."""
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= _P:
        return None  # non-canonical encoding
    y2 = y * y % _P
    u = (y2 - 1) % _P
    v = (_D * y2 + 1) % _P
    x2 = u * pow(v, -1, _P) % _P
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * pow(2, (_P - 1) // 4, _P) % _P
        if (x * x - x2) % _P != 0:
            return None
    if x == 0 and sign == 1:
        return None
    if x & 1 != sign:
        x = _P - x
    return (x, y, 1, x * y % _P)


def _add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = 2 * t1 * t2 * _D % _P
    d = 2 * z1 * z2 % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(pt, n):
    acc = _ID
    while n:
        if n & 1:
            acc = _add(acc, pt)
        pt = _add(pt, pt)
        n >>= 1
    return acc


def _is_identity(pt) -> bool:
    x, y, z, _ = pt
    return x % _P == 0 and (y - z) % _P == 0


def ed25519_key_ok(pub: bytes) -> tuple[bool, str]:
    """§6.1: canonical encoding of a point that is not of small order (we also require prime order)."""
    pt = _decode_point(pub)
    if pt is None:
        return False, "non-canonical or off-curve Ed25519 public key"
    if _is_identity(_mul(pt, 8)):
        return False, "small-order Ed25519 public key"
    if not _is_identity(_mul(pt, _L)):
        return False, "mixed-order Ed25519 public key"
    return True, ""


def ed25519_verify(pub: bytes, msg: bytes, sig: bytes) -> bool:
    """Strict: canonical key (not small order), canonical R, S < L, then the RFC 8032 equation via the library."""
    ok, _ = ed25519_key_ok(pub)
    if not ok or len(sig) != 64:
        return False
    if _decode_point(sig[:32]) is None:
        return False
    if int.from_bytes(sig[32:], "little") >= _L:
        return False
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:  # pragma: no cover
        raise RuntimeError("cryptography is required for Ed25519")
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


def ed25519_public_from_seed(seed: bytes) -> bytes:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    k = Ed25519PrivateKey.from_private_bytes(seed)
    return k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


# --------------------------------------------------------------------------- ML-DSA via the openssl binary
def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _der(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(body)) + body


def _der_oid(dotted: str) -> bytes:
    parts = [int(x) for x in dotted.split(".")]
    body = bytearray([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        enc = bytearray([p & 0x7F])
        p >>= 7
        while p:
            enc.insert(0, 0x80 | (p & 0x7F))
            p >>= 7
        body += enc
    return _der(0x06, bytes(body))


def spki(alg: str, pub: bytes) -> bytes:
    return _der(0x30, _der(0x30, _der_oid(ML_DSA_OID[alg])) + _der(0x03, b"\x00" + pub))


_OPENSSL_OK: dict[str, bool] = {}


def mldsa_backend(alg: str) -> bool:
    if alg not in _OPENSSL_OK:
        try:
            out = subprocess.run(["openssl", "list", "-signature-algorithms"], capture_output=True, text=True, timeout=20).stdout
            _OPENSSL_OK[alg] = alg.upper() in out.upper()
        except Exception:
            _OPENSSL_OK[alg] = False
    return _OPENSSL_OK[alg]


def mldsa_verify(alg: str, pub: bytes, msg: bytes, sig: bytes) -> bool:
    """Pure ML-DSA (empty context) with the system openssl. Raises RuntimeError when the backend is absent."""
    if not mldsa_backend(alg):
        raise RuntimeError(f"no {alg} backend")
    with tempfile.TemporaryDirectory() as td:
        kp, mp, sp = (os.path.join(td, n) for n in ("k.der", "m.bin", "s.bin"))
        with open(kp, "wb") as f:
            f.write(spki(alg, pub))
        with open(mp, "wb") as f:
            f.write(msg)
        with open(sp, "wb") as f:
            f.write(sig)
        r = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", kp, "-keyform", "DER", "-rawin",
                            "-in", mp, "-sigfile", sp], capture_output=True, text=True, timeout=60)
        return r.returncode == 0 and "Signature Verified Successfully" in r.stdout


def mldsa_public_from_seed(alg: str, seed: bytes) -> bytes | None:
    """FIPS 204 key from ξ via `openssl genpkey -pkeyopt hexseed:`; None when unsupported."""
    if not mldsa_backend(alg):
        return None
    r = subprocess.run(["openssl", "genpkey", "-algorithm", alg.upper(), "-pkeyopt", "hexseed:" + seed.hex(), "-outform", "PEM"],
                       capture_output=True, timeout=60)
    if r.returncode != 0:
        return None
    r2 = subprocess.run(["openssl", "pkey", "-pubout", "-outform", "DER"], input=r.stdout, capture_output=True, timeout=60)
    if r2.returncode != 0:
        return None
    n = ALGS[alg][0]
    return r2.stdout[-n:]


def sig_verify(alg: str, pub: bytes, msg: bytes, sig: bytes) -> bool:
    if alg == "ed25519":
        return ed25519_verify(pub, msg, sig)
    return mldsa_verify(alg, pub, msg, sig)


# --------------------------------------------------------------------------- receipt id, message, stream digest (§5.3, §5.6)
def receipt_id(payload: dict) -> str:
    return sha256_hex(jcs_bytes(payload))


def signed_message(rid: str) -> bytes:
    return RECEIPT_DOMAIN + b"\n" + rid.encode("ascii")


def stream_digest(frames: list[bytes]) -> tuple[str, list[str]]:
    d = hashlib.sha256(STREAM_DOMAIN).digest()
    steps = [d.hex()]
    for f in frames:
        d = hashlib.sha256(d + len(f).to_bytes(8, "big") + f).digest()
        steps.append(d.hex())
    return d.hex(), steps


# --------------------------------------------------------------------------- SSE parsing (§5.6, HTML "Server-sent events")
def sse_events(text: str) -> tuple[list[dict], bool]:
    """Events an EventSource would dispatch, in order. Returns (events, pending_discarded)."""
    if text.startswith("﻿"):
        text = text[1:]
    lines = re.split(r"\r\n|\r|\n", text)
    # the text ends with a line terminator iff the last split element is ""; a non-empty tail is a pending line
    events: list[dict] = []
    data: list[str] = []
    etype = ""
    last_id: str | None = None
    cur_id: str | None = None
    saw_fields_since_dispatch = False
    for ln in lines[:-1] if lines and lines[-1] == "" else lines:
        if ln == "":
            if data:  # dispatch (empty data buffer: no event)
                events.append({"event": etype or "message", "data": "\n".join(data), "id": last_id})
            data, etype = [], ""
            saw_fields_since_dispatch = False
            continue
        saw_fields_since_dispatch = True
        if ln.startswith(":"):
            continue
        if ":" in ln:
            field, value = ln.split(":", 1)
            if value.startswith(" "):
                value = value[1:]
        else:
            field, value = ln, ""
        if field == "event":
            etype = value
        elif field == "data":
            data.append(value)
        elif field == "id":
            if "\x00" not in value:
                last_id = value
        # retry and unknown fields: ignored
    pending = bool(data) or saw_fields_since_dispatch  # an unterminated event is discarded
    return events, pending


# --------------------------------------------------------------------------- shape checks
def _exact_members(obj: dict, types: dict[str, tuple], where: str, code: str) -> None:
    if not isinstance(obj, dict):
        raise Fail(code, f"{where}: not an object")
    missing = set(types) - set(obj)
    extra = set(obj) - set(types)
    if missing:
        raise Fail(code, f"{where}: missing {sorted(missing)}")
    if extra:
        raise Fail(code, f"{where}: unknown members {sorted(extra)}")
    for k, ts in types.items():
        v = obj[k]
        if isinstance(v, bool) and int in ts and bool not in ts:
            raise Fail(code, f"{where}.{k}: boolean where {ts} expected")
        if not isinstance(v, ts):
            raise Fail(code, f"{where}.{k}: wrong type {type(v).__name__}")


def check_payload(p: dict) -> None:
    """§5.2 members and types, §3 subset, §5.4/§5.6 delivery shapes, §6 nothing (signatures separate)."""
    check_subset(p, "payload")
    _exact_members(p, PAYLOAD_TYPES, "payload", "PAYLOAD_SHAPE")
    if p["version"] != 1:
        raise Fail("PAYLOAD_VERSION", "payload.version is not 1")
    if not is_origin_string(p["issuer"]):
        raise Fail("PAYLOAD_ISSUER", "payload.issuer is not an origin")
    origin_of(p["resourceUrl"], "payload.resourceUrl")
    if not p["method"] or p["method"] != p["method"].upper():
        raise Fail("PAYLOAD_METHOD", "payload.method is not an upper-case method")
    if not CAIP2_RE.match(p["network"]):
        raise Fail("PAYLOAD_NETWORK", "payload.network is not CAIP-2")
    if p["transaction"] == "":
        raise Fail("PAYLOAD_TRANSACTION", "payload.transaction is empty")
    if p["logIndex"] is not None and p["logIndex"] < 0:
        raise Fail("PAYLOAD_LOGINDEX", "negative logIndex")
    if p["keyDirectoryEpoch"] < 1:
        raise Fail("PAYLOAD_EPOCH", "keyDirectoryEpoch < 1")
    if not HEX64.match(p["keyDirectoryDigest"]):
        raise Fail("PAYLOAD_DIGEST", "keyDirectoryDigest is not 64 lowercase hex")
    d = p["delivery"]
    if not isinstance(d, dict) or "mode" not in d:
        raise Fail("DELIVERY_SHAPE", "delivery without mode")
    if d["mode"] == "body":
        if set(d) != {"mode", "sha256"} or not isinstance(d["sha256"], str) or not HEX64.match(d["sha256"]):
            raise Fail("DELIVERY_SHAPE", "body delivery must be exactly {mode, sha256(hex64)}")
    elif d["mode"] == "stream":
        if set(d) != {"mode", "framing", "frameCount", "digest"}:
            raise Fail("DELIVERY_SHAPE", "stream delivery must be exactly {mode, framing, frameCount, digest}")
        if d["framing"] != "sse":
            raise Fail("DELIVERY_FRAMING", f"unregistered framing {d['framing']!r}")
        if not _is_int(d["frameCount"]) or d["frameCount"] < 0 or not isinstance(d["digest"], str) or not HEX64.match(d["digest"]):
            raise Fail("DELIVERY_SHAPE", "stream frameCount/digest ill-typed")
    else:
        raise Fail("DELIVERY_SHAPE", f"unknown delivery mode {d['mode']!r}")


def check_signatures(sigs: Any) -> list[dict]:
    """§5.3 / §6: 2–4 entries, distinct registered algs, both baselines, canonical base64 with the table's sizes."""
    if not isinstance(sigs, list) or not 2 <= len(sigs) <= 4:
        raise Fail("SIGNATURES_SHAPE", "signatures must hold 2–4 entries")
    seen = set()
    out = []
    for i, s in enumerate(sigs):
        if not isinstance(s, dict) or set(s) != {"alg", "kid", "signature"}:
            raise Fail("SIGNATURES_SHAPE", f"signatures[{i}] must be exactly {{alg, kid, signature}}")
        alg, kid, sig = s["alg"], s["kid"], s["signature"]
        if alg not in ALGS:
            raise Fail("SIGNATURE_ALG", f"signatures[{i}].alg {alg!r} is not registered")
        if alg in seen:
            raise Fail("SIGNATURES_SHAPE", f"duplicate alg {alg}")
        seen.add(alg)
        if not isinstance(kid, str) or not KID_RE.match(kid):
            raise Fail("SIGNATURES_SHAPE", f"signatures[{i}].kid ill-formed")
        raw = b64_canonical(sig, f"signatures[{i}].signature")
        if len(raw) != ALGS[alg][1]:
            raise Fail("SIGNATURE_SIZE", f"signatures[{i}]: {len(raw)} bytes, {ALGS[alg][1]} expected for {alg}")
        out.append({"alg": alg, "kid": kid, "raw": raw})
    if not all(a in seen for a in BASELINE):
        raise Fail("SIGNATURES_BASELINE", "both ed25519 and ml-dsa-65 are required")
    return out


def check_receipt_object(r: Any) -> tuple[dict, list[dict]]:
    if not isinstance(r, dict) or set(r) != {"payload", "signatures"}:
        raise Fail("RECEIPT_SHAPE", "receipt must be exactly {payload, signatures}")
    check_payload(r["payload"])
    return r["payload"], check_signatures(r["signatures"])


# --------------------------------------------------------------------------- key directory (§7.2–7.4)
def directory_root(doc: dict) -> str:
    gov = sorted(doc["governanceKeys"], key=lambda g: g["alg"])
    keys = sorted(doc["keys"], key=lambda k: k["kid"])
    pre = {"spec": doc["spec"], "issuer": doc["issuer"], "epoch": doc["epoch"], "prevRoot": doc["prevRoot"],
           "publishedAt": doc["publishedAt"], "governanceKeys": gov, "keys": keys}
    return sha256_hex(jcs_bytes(pre))


def check_directory(doc: Any, *, path_alg: str, expected_issuer: str, pinned: dict | None) -> dict:
    """§7.3 in order. Returns {root, trust, gov_key_used, keys_by_kid, ...}; raises Fail."""
    if not isinstance(doc, dict) or doc.get("spec") != DIR_SPEC:
        raise Fail("DIRECTORY_SPEC", "directory.spec is not x402-receipt-key-directory/1")
    check_subset(doc, "directory")
    _exact_members(doc, DIR_TYPES, "directory", "DIRECTORY_SHAPE")
    if doc["epoch"] < 1:
        raise Fail("DIRECTORY_SHAPE", "epoch < 1")
    if not HEX64.match(doc["prevRoot"]) or not HEX64.match(doc["root"]):
        raise Fail("DIRECTORY_SHAPE", "prevRoot/root not hex64")
    if (doc["prevRoot"] == "0" * 64) != (doc["epoch"] == 1):
        raise Fail("DIRECTORY_SHAPE", "prevRoot is 64 zeros iff epoch is 1")
    if not is_origin_string(doc["issuer"]):
        raise Fail("DIRECTORY_SHAPE", "issuer is not an origin")
    gov = doc["governanceKeys"]
    if not 1 <= len(gov) <= 4:
        raise Fail("DIRECTORY_SHAPE", "governanceKeys must hold 1–4 entries")
    gov_by_alg: dict[str, bytes] = {}
    for i, g in enumerate(gov):
        if not isinstance(g, dict) or set(g) != {"alg", "publicKey"} or g["alg"] not in ALGS or g["alg"] in gov_by_alg:
            raise Fail("DIRECTORY_SHAPE", f"governanceKeys[{i}] ill-formed or duplicate alg")
        raw = b64_canonical(g["publicKey"], f"governanceKeys[{i}].publicKey")
        if len(raw) != ALGS[g["alg"]][0]:
            raise Fail("DIRECTORY_SHAPE", f"governanceKeys[{i}]: key size {len(raw)} for {g['alg']}")
        if g["alg"] == "ed25519":
            ok, why = ed25519_key_ok(raw)
            if not ok:
                raise Fail("DIRECTORY_KEY", f"governanceKeys[{i}]: {why}")
        gov_by_alg[g["alg"]] = raw
    if not all(a in gov_by_alg for a in BASELINE):
        raise Fail("DIRECTORY_SHAPE", "governanceKeys must include ed25519 and ml-dsa-65")
    keys = doc["keys"]
    if not 1 <= len(keys) <= 256:
        raise Fail("DIRECTORY_SHAPE", "keys must hold 1–256 entries")
    by_kid: dict[str, dict] = {}
    gov_pub_set = set(gov_by_alg.values())
    for i, k in enumerate(keys):
        _exact_members(k, KEY_TYPES, f"keys[{i}]", "DIRECTORY_SHAPE")
        if not KID_RE.match(k["kid"]) or k["kid"] in by_kid:
            raise Fail("DIRECTORY_SHAPE", f"keys[{i}].kid ill-formed or duplicate")
        if k["alg"] not in ALGS or k["status"] not in STATUSES:
            raise Fail("DIRECTORY_SHAPE", f"keys[{i}]: unregistered alg or status")
        raw = b64_canonical(k["publicKey"], f"keys[{i}].publicKey")
        if len(raw) != ALGS[k["alg"]][0]:
            raise Fail("DIRECTORY_SHAPE", f"keys[{i}]: key size {len(raw)} for {k['alg']}")
        if raw in gov_pub_set:
            raise Fail("DIRECTORY_SHAPE", f"keys[{i}]: a governance key MUST NOT appear in keys")
        if k["alg"] == "ed25519":
            ok, why = ed25519_key_ok(raw)
            if not ok:
                raise Fail("DIRECTORY_KEY", f"keys[{i}]: {why}")
        by_kid[k["kid"]] = dict(k, raw=raw)
    root = directory_root(doc)
    if root != doc["root"]:
        raise Fail("DIRECTORY_ROOT", f"root does not recompute (got {root[:16]}…)")
    sigs = doc["signatures"]
    if not isinstance(sigs, list) or len(sigs) != len(gov):
        raise Fail("DIRECTORY_SHAPE", "one signature per governance key")
    sig_by_alg: dict[str, bytes] = {}
    for i, s in enumerate(sigs):
        if not isinstance(s, dict) or set(s) != {"alg", "signature"} or s["alg"] not in gov_by_alg or s["alg"] in sig_by_alg:
            raise Fail("DIRECTORY_SHAPE", f"signatures[{i}] ill-formed")
        raw = b64_canonical(s["signature"], f"directory.signatures[{i}]")
        if len(raw) != ALGS[s["alg"]][1]:
            raise Fail("DIRECTORY_SHAPE", f"signatures[{i}]: signature size {len(raw)} for {s['alg']}")
        sig_by_alg[s["alg"]] = raw
    if path_alg not in sig_by_alg:
        raise Fail("DIRECTORY_SIGNATURE", f"no governance signature for the path's algorithm {path_alg}")
    msg = DIR_DOMAIN + b"\n" + root.encode("ascii")
    if not sig_verify(path_alg, gov_by_alg[path_alg], msg, sig_by_alg[path_alg]):
        raise Fail("DIRECTORY_SIGNATURE", f"governance {path_alg} signature over the root verifies false")
    if doc["issuer"] != expected_issuer:
        raise Fail("DIRECTORY_ISSUER", f"directory.issuer {doc['issuer']} != expected {expected_issuer}")
    # trust basis: pinned iff the governance key whose signature we verified equals the pinned key of that alg
    trust = None
    if pinned and isinstance(pinned, dict) and path_alg in pinned:
        try:
            pinned_raw = b64_canonical(pinned[path_alg], f"pinnedGovernanceKeys.{path_alg}")
        except Fail:
            pinned_raw = None
        if pinned_raw == gov_by_alg[path_alg]:
            trust = "pinned"
    return {"root": root, "trust": trust, "gov": gov_by_alg, "keys": by_kid, "epoch": doc["epoch"],
            "publishedAt": doc["publishedAt"], "prevRoot": doc["prevRoot"]}


def key_authorizes(k: dict, alg: str, t: int) -> tuple[bool, str]:
    """§7.4 at T = issuedAt."""
    if k["use"] != KEY_USE:
        return False, "key use is not x402-delivery-receipt"
    if k["alg"] != alg:
        return False, "key alg differs from the signature alg"
    st, nb, na = k["status"], k["notBefore"], k["notAfter"]
    if st == "active":
        if nb is None or nb > t:
            return False, "active key not yet valid at issuedAt"
        if na is not None and t > na:
            return False, "active key past notAfter at issuedAt"
        return True, ""
    if st in ("retiring", "retired"):
        if nb is None or na is None or not (nb <= t <= na):
            return False, f"{st} key outside [notBefore, notAfter] at issuedAt"
        return True, ""
    return False, f"status {st} never authorizes"


# --------------------------------------------------------------------------- reference resolution (§5.5)
def resolve_reference(ref: Any, document: Any, accepted_origin: str) -> tuple[dict, str]:
    """Returns (receipt object, document text). Any failure is a missing receipt."""
    if not isinstance(ref, dict) or set(ref) != {"receiptId", "receiptUrl", "digest"}:
        raise Fail("REFERENCE_SHAPE", "reference must be exactly {receiptId, receiptUrl, digest}")
    rid, url, dg = ref["receiptId"], ref["receiptUrl"], ref["digest"]
    if not (isinstance(rid, str) and HEX64.match(rid) and isinstance(dg, str) and HEX64.match(dg) and isinstance(url, str)):
        raise Fail("REFERENCE_SHAPE", "receiptId/digest not hex64 or receiptUrl not a string")
    u = urlsplit(url)
    if u.scheme != "https" or u.query or u.fragment or origin_of(url, "receiptUrl") != accepted_origin:
        raise Fail("REFERENCE_URL", "receiptUrl must be https, same-origin with the accepted issuer, no query/fragment")
    if u.path.rsplit("/", 1)[-1] != rid:
        raise Fail("REFERENCE_URL", "receiptUrl does not end with /<receiptId>")
    if not isinstance(document, (str, bytes)):
        raise Fail("RECEIPT_UNAVAILABLE", "no receipt document to verify against the reference")
    octets = document.encode("utf-8") if isinstance(document, str) else document
    if len(octets) > 256 * 1024:
        raise Fail("REFERENCE_SIZE", "document larger than the 256 KiB bound")
    if sha256_hex(octets) != dg:
        raise Fail("REFERENCE_DIGEST", "SHA-256 of the served octets differs from digest")
    try:
        obj = parse_strict(octets)
    except (ValueError, UnicodeDecodeError) as e:
        raise Fail("REFERENCE_PARSE", f"document is not strict JSON: {e}")
    check_subset(obj, "document")
    if jcs_bytes(obj) != octets:
        raise Fail("REFERENCE_JCS", "document is not the JCS text of the parsed object")
    if not isinstance(obj, dict) or "payload" not in obj:
        raise Fail("REFERENCE_PARSE", "document is not a receipt")
    try:
        got = receipt_id(obj["payload"])
    except Fail as e:
        raise Fail("REFERENCE_PARSE", f"payload not canonicalizable: {e}")
    if got != rid:
        raise Fail("REFERENCE_ID", "recomputed receipt id differs from receiptId")
    if not isinstance(obj["payload"], dict) or obj["payload"].get("issuer") != origin_of(url, "receiptUrl"):
        raise Fail("REFERENCE_ISSUER", "payload.issuer is not the origin of receiptUrl")
    return obj, octets.decode("utf-8")


# --------------------------------------------------------------------------- stream handling (§5.6)
def parse_stream(text: str) -> dict:
    """Frames, terminal event and defects of an SSE event stream."""
    if not isinstance(text, str):
        raise Fail("STREAM_INPUT", "eventStream is not text")
    norm = text.replace("\r\n", "\n").replace("\r", "\n")  # hash frames as an EventSource sees them
    events, pending = sse_events(norm)
    frames: list[bytes] = []
    terminal = None
    after_terminal = 0
    for ev in events:
        if terminal is not None:
            after_terminal += 1
            continue
        if ev["event"] == TERMINAL_EVENT:
            terminal = ev
            continue
        frames.append(ev["data"].encode("utf-8"))
    digest, _ = stream_digest(frames)
    return {"frames": frames, "frameCount": len(frames), "digest": digest, "terminal": terminal,
            "after_terminal": after_terminal, "pending_discarded": pending}


def terminal_payload(term: dict) -> dict:
    data = term["data"]
    if "\n" in data:
        raise Fail("TERMINAL_SHAPE", "terminal data is not a single line")
    try:
        obj = parse_strict(data)
    except ValueError as e:
        raise Fail("TERMINAL_SHAPE", f"terminal data is not strict JSON: {e}")
    if not isinstance(obj, dict) or not ({"frameCount", "digest"} <= set(obj)) or not (set(obj) - {"frameCount", "digest"}) in ({"receipt"}, {"reference"}):
        raise Fail("TERMINAL_SHAPE", "terminal must be {frameCount, digest, receipt | reference}")
    if not _is_int(obj["frameCount"]) or not isinstance(obj["digest"], str) or not HEX64.match(obj["digest"]):
        raise Fail("TERMINAL_SHAPE", "terminal frameCount/digest ill-typed")
    return obj


# --------------------------------------------------------------------------- the verifier (§8)
def _lower_if_evm(s: Any) -> Any:
    return s.lower() if isinstance(s, str) and EVM_ADDR_RE.match(s) else s


def verify(inputs: dict, *, path: str, offline: bool = False, skew: int = 300, vector: dict | None = None) -> dict:
    """One verifier run. Never raises: an internal error is a failing verdict (§8.1)."""
    if path not in ("session", "archival"):
        raise ValueError("path must be session or archival")
    path_alg = "ed25519" if path == "session" else "ml-dsa-65"
    levels = {lv: "not-evaluated" for lv in LEVELS}
    report: dict[str, Any] = {"path": path, "offline": offline, "notes": [], "unchecked_algs": [], "trust": None,
                              "latest_epoch_chained": None, "receipt_available": None}
    reason = None
    try:
        now = inputs.get("now")
        if not _is_int(now):
            raise Fail("INPUT_NOW", "now is required")
        accepted_origin = None
        if isinstance(inputs.get("resourceUrl"), str):
            try:
                accepted_origin = origin_of(inputs["resourceUrl"], "resourceUrl")
            except Fail:
                accepted_origin = None

        # ---- obtain the receipt: inline | reference+document | event stream
        stream_info = None
        receipt_obj = None
        try:
            if "eventStream" in inputs:
                stream_info = parse_stream(inputs["eventStream"])
                if stream_info["terminal"] is None:
                    raise Fail("RECEIPT_MISSING", "stream ended without the terminal event")
                term = terminal_payload(stream_info["terminal"])
                stream_info["terminal_obj"] = term
                if "receipt" in term:
                    receipt_obj = term["receipt"]
                else:
                    if accepted_origin is None:
                        raise Fail("REFERENCE_URL", "no accepted issuer origin (resourceUrl missing)")
                    ref = term["reference"]
                    if "reference" in inputs and inputs["reference"] != ref:
                        raise Fail("REFERENCE_SHAPE", "reference given to the verifier differs from the terminal's")
                    receipt_obj, _doc = resolve_reference(ref, inputs.get("receiptDocument"), accepted_origin)
                    report["receipt_available"] = True
            elif "reference" in inputs:
                if accepted_origin is None:
                    raise Fail("REFERENCE_URL", "no accepted issuer origin (resourceUrl missing)")
                receipt_obj, _doc = resolve_reference(inputs["reference"], inputs.get("receiptDocument"), accepted_origin)
                report["receipt_available"] = True
            elif "receipt" in inputs:
                receipt_obj = inputs["receipt"]
            else:
                raise Fail("RECEIPT_MISSING", "no receipt, reference or event stream")
            payload, sigs = check_receipt_object(receipt_obj)
            if stream_info is not None:
                if payload["delivery"]["mode"] != "stream":
                    raise Fail("DELIVERY_SHAPE", "an event stream was observed but the receipt is not stream mode")
            levels["integrity"] = "pass"
        except Fail as e:
            levels["integrity"] = "fail"
            raise

        rid = receipt_id(payload)
        msg = signed_message(rid)

        # ---- directory and trust (needed for authentic: the key of the kid lives in the directory)
        dir_doc = inputs.get("directory")
        dir_info = None
        dir_fail: Fail | None = None
        try:
            if dir_doc is None:
                raise Fail("DIRECTORY_MISSING", "no directory epoch supplied")
            dir_info = check_directory(dir_doc, path_alg=path_alg, expected_issuer=payload["issuer"],
                                       pinned=inputs.get("pinnedGovernanceKeys"))
        except Fail as e:
            dir_fail = e

        # ---- authentic
        try:
            if dir_info is None:
                raise Fail("AUTHENTIC_NO_DIRECTORY", f"cannot resolve kid without a verified directory ({dir_fail})")
            to_check = sigs if path == "archival" else [s for s in sigs if s["alg"] == path_alg]
            report["unchecked_algs"] = [s["alg"] for s in sigs if s not in to_check]
            for s in to_check:
                k = dir_info["keys"].get(s["kid"])
                if k is None:
                    raise Fail("KID_UNKNOWN", f"kid {s['kid']} not in epoch {dir_info['epoch']}")
                if k["alg"] != s["alg"]:
                    raise Fail("SIGNATURE_ALG", f"signature alg {s['alg']} differs from the directory entry {k['alg']}")
                try:
                    ok = sig_verify(s["alg"], k["raw"], msg, s["raw"])
                except RuntimeError as e:
                    raise Fail("BACKEND_MISSING", str(e))
                if not ok:
                    raise Fail("SIGNATURE_INVALID", f"{s['alg']} signature verifies false")
            levels["authentic"] = "pass"
        except Fail:
            levels["authentic"] = "fail"
            raise

        # ---- trusted
        try:
            if dir_info["trust"] is None:
                raise Fail("TRUST_BASIS", "governance key is neither pinned nor fetched over TLS (offline copy)")
            report["trust"] = dir_info["trust"]
            if dir_info["epoch"] != payload["keyDirectoryEpoch"]:
                raise Fail("EPOCH_MISMATCH", f"directory epoch {dir_info['epoch']} != payload epoch {payload['keyDirectoryEpoch']}")
            if dir_info["root"] != payload["keyDirectoryDigest"]:
                raise Fail("KEY_DIRECTORY_DIGEST_MISMATCH", "epoch root differs from payload.keyDirectoryDigest")
            t = payload["issuedAt"]
            if not dir_info["publishedAt"] <= t + skew:
                raise Fail("EPOCH_NOT_IN_FORCE", "epoch published after issuedAt + skew")
            if t > now + skew:
                raise Fail("ISSUED_IN_FUTURE", "issuedAt beyond the clock-skew allowance")
            report["latest_epoch_chained"] = dir_info["epoch"]  # a single epoch was supplied; nothing later to chain
            for s in (sigs if path == "archival" else [s for s in sigs if s["alg"] == path_alg]):
                ok, why = key_authorizes(dir_info["keys"][s["kid"]], s["alg"], t)
                if not ok:
                    raise Fail("KEY_NOT_AUTHORIZED", f"kid {s['kid']}: {why}")
            # §8.2 issuer authorization: default policy, issuer origin == resourceUrl origin
            if payload["issuer"] != origin_of(payload["resourceUrl"], "payload.resourceUrl"):
                raise Fail("ISSUER_NOT_AUTHORIZED", "issuer origin differs from resourceUrl origin")
            levels["trusted"] = "pass"
        except Fail:
            levels["trusted"] = "fail"
            raise

        # ---- settlement (§8.3) — evaluated when the client observations are present
        settle, req = inputs.get("settle"), inputs.get("requirements")
        if settle is not None or req is not None or not offline:
            try:
                if not isinstance(settle, dict) or not isinstance(req, dict):
                    raise Fail("SETTLEMENT_INPUT", "settle and requirements are required")
                if settle.get("success") is not True:
                    raise Fail("SETTLEMENT_NOT_SUCCESS", "a receipt MUST NOT exist for a failed settle")
                if payload["transaction"] != settle.get("transaction") or payload["network"] != settle.get("network"):
                    raise Fail("SETTLEMENT_MISMATCH", "transaction/network differ from SettleResponse")
                if _lower_if_evm(payload["payer"]) != _lower_if_evm(settle.get("payer")) or not isinstance(settle.get("payer"), str):
                    raise Fail("SETTLEMENT_MISMATCH", "payer differs from SettleResponse")
                for f in ("scheme", "asset", "payTo"):
                    if payload[f] != req.get(f):
                        raise Fail("SETTLEMENT_MISMATCH", f"{f} differs from the accepted requirements")
                exp_amount = settle["amount"] if "amount" in settle else req.get("amount")
                if payload["amount"] != exp_amount:
                    raise Fail("SETTLEMENT_MISMATCH", "amount differs")
                if payload["resourceUrl"] != inputs.get("resourceUrl") or payload["method"] != inputs.get("method"):
                    raise Fail("SETTLEMENT_MISMATCH", "resourceUrl/method differ from the request made")
                if payload["paymentId"] != inputs.get("paymentId"):
                    raise Fail("SETTLEMENT_MISMATCH", "paymentId differs from the id the client sent")
                offer = inputs.get("offerReceipt")
                if offer is None and isinstance(settle.get("extensions"), dict):
                    offer = (settle["extensions"].get("offer-receipt") or {}).get("info", {}).get("receipt")
                if isinstance(offer, dict):
                    op = offer.get("payload", offer)
                    if op.get("network") != payload["network"] or _lower_if_evm(op.get("payer")) != _lower_if_evm(payload["payer"]):
                        raise Fail("OFFER_RECEIPT_DISAGREES", "offer-receipt network/payer differ (§2.1)")
                    if "transaction" in op and op["transaction"] != payload["transaction"]:
                        raise Fail("OFFER_RECEIPT_DISAGREES", "offer-receipt transaction differs (§2.1)")
                levels["settlement"] = "pass"
            except Fail:
                levels["settlement"] = "fail"
                raise

        # ---- delivery
        d = payload["delivery"]
        observed_status = inputs.get("responseStatus")
        try:
            if d["mode"] == "body":
                if "responseBody" not in inputs:
                    raise Fail("DELIVERY_UNCONFIRMED", "no observed body", )
                body = inputs["responseBody"]
                octets = body.encode("utf-8") if isinstance(body, str) else bytes(body)
                if sha256_hex(octets) != d["sha256"]:
                    raise Fail("BODY_DIGEST_MISMATCH", "SHA-256 of the observed body differs")
            else:
                if stream_info is None:
                    raise Fail("DELIVERY_UNCONFIRMED", "no observed event stream")
                term = stream_info["terminal_obj"]
                if stream_info["after_terminal"]:
                    raise Fail("EVENTS_AFTER_TERMINAL", f"{stream_info['after_terminal']} event(s) after the terminal event")
                if term["frameCount"] != d["frameCount"] or term["digest"] != d["digest"]:
                    raise Fail("TERMINAL_MISMATCH", "terminal frameCount/digest differ from the signed payload")
                if stream_info["frameCount"] != d["frameCount"] or stream_info["digest"] != d["digest"]:
                    raise Fail("STREAM_DIGEST_MISMATCH", f"recomputed ({stream_info['frameCount']}, {stream_info['digest'][:16]}…) differs")
            # §8.1: "responseStatus, when not null, equals the observed status". Reading (v2, 2026-10-19): the
            # comparison runs only when the client recorded a status; an unrecorded status is reported, not failed.
            # v1 failed closed here (STATUS_UNOBSERVED) and disagreed with endToEnd/stream/*, where no status is given.
            if payload["responseStatus"] is not None and observed_status is not None:
                if payload["responseStatus"] != observed_status:
                    raise Fail("STATUS_MISMATCH", "responseStatus differs from the observed status")
            report["status_compared"] = payload["responseStatus"] is not None and observed_status is not None
            levels["delivery"] = "pass"
        except Fail as e:
            levels["delivery"] = "not-evaluated" if e.code == "DELIVERY_UNCONFIRMED" else "fail"
            raise
    except Fail as e:
        lvl = next((lv for lv in LEVELS if levels[lv] != "pass"), "integrity")
        reason = {"level": lvl, "code": e.code, "detail": str(e)}
    except Exception as e:  # verifier error → failing verdict, never a passing one
        lvl = next((lv for lv in LEVELS if levels[lv] != "pass"), "integrity")
        levels[lvl] = "fail"
        reason = {"level": lvl, "code": "VERIFIER_ERROR", "detail": f"{type(e).__name__}: {e}"}

    valid = all(levels[lv] == "pass" for lv in LEVELS)
    if offline and levels["settlement"] == "not-evaluated":
        valid = all(levels[lv] == "pass" for lv in LEVELS if lv != "settlement")
    long_term = path == "archival" and levels["authentic"] == "pass" and levels["trusted"] == "pass"
    out = {"path": path, "levels": levels, "valid": valid, "longTermEvidence": long_term, "reason": reason, "report": report}

    # §8.4 outcomes (informative; A.7 convention)
    outcomes = {
        "receiptValidity": "valid" if all(levels[l] == "pass" for l in ("integrity", "authentic", "trusted")) else "not-valid",
        "receiptAvailability": "receiptAvailableToVerifier" if report["receipt_available"] else "not-evaluated",
        "buyerObservedOutput": "captured" if ("responseBody" in inputs or "eventStream" in inputs) else "none",
    }
    rw = (vector or {}).get("recoveryWindow") if isinstance(vector, dict) else None
    if isinstance(rw, dict) and _is_int(rw.get("until")) and _is_int(inputs.get("now")):
        outcomes["resultRecoverability"] = "window-open" if inputs["now"] < rw["until"] else "expired"
    else:
        outcomes["resultRecoverability"] = "not-evaluated"
    out["outcomes"] = outcomes
    out["automaticRepayment"] = False
    return out
