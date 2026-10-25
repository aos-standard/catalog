#!/usr/bin/env python3
"""Lax variants of x402_offer_receipt.py, each dropping or bending one rule; the vectors must catch each one.

Each variant is a small wrapper or patch over the frozen verifier, written to the mistake its name describes.
A variant is caught when at least one vector's accept/reject changes against `expect`.
Usage: python3 -I -B lax_battery.py <jws.json> <eip712.json> <now>
"""
from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import x402_offer_receipt as v  # noqa: E402


@contextlib.contextmanager
def patched(**attrs):
    old = {k: getattr(v, k) for k in attrs}
    for k, val in attrs.items():
        setattr(v, k, val)
    try:
        yield
    finally:
        for k, val in old.items():
            setattr(v, k, val)


def jws_alg_from_header(kind, compact, keys, now=None):
    """Dispatch on the header's alg: none = no signature, HS256 = HMAC keyed with the key bytes."""
    try:
        h64, p64, s64 = compact.split(".")
        header = json.loads(v._b64url(h64))
        sig = v._b64url(s64)
    except Exception:
        return v.verify_jws(kind, compact, keys, now)
    key = keys.get(header.get("kid")) if isinstance(header, dict) else None
    if key and header.get("alg") in ("none", "HS256"):
        good = header["alg"] == "none" or hmac.compare_digest(
            hmac.new(key["public_key"], (h64 + "." + p64).encode(), hashlib.sha256).digest(), sig)
        if good:
            payload = json.loads(v._b64url(p64))
            p = v.schema_problem(kind, payload)
            return {"accept": not p, "stage": "schema" if p else None, "detail": p or ""}
    return v.verify_jws(kind, compact, keys, now)


def jws_kid_optional(kind, compact, keys, now=None):
    try:
        h64, p64, s64 = compact.split(".")
        header = json.loads(v._b64url(h64))
        if isinstance(header, dict) and "kid" not in header and len(keys) == 1:
            header["kid"] = next(iter(keys))
            h2 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
            # verify the original signing input under the only key, then run the rest of the checks
            key = next(iter(keys.values()))
            if v.ed25519_verify(key["public_key"], (h64 + "." + p64).encode(), v._b64url(s64)):
                payload = json.loads(v._b64url(p64))
                p = v.schema_problem(kind, payload)
                return {"accept": not p, "stage": "schema" if p else None, "detail": p or "", "_h2": h2}
    except Exception:
        pass
    return v.verify_jws(kind, compact, keys, now)


def run(jws, eip, now, jws_fn=None, eip_fn=None, patch=None):
    jws_fn = jws_fn or v.verify_jws
    eip_fn = eip_fn or v.verify_eip712
    sg = jws["signing"]
    keys = {sg["kid"]: {"alg": "EdDSA", "public_key": bytes.fromhex(sg["public_key_hex"]), "authorized": True}}
    auth = {eip["signing"]["address"].lower()}
    out = {}

    def safe(fn, *a):
        try:
            return fn(*a)["accept"]
        except Exception:  # a crash on a stranger's input is not an acceptance
            return False

    with patched(**(patch or {})):
        for vec in jws["valid"] + jws["invalid"]:
            kind = "receipt" if vec["name"].startswith("receipt") else "offer"
            out["jws/" + vec["name"]] = (safe(jws_fn, kind, vec["jws"], keys, now), vec["expect"] == "accept")
        for vec in eip["valid"] + eip["invalid"]:
            out["eip712/" + vec["name"]] = (safe(eip_fn, vec["kind"], vec["artifact"], auth, now), vec["expect"] == "accept")
    return [k for k, (got, want) in out.items() if got != want]


def main() -> int:
    jws, eip = json.loads(Path(sys.argv[1]).read_text()), json.loads(Path(sys.argv[2]).read_text())
    now = int(sys.argv[3])
    real_schema, real_ds, real_sh = v.schema_problem, v.domain_separator, v.struct_hash

    def no_receipt_schema(kind, payload, **kw):
        return None if kind == "receipt" and isinstance(payload, dict) and payload.get("version") == 1 else real_schema(kind, payload, **kw)

    def ds_from_network(kind):
        return real_ds(kind)  # replaced per artifact below

    def eip_chain_from_network(kind, artifact, authorized, now=None):
        try:
            cid = int(artifact["payload"]["network"].split(":")[1])
        except Exception:
            return v.verify_eip712(kind, artifact, authorized, now)
        th = v.keccak256(b"EIP712Domain(string name,string version,uint256 chainId)")
        ds = v.keccak256(th + v.keccak256(v.DOMAIN_NAME[kind].encode()) + v.keccak256(b"1") + cid.to_bytes(32, "big"))
        with patched(domain_separator=lambda k: ds):
            return v.verify_eip712(kind, artifact, authorized, now)

    def eip_transmitted_types(kind, artifact, authorized, now=None):
        if not isinstance(artifact, dict) or "types" not in artifact:
            return v.verify_eip712(kind, artifact, authorized, now)
        a = {k: x for k, x in artifact.items() if k not in ("types", "primaryType")}
        prim = artifact.get("primaryType", v.PRIMARY[kind])
        fields = [(f["name"], f["type"]) for f in artifact["types"][prim]]
        def sh(k, p):
            ts = f"{prim}({','.join(f'{t} {n}' for n, t in fields)})".encode()
            return v.keccak256(v.keccak256(ts) + b"".join(
                v.keccak256(str(p[n]).encode()) if t == "string" else int(p[n]).to_bytes(32, "big") for n, t in fields))
        with patched(struct_hash=sh, schema_problem=lambda k, p, **kw: None, _expired=lambda *x: None):
            return v.verify_eip712(kind, a, authorized, now)

    def eip_omitted_as_empty(kind, artifact, authorized, now=None):
        if isinstance(artifact, dict) and isinstance(artifact.get("payload"), dict):
            p = dict(artifact["payload"])
            p.setdefault("validUntil", 0) if kind == "offer" else p.setdefault("transaction", "")
            artifact = dict(artifact, payload=p)
        return v.verify_eip712(kind, artifact, authorized, now)

    def eip_signature_only(kind, artifact, authorized, now=None):
        r = v.verify_eip712(kind, artifact, authorized, now)
        if not r["accept"] and r["stage"] == "authorization":
            return dict(r, accept=True)
        return r

    def eip_any_v(kind, artifact, authorized, now=None):
        if isinstance(artifact, dict) and isinstance(artifact.get("signature"), str) and len(artifact["signature"]) == 132:
            raw = bytearray(bytes.fromhex(artifact["signature"][2:]))
            if raw[64] not in (27, 28, 0, 1):
                raw[64] = 27 + (raw[64] & 1)
            artifact = dict(artifact, signature="0x" + raw.hex())
        return v.verify_eip712(kind, artifact, authorized, now)

    def reject_expired(fn):
        def g(*a, **kw):
            r = fn(*a, **kw)
            return dict(r, accept=False) if r.get("accept") and r.get("expired") else r
        return g

    variants = {
        "jws: alg from the header": dict(jws_fn=jws_alg_from_header),
        "jws: kid optional": dict(jws_fn=jws_kid_optional),
        "jws: no signature check": dict(patch={"ed25519_verify": lambda *a: True}),
        "both: no payload schema": dict(patch={"schema_problem": lambda *a, **k: None}),
        "both: no receipt schema": dict(patch={"schema_problem": no_receipt_schema}),
        "both: expired offers rejected": dict(jws_fn=reject_expired(v.verify_jws), eip_fn=reject_expired(v.verify_eip712)),
        "eip712: chainId from the payment network": dict(eip_fn=eip_chain_from_network),
        "eip712: types taken from the artifact": dict(eip_fn=eip_transmitted_types),
        "eip712: omitted optional field signed as empty": dict(eip_fn=eip_omitted_as_empty),
        "eip712: signature only, no authorization": dict(eip_fn=eip_signature_only),
        "eip712: any v byte": dict(eip_fn=eip_any_v),
    }
    caught = 0
    for name, kw in variants.items():
        fails = run(jws, eip, now, **kw)
        caught += bool(fails)
        print(f"{'caught' if fails else 'MISSED':6} {name:48} by {fails}")
    print(f"{caught}/{len(variants)} lax variants caught")
    return 0 if caught == len(variants) else 1


if __name__ == "__main__":
    raise SystemExit(main())
