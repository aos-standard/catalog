#!/usr/bin/env python3
"""Re-verify, with the local `openssl` binary, the signatures this run decides.

JWS (Ed25519): every vector whose header and signature decode is verified by `openssl pkeyutl -verify -rawin`
over the same signing input and compared with this verifier's signature step.
EIP-712 (secp256k1): for every artifact that parses, the public key this verifier recovered is written as a PEM
and `openssl pkeyutl -verify` checks (r, s) over the same 32-byte digest; and the authorized address in the
file is re-derived by openssl from the published test seed.
Usage: python3 -I -B xcheck_openssl.py <jws.json> <eip712.json> <out.json>
"""
from __future__ import annotations

import base64
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import x402_offer_receipt as v  # noqa: E402


def der_len(n):
    return bytes([n]) if n < 128 else bytes([0x81, n])


def der_int(x):
    b = x.to_bytes(32, "big").lstrip(b"\0") or b"\0"
    if b[0] & 0x80:
        b = b"\0" + b
    return b"\x02" + der_len(len(b)) + b


def ecdsa_der(r, s):
    body = der_int(r) + der_int(s)
    return b"\x30" + der_len(len(body)) + body


def pem_secp256k1_pub(pt):
    spki_prefix = bytes.fromhex("3056301006072a8648ce3d020106052b8104000a034200")
    der = spki_prefix + b"\x04" + pt[0].to_bytes(32, "big") + pt[1].to_bytes(32, "big")
    return b"-----BEGIN PUBLIC KEY-----\n" + base64.encodebytes(der) + b"-----END PUBLIC KEY-----\n"


def pem_ed25519_pub(pub):
    der = bytes.fromhex("302a300506032b6570032100") + pub
    return b"-----BEGIN PUBLIC KEY-----\n" + base64.encodebytes(der) + b"-----END PUBLIC KEY-----\n"


def ossl_verify(pem, msg, sig, rawin):
    with tempfile.TemporaryDirectory() as d:
        p = Path(d)
        (p / "k.pem").write_bytes(pem); (p / "m").write_bytes(msg); (p / "s").write_bytes(sig)
        cmd = ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(p / "k.pem"), "-in", str(p / "m"), "-sigfile", str(p / "s")]
        if rawin:
            cmd.insert(3, "-rawin")
        r = subprocess.run(cmd, capture_output=True, text=True)
        return "Signature Verified Successfully" in r.stdout


def main() -> int:
    jws, eip = json.loads(Path(sys.argv[1]).read_text()), json.loads(Path(sys.argv[2]).read_text())
    rows = []
    pub = bytes.fromhex(jws["signing"]["public_key_hex"])
    for vec in jws["valid"] + jws["invalid"]:
        parts = vec["jws"].split(".")
        if len(parts) != 3:
            continue
        try:
            sig = v._b64url(parts[2])
        except ValueError:
            continue
        msg = (parts[0] + "." + parts[1]).encode()
        mine = v.ed25519_verify(pub, msg, sig)
        theirs = ossl_verify(pem_ed25519_pub(pub), msg, sig, True) if len(sig) == 64 else False
        rows.append({"set": "jws", "id": vec["name"], "this_verifier": mine, "openssl": theirs, "agree": mine == theirs})
    for vec in eip["valid"] + eip["invalid"]:
        a = vec["artifact"]
        sig = a.get("signature", "")
        try:
            raw = bytes.fromhex(sig[2:])
        except ValueError:
            continue
        if len(raw) != 65 or raw[64] not in (27, 28, 0, 1) or not isinstance(a.get("payload"), dict):
            continue
        p = a["payload"]
        if v.schema_problem(vec["kind"], p, all_fields=True):
            continue
        digest = v.keccak256(b"\x19\x01" + v.domain_separator(vec["kind"]) + v.struct_hash(vec["kind"], p))
        r, s, rec = int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:64], "big"), raw[64]
        pt = v.secp256k1_recover(digest, r, s, rec - 27 if rec >= 27 else rec)
        ok = pt is not None and ossl_verify(pem_secp256k1_pub(pt), digest, ecdsa_der(r, s), False)
        rows.append({"set": "eip712", "id": vec["name"], "recovered": v.eth_address(pt) if pt else None,
                     "openssl_verifies_with_recovered_key": ok, "agree": ok})
    seed = eip["signing"]["test_seed_hex"][2:]
    der = bytes.fromhex("302e0201010420" + seed + "a00706052b8104000a")
    with tempfile.TemporaryDirectory() as d:
        k = Path(d) / "k.der"; k.write_bytes(der)
        out = subprocess.run(["openssl", "ec", "-inform", "DER", "-in", str(k), "-pubout", "-outform", "DER"],
                             capture_output=True).stdout
    q = out[-64:]
    derived = "0x" + v.keccak256(q)[12:].hex()
    addr_ok = derived == eip["signing"]["address"].lower()
    for r in rows:
        print(f"{'agree' if r['agree'] else 'DIFFER':6} {r['set']:6} {r['id']:44} {({k: r[k] for k in r if k not in ('set','id','agree')})}")
    print(f"authorized address from the published seed via openssl: {derived} {'matches' if addr_ok else 'DIFFERS'}")
    agree = sum(r["agree"] for r in rows)
    print(f"{agree}/{len(rows)} signature decisions agree with openssl")
    Path(sys.argv[3]).write_text(json.dumps({"rows": rows, "address_from_seed": derived, "address_ok": addr_ok}, indent=1) + "\n")
    return 0 if agree == len(rows) and addr_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
