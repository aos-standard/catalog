#!/usr/bin/env python3
"""Check an anchor pointer (draft 0) against the anchored bytes, the proof bytes and a set of block headers.

An anchor pointer says, for one record: which digest was anchored, over which bytes, by which mechanism, with which
proof, and where the claim lands. Draft 0 defines one mechanism, `opentimestamps` with a Bitcoin attestation; the
pointer's other fields do not depend on it.

    {"anchor_pointer": "0",
     "anchored_digest": {"alg": "sha-256", "hex": "<64 lowercase hex>"},
     "anchored_set": {"locator": "<where the anchored bytes can be fetched, pinned>"},
     "mechanism": "opentimestamps",
     "proof": {"locator": "<where the proof bytes can be fetched, pinned>", "sha256": "<64 lowercase hex>"},
     "claimed": {"chain": "bitcoin", "height": <int>}}

Checks run in this order and the first failure is the result:
  malformed               a field above is missing or of the wrong shape
  unsupported_mechanism   mechanism or claimed.chain is not one this reader implements
  set_digest_mismatch     sha-256 of the anchored bytes is not anchored_digest
  proof_sha_mismatch      sha-256 of the proof bytes is not proof.sha256
  proof_unparseable       the proof bytes are not a complete OpenTimestamps proof for sha-256
  proof_for_other_digest  the proof's file digest is not anchored_digest
  pending                 the proof has no Bitcoin attestation (only calendar commitments)
  height_not_in_proof     no Bitcoin attestation in the proof is at claimed.height
  header_unavailable      the supplied headers have no merkle root for claimed.height
  root_mismatch           the proof's path to claimed.height does not end at that block's merkle root
  anchored                otherwise

The headers are an input: the reader supplies merkle roots from a source it trusts (its own node, or two explorers).
A result of `anchored` says the bytes existed no later than that block. It says nothing about who made them or
whether their content is true.

Usage: python3 -I anchor_pointer_check.py <vectors.json> [<out.json>]   (runs every vector, compares `expected`)
Standard library only.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import sys
from pathlib import Path

MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
BITCOIN_TAG = bytes.fromhex("0588960d73d71901")
PENDING_TAG = bytes.fromhex("83dfe30d2ef90c8e")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class Unparseable(Exception):
    pass


class _Reader:
    def __init__(self, b: bytes):
        self.b, self.i = b, 0

    def byte(self) -> int:
        if self.i >= len(self.b):
            raise Unparseable("truncated")
        self.i += 1
        return self.b[self.i - 1]

    def take(self, n: int) -> bytes:
        if self.i + n > len(self.b):
            raise Unparseable("truncated")
        self.i += n
        return self.b[self.i - n:self.i]

    def varuint(self) -> int:
        v = shift = 0
        while True:
            c = self.byte()
            v |= (c & 0x7F) << shift
            if not c & 0x80:
                return v
            shift += 7
            if shift > 63:
                raise Unparseable("varuint too long")

    def varbytes(self) -> bytes:
        return self.take(self.varuint())


def _op(tag: int, r: _Reader, msg: bytes) -> bytes:
    if tag == 0xF0:
        return msg + r.varbytes()
    if tag == 0xF1:
        return r.varbytes() + msg
    if tag == 0x08:
        return hashlib.sha256(msg).digest()
    if tag == 0x02:
        return hashlib.sha1(msg).digest()
    if tag == 0x03:
        return hashlib.new("ripemd160", msg).digest()
    if tag == 0xF2:
        return msg[::-1]
    raise Unparseable(f"unknown op 0x{tag:02x}")


def _walk(r: _Reader, msg: bytes, out: list[tuple[str, object, bytes]], depth: int = 0) -> None:
    if depth > 256:
        raise Unparseable("too deep")

    def one(tag: int) -> None:
        if tag == 0x00:
            atag, payload = r.take(8), r.varbytes()
            if atag == BITCOIN_TAG:
                out.append(("bitcoin", _Reader(payload).varuint(), msg))
            elif atag == PENDING_TAG:
                out.append(("pending", _Reader(payload).varbytes().decode("utf-8", "replace"), msg))
            else:
                out.append(("unknown", atag.hex(), msg))
        else:
            _walk(r, _op(tag, r, msg), out, depth + 1)

    tag = r.byte()
    while tag == 0xFF:
        one(r.byte())
        tag = r.byte()
    one(tag)


def parse_ots(b: bytes) -> tuple[bytes, list[tuple[str, object, bytes]]]:
    """Return (file digest, attestations as (kind, value, message at the attestation))."""
    r = _Reader(b)
    if r.take(len(MAGIC)) != MAGIC:
        raise Unparseable("magic")
    if r.varuint() != 1:
        raise Unparseable("version")
    if r.byte() != 0x08:
        raise Unparseable("file hash is not sha256")
    digest = r.take(32)
    atts: list[tuple[str, object, bytes]] = []
    _walk(r, digest, atts)
    if r.i != len(b):
        raise Unparseable("trailing bytes")
    return digest, atts


def _shape_ok(p: object) -> bool:
    try:
        return (p["anchor_pointer"] == "0" and p["anchored_digest"]["alg"] == "sha-256"
                and bool(HEX64.match(p["anchored_digest"]["hex"])) and isinstance(p["anchored_set"]["locator"], str)
                and isinstance(p["mechanism"], str) and isinstance(p["proof"]["locator"], str)
                and bool(HEX64.match(p["proof"]["sha256"])) and isinstance(p["claimed"]["chain"], str)
                and type(p["claimed"]["height"]) is int and p["claimed"]["height"] >= 0)
    except (KeyError, TypeError):
        return False


def check(pointer: object, set_bytes: bytes, proof_bytes: bytes, headers: dict[str, str]) -> str:
    if not _shape_ok(pointer):
        return "malformed"
    if pointer["mechanism"] != "opentimestamps" or pointer["claimed"]["chain"] != "bitcoin":
        return "unsupported_mechanism"
    want = pointer["anchored_digest"]["hex"]
    if hashlib.sha256(set_bytes).hexdigest() != want:
        return "set_digest_mismatch"
    if hashlib.sha256(proof_bytes).hexdigest() != pointer["proof"]["sha256"]:
        return "proof_sha_mismatch"
    try:
        digest, atts = parse_ots(proof_bytes)
    except Unparseable:
        return "proof_unparseable"
    if digest.hex() != want:
        return "proof_for_other_digest"
    btc = [(h, m) for kind, h, m in atts if kind == "bitcoin"]
    if not btc:
        return "pending"
    height = pointer["claimed"]["height"]
    at_height = [m for h, m in btc if h == height]
    if not at_height:
        return "height_not_in_proof"
    root = headers.get(str(height))
    if root is None:
        return "header_unavailable"
    # Block explorers print the merkle root byte-reversed relative to the header bytes the proof ends at.
    return "anchored" if any(m == bytes.fromhex(root)[::-1] for m in at_height) else "root_mismatch"


def main() -> int:
    d = json.loads(Path(sys.argv[1]).read_text())
    blobs = {k: base64.b64decode(v) for k, v in d["blobs"].items()}
    rows, agree = [], 0
    for v in d["vectors"]:
        got = check(v["pointer"], blobs[v["anchored_bytes"]], blobs[v["proof_bytes"]], v["headers"])
        ok = got == v["expected"]
        agree += ok
        rows.append({"id": v["id"], "expected": v["expected"], "got": got, "agree": ok})
        print(f"{'agree' if ok else 'DIFFER':6} {v['id']:5} expected={v['expected']:24} got={got}")
    print(f"{agree}/{len(rows)}")
    if len(sys.argv) > 2:
        Path(sys.argv[2]).write_text(json.dumps({"agree": agree, "total": len(rows), "rows": rows}, indent=1) + "\n")
    return 0 if agree == len(rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
