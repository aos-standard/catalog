#!/usr/bin/env python3
"""Check an anchor pointer (draft 1) for two mechanisms: `opentimestamps` on Bitcoin, and `evm-log`.

Draft 1 keeps draft 0's fields and adds three things (aeoess/agent-governance-vocabulary#217):

    {"anchor_pointer": "1",
     "anchored_digest": {"alg": "sha-256", "hex": "<64 lowercase hex>"},
     "anchored_set": {"locator": "<pinned>", "select": {"kind": "line", "index": 0}},   # select is optional
     "mechanism": "opentimestamps" | "evm-log",
     "proof": {"locator": "<pinned>", "sha256": "<64 lowercase hex>"},                 # opentimestamps only
     "claimed": {"chain": "bitcoin", "height": <int>}                                   # opentimestamps
              | {"chain": "eip155:<id>", "contract": "0x<40 hex>", "tx": "0x<64 hex>",
                 "log_index": <int>, "height": <int>}}                                   # evm-log

- `anchored_set` is optional. When present, `select` picks the anchored bytes out of the fetched resource. Draft 1
  defines one kind, `line`: lines are separated by LF (0x0A), a line's bytes exclude its LF and nothing else is
  stripped, `index` counts from 0, and an empty segment after a final LF is not a line. Without `select` the whole
  resource is the anchored bytes. When `anchored_set` is absent, or the reader is not given its bytes, the result
  says `set_checked: false`.
- For `evm-log` there is no proof file: the reader queries the declared chain, and `proof` must be absent or null.
- When an OpenTimestamps proof reaches more than one block, `claimed.height` may be any of them; the result reports
  `earliest_height`, which is the tight bound.

Result codes, first failure wins. Shared: `malformed`, `unsupported_mechanism`, `unsupported_select`,
`select_out_of_range`, `set_digest_mismatch`. opentimestamps: `proof_sha_mismatch`, `proof_unparseable`,
`proof_for_other_digest`, `pending`, `height_not_in_proof`, `header_unavailable`, `root_mismatch`. evm-log:
`unsupported_chain`, `tx_not_found`, `tx_reverted`, `log_not_found`, `contract_mismatch`, `event_mismatch`,
`height_unreachable`, `height_mismatch`, `digest_mismatch`, `not_final`. Otherwise `anchored`.

The trust inputs are the reader's, not the pointer's: block headers for Bitcoin, RPC endpoints for EVM chains.
`anchored` says the bytes existed no later than that block, not who made them or whether they are true.

Usage: python3 -I -B anchor_pointer_check_d1.py <vectors.json> [<out.json>]
Standard library only (plus network for evm-log vectors).
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import sys
import urllib.request
from pathlib import Path

MAGIC = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
BITCOIN_TAG = bytes.fromhex("0588960d73d71901")
PENDING_TAG = bytes.fromhex("83dfe30d2ef90c8e")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
EVM_TOPIC0 = "0xfe2289542f7a0110ac112c3a4d712afdcaaf2900a1326f4e6f340b563a0e8734"  # Anchored(bytes32,address,uint256)
RPC = {8453: "https://mainnet.base.org", 42161: "https://arb1.arbitrum.io/rpc"}


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


def _walk(r: _Reader, msg: bytes, out: list, depth: int = 0) -> None:
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


def parse_ots(b: bytes) -> tuple[bytes, list]:
    r = _Reader(b)
    if r.take(len(MAGIC)) != MAGIC:
        raise Unparseable("magic")
    if r.varuint() != 1:
        raise Unparseable("version")
    if r.byte() != 0x08:
        raise Unparseable("file hash is not sha256")
    digest = r.take(32)
    atts: list = []
    _walk(r, digest, atts)
    if r.i != len(b):
        raise Unparseable("trailing bytes")
    return digest, atts


def _nonneg_int(x: object) -> bool:
    return type(x) is int and x >= 0


def _shape_ok(p: object) -> bool:
    try:
        if p["anchor_pointer"] not in ("0", "1"):
            return False
        if p["anchored_digest"]["alg"] != "sha-256" or not HEX64.match(p["anchored_digest"]["hex"]):
            return False
        s = p.get("anchored_set")
        if s is not None:
            if not isinstance(s.get("locator"), str):
                return False
            sel = s.get("select")
            if sel is not None and (p["anchor_pointer"] == "0" or not isinstance(sel.get("kind"), str)
                                    or ("index" in sel and not _nonneg_int(sel["index"]))):
                return False
        if not isinstance(p["mechanism"], str) or not isinstance(p["claimed"], dict):
            return False
        if p["mechanism"] == "opentimestamps":
            if p["anchor_pointer"] == "0" and s is None:
                return False
            return (isinstance(p["proof"]["locator"], str) and bool(HEX64.match(p["proof"]["sha256"]))
                    and isinstance(p["claimed"]["chain"], str) and _nonneg_int(p["claimed"]["height"]))
        if p["mechanism"] == "evm-log" and p["anchor_pointer"] == "1":
            c = p["claimed"]
            return (p.get("proof") is None
                    and bool(re.fullmatch(r"eip155:[1-9][0-9]*", str(c["chain"])))
                    and bool(re.fullmatch(r"0x[0-9a-fA-F]{40}", str(c["contract"])))
                    and bool(re.fullmatch(r"0x[0-9a-fA-F]{64}", str(c["tx"])))
                    and _nonneg_int(c["log_index"]) and _nonneg_int(c["height"]))
        return True  # an unknown mechanism (and evm-log in draft 0) is well-formed here and unsupported below
    except (KeyError, TypeError, AttributeError):
        return False


def _selected(pointer: dict, resource: bytes) -> tuple[str | None, bytes]:
    sel = (pointer.get("anchored_set") or {}).get("select")
    if sel is None:
        return None, resource
    if sel["kind"] != "line" or "index" not in sel:
        return "unsupported_select", b""
    lines = resource.split(b"\n")
    if resource.endswith(b"\n"):
        lines = lines[:-1]
    if sel["index"] >= len(lines):
        return "select_out_of_range", b""
    return None, lines[sel["index"]]


def _rpc(url: str, method: str, params: list):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(url, body, {"Content-Type": "application/json", "User-Agent": "aos-catalog-reader"})
    with urllib.request.urlopen(req, timeout=30) as r:
        out = json.loads(r.read())
    if "error" in out:
        raise RuntimeError(out["error"])
    return out["result"]


def _evm(p: dict) -> tuple[str, dict]:
    c = p["claimed"]
    url = RPC.get(int(c["chain"].split(":", 1)[1]))
    if url is None:
        return "unsupported_chain", {}
    rc = _rpc(url, "eth_getTransactionReceipt", [c["tx"].lower()])
    if rc is None:
        return "tx_not_found", {}
    if rc.get("status") != "0x1":
        return "tx_reverted", {"status": rc.get("status")}
    logs = [lg for lg in rc["logs"] if int(lg["logIndex"], 16) == c["log_index"]]
    if not logs:
        return "log_not_found", {}
    lg = logs[0]
    if lg["address"].lower() != c["contract"].lower():
        return "contract_mismatch", {}
    if not lg["topics"] or lg["topics"][0].lower() != EVM_TOPIC0:
        return "event_mismatch", {}
    head = int(_rpc(url, "eth_blockNumber", []), 16)
    if c["height"] > head:
        return "height_unreachable", {"head": head}
    block = int(lg["blockNumber"], 16)
    if block != c["height"]:
        return "height_mismatch", {"log_block": block}
    if len(lg["topics"]) < 2 or lg["topics"][1].lower() != "0x" + p["anchored_digest"]["hex"]:
        return "digest_mismatch", {}
    fin = int(_rpc(url, "eth_getBlockByNumber", ["finalized", False])["number"], 16)
    if block > fin:
        return "not_final", {"finalized": fin}
    return "anchored", {"finalized": fin}


def check(pointer: object, resource: bytes | None = None, proof_bytes: bytes | None = None,
          headers: dict | None = None) -> dict:
    """Return {"result": code, "set_checked": bool, ...}."""
    if not _shape_ok(pointer):
        return {"result": "malformed", "set_checked": False}
    known = ("opentimestamps",) if pointer["anchor_pointer"] == "0" else ("opentimestamps", "evm-log")
    if pointer["mechanism"] not in known or (
            pointer["mechanism"] == "opentimestamps" and pointer["claimed"]["chain"] != "bitcoin"):
        return {"result": "unsupported_mechanism", "set_checked": False}
    want = pointer["anchored_digest"]["hex"]
    set_checked = pointer.get("anchored_set") is not None and resource is not None
    if set_checked:
        err, anchored = _selected(pointer, resource)
        if err:
            return {"result": err, "set_checked": False}
        if hashlib.sha256(anchored).hexdigest() != want:
            return {"result": "set_digest_mismatch", "set_checked": True}
    if pointer["mechanism"] == "evm-log":
        res, info = _evm(pointer)
        return dict({"result": res, "set_checked": set_checked}, **info)
    if proof_bytes is None or hashlib.sha256(proof_bytes).hexdigest() != pointer["proof"]["sha256"]:
        return {"result": "proof_sha_mismatch", "set_checked": set_checked}
    try:
        digest, atts = parse_ots(proof_bytes)
    except Unparseable:
        return {"result": "proof_unparseable", "set_checked": set_checked}
    if digest.hex() != want:
        return {"result": "proof_for_other_digest", "set_checked": set_checked}
    btc = [(h, m) for kind, h, m in atts if kind == "bitcoin"]
    if not btc:
        return {"result": "pending", "set_checked": set_checked}
    out = {"set_checked": set_checked, "earliest_height": min(h for h, _ in btc)}
    height = pointer["claimed"]["height"]
    at = [m for h, m in btc if h == height]
    if not at:
        return dict(out, result="height_not_in_proof")
    root = (headers or {}).get(str(height))
    if root is None:
        return dict(out, result="header_unavailable")
    # Explorers print the merkle root byte-reversed relative to the header bytes the proof ends at.
    ok = any(m == bytes.fromhex(root)[::-1] for m in at)
    return dict(out, result="anchored" if ok else "root_mismatch")


def main() -> int:
    d = json.loads(Path(sys.argv[1]).read_text())
    blobs = {k: base64.b64decode(v) for k, v in d.get("blobs", {}).items()}
    rows, agree = [], 0
    for v in d["vectors"]:
        got = check(v["pointer"], blobs.get(v.get("anchored_bytes")), blobs.get(v.get("proof_bytes")), v.get("headers"))
        exp = v["expected"] if isinstance(v["expected"], dict) else {"result": v["expected"]}
        ok = all(got.get(k) == val for k, val in exp.items())
        agree += ok
        rows.append({"id": v["id"], "expected": exp, "got": got, "agree": ok})
        print(f"{'agree' if ok else 'DIFFER':6} {v['id']:7} expected={json.dumps(exp, sort_keys=True)} got={json.dumps(got, sort_keys=True)}")
    print(f"{agree}/{len(rows)}")
    if len(sys.argv) > 2:
        Path(sys.argv[2]).write_text(json.dumps({"agree": agree, "total": len(rows), "rows": rows}, indent=1) + "\n")
    return 0 if agree == len(rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
