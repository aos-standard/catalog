#!/usr/bin/env python3
"""EVM-log anchor pointer reader, written from the `mechanism` block of anchor-pointer-evm-log-v1/vectors.json
(giskard09/argentum-core 63711d8) and the event signature alone; no code from that repository was read.

Checks, in order (the first failure is the result):
  malformed            a field has the wrong shape (chain must be CAIP-2 `eip155:<id>`)
  unsupported_chain    no RPC endpoint configured for the chain id
  tx_not_found         eth_getTransactionReceipt returns null on that chain
  tx_reverted          receipt status is not 0x1
  log_not_found        the receipt has no log at `log_index`
  contract_mismatch    log.address != contract
  event_mismatch       log.topics[0] != keccak256 of the event signature (given in the vectors, not recomputed here)
  height_unreachable   declared height is above the chain head at read time
  height_mismatch      log.blockNumber != height
  digest_mismatch      log.topics[1] != anchored_digest
  not_final            the block is above the chain's `finalized` block at read time
  anchored             all of the above hold

Usage: python3 -I evm_log_pointer_check.py <vectors.json> <out.json>
"""
from __future__ import annotations

import json
import re
import sys
import urllib.request
from pathlib import Path

RPC = {8453: "https://mainnet.base.org", 42161: "https://arb1.arbitrum.io/rpc"}
TOPIC0 = "0xfe2289542f7a0110ac112c3a4d712afdcaaf2900a1326f4e6f340b563a0e8734"
HEX = lambda n: re.compile(r"0x[0-9a-fA-F]{%d}" % n)  # noqa: E731


def rpc(url: str, method: str, params: list):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(url, body, {"Content-Type": "application/json", "User-Agent": "aos-catalog-reader"})
    with urllib.request.urlopen(req, timeout=30) as r:
        out = json.loads(r.read())
    if "error" in out:
        raise RuntimeError(out["error"])
    return out["result"]


def check(p: dict) -> tuple[str, dict]:
    m = re.fullmatch(r"eip155:([1-9][0-9]*)", str(p.get("chain", "")))
    if not m:
        return "malformed", {"field": "chain"}
    for f, n in (("contract", 40), ("tx", 64), ("anchored_digest", 64)):
        if not isinstance(p.get(f), str) or not HEX(n).fullmatch(p[f]):
            return "malformed", {"field": f}
    for f in ("log_index", "height"):
        if not isinstance(p.get(f), int) or isinstance(p.get(f), bool) or p[f] < 0:
            return "malformed", {"field": f}
    url = RPC.get(int(m.group(1)))
    if url is None:
        return "unsupported_chain", {}
    rc = rpc(url, "eth_getTransactionReceipt", [p["tx"].lower()])
    if rc is None:
        return "tx_not_found", {}
    if rc.get("status") != "0x1":
        return "tx_reverted", {"status": rc.get("status")}
    logs = [lg for lg in rc["logs"] if int(lg["logIndex"], 16) == p["log_index"]]
    if not logs:
        return "log_not_found", {"log_indexes": [int(lg["logIndex"], 16) for lg in rc["logs"]]}
    lg = logs[0]
    if lg["address"].lower() != p["contract"].lower():
        return "contract_mismatch", {"log_address": lg["address"]}
    if not lg["topics"] or lg["topics"][0].lower() != TOPIC0:
        return "event_mismatch", {}
    head = int(rpc(url, "eth_blockNumber", []), 16)
    if p["height"] > head:
        return "height_unreachable", {"head": head}
    block = int(lg["blockNumber"], 16)
    if block != p["height"]:
        return "height_mismatch", {"log_block": block}
    if len(lg["topics"]) < 2 or lg["topics"][1].lower() != p["anchored_digest"].lower():
        return "digest_mismatch", {}
    fin = int(rpc(url, "eth_getBlockByNumber", ["finalized", False])["number"], 16)
    if block > fin:
        return "not_final", {"finalized": fin}
    return "anchored", {"block": block, "finalized": fin, "head": head}


def main() -> int:
    d = json.loads(Path(sys.argv[1]).read_text())
    rows, agree = [], 0
    for v in d["vectors"]:
        res, info = check(v["input"])
        ok = (res == "anchored") == (v["expected"] == "PASS")
        agree += ok
        rows.append({"id": v["id"], "expected": v["expected"], "their_mode": v.get("failure_mode"),
                     "result": res, "detail": info, "agree": ok})
        print(f"{'agree' if ok else 'DIFFER':6} {v['id']:58} expected={v['expected']:4} "
              f"their_mode={v.get('failure_mode')} here={res} {info}")
    print(f"{agree}/{len(rows)} agree on pass/fail")
    Path(sys.argv[2]).write_text(json.dumps({"rows": rows}, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
