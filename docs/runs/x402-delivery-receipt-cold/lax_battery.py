#!/usr/bin/env python3
"""Mutation battery: each mutation of the endToEnd fixtures must make a level fail (or be not-evaluated).

A mutation the verifier still passes is a check the vectors do not exercise and this verifier does not enforce.
Usage: python3 lax_battery.py <vectors.json> <out.json>
"""
from __future__ import annotations

import base64
import copy
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import dr_cold_verifier as V  # noqa: E402
from run_vectors import deref, jptr  # noqa: E402


def base_inputs(doc, run_id):
    ev = next(e for e in doc["expectedVerdicts"] if e["id"] == run_id)
    return {k: copy.deepcopy(deref(doc, v)) for k, v in ev["inputs"].items()}, ev["path"]


def flip_b64(s: str, pos: int = 3) -> str:
    raw = bytearray(base64.b64decode(s)); raw[pos] ^= 0x01
    return base64.b64encode(bytes(raw)).decode()


def main() -> int:
    doc = V.parse_strict(Path(sys.argv[1]).read_bytes())
    e2e = doc["endToEnd"]
    muts = []

    def add(name, run_id, mutate, expect_level):
        inputs, path = base_inputs(doc, run_id)
        mutate(inputs)
        muts.append((name, run_id, path, inputs, expect_level))

    # integrity
    add("M01 drop ml-dsa-65 signature entry", "endToEnd/body/archival", lambda i: i["receipt"]["signatures"].pop(1), "integrity")
    add("M02 unregistered alg entry added", "endToEnd/body/archival", lambda i: i["receipt"]["signatures"].append({"alg": "rsa-pss", "kid": "x", "signature": "AA=="}), "integrity")
    add("M03 extra payload member", "endToEnd/body/session", lambda i: i["receipt"]["payload"].__setitem__("note", "x"), "integrity")
    add("M04 float in payload (logIndex 312.0)", "endToEnd/body/session", lambda i: i["receipt"]["payload"].__setitem__("logIndex", 312.0), "integrity")
    add("M05 non-canonical base64 (unpadded) signature", "endToEnd/body/session", lambda i: i["receipt"]["signatures"][0].__setitem__("signature", i["receipt"]["signatures"][0]["signature"].rstrip("=")), "integrity")
    add("M06 unregistered framing", "endToEnd/stream/session", lambda i: None, "delivery")  # placeholder replaced below
    muts.pop()
    add("M07 reference digest mismatch (document with one byte changed)", "endToEnd/reference/session",
        lambda i: i.__setitem__("receiptDocument", i["receiptDocument"][:-2] + "}" + " "), "integrity")
    add("M08 document not JCS (pretty-printed, digest recomputed)", "endToEnd/reference/session",
        lambda i: (i.__setitem__("receiptDocument", json.dumps(json.loads(i["receiptDocument"]), indent=1)),
                   i["reference"].__setitem__("digest", V.sha256_hex(i["receiptDocument"].encode()))), "integrity")
    add("M09 duplicate member in document (digest recomputed)", "endToEnd/reference/session",
        lambda i: (i.__setitem__("receiptDocument", i["receiptDocument"][:-1] + ',"payload":{}}'),
                   i["reference"].__setitem__("digest", V.sha256_hex(i["receiptDocument"].encode()))), "integrity")
    add("M10 receiptUrl on another origin", "endToEnd/reference/session",
        lambda i: i["reference"].__setitem__("receiptUrl", i["reference"]["receiptUrl"].replace("api.example.com", "cdn.example.net")), "integrity")
    # authentic
    add("M11 ed25519 signature byte flipped", "endToEnd/body/session", lambda i: i["receipt"]["signatures"][0].__setitem__("signature", flip_b64(i["receipt"]["signatures"][0]["signature"])), "authentic")
    add("M12 ml-dsa-65 signature byte flipped (archival)", "endToEnd/body/archival", lambda i: i["receipt"]["signatures"][1].__setitem__("signature", flip_b64(i["receipt"]["signatures"][1]["signature"])), "authentic")
    add("M13 ml-dsa-65 signature byte flipped on the SESSION path (must still be reported unchecked, not fail)", "endToEnd/body/session",
        lambda i: i["receipt"]["signatures"][1].__setitem__("signature", flip_b64(i["receipt"]["signatures"][1]["signature"])), None)
    add("M14 kid points at the other key (alg mismatch)", "endToEnd/body/session", lambda i: i["receipt"]["signatures"][0].__setitem__("kid", "c47ca781ddf6ace8"), "authentic")
    add("M15 unknown kid", "endToEnd/body/session", lambda i: i["receipt"]["signatures"][0].__setitem__("kid", "deadbeefdeadbeef"), "authentic")
    add("M16 payload amount edited (signature stale)", "endToEnd/body/session", lambda i: i["receipt"]["payload"].__setitem__("amount", "10001"), "authentic")
    add("M17 directory governance ed25519 signature flipped (session)", "endToEnd/body/session",
        lambda i: i["directory"]["signatures"][0].__setitem__("signature", flip_b64(i["directory"]["signatures"][0]["signature"])), "authentic")
    add("M18 directory root edited", "endToEnd/body/session", lambda i: i["directory"].__setitem__("root", "0" * 64), "authentic")
    add("M19 governance key replaced by small-order point", "endToEnd/body/session",
        lambda i: i["directory"]["governanceKeys"][0].__setitem__("publicKey", base64.b64encode(b"\x01" + b"\x00" * 31).decode()), "authentic")
    # trusted
    add("M20 pinned governance key differs (trust basis absent)", "endToEnd/body/session",
        lambda i: i["pinnedGovernanceKeys"].__setitem__("ed25519", i["pinnedGovernanceKeys"]["ml-dsa-65"][:43] + "=") , "trusted")
    add("M21 pinned only ml-dsa-65 while checking ed25519 (session)", "endToEnd/body/session",
        lambda i: i["pinnedGovernanceKeys"].pop("ed25519"), "trusted")
    add("M22 payload keyDirectoryDigest differs → KEY_DIRECTORY_DIGEST_MISMATCH (needs re-sign; expect authentic to fail first)", "endToEnd/body/session",
        lambda i: i["receipt"]["payload"].__setitem__("keyDirectoryDigest", "1" * 64), "authentic")
    add("M23 directory epoch 2 with same content (prevRoot zeros) → shape", "endToEnd/body/session",
        lambda i: i["directory"].__setitem__("epoch", 2), "authentic")
    add("M24 signing key status revoked", "endToEnd/body/session", lambda i: i["directory"]["keys"][0].__setitem__("status", "revoked"), None)  # root changes → authentic fails first
    add("M25 issuedAt far in the future (now moved back)", "endToEnd/body/session", lambda i: i.__setitem__("now", e2e["now"] - 10_000), "trusted")
    add("M26 resourceUrl on another origin than issuer (settlement vs trusted)", "endToEnd/body/session",
        lambda i: i.__setitem__("resourceUrl", "https://other.example.org/premium-data"), None)
    # settlement
    add("M27 settle transaction differs", "endToEnd/body/session", lambda i: i["settle"].__setitem__("transaction", "0x" + "ab" * 32), "settlement")
    add("M28 settle payer case changed (must still pass)", "endToEnd/body/session", lambda i: i["settle"].__setitem__("payer", i["settle"]["payer"].lower()), "pass")
    add("M29 settle payer non-string", "endToEnd/body/session", lambda i: i["settle"].__setitem__("payer", 12345), "settlement")
    add("M30 requirements amount differs", "endToEnd/body/session", lambda i: i["requirements"].__setitem__("amount", "10001"), "settlement")
    add("M31 settle.amount present and equal (must pass)", "endToEnd/body/session", lambda i: i["settle"].__setitem__("amount", "10000"), "pass")
    add("M32 settle.amount present and different", "endToEnd/body/session", lambda i: i["settle"].__setitem__("amount", "999"), "settlement")
    add("M33 method differs", "endToEnd/body/session", lambda i: i.__setitem__("method", "POST"), "settlement")
    add("M34 client sent a paymentId but payload has null", "endToEnd/body/session", lambda i: i.__setitem__("paymentId", "pid-1"), "settlement")
    add("M35 offer-receipt in settle disagrees on payer", "endToEnd/body/session",
        lambda i: i["settle"].__setitem__("extensions", {"offer-receipt": {"info": {"receipt": {"payload": {"network": "eip155:8453", "payer": "0x" + "11" * 20}}}}}), "settlement")
    add("M36 settle success false", "endToEnd/body/session", lambda i: i["settle"].__setitem__("success", False), "settlement")
    # delivery
    add("M37 body differs by one byte", "endToEnd/body/session", lambda i: i.__setitem__("responseBody", i["responseBody"] + " "), "delivery")
    add("M38 no body → DELIVERY_UNCONFIRMED (not-evaluated)", "endToEnd/body/session", lambda i: i.pop("responseBody"), "not-evaluated")
    add("M39 stream: one frame dropped", "endToEnd/stream/session",
        lambda i: i.__setitem__("eventStream", i["eventStream"].replace('data: {"seq":1,"price":"64001"}\n\n', "")), "delivery")
    add("M40 stream: frames reordered", "endToEnd/stream/session",
        lambda i: i.__setitem__("eventStream", i["eventStream"].replace('data: {"seq":0,"price":"64000"}\n\ndata: {"seq":1,"price":"64001"}\n\n', 'data: {"seq":1,"price":"64001"}\n\ndata: {"seq":0,"price":"64000"}\n\n')), "delivery")
    add("M41 stream: event after the terminal event", "endToEnd/stream/session", lambda i: i.__setitem__("eventStream", i["eventStream"] + "data: late\n\n"), "delivery")
    add("M42 stream: CRLF line ends (must pass)", "endToEnd/stream/session", lambda i: i.__setitem__("eventStream", i["eventStream"].replace("\n", "\r\n")), "pass")
    add("M43 stream: comment and retry lines inserted (must pass)", "endToEnd/stream/session",
        lambda i: i.__setitem__("eventStream", ": keep-alive\n\nretry: 5000\n\n" + i["eventStream"]), "pass")
    add("M44 stream: terminal event without its blank line (pending, discarded)", "endToEnd/stream/session",
        lambda i: i.__setitem__("eventStream", i["eventStream"].rstrip("\n") + "\n"), "integrity")
    add("M45 stream: terminal frameCount edited", "endToEnd/stream/session",
        lambda i: i.__setitem__("eventStream", i["eventStream"].replace('data: {"frameCount":3,', 'data: {"frameCount":4,')), "delivery")
    add("M46 streamSession observed status 500", "streamSession/session", lambda i: i.__setitem__("responseStatus", 500), "delivery")
    add("M47 streamSession: terminal reference digest edited", "streamSession/session",
        lambda i: i.__setitem__("eventStream", i["eventStream"].replace(i["reference"]["digest"], "0" * 64)) or i["reference"].__setitem__("digest", "0" * 64), "integrity")
    add("M48 directory keys array reversed (root sorts; must pass)", "endToEnd/body/session", lambda i: i["directory"]["keys"].reverse(), "pass")
    add("M49 directory governanceKeys reversed (must pass)", "endToEnd/body/session", lambda i: i["directory"]["governanceKeys"].reverse(), "pass")

    rows = []
    for name, run_id, path, inputs, expect in muts:
        vec = jptr(doc, next(e for e in doc["expectedVerdicts"] if e["id"] == run_id)["vector"])
        got = V.verify(inputs, path=path, vector=vec if isinstance(vec, dict) else None)
        first_bad = next((lv for lv in V.LEVELS if got["levels"][lv] != "pass"), None)
        if expect == "pass":
            ok = got["valid"] is True
        elif expect == "not-evaluated":
            ok = got["levels"]["delivery"] == "not-evaluated" and got["valid"] is False
        elif expect is None:
            ok = None  # recorded only
        else:
            ok = (first_bad == expect) and got["valid"] is False
        rows.append({"mutation": name, "run": run_id, "expected": expect, "first_failing_level": first_bad,
                     "levels": got["levels"], "valid": got["valid"], "reason": got["reason"], "unchecked_algs": got["report"]["unchecked_algs"], "ok": ok})
    out = {"n": len(rows), "ok": sum(1 for r in rows if r["ok"] is True), "not_ok": [r["mutation"] for r in rows if r["ok"] is False],
           "recorded_only": [(r["mutation"], r["first_failing_level"], (r["reason"] or {}).get("code")) for r in rows if r["ok"] is None], "rows": rows}
    Path(sys.argv[2]).write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n")
    print(f"battery: {out['ok']} ok / {len(rows)} ; not ok: {out['not_ok']}")
    for m in out["recorded_only"]:
        print("  recorded:", m)
    return 0 if not out["not_ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
