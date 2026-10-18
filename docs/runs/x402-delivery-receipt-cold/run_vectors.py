#!/usr/bin/env python3
"""Run dr_cold_verifier over delivery-receipt.vectors.json: Appendix A checks (A.1–A.6) and the 14 expectedVerdicts.

Usage: python3 run_vectors.py <vectors.json> <out.json>
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import dr_cold_verifier as V  # noqa: E402


def jptr(doc, ptr: str):
    if ptr == "":
        return doc
    cur = doc
    for tok in ptr.lstrip("/").split("/"):
        tok = tok.replace("~1", "/").replace("~0", "~")
        cur = cur[int(tok)] if isinstance(cur, list) else cur[tok]
    return cur


def deref(doc, v):
    if isinstance(v, dict) and set(v) == {"$ref"}:
        return jptr(doc, v["$ref"])
    return v


def main() -> int:
    src, out_path = Path(sys.argv[1]), Path(sys.argv[2])
    raw = src.read_bytes()
    doc = V.parse_strict(raw)
    result = {"source_sha256": hashlib.sha256(raw).hexdigest(), "appendix": {}, "runs": [], "backend": {
        "ml-dsa-65": V.mldsa_backend("ml-dsa-65"), "ml-dsa-87": V.mldsa_backend("ml-dsa-87")}}

    # ---- A.1 / A.2–A.4: receipt-message and the three signature rows
    app = result["appendix"]
    for row in doc["signatures"]:
        alg = row["alg"]
        r: dict = {"alg": alg}
        pl = row["payload"]
        jcs_text = V.jcs_bytes(pl).decode()
        rid = V.receipt_id(pl)
        msg = V.signed_message(rid)
        r["jcs_matches"] = jcs_text == row["jcs"]
        r["receiptId_matches"] = rid == row["receiptId"] == row.get("jcsSha256", rid)
        r["message_matches"] = msg.decode() == row["message"] and msg.hex() == row["messageHex"] and len(msg) == 88
        pub = V.b64_canonical(row["publicKey"], "publicKey")
        sig = V.b64_canonical(row["signature"], "signature")
        r["sizes_match"] = (len(pub), len(sig)) == V.ALGS[alg]
        seed = bytes.fromhex(row["seed"])
        if alg == "ed25519":
            r["key_from_seed_matches"] = V.ed25519_public_from_seed(seed) == pub
            r["key_canonical_prime_order"] = V.ed25519_key_ok(pub)[0]
        else:
            derived = V.mldsa_public_from_seed(alg, seed)
            r["key_from_seed_matches"] = None if derived is None else derived == pub
        r["kid_derivation_matches"] = hashlib.sha256(row["publicKey"].encode()).hexdigest()[:16] == row["kid"]
        try:
            r["signature_verifies"] = V.sig_verify(alg, pub, msg, sig)
            tampered = bytearray(msg); tampered[-1] ^= 0x01
            r["tamper_rejected"] = not V.sig_verify(alg, pub, bytes(tampered), sig)
            bad_sig = bytearray(sig); bad_sig[0] ^= 0x01
            r["flipped_signature_rejected"] = not V.sig_verify(alg, pub, msg, bytes(bad_sig))
        except RuntimeError as e:
            r["signature_verifies"] = None; r["tamper_rejected"] = None; r["flipped_signature_rejected"] = None; r["skip"] = str(e)
        app[f"signature/{alg}"] = r

    # ---- A.5 stream digest
    st = doc["stream"]
    frames = [f.encode("utf-8") for f in st["frames"]]
    dg, steps = V.stream_digest(frames)
    app["stream"] = {"steps_match": steps == st["steps"], "digest_matches": dg == st["digest"] and len(frames) == st["frameCount"],
                     "domain_matches": V.STREAM_DOMAIN.decode() == st["domain"]}

    # ---- A.6 directory root and the five wrong projections (diagnostic)
    d = doc["endToEnd"]["directory"]
    root = V.directory_root(d)
    seven = {k: d[k] for k in ("spec", "issuer", "epoch", "prevRoot", "publishedAt", "governanceKeys", "keys")}
    def h(obj): return hashlib.sha256(V.jcs_bytes(obj)).hexdigest()
    wrong = {
        "without_signatures_root_inside": h({k: v for k, v in d.items() if k != "signatures"}),
        "whole_document": h(d),
        "seven_unsorted_reversed": h(dict(seven, governanceKeys=list(reversed(sorted(d["governanceKeys"], key=lambda g: g["alg"]))),
                                         keys=list(reversed(sorted(d["keys"], key=lambda k: k["kid"]))))),
        "six_without_publishedAt": h({k: v for k, v in seven.items() if k != "publishedAt"}),
        "seven_insertion_order": hashlib.sha256(json.dumps(seven, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest(),
    }
    app["directory_root"] = {"root_matches": root == d["root"] == "40b0560cd3637678eef1ff13743dfbac97ed6f153dcabebc536e3bc5e1e9e4a6",
                             "preimage_octets": len(V.jcs_bytes(seven)), "wrong_projections": wrong}

    # ---- expectedVerdicts
    agree = 0
    for ev in doc["expectedVerdicts"]:
        inputs = {k: deref(doc, v) for k, v in ev["inputs"].items()}
        vec = jptr(doc, ev["vector"])
        got = V.verify(inputs, path=ev["path"], offline=ev.get("offline", False), vector=vec if isinstance(vec, dict) else None)
        diffs = {}
        if got["path"] != ev["path"]:
            diffs["path"] = {"expected": ev["path"], "got": got["path"]}
        for lv in V.LEVELS:
            if got["levels"][lv] != ev["levels"][lv]:
                diffs[f"levels.{lv}"] = {"expected": ev["levels"][lv], "got": got["levels"][lv]}
        for k in ("valid", "longTermEvidence"):
            if got[k] != ev[k]:
                diffs[k] = {"expected": ev[k], "got": got[k]}
        exp_reason, got_reason = ev.get("reason"), got.get("reason")
        if (exp_reason is None) != (got_reason is None):
            diffs["reason"] = {"expected": exp_reason, "got": got_reason}
        elif exp_reason is not None:
            if exp_reason["level"] != got_reason["level"]:
                diffs["reason.level"] = {"expected": exp_reason["level"], "got": got_reason["level"]}
            if exp_reason.get("code") in ("KEY_DIRECTORY_DIGEST_MISMATCH", "DELIVERY_UNCONFIRMED") and exp_reason["code"] != got_reason["code"]:
                diffs["reason.code"] = {"expected": exp_reason["code"], "got": got_reason["code"]}
        # informative comparisons (not part of conformance per A.7)
        info = {}
        if "outcomes" in ev:
            for k, v in ev["outcomes"].items():
                if got["outcomes"].get(k) != v:
                    info[f"outcomes.{k}"] = {"expected": v, "got": got["outcomes"].get(k)}
        if "automaticRepayment" in ev and ev["automaticRepayment"] != got["automaticRepayment"]:
            info["automaticRepayment"] = {"expected": ev["automaticRepayment"], "got": got["automaticRepayment"]}
        status = "AGREE" if not diffs else "DISAGREE"
        agree += status == "AGREE"
        result["runs"].append({"id": ev["id"], "path": ev["path"], "status": status, "diffs": diffs,
                               "informative_diffs": info, "got": {"levels": got["levels"], "valid": got["valid"],
                               "longTermEvidence": got["longTermEvidence"], "reason": got["reason"], "outcomes": got["outcomes"],
                               "trust": got["report"]["trust"], "unchecked_algs": got["report"]["unchecked_algs"]}})
    result["agree"] = agree
    result["n"] = len(doc["expectedVerdicts"])
    out_path.write_text(json.dumps(result, indent=1, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    app_ok = all(all(v is True for k, v in r.items() if isinstance(v, bool)) for r in app.values() if isinstance(r, dict))
    print(f"expectedVerdicts: {agree}/{len(doc['expectedVerdicts'])} agree; appendix checks all true: {app_ok}")
    for r in result["runs"]:
        if r["status"] != "AGREE":
            print(" ", r["id"], json.dumps(r["diffs"])[:300], "| reason:", json.dumps(r["got"]["reason"])[:200])
    for k, r in app.items():
        bad = {kk: vv for kk, vv in r.items() if vv is False}
        if bad:
            print("  appendix", k, bad)
    return 0 if agree == len(doc["expectedVerdicts"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
