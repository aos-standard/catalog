#!/usr/bin/env python3
"""Build three proposed negative vectors, in the vectors' own format, for the three checks that no committed vector
or scenario exercises (mutation_battery.py: M15, M24, M28). Signed with the published test seeds at the vectors'
clock; nonces are deterministic (seeded) so the files rebuild byte for byte."""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
W = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import scenario_harness as H  # noqa: E402
import wba_cold_verifier as V  # noqa: E402

NOW = H.NOW
SPEC = "WEB_BOT_AUTH.md"
BASE_URL = "https://github.com/IABTechLab/iab-agentic-primitives/blob/main/WEB_BOT_AUTH.md"
OTHER = next(k for k in H.KEYS if k["identity"] == "https://other.example.com")["kid"]
BUYER = H.S["signer"]["kid"]


def bases(op):
    out = {}
    if op["op"] == "verify_response":
        m, reqp = op["response"], V.prepare_request(op["request"], None)
        si, _sg, _sa = V.parse_signature_fields(m["headers"])
        for lab, mm in si:
            out[lab] = V.signature_base(mm[1], mm[2], {"headers": m["headers"], "status": m["status"]}, reqp, None).decode()
    else:
        m = op["request"]
        si, _sg, _sa = V.parse_signature_fields(m["headers"])
        for lab, mm in si:
            out[lab] = V.signature_base(mm[1], mm[2], V.prepare_request(m, op["authority"]), None, None).decode()
    return out


def vector(name, op, rule, anchor, comment):
    return {
        "$comment": comment,
        "name": name,
        "tier": "profile",
        "spec": SPEC,
        "spec_reference": BASE_URL + anchor,
        "signing_profile": "web-bot-auth",
        "reference_now": NOW,
        "operation": op,
        "replay_cache_entries": [],
        "expected_signature_base": bases(op),
        "expected": {"ok": False, "status": 403, "rule": rule,
                     "rationale": "proposed by an independent implementation; see $comment"},
    }


def response_by_other_origin():
    """The seller's request is answered by a response that other.example.com signs with its own, valid directory."""
    H.S["responder"] = {"identity": "https://other.example.com", "kid": OTHER,
                        "signature_agent": "https://other.example.com/.well-known/http-message-signatures-directory"}
    op = H.response_op({"label": "sig1", "request": "bound"}, NOW)
    op["expected_origin"] = "https://seller.example.com"
    return op


def directory_kid_not_thumbprint():
    jwk = dict(H.JWK[BUYER])
    jwk["kid"] = OTHER  # a well-formed thumbprint, but of another key
    op = H.directory_op({}, NOW)
    saved = H.JWK[BUYER]
    H.JWK[BUYER] = jwk  # the directory body lists the edited JWK and is signed over that body
    try:
        d = H.directory("https://buyer.example.com", [BUYER], NOW)
    finally:
        H.JWK[BUYER] = saved
    op["directories"] = {"https://buyer.example.com": d}
    return op


def directory_wrong_tag():
    op = H.directory_op({}, NOW)
    # rebuild the directory with tag "web-bot-auth" in place of "http-message-signatures-directory"
    orig_member = H.si_member

    def si_member(label, items, plist):
        plist = [(k, "web-bot-auth" if k == "tag" and v == "http-message-signatures-directory" else v) for k, v in plist]
        return orig_member(label, items, plist)
    orig_sign = H.sign

    def sign(msg, items, plist, kid, req=None):
        plist = [(k, "web-bot-auth" if k == "tag" and v == "http-message-signatures-directory" else v) for k, v in plist]
        return orig_sign(msg, items, plist, kid, req)
    H.si_member, H.sign = si_member, sign
    try:
        d = H.directory("https://buyer.example.com", [BUYER], NOW)
    finally:
        H.si_member, H.sign = orig_member, orig_sign
    op["directories"] = {"https://buyer.example.com": d}
    return op


def main():
    out_dir = os.path.join(W, "proposed")
    os.makedirs(out_dir, exist_ok=True)
    vs = {
        "x01-response-other-origin.json": vector(
            "A response to the seller's request, signed by another origin with a valid directory",
            response_by_other_origin(), "origin-mismatch", "#verification-procedure",
            "Verification procedure, Check the signer: the response is signed by the origin expected_origin names. "
            "Every other check passes: other.example.com's key, directory and binding to the request are valid. "
            "Catches a response verifier that accepts any signer whose own directory checks out."),
        "x02-directory-kid-not-thumbprint.json": vector(
            "The signer's directory lists its key under the kid of another key",
            directory_kid_not_thumbprint(), "directory-kid", "#profile-rules",
            "Profile rules, Keys: each kid is the key's RFC 7638 thumbprint. The directory is signed by the listed key "
            "and its Content-Digest matches; only the kid is wrong (it is the thumbprint of other.example.com's key). "
            "Catches a verifier that trusts the directory's kid instead of computing the thumbprint."),
        "x03-directory-signature-wrong-tag.json": vector(
            "The signer's directory is signed with tag=\"web-bot-auth\" instead of the directory tag",
            directory_wrong_tag(), "directory-tag", "#profile-rules",
            "Profile rules, Directory signatures: tag=\"http-message-signatures-directory\". The signature is otherwise "
            "valid. Catches a verifier that checks the directory signature without its tag, so a request signature's "
            "tag would also pass as a directory signature."),
    }
    for fn, v in vs.items():
        with open(os.path.join(out_dir, fn), "w", encoding="utf-8") as f:
            json.dump(v, f, indent=2, ensure_ascii=False)
            f.write("\n")
        print(fn, json.dumps(V.run(v["operation"])))


if __name__ == "__main__":
    main()
