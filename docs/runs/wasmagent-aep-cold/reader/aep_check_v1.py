#!/usr/bin/env python3
"""AEP record checker written from the public text of WasmAgent/wasmagent-protocol at 0039ad6
(conformance/aep/README.md, IMPLEMENTER.md, verifier-result-contract.md, schemas/aep/aep-record.schema.json,
docs/standards-readiness/security-considerations.md, the non-fixture parts of manifest.json).
Not opened: index.js, bin/, scripts/ (including run-aep-conformance-corpus.py), wasmagent-js.
Where the text does not decide, the reading is named R<n> in a comment and listed in README.md of the record.

Python stdlib + cryptography (system package, Ed25519 only). No WasmAgent code imported.

Per record:  structural -> "valid"|"invalid"; semantic -> "valid"|"invalid"; authenticity -> "unsigned"|"dsse-valid"|"invalid"
Per sequence (.jsonl): the three above aggregated over records, plus chain -> "not-present"|"intact"|"partial"|"orphaned"|"broken"
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

INTOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://wasmagent.dev/attestations/aep/v0.4"
SIG_FIELDS = ("signature", "dsse_envelope")
GRADE_ORDER = ["unknown", "operator_asserted", "principal_key_signed", "qualified_signature"]  # weakest -> strongest (schema text)


# ---------------------------------------------------------------- canonical form
def canonical(obj) -> bytes:
    # R1: sorted keys, no whitespace, UTF-8, non-ASCII unescaped. The text says "canonical JSON" without naming
    # RFC 8785; key order by UTF-16 code units as in RFC 8785 (indistinguishable from code-point order on this corpus).
    def enc(x):
        if isinstance(x, dict):
            return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + enc(x[k])
                                  for k in sorted(x, key=lambda k: k.encode("utf-16-be"))) + "}"
        if isinstance(x, list):
            return "[" + ",".join(enc(i) for i in x) + "]"
        if isinstance(x, float) and x.is_integer() and abs(x) < 2 ** 53:
            return str(int(x))
        return json.dumps(x, ensure_ascii=False)
    return enc(obj).encode("utf-8")


def body(record: dict) -> dict:
    # R1: the record as bound by the signature = the record without its signature carriers.
    return {k: v for k, v in record.items() if k not in SIG_FIELDS}


def record_hash(record: dict) -> str:
    # R3: prev_record_hash = hex sha256 of canonical(body(previous record)).
    return hashlib.sha256(canonical(body(record))).hexdigest()


# ---------------------------------------------------------------- structural (JSON Schema subset)
def _type_ok(v, t) -> bool:
    if isinstance(t, list):
        return any(_type_ok(v, x) for x in t)
    if t == "object":
        return isinstance(v, dict)
    if t == "array":
        return isinstance(v, list)
    if t == "string":
        return isinstance(v, str)
    if t == "boolean":
        return isinstance(v, bool)
    if t == "null":
        return v is None
    if t == "number":
        return isinstance(v, (int, float)) and not isinstance(v, bool)
    if t == "integer":  # 2020-12: a number with zero fractional part
        return (isinstance(v, int) and not isinstance(v, bool)) or (isinstance(v, float) and v.is_integer())
    raise ValueError("unsupported type " + str(t))


SUPPORTED = {"$schema", "$id", "title", "description", "type", "required", "properties", "items", "enum",
             "uniqueItems", "minimum", "minItems", "additionalProperties", "contentEncoding"}


def schema_errors(v, s, path="$") -> list[str]:
    unknown = set(s) - SUPPORTED
    if unknown:
        raise ValueError("schema keyword not implemented: %s at %s" % (sorted(unknown), path))
    errs = []
    if "type" in s and not _type_ok(v, s["type"]):
        return [path + ": type"]
    if "enum" in s and not any(v == e and type(v) is type(e) for e in s["enum"]):
        errs.append(path + ": enum")
    if isinstance(v, (int, float)) and not isinstance(v, bool) and "minimum" in s and v < s["minimum"]:
        errs.append(path + ": minimum")
    if isinstance(v, dict):
        for r in s.get("required", []):
            if r not in v:
                errs.append(path + ": required " + r)
        props = s.get("properties", {})
        for k, sub in props.items():
            if k in v:
                errs += schema_errors(v[k], sub, path + "." + k)
        ap = s.get("additionalProperties", True)
        if ap is False:
            errs += [path + ": additional " + k for k in v if k not in props]
    if isinstance(v, list):
        if "minItems" in s and len(v) < s["minItems"]:
            errs.append(path + ": minItems")
        if s.get("uniqueItems"):
            seen = [canonical(x) for x in v]
            if len(set(seen)) != len(seen):
                errs.append(path + ": uniqueItems")
        if "items" in s:
            for i, x in enumerate(v):
                errs += schema_errors(x, s["items"], "%s[%d]" % (path, i))
    return errs


# ---------------------------------------------------------------- semantic (attribution floor / vocabulary / count)
def semantic_violations(r: dict) -> list[str]:
    out = []
    has_floor = "run_attribution_backing_floor" in r
    has_obs = "run_attribution_backing_observed" in r
    floor = r.get("run_attribution_backing_floor")
    obs = r.get("run_attribution_backing_observed")
    for key in ("attribution_backing", "run_attribution_backing_floor"):
        if key in r and r[key] not in GRADE_ORDER:
            out.append("vocabulary:" + key)
    if has_obs:
        if not isinstance(obs, list):
            out.append("observed:not-a-list")
            obs = []
        bad = [g for g in obs if g not in GRADE_ORDER]
        if bad:
            out.append("vocabulary:observed")
        if len(set(map(str, obs))) != len(obs):
            out.append("observed:duplicate")
    # pair-presence: floor and a non-empty observed set ship together (schema: "Report together ... never instead of")
    if has_floor and (not has_obs or not obs):
        out.append("pair:floor-without-observed")
    if has_obs and not has_floor:
        out.append("pair:observed-without-floor")  # R4: covers the empty observed set with no floor as well
    if has_floor and has_obs and obs and floor in GRADE_ORDER:
        known = [g for g in obs if g in GRADE_ORDER]
        if floor not in obs:
            out.append("floor:not-observed")
        elif known and floor != min(known, key=GRADE_ORDER.index):
            out.append("floor:not-weakest")
    if "authorization_evidence_count" in r:
        c = r["authorization_evidence_count"]
        if not (isinstance(c, int) and not isinstance(c, bool)) or c < 0:
            out.append("count:negative-or-non-integer")
        elif has_obs and isinstance(obs, list) and len(set(map(str, obs))) > c:
            out.append("count:fewer-items-than-observed-grades")  # R5
    return out


# ---------------------------------------------------------------- authenticity (DSSE, aep-dsse-ed25519-decoded-body-v1)
def pae(payload_type: str, body_bytes: bytes) -> bytes:
    t = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(body_bytes), body_bytes)


def load_key(hex_text: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(hex_text.strip()))


def authenticity(r: dict, keys: dict) -> tuple[str, list[str]]:
    env = r.get("dsse_envelope")
    if env is None:
        if "signature" in r:
            return "invalid", ["legacy-inline-signature-only"]  # R6: retired constructions are not the target
        return "unsigned", []
    why = []
    if not isinstance(env, dict) or not all(k in env for k in ("payloadType", "payload", "signatures")):
        return "invalid", ["envelope:shape"]
    if env["payloadType"] != INTOTO_PAYLOAD_TYPE:
        why.append("envelope:payloadType")
    sigs = env["signatures"]
    if not isinstance(sigs, list) or len(sigs) != 1:
        return "invalid", why + ["envelope:signature-count"]
    s = sigs[0]
    try:
        raw = base64.b64decode(env["payload"], validate=True)
        sig = base64.b64decode(s["sig"], validate=True)
    except Exception:
        return "invalid", why + ["envelope:base64"]
    key = keys.get(s.get("keyid"))
    if key is None:
        return "invalid", why + ["key:unknown-keyid"]
    try:
        key.verify(sig, pae(env["payloadType"], raw))
    except InvalidSignature:
        return "invalid", why + ["signature:ed25519"]
    try:
        st = json.loads(raw)
    except Exception:
        return "invalid", why + ["statement:json"]
    if not isinstance(st, dict) or st.get("_type") != STATEMENT_TYPE:
        why.append("statement:_type")
    if not isinstance(st, dict) or st.get("predicateType") != PREDICATE_TYPE:
        why.append("statement:predicateType")
    pred = st.get("predicate") if isinstance(st, dict) else None
    subj = st.get("subject") if isinstance(st, dict) else None
    b = body(r)
    if pred != b:
        why.append("binding:predicate-differs-from-record")  # R7: the inline record must equal the signed predicate
    if not isinstance(subj, list) or len(subj) != 1 or not isinstance(subj[0], dict):
        why.append("subject:shape")  # R8: exactly one subject
    else:
        name = subj[0].get("name")
        if name is None:
            why.append("subject:name-missing")
        elif name != "urn:wasmagent:run:" + str(r.get("run_id")):  # R2
            why.append("subject:name-not-this-run")
        d = (subj[0].get("digest") or {}).get("sha256")
        if d != hashlib.sha256(canonical(b)).hexdigest():  # R1
            why.append("subject:digest")
    legacy = r.get("signature")
    if isinstance(legacy, dict) and (legacy.get("sig") != s.get("sig") or legacy.get("key_id") != s.get("keyid")):
        why.append("legacy-field:not-derived-from-envelope")  # R9
    return ("invalid", why) if why else ("dsse-valid", [])


# ---------------------------------------------------------------- chain
def chain_status(records: list[dict]) -> tuple[str, dict]:
    # R10: link i (i>=1) is present when prev_record_hash is a non-null string; present links must equal
    # record_hash(record i-1). The first record's link must be null/absent unless its predecessor is unavailable.
    n = len(records)
    first_prev = records[0].get("prev_record_hash") if n else None
    links = [records[i].get("prev_record_hash") for i in range(1, n)]
    broken = [i for i in range(1, n) if records[i].get("prev_record_hash") is not None
              and records[i]["prev_record_hash"] != record_hash(records[i - 1])]
    missing = [i for i in range(1, n) if records[i].get("prev_record_hash") is None]
    if broken:
        return "broken", {"brokenAt": broken[0] - 1, "broken": broken}
    if first_prev is not None:
        return "orphaned", {}
    if n > 1 and len(missing) == n - 1:
        return "not-present", {}
    if missing:
        return "partial", {"missing": missing}
    if n <= 1:
        return "not-present", {}  # R11: one record with no predecessor claims no chain
    return "intact", {}


# ---------------------------------------------------------------- driver
def load_records(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".jsonl":
        return [json.loads(l) for l in text.splitlines() if l.strip()]
    return [json.loads(text)]


def check_file(path: Path, schema: dict, keys: dict) -> dict:
    recs = load_records(path)
    st = ["valid" if not schema_errors(r, schema) else "invalid" for r in recs]
    se = ["valid" if not semantic_violations(r) else "invalid" for r in recs]
    au = [authenticity(r, keys) for r in recs]
    out = {
        "structural": "valid" if all(x == "valid" for x in st) else "invalid",
        "semantic": "valid" if all(x == "valid" for x in se) else "invalid",
        # R12: a sequence is dsse-valid only if every record is; unsigned only if every record is
        "authenticity": ("invalid" if any(a == "invalid" for a, _ in au) else
                         "unsigned" if all(a == "unsigned" for a, _ in au) else
                         "dsse-valid" if all(a == "dsse-valid" for a, _ in au) else "invalid"),
        "detail": {"structural": [schema_errors(r, schema) for r in recs],
                   "semantic": [semantic_violations(r) for r in recs],
                   "authenticity": [w for _, w in au]},
    }
    if len(recs) > 1 or path.suffix == ".jsonl":
        c, info = chain_status(recs)
        out["chain"] = c
        out["detail"]["chain"] = info
    return out
