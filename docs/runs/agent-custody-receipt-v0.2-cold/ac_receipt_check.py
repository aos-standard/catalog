#!/usr/bin/env python3
"""ac_receipt_check — a clean-room verifier for agent-custody receipts, written from site/receipt/v0.2.md alone.

Source: svayatta/agent-custody at bd57844be2db50ade7b5ce991f29c1522060e3e4, the page site/receipt/v0.2.md and
site/receipt/vectors.md (how the vector files are laid out). Not opened: packages/receipts/src/verify.ts, the browser
verifier, packages/python, scripts/vectors.ts, any test. Answer-exposed before writing: the names in `expected.failing`
and the `description` of every vector were read, to map which names the page defines (see README).

Standard library plus `cryptography` (Ed25519, SPKI). Check names are the page's where the page names a check; where the
page describes a check in prose without naming it (authorization, strict mode, the log id, delegation chains, financial
reconciliation) the name is the one the vectors use, and the README says so for each. Readings R1–R26 are listed in
the README and marked in the code as `# R<n>`.

v2 (after the first scored run): eight edits marked `# v2`; v3 (after the second): two edits marked `# v3`. v1 and v2 and their runs are kept; all listed in FROZEN.txt.

verify_bundle(bundle, keys, options) -> {"ok", "failing": [...], "checks": [{"name", "ok", "detail"}]}
audit_extends(older, newer, proof, keys) -> same shape
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
RECEIPT_PREDICATE = "https://agent-custody.dev/receipt/v0.2"
AUTHORIZATION_PREDICATE = "https://agent-custody.dev/authorization/v0.1"
PT_INTOTO = "application/vnd.in-toto+json"
PT_TREEHEAD = "application/vnd.agent-custody.treehead+json"
PT_UPSTREAM = "application/vnd.agent-custody.upstream+json"
PT_APPROVAL = "application/vnd.agent-custody.approval+json"
PT_DELEGATION = "application/vnd.agent-custody.delegation+json"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
FORWARDED = ("executed", "failed", "error")       # R2: not denied, not withheld
EXECUTED_LIKE = ("executed", "failed")            # the statuses that carry a result
STRIPE_TOLERANCE_S = 300                           # R12
MAX_SAFE_INT = 2 ** 53 - 1


# ----------------------------------------------------------------------------------------------- primitives
def canonical(value: Any) -> str:
    """Canonical JSON: keys sorted (UTF-16 code unit order, R1), no whitespace, non-ASCII unescaped."""
    if value is None or isinstance(value, bool):
        return json.dumps(value)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            return "null"
        if value == int(value) and abs(value) < 1e21:
            return str(int(value))
        return repr(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(canonical(v) for v in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + canonical(value[k]) for k in keys) + "}"
    raise TypeError(type(value).__name__)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(value: Any) -> str:
    return sha256_hex(canonical(value).encode("utf-8"))


def keyid_of_pem(pem: str) -> str:
    pub = serialization.load_pem_public_key(pem.encode("utf-8"))
    der = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return sha256_hex(der)


def load_key(pem: str) -> Ed25519PublicKey:
    pub = serialization.load_pem_public_key(pem.encode("utf-8"))
    if not isinstance(pub, Ed25519PublicKey):
        raise ValueError("not an Ed25519 key")
    return pub


def pae(payload_type: str, payload: bytes) -> bytes:
    return b"DSSEv1 " + str(len(payload_type.encode("utf-8"))).encode() + b" " + payload_type.encode("utf-8") + \
        b" " + str(len(payload)).encode() + b" " + payload


def b64decode_strict(s: Any) -> bytes | None:
    if not isinstance(s, str):
        return None
    try:
        raw = base64.b64decode(s, validate=True)
    except Exception:
        return None
    if base64.b64encode(raw).decode() != s:
        return None
    return raw


def is_envelope(env: Any) -> bool:
    return (isinstance(env, dict) and isinstance(env.get("payloadType"), str) and isinstance(env.get("payload"), str)
            and isinstance(env.get("signatures"), list) and len(env["signatures"]) > 0
            and all(isinstance(s, dict) and isinstance(s.get("keyid"), str) and isinstance(s.get("sig"), str)
                    for s in env["signatures"]))


def envelope_payload(env: dict) -> Any:
    raw = b64decode_strict(env.get("payload"))
    if raw is None:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return None


def verified_signers(env: dict, trusted: dict[str, Ed25519PublicKey]) -> list[str]:
    """Distinct trusted keyids whose signature over the PAE verifies (a repeated signature counts once)."""
    if not is_envelope(env):
        return []
    raw = b64decode_strict(env["payload"])
    if raw is None:
        return []
    msg = pae(env["payloadType"], raw)
    out: list[str] = []
    for s in env["signatures"]:
        kid = s["keyid"]
        key = trusted.get(kid)
        sig = b64decode_strict(s["sig"])
        if key is None or sig is None or kid in out:
            continue
        try:
            key.verify(sig, msg)
            out.append(kid)
        except InvalidSignature:
            pass
    return out


# ----------------------------------------------------------------------------------------------- Merkle (RFC 6962 / 9162)
EMPTY_ROOT = sha256_hex(b"")


def leaf_hash(leaf: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + leaf).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def mth(leaf_hashes: list[bytes]) -> bytes:
    n = len(leaf_hashes)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaf_hashes[0]
    k = 1
    while k * 2 < n:
        k *= 2
    return node_hash(mth(leaf_hashes[:k]), mth(leaf_hashes[k:]))


def root_from_inclusion(leaf: bytes, index: int, size: int, proof: list[bytes]) -> bytes | None:
    """RFC 9162 §2.1.3.2."""
    if not (0 <= index < size):
        return None
    fn, sn, r = index, size - 1, leaf
    for p in proof:
        if sn == 0:
            return None
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            while not (fn & 1) and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return r if sn == 0 else None


def consistency_ok(old_size: int, new_size: int, old_root: bytes, new_root: bytes, proof: list[bytes]) -> bool:
    """RFC 9162 §2.1.4.2."""
    if old_size < 0 or new_size < old_size:
        return False
    if old_size == new_size:
        return proof == [] and old_root == new_root
    if old_size == 0:
        return proof == [] and new_root == new_root  # the empty tree is consistent with any tree
    if not proof:
        return False
    proof = list(proof)
    fn, sn = old_size - 1, new_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    if fn == 0:
        fr = sr = old_root
        rest = proof
    else:
        fr = sr = proof[0]
        rest = proof[1:]
    for c in rest:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            while not (fn & 1) and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == old_root and sr == new_root


def hexes(items: Any) -> list[bytes] | None:
    if not isinstance(items, list):
        return None
    out = []
    for h in items:
        if not isinstance(h, str) or not HEX64.match(h):
            return None
        out.append(bytes.fromhex(h))
    return out


def log_leaf_hash(line: Any) -> bytes | None:
    """A log copy line is a leaf (the canonical envelope string) or, in a hash-only log, the leaf hash itself, as a hex
    string or as {"hash": hex} (R14; v2: the object form)."""
    if isinstance(line, dict) and isinstance(line.get("hash"), str) and HEX64.match(line["hash"]):
        return bytes.fromhex(line["hash"])
    if isinstance(line, str):
        return bytes.fromhex(line) if HEX64.match(line) else leaf_hash(line.encode("utf-8"))
    return None


# ----------------------------------------------------------------------------------------------- small helpers
def parse_time(value: Any) -> datetime | None:
    """ISO 8601 with an offset (Z or ±HH:MM); without one the time is not accepted (R22)."""
    if not isinstance(value, str) or not value:
        return None
    s = value
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    if not re.search(r"[+-]\d\d:\d\d$", s):
        return None
    try:
        t = datetime.fromisoformat(s)
    except ValueError:
        return None
    return t.astimezone(timezone.utc)


def is_uuid(value: Any) -> bool:
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value.lower()
    except ValueError:
        return False


def obj(v: Any) -> dict:
    return v if isinstance(v, dict) else {}


def get_path(value: Any, path: list[str]) -> tuple[bool, Any]:
    cur = value
    for seg in path:
        if isinstance(cur, dict) and seg in cur:
            cur = cur[seg]
        else:
            return False, None
    return True, cur


def is_commitment(v: Any) -> bool:
    """R20/R21: a commitment is a well-formed object; a tag without the fields a verifier checks is not one."""
    if not isinstance(v, dict):
        return False
    kind = v.get("$custody")
    if not isinstance(v.get("sha256"), str) or not HEX64.match(v["sha256"]):
        return False
    if kind == "withheld":
        return set(v.keys()) <= {"$custody", "sha256"}
    if kind == "encrypted":
        if v.get("alg") != "A256GCM":
            return False
        for k in ("keyid", "iv", "ciphertext", "tag"):
            if not isinstance(v.get(k), str):
                return False
        tag = b64decode_strict(v["tag"])
        iv = b64decode_strict(v["iv"])
        if tag is None or len(tag) != 16 or iv is None or len(iv) == 0 or b64decode_strict(v["ciphertext"]) is None:
            return False
        return set(v.keys()) <= {"$custody", "sha256", "alg", "keyid", "iv", "ciphertext", "tag"}
    return False


def path_str(path: list[str]) -> str:
    return ".".join(path)


def under(path: list[str], prefix: list[str]) -> bool:
    return path[:len(prefix)] == prefix


# R21: what a note may not name, because every check reads it in clear
STRUCTURAL_PREFIXES = [
    ["receiptId"], ["timestamp"], ["issuer"], ["principal"], ["agent"], ["tool"], ["delegation"], ["capture"],
    ["execution", "status"], ["execution", "resultDigest"], ["request", "argsDigest"], ["request", "provenance"],
    ["policy", "decision"], ["policy", "policyDigest"], ["policy", "enforced"], ["policy", "provenance"],
    ["authorization"], ["operation", "idempotencyKey"], ["operation", "status"], ["operation", "originalReceiptId"],
    ["operation", "lookupDigest"],
    ["approval", "status"], ["approval", "requiredApprovers"], ["approval", "checkedAt"], ["approval", "consumedAt"],
    ["approval", "approverKeyids"], ["approval", "fields"], ["approval", "provenance"],
]


class Report:
    def __init__(self) -> None:
        self.checks: list[dict] = []

    def add(self, name: str, ok: bool, detail: str = "") -> bool:
        self.checks.append({"name": name, "ok": bool(ok), "detail": detail})
        return bool(ok)

    def result(self) -> dict:
        failing = sorted({c["name"] for c in self.checks if not c["ok"]})
        return {"ok": not failing, "failing": failing, "checks": self.checks}


# ----------------------------------------------------------------------------------------------- the note (capture)
def note_paths(pred: dict) -> tuple[list[list[str]] | None, str]:
    """Returns (paths, problem). paths is None when there is no note."""
    if "capture" not in pred:
        return None, ""
    note = pred["capture"]
    if not isinstance(note, dict):
        return [], "capture note is not an object"
    if note.get("mode") not in ("digest", "encrypted"):
        return [], "capture note mode"
    w = note.get("withheld")
    if not isinstance(w, list):
        return [], "capture note withheld is not a list"
    paths: list[list[str]] = []
    seen = set()
    for p in w:
        if not isinstance(p, list) or not p or not all(isinstance(s, str) and s for s in p):
            return [], "capture note path is not a list of segments"
        key = "\x00".join(p)
        if key in seen:
            return [], f"capture note names {path_str(p)} twice"
        seen.add(key)
        if any(under(p, sp) for sp in STRUCTURAL_PREFIXES):
            return [], f"capture note names a structural part: {path_str(p)}"
        paths.append(p)
    return paths, ""


# ----------------------------------------------------------------------------------------------- approvals
APPROVAL_KEYS = {"version", "approvalId", "principal", "agent", "tool", "argsDigest", "amount", "currency",
                 "beneficiary", "issuedAt", "expiresAt"}


def approval_payload_ok(p: Any) -> tuple[bool, str]:
    """R3: the schema of the signed approval payload."""
    if not isinstance(p, dict) or not set(p.keys()) <= APPROVAL_KEYS:
        return False, "unknown field or not an object"
    if p.get("version") != "0.1" or not is_uuid(p.get("approvalId")):
        return False, "version or approvalId"
    for k in ("principal", "agent", "tool"):
        if not isinstance(p.get(k), str) or not p[k]:
            return False, k
    if not isinstance(p.get("argsDigest"), str) or not HEX64.match(p["argsDigest"]):
        return False, "argsDigest"
    issued, expires = parse_time(p.get("issuedAt")), parse_time(p.get("expiresAt"))
    if issued is None or expires is None or not expires > issued:
        return False, "issuedAt/expiresAt"
    if "amount" in p and (isinstance(p["amount"], bool) or not isinstance(p["amount"], int)
                          or abs(p["amount"]) > MAX_SAFE_INT):
        return False, "amount is not a safe integer"
    for k in ("currency", "beneficiary"):
        if k in p and (not isinstance(p[k], str) or not p[k]):
            return False, k
    return True, ""


def approval_record_shape_ok(a: Any) -> bool:
    """R21: the parts of an approval record every check reads, in clear and of the right type."""
    if not isinstance(a, dict):
        return False
    if a.get("status") not in ("approved", "denied") or a.get("requiredApprovers") not in (1, 2):
        return False
    if not isinstance(a.get("approverKeyids"), list) or not all(isinstance(k, str) for k in a["approverKeyids"]):
        return False
    if parse_time(a.get("checkedAt")) is None:
        return False
    if "consumedAt" in a and a["consumedAt"] is not None and parse_time(a["consumedAt"]) is None:
        return False
    if "fields" in a and a["fields"] is not None and not isinstance(a["fields"], (dict, list)):
        return False
    return True


def action_field_map(a: dict) -> dict[str, str]:
    f = a.get("fields")
    if isinstance(f, dict):
        return {k: v for k, v in f.items() if isinstance(k, str) and isinstance(v, str)}
    return {"amount": "amount", "currency": "currency", "beneficiary": "beneficiary"}


# ----------------------------------------------------------------------------------------------- delegation
def grant_payload_ok(g: Any) -> bool:
    return (isinstance(g, dict) and g.get("version") == "0.1" and isinstance(g.get("principal"), str)
            and isinstance(g.get("agent"), str) and isinstance(g.get("scopes"), list)
            and all(isinstance(s, str) for s in g["scopes"])
            and parse_time(g.get("issuedAt")) is not None and parse_time(g.get("expiresAt")) is not None)


def chain_to_principal(leaf_env: dict, principal_keyid: str, principal_keys: dict[str, Ed25519PublicKey]) -> tuple[bool, str, dict | None]:
    """R15: a grant whose payload carries `parent` is a link; each link is signed by the key its parent names in
    `agentKey`, the root by the principal's key; windows nest as instants; scopes narrow; the principal is one."""
    links: list[tuple[dict, dict]] = []  # (envelope, payload) from leaf to root
    env, seen = leaf_env, 0
    while True:
        if not is_envelope(env) or env.get("payloadType") != PT_DELEGATION:
            return False, "link is not a delegation envelope", None
        g = envelope_payload(env)
        if not grant_payload_ok(g):
            return False, "link payload malformed", None
        links.append((env, g))
        seen += 1
        if "parent" not in g:
            break
        if seen > 8:
            return False, "chain too long", None
        env = g["parent"]
    root_env, root = links[-1]
    if verified_signers(root_env, principal_keys) != [principal_keyid] and principal_keyid not in verified_signers(root_env, principal_keys):
        return False, "root grant is not signed by the attested principal key", None
    parent_env, parent = root_env, root
    for env, g in reversed(links[:-1]):
        pem = parent.get("agentKey")
        if not isinstance(pem, str):
            return False, "parent names no agentKey", None
        try:
            kid = keyid_of_pem(pem)
            key = load_key(pem)
        except Exception:
            return False, "parent agentKey unreadable", None
        if kid not in verified_signers(env, {kid: key}):
            return False, "link not signed by the parent's agent key", None
        if g.get("principal") != parent.get("principal"):
            return False, "principal changes along the chain", None
        if not set(g["scopes"]) <= set(parent["scopes"]):
            return False, "link widens the scopes", None
        if not (parse_time(parent["issuedAt"]) <= parse_time(g["issuedAt"])
                and parse_time(g["expiresAt"]) <= parse_time(parent["expiresAt"])):
            return False, "link window outside the parent's", None
        parent_env, parent = env, g
    return True, "", links[0][1]


# ----------------------------------------------------------------------------------------------- tree heads
def check_tree_head(rep: Report, label: str, th: Any, inclusion: Any, log_keys: dict, issuer_keys: dict,
                    log_id: str | None, leaf: bytes, check_log_id: bool) -> tuple[dict | None, bool]:
    """The tree head and inclusion checks, named `<label>...`. Returns (payload, inclusion_ok)."""
    name_sig = f"{label}tree head signature"
    name_size = f"{label}tree head matches inclusion proof size"
    name_incl = f"{label}log inclusion proof"
    if not is_envelope(th) or th.get("payloadType") != PT_TREEHEAD:
        rep.add(name_sig, False, "not a tree head envelope")
        return None, False
    signer = None
    for who, keys in (("log key", log_keys), ("issuer key", issuer_keys)):
        s = verified_signers(th, keys)
        if s:
            signer = (who, s[0])
            break
    payload = envelope_payload(th)
    if signer is None or not isinstance(payload, dict) or not isinstance(payload.get("treeSize"), int) \
            or not isinstance(payload.get("rootHash"), str) or not HEX64.match(payload["rootHash"]):
        rep.add(name_sig, False, "no trusted log or issuer key signed it" if signer is None else "payload malformed")
        return None, False
    rep.add(name_sig, True, f"signed by {signer[0]} {signer[1][:12]}")
    if check_log_id:  # R13
        rep.add("tree head names the expected log", payload.get("log") == log_id,
                f"tree head log={payload.get('log')!r}, expected {log_id!r}")
    inc = obj(inclusion)
    size_ok = isinstance(inc.get("treeSize"), int) and inc["treeSize"] == payload["treeSize"]
    rep.add(name_size, size_ok, f"proof size {inc.get('treeSize')}, head size {payload['treeSize']}")
    proof = hexes(inc.get("hashes"))
    root = None
    if size_ok and isinstance(inc.get("leafIndex"), int) and proof is not None:
        root = root_from_inclusion(leaf, inc["leafIndex"], inc["treeSize"], proof)
    ok = root is not None and root.hex() == payload["rootHash"]
    rep.add(name_incl, ok, "root recomputed from the leaf and the proof equals rootHash" if ok else "recomputed root differs or proof malformed")
    return payload, ok


# ----------------------------------------------------------------------------------------------- the verifier
def verify_bundle(bundle: dict, keys: dict, options: dict | None = None) -> dict:
    """keys: {"issuer": {keyid: pem}, "principal": {...}, "log": {...}, "approval": {...}, "upstream": {...}}
    options: {"requireStrict": bool, "logId": str, "providerSecrets": {"stripe": secret, "github": secret}, "log": [lines]}"""
    options = options or {}
    rep = Report()
    K = {k: {kid: load_key(pem) for kid, pem in (keys.get(k) or {}).items()} for k in ("issuer", "principal", "log", "approval", "upstream")}

    env = bundle.get("envelope") if isinstance(bundle, dict) else None
    # 1 receipt signature
    signers = verified_signers(env, K["issuer"]) if is_envelope(env) else []
    if not rep.add("receipt signature (issuer key)", bool(signers), f"signed by {signers[0][:12]}" if signers else "no trusted issuer key verifies the envelope"):
        return rep.result()
    signer = signers[0]
    st = envelope_payload(env)
    # 2 payload type
    if not rep.add("receipt payload type", env.get("payloadType") == PT_INTOTO and isinstance(st, dict)
                   and st.get("_type") == STATEMENT_TYPE and st.get("predicateType") == RECEIPT_PREDICATE):
        return rep.result()
    pred = obj(st.get("predicate"))
    subject = st.get("subject")
    # 3 structural parts in clear
    paths, note_problem = note_paths(pred)
    problems = [note_problem] if note_problem else []
    issuer, principal, agent, tool = obj(pred.get("issuer")), obj(pred.get("principal")), obj(pred.get("agent")), obj(pred.get("tool"))
    request, execution, policy = obj(pred.get("request")), obj(pred.get("execution")), pred.get("policy")
    if not isinstance(pred.get("receiptId"), str) or parse_time(pred.get("timestamp")) is None:
        problems.append("receiptId or timestamp")
    if not isinstance(issuer.get("kind"), str) or not isinstance(issuer.get("keyid"), str):
        problems.append("issuer")
    if not isinstance(pred.get("tool"), dict) or not isinstance(tool.get("name"), str):
        problems.append("tool")
    if principal.get("provenance") not in ("attested", "claimed") or \
            (principal.get("provenance") == "attested" and not isinstance(principal.get("keyid"), str)):
        problems.append("principal")
    if not isinstance(agent.get("id"), str):
        problems.append("agent")
    if not isinstance(execution.get("status"), str) or execution["status"] not in ("executed", "failed", "denied", "error", "withheld"):
        problems.append("execution.status")
    if not isinstance(request.get("argsDigest"), str) or not HEX64.match(request["argsDigest"]) or "args" not in request:
        problems.append("request")
    if execution.get("status") in EXECUTED_LIKE and (not isinstance(execution.get("resultDigest"), str) or not HEX64.match(execution["resultDigest"]) or "result" not in execution):
        problems.append("execution.result")
    if policy is not None and (not isinstance(policy, dict) or not isinstance(policy.get("decision"), str)
                               or not isinstance(policy.get("policyDigest"), str) or not HEX64.match(policy["policyDigest"])):
        problems.append("policy")
    if "delegation" in pred and (not isinstance(pred["delegation"], dict) or not is_envelope(pred["delegation"].get("envelope"))):
        problems.append("delegation")
    if "approval" in pred and not approval_record_shape_ok(pred["approval"]):
        problems.append("approval")
    if "authorization" in pred:
        a = pred["authorization"]
        if not isinstance(a, dict) or not is_envelope(a.get("envelope")) or not is_envelope(a.get("treeHead")) \
                or not isinstance(a.get("inclusion"), dict):
            problems.append("authorization")
    if not (isinstance(subject, list) and len(subject) == 1 and isinstance(subject[0], dict)
            and isinstance(obj(subject[0].get("digest")).get("sha256"), str)):
        problems.append("subject")
    if not rep.add("structural parts in clear", not problems, "; ".join(problems)):
        return rep.result()
    paths = paths or []
    rep.add("issuer kind is known", issuer["kind"] in ("gateway", "sdk"), issuer["kind"])
    rep.add("issuer keyid matches signer", issuer["keyid"] == signer and env["signatures"][0]["keyid"] == signer)
    gateway = issuer["kind"] == "gateway"
    status = execution["status"]
    forwarded = status in FORWARDED
    receipt_time = parse_time(pred["timestamp"])
    args_withheld = [p for p in paths if under(p, ["request", "args"])]
    result_withheld = [p for p in paths if under(p, ["execution"])]

    def named_paths_hold_commitments(ps: list[list[str]]) -> list[str]:
        bad = []
        for p in ps:
            found, v = get_path(pred, p)
            if not found or not is_commitment(v):
                bad.append(path_str(p))
        return bad

    # 4 gateway parts
    if gateway:
        rep.add("gateway receipt carries a delegation", isinstance(pred.get("delegation"), dict))
        rep.add("gateway receipt carries a policy decision", isinstance(policy, dict))
    # 5 delegation
    grant = None
    if isinstance(pred.get("delegation"), dict):
        denv = pred["delegation"]["envelope"]
        g = envelope_payload(denv) if denv.get("payloadType") == PT_DELEGATION else None
        pk = principal.get("keyid")
        direct = isinstance(pk, str) and pk in verified_signers(denv, K["principal"])
        if isinstance(g, dict) and "parent" in g:  # R15 chain
            chain_ok, why, leaf_grant = chain_to_principal(denv, pk or "", K["principal"])
            rep.add("delegation signature (principal key)", chain_ok, why or "leaf signed by the key the chain establishes")
            rep.add("delegation chain to the principal", chain_ok, why)
            grant = leaf_grant if chain_ok else (g if grant_payload_ok(g) else None)
        else:
            rep.add("delegation signature (principal key)", direct, "signed by the receipt's attested principal key" if direct else "not signed by the attested principal key")
            grant = g if grant_payload_ok(g) else None
        if grant is None:
            rep.add("delegation binds principal and agent", False, "grant payload malformed")
        else:
            rep.add("delegation binds principal and agent", grant["principal"] == principal.get("id") and grant["agent"] == agent["id"]
                    and principal.get("provenance") == "attested")
            issued, expires = parse_time(grant["issuedAt"]), parse_time(grant["expiresAt"])
            inside = issued <= receipt_time < expires
            if forwarded:  # R18
                rep.add("delegation valid at receipt time", inside, f"receipt at {pred['timestamp']}, grant {grant['issuedAt']}..{grant['expiresAt']}")
            else:
                rep.add("delegation valid at receipt time", True, ("inside the window" if inside else "outside the window, but the call was not forwarded"))
            if status in EXECUTED_LIKE:  # R19
                rep.add("executed tool within delegated scope", tool["name"] in grant["scopes"], tool["name"])
            else:
                rep.add("executed tool within delegated scope", True, f"status {status}: no execution to scope")
    else:
        rep.add("principal is claimed, not attested", principal.get("provenance") == "claimed")

    # 6 approvals (forwarded calls only)  -- v2: observations are the envelope's own signature keyids (D1); a malformed
    # payload or an envelope withheld beside clear arguments fails the signatures check only (D2, D6)
    approval = pred.get("approval")
    approval_env_withheld = any(p == ["approval", "envelope"] for p in paths)
    args_digest_full = None if args_withheld else digest(request.get("args"))

    def observations(env_: Any) -> list[str]:
        return sorted({s_["keyid"] for s_ in env_["signatures"]}) if is_envelope(env_) else []

    if isinstance(approval, dict) and forwarded:
        aenv = approval.get("envelope")
        ap = envelope_payload(aenv) if is_envelope(aenv) and aenv.get("payloadType") == PT_APPROVAL else None
        committed = approval_env_withheld and bool(args_withheld)
        obs_ok = True
        if approval_env_withheld and not args_withheld:  # the page: fails for a forwarded call
            rep.add("approval signatures (human keys)", False, "envelope withheld beside arguments in clear")
        elif committed:
            rep.add("approval signatures (human keys)", is_commitment(approval.get("envelope")), "passes as committed")
            rep.add("approval payload binding", True, "passes as committed")
            rep.add("approval valid at forward time", True, "passes as committed")
        else:
            shape_ok, why = approval_payload_ok(ap)
            signer_set = verified_signers(aenv, K["approval"]) if shape_ok else []
            need = approval["requiredApprovers"]
            rep.add("approval signatures (human keys)", shape_ok and len(signer_set) >= need,
                    f"{len(signer_set)} distinct trusted signatures, {need} required" if shape_ok else f"payload malformed: {why}")
            if shape_ok:
                fm = action_field_map(approval)
                args = request.get("args") if isinstance(request.get("args"), dict) else {}
                binds = ap["principal"] == principal.get("id") and ap["agent"] == agent["id"] and ap["tool"] == tool["name"]
                if args_digest_full is not None:
                    binds = binds and ap["argsDigest"] == args_digest_full
                for k in ("amount", "currency", "beneficiary"):
                    if k in ap and not args_withheld:
                        binds = binds and args.get(fm.get(k, k)) == ap[k]
                rep.add("approval payload binding", binds)
                issued, expires = parse_time(ap["issuedAt"]), parse_time(ap["expiresAt"])
                checked, consumed = parse_time(approval.get("checkedAt")), parse_time(approval.get("consumedAt"))
                in_win = lambda t: t is not None and issued <= t < expires  # noqa: E731
                rep.add("approval valid at forward time", in_win(checked) and (approval.get("consumedAt") is None or in_win(consumed)),
                        f"checkedAt {approval.get('checkedAt')}, consumedAt {approval.get('consumedAt')}, window {ap['issuedAt']}..{ap['expiresAt']}")
                obs_ok = sorted(set(approval.get("approverKeyids", []))) == observations(aenv)
        consistent = approval.get("status") == "approved" and parse_time(approval.get("consumedAt")) is not None and obs_ok
        rep.add("approval consistent with execution", consistent, "approved, consumed, signer observations match the envelope" if consistent else "not an approved, consumed record with matching signer observations")

    # 7 digests
    bad = named_paths_hold_commitments(args_withheld)
    subj_digest = obj(subject[0].get("digest")).get("sha256")
    if args_withheld:
        rep.add("request args digest", not bad and subj_digest == request["argsDigest"],
                ("passes as committed; subject digest checked" if not bad else "named path holds no commitment: " + ", ".join(bad)))
    else:
        rep.add("request args digest", args_digest_full == request["argsDigest"] == subj_digest)
    if status in EXECUTED_LIKE:
        badr = named_paths_hold_commitments(result_withheld)
        if result_withheld:
            rep.add("execution result digest", not badr, "passes as committed" if not badr else "named path holds no commitment: " + ", ".join(badr))
        else:
            rep.add("execution result digest", digest(execution.get("result")) == execution["resultDigest"])
    for p in paths:  # fact lines and withheld lines
        if under(p, ["request", "args"]) or under(p, ["execution", "result"]):
            continue
        found, v = get_path(pred, p)
        ok = found and is_commitment(v)
        if len(p) >= 4 and p[0] == "facts" and p[2] in ("value", "args"):
            rep.add(f"fact {p[1]} {p[2]}", ok, "committed" if ok else "named path holds no commitment")
        elif under(p, ["execution"]):
            if not ok:
                rep.add("execution result digest", False, f"named path holds no commitment: {path_str(p)}")
            rep.add(f"withheld {path_str(p)}", ok, "committed" if ok else "named path holds no commitment")
        else:
            rep.add(f"withheld {path_str(p)}", ok, "committed" if ok else "named path holds no commitment")

    # 8 upstream
    up = execution.get("upstream")
    result = execution.get("result")
    env_withheld = any(p == ["execution", "upstream", "envelope"] for p in paths)
    result_content_withheld = any(under(p, ["execution", "result"]) for p in paths)
    if K["upstream"] and status in EXECUTED_LIKE:
        uenv = obj(up).get("envelope")
        if env_withheld and result_content_withheld and is_commitment(uenv):
            rep.add("upstream signature not checked", True, "envelope withheld with the result")
        elif env_withheld:
            rep.add("upstream signature (upstream key)", False, "envelope withheld beside a result in clear")
        else:
            ok = False
            detail = "no envelope"
            if is_envelope(uenv) and uenv.get("payloadType") == PT_UPSTREAM:
                s = verified_signers(uenv, K["upstream"])
                p = envelope_payload(uenv)
                content = {"content": obj(result).get("content"), "isError": obj(result).get("isError", False)} if isinstance(result, dict) else {}  # v2 R11: isError defaults to false
                if result_content_withheld and (not isinstance(result, dict) or "content" not in result):
                    rep.add("upstream signature not checked", True, "result withheld")
                    ok, detail = None, ""
                else:
                    ok = bool(s) and isinstance(p, dict) and p.get("receiptId") == pred["receiptId"] and p.get("tool") == tool["name"] \
                        and p.get("contentDigest") == digest(content)
                    detail = f"signed by {s[0][:12]}, bound to this receipt, tool and content" if ok else ("no trusted upstream key verifies it" if not s else "binding differs")
            if ok is not None:
                rep.add("upstream signature (upstream key)", ok, detail)
    secrets = options.get("providerSecrets") or {}
    if isinstance(up, dict) and up.get("provider") in ("stripe-webhook", "github-delivery") and status in EXECUTED_LIKE:
        secret = secrets.get("stripe" if up["provider"] == "stripe-webhook" else "github")
        if secret is not None:
            raw_withheld = any(p == ["execution", "upstream", "rawBody"] for p in paths)
            if raw_withheld or result_content_withheld:
                rep.add("upstream signature not checked", True, "delivery body or result withheld")
            else:
                ok, detail = provider_delivery_ok(up, secret, result, receipt_time)
                rep.add("upstream signature (provider secret)", ok, detail)

    # 9 policy
    if isinstance(policy, dict):
        decision, enforced = policy.get("decision"), policy.get("enforced")
        if decision == "allow":
            ok, detail = status != "denied", "allow never pairs with denied"
        elif decision == "deny":
            if enforced is False:
                ok, detail = True, "observe mode: a deny beside " + status
            else:
                ok, detail = status == "denied", "an enforced deny pairs with denied only"
        else:
            ok, detail = False, f"unknown decision {decision!r}"
        rep.add("policy decision consistent with execution", ok, detail)
        errors = policy.get("errors")
        if decision == "allow":
            if is_commitment(errors) and any(p == ["policy", "errors"] for p in paths):
                rep.add("no policy errors on an allow", True, "errors committed")
            else:
                rep.add("no policy errors on an allow", isinstance(errors, list) and not errors)

    # 10 tree head and inclusion
    leaf = leaf_hash(canonical(env).encode("utf-8"))
    th_payload, incl_ok = check_tree_head(rep, "", bundle.get("treeHead"), bundle.get("inclusion"), K["log"], K["issuer"],
                                          options.get("logId"), leaf, "logId" in options)
    # authorization (prose on the page; names from the vectors)
    auth = pred.get("authorization")
    if isinstance(auth, dict):
        a_st = envelope_payload(auth["envelope"])
        a_pred = obj(obj(a_st).get("predicate"))
        a_signed = bool(verified_signers(auth["envelope"], K["issuer"]))
        names = a_signed and obj(a_st).get("predicateType") == AUTHORIZATION_PREDICATE and a_pred.get("receiptId") == pred["receiptId"] \
            and obj(a_st).get("subject") == subject and auth["envelope"].get("payloadType") == PT_INTOTO
        rep.add("authorization names this call", names, "signed by the issuer, names this receipt id and subject" if names else "does not name this call")
        a_leaf = leaf_hash(canonical(auth["envelope"]).encode("utf-8"))
        a_payload, a_incl_ok = check_tree_head(rep, "authorization ", auth["treeHead"], auth["inclusion"], K["log"], K["issuer"], None, a_leaf, False)
        inc, a_inc = obj(bundle.get("inclusion")), obj(auth["inclusion"])
        before = isinstance(a_inc.get("leafIndex"), int) and isinstance(inc.get("leafIndex"), int) and a_inc["leafIndex"] < inc["leafIndex"]  # v3 E1: by the proofs' indexes alone
        rep.add("authorization logged before execution", before, f"authorization leaf {a_inc.get('leafIndex')}, receipt leaf {inc.get('leafIndex')}")
        if isinstance(approval, dict) and forwarded:  # v2 D5: approval checks run on forwarded calls only
            a_ap = a_pred.get("approval")
            carries = isinstance(a_ap, dict) and a_ap.get("envelope") == approval.get("envelope") \
                and a_ap.get("requiredApprovers") == approval.get("requiredApprovers") and a_ap.get("fields") == approval.get("fields")
            rep.add("authorization carries this approval", carries)
            valid = False
            detail = ""
            if isinstance(a_ap, dict) and approval_record_shape_ok(a_ap):
                aenv = a_ap.get("envelope")
                a_env_withheld = is_commitment(aenv)  # v3 E2: the precommit's own envelope, not the receipt's note
                if a_env_withheld and args_withheld:
                    valid, detail = a_ap.get("status") == "approved", "passes as committed"
                elif a_env_withheld:
                    valid, detail = False, "envelope withheld beside arguments in clear"
                else:
                    ap = envelope_payload(aenv) if is_envelope(aenv) and aenv.get("payloadType") == PT_APPROVAL else None
                    shape_ok, _ = approval_payload_ok(ap)
                    s = verified_signers(aenv, K["approval"]) if shape_ok else []
                    if shape_ok:
                        issued, expires = parse_time(ap["issuedAt"]), parse_time(ap["expiresAt"])
                        checked = parse_time(a_ap.get("checkedAt"))
                        valid = a_ap.get("status") == "approved" and len(s) >= a_ap["requiredApprovers"] \
                            and sorted(set(a_ap.get("approverKeyids", []))) == observations(aenv) and checked is not None and issued <= checked < expires  # v2 D1
                        detail = "approved in the precommit, distinct trusted signers, checked inside the window" if valid else "precommit approval not valid"
            rep.add("authorization approval was valid", valid, detail)
    # strict (R9; names from the vectors)
    if options.get("requireStrict"):
        rep.add("strict mode in force", issuer.get("strict") is True, f"issuer.strict={issuer.get('strict')!r}")
        rep.add("strict: call precommitted before forwarding", (not forwarded) or isinstance(auth, dict),
                "authorization present" if isinstance(auth, dict) else f"status {status}, no authorization")
    # financial reconciliation (R16; names from the vectors)
    op, rec = pred.get("operation"), pred.get("reconciliation")
    if isinstance(rec, dict) and isinstance(op, dict):
        orig = obj(rec.get("original"))
        o_st = envelope_payload(orig.get("envelope")) if is_envelope(orig.get("envelope")) else None
        o_pred = obj(obj(o_st).get("predicate"))
        o_op = obj(o_pred.get("operation"))
        o_inc = obj(orig.get("inclusion"))
        o_signed = bool(verified_signers(orig.get("envelope"), K["issuer"])) if is_envelope(orig.get("envelope")) else False
        links = o_signed and o_pred.get("receiptId") == op.get("originalReceiptId") and o_op.get("id") == op.get("id") \
            and o_op.get("idempotencyKey") == op.get("idempotencyKey") \
            and isinstance(o_inc.get("leafIndex"), int) and isinstance(obj(bundle.get("inclusion")).get("leafIndex"), int) \
            and o_inc["leafIndex"] < bundle["inclusion"]["leafIndex"]
        rep.add("reconciliation links the original operation", links)
        lookup = rec.get("lookup")
        rep.add("reconciliation lookup matches authorization", isinstance(lookup, dict) and digest(lookup) == op.get("lookupDigest") == o_op.get("lookupDigest"))
        ok, detail = False, "provider record unreadable"
        rec_json = provider_record(result)
        if isinstance(lookup, dict) and isinstance(rec_json, dict):
            f_status, _ = get_path(rec_json, str(lookup.get("statusPath", "")).split("."))
            f_ident, ident = get_path(rec_json, str(lookup.get("identityPath", "")).split("."))
            found_status = f_status and (get_path(rec_json, str(lookup.get("statusPath")).split("."))[1])
            mapped = "confirmed" if found_status in (lookup.get("confirmed") or []) else ("failed" if found_status in (lookup.get("failed") or []) else None)
            ok = f_ident and ident == op.get("idempotencyKey") and mapped is not None and mapped == op.get("status")
            detail = f"status {found_status!r} maps to {mapped}, operation says {op.get('status')}; identity {'matches' if ident == op.get('idempotencyKey') else 'differs'}"
        rep.add("reconciliation provider status", ok, detail)

    # 11 log copy
    log = options.get("log")
    if isinstance(log, list) and th_payload is not None:
        size = th_payload["treeSize"]
        hashes_ = [log_leaf_hash(l) for l in log[:size]]
        ok = len(log) >= size and all(h is not None for h in hashes_) and mth(hashes_).hex() == th_payload["rootHash"]  # v2
        rep.add("log file root matches tree head", ok, f"root of the first {size} lines")
    return rep.result()


def provider_record(result: Any) -> Any:
    """R16: the provider JSON is the text of the result's first content item, else the result itself."""
    if isinstance(result, dict) and isinstance(result.get("content"), list) and result["content"] \
            and isinstance(result["content"][0], dict) and isinstance(result["content"][0].get("text"), str):
        try:
            return json.loads(result["content"][0]["text"])
        except ValueError:
            return None
    return result


def provider_delivery_ok(up: dict, secret: str, result: Any, receipt_time: datetime | None) -> tuple[bool, str]:
    """R12: Stripe: HMAC-SHA256 over `<t>.<rawBody>`, t within tolerance of the receipt; GitHub: over the raw body.
    The bound value (dot path into the body) must appear in the result outside the delivery's own copy in _meta."""
    raw, sig, bind = up.get("rawBody"), up.get("signature"), up.get("bind")
    if not isinstance(raw, str) or not isinstance(sig, str) or not isinstance(bind, str):
        return False, "delivery incomplete"
    if up["provider"] == "stripe-webhook":
        parts = dict(kv.split("=", 1) for kv in sig.split(",") if "=" in kv)
        t, v1 = parts.get("t"), parts.get("v1")
        if t is None or v1 is None or not t.isdigit():
            return False, "signature header malformed"
        want = hmac.new(secret.encode(), f"{t}.{raw}".encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(want, v1):
            return False, "HMAC differs"
        if receipt_time is None or abs(int(t) - int(receipt_time.timestamp())) > STRIPE_TOLERANCE_S:
            return False, "timestamp outside tolerance"
    else:
        want = "sha256=" + hmac.new(secret.encode(), raw.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(want, sig):
            return False, "HMAC differs"
    try:
        body = json.loads(raw)
    except ValueError:
        return False, "raw body is not JSON"
    found, value = get_path(body, bind.split("."))
    if not found or not isinstance(value, (str, int)):
        return False, "bound value absent from the body"
    visible = {k: v for k, v in result.items() if k != "_meta"} if isinstance(result, dict) else result
    if json.dumps(value) not in canonical(visible) and str(value) not in canonical(visible):
        return False, "bound value does not appear in the result"
    return True, f"HMAC verifies, bound {bind}={value!r} appears in the result"


def audit_extends(older: dict, newer: dict, proof: list, keys: dict[str, str]) -> dict:
    """Two signed tree heads and the log's consistency proof between their sizes."""
    rep = Report()
    K = {kid: load_key(pem) for kid, pem in keys.items()}
    heads = {}
    for label, th in (("older", older), ("newer", newer)):
        s = verified_signers(th, K) if is_envelope(th) and th.get("payloadType") == PT_TREEHEAD else []
        p = envelope_payload(th) if s else None
        ok = bool(s) and isinstance(p, dict) and isinstance(p.get("treeSize"), int) and isinstance(p.get("rootHash"), str) and HEX64.match(p["rootHash"])
        rep.add(f"{label} tree head signature", ok)
        heads[label] = p if ok else None
    o, n = heads["older"], heads["newer"]
    if o is None or n is None:
        return rep.result()
    if not rep.add("older is not larger than newer", o["treeSize"] <= n["treeSize"], f"{o['treeSize']} <= {n['treeSize']}"):
        return rep.result()  # v2: nothing to extend when the order is wrong
    ph = hexes(proof)
    ok = ph is not None and o["treeSize"] <= n["treeSize"] and consistency_ok(o["treeSize"], n["treeSize"], bytes.fromhex(o["rootHash"]), bytes.fromhex(n["rootHash"]), ph)
    rep.add("newer log extends older log", ok)
    return rep.result()


if __name__ == "__main__":
    import sys
    case = json.load(open(sys.argv[1], encoding="utf-8"))
    print(json.dumps(verify_bundle(case["bundle"], case["keys"], case.get("options")), indent=1, ensure_ascii=False))
