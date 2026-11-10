"""x402 exact/lnbtc client validation and facilitator /settle, from scheme_exact_lnbtc.md at 63d5640 only.

Sections read: Scheme and Networks, Asset Transfer Method, Terminology, Amounts, PaymentRequirements, Request Binding,
PaymentPayload, Client Payment Construction, Facilitator Validation, Paid-but-expired Policy, Settlement and Replay
Protection, Error Vocabulary; README Layout / Inputs / Expectations. BOLT11 and secp256k1 from BOLT #11, BIP-173 and
SEC 1, written here from those documents. Standard library only. Readings marked P1..Pn.
"""
from __future__ import annotations

import copy
import hashlib
import re

import lnbtc_binding_v1 as B

NETWORKS = {"lnbtc:000000000019d6689c085ae165831e93": "bc", "lnbtc:000000000933ea01ad0ee984209779ba": "tb"}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX66 = re.compile(r"^[0-9a-f]{66}$")
DEC = re.compile(r"^[0-9]+$")


class Fail(Exception):
    def __init__(self, reason, step=None):
        super().__init__(reason)
        self.reason, self.step = reason, step


# ------------------------------------------------------------------ secp256k1 (SEC 1)
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        l = 3 * a[0] * a[0] * pow(2 * a[1], -1, P) % P
    else:
        l = (b[1] - a[1]) * pow(b[0] - a[0], -1, P) % P
    x = (l * l - a[0] - b[0]) % P
    return (x, (l * (a[0] - x) - a[1]) % P)


def _mul(pt, k):
    acc = None
    while k:
        if k & 1:
            acc = _add(acc, pt)
        pt = _add(pt, pt)
        k >>= 1
    return acc


def _lift(x, odd):
    if x >= P:
        return None
    y2 = (pow(x, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    if y * y % P != y2:
        return None
    if (y & 1) != odd:
        y = P - y
    return (x, y)


def pubkey_from_hex(h):
    """Valid compressed secp256k1 key as 66 lowercase hex chars, else None."""
    if not isinstance(h, str) or not HEX66.match(h) or h[:2] not in ("02", "03"):
        return None
    return _lift(int(h[2:], 16), h[:2] == "03")


def compress(pt):
    return ("03" if pt[1] & 1 else "02") + "%064x" % pt[0]


def ecdsa_verify(pt, z, r, s):
    if not (1 <= r < N and 1 <= s < N):
        return False
    w = pow(s, -1, N)
    q = _add(_mul(G, z * w % N), _mul(pt, r * w % N))
    return q is not None and q[0] % N == r


def ecdsa_recover(z, r, s, recid):
    if not (1 <= r < N and 1 <= s < N) or recid not in (0, 1, 2, 3):
        return None
    x = r + (recid >> 1) * N
    R = _lift(x, recid & 1)
    if R is None:
        return None
    rinv = pow(r, -1, N)
    q = _mul(_add(_mul(R, s), _mul(G, (-z) % N)), rinv)
    return q


# ------------------------------------------------------------------ BOLT #11
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk


def _hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _to_bytes(groups):
    acc, bits, out = 0, 0, bytearray()
    for g in groups:
        acc = (acc << 5) | g
        bits += 5
        while bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    return bytes(out), bits, acc & ((1 << bits) - 1)


def _int(groups):
    v = 0
    for g in groups:
        v = v * 32 + g
    return v


MULT = {"m": 10**8, "u": 10**5, "n": 10**2}


def decode_bolt11(inv):
    """Strict BOLT #11 decode. Returns a dict; raises Fail('invalid_exact_lnbtc_invoice_decode_failed')."""
    bad = Fail("invalid_exact_lnbtc_invoice_decode_failed")
    if not isinstance(inv, str) or inv == "":
        raise bad
    if inv != inv.lower() and inv != inv.upper():
        raise bad
    s = inv.lower()
    pos = s.rfind("1")
    if pos < 1 or len(s) - pos - 1 < 6 + 7 + 104:
        raise bad
    hrp, data = s[:pos], s[pos + 1:]
    if any(ord(c) < 33 or ord(c) > 126 for c in hrp) or any(c not in CHARSET for c in data):
        raise bad
    groups = [CHARSET.index(c) for c in data]
    if _polymod(_hrp_expand(hrp) + groups) != 1:  # P1: bech32 (BIP-173) constant, not bech32m
        raise bad
    groups = groups[:-6]
    m = re.match(r"^ln(bcrt|bc|tbs|tb|sb)(\d*)([munp]?)$", hrp)
    if not m:
        raise bad
    currency, amt, mult = m.group(1), m.group(2), m.group(3)
    msat = None
    if amt:
        if amt.startswith("0"):  # P2: no leading zeros (BOLT #11: "MUST fail if ... not a valid number")
            raise bad
        n = int(amt)
        if mult == "p":
            if n % 10:
                raise bad  # BOLT #11: p multiplier with a non-zero last digit
            msat = n // 10
        elif mult:
            msat = n * MULT[mult]
        else:
            msat = n * 10**11
        if msat == 0:
            raise bad
    elif mult:
        raise bad
    if len(groups) < 7 + 104:
        raise bad
    sig_groups = groups[-104:]
    body = groups[:-104]
    ts = _int(body[:7])
    i = 7
    fields = []
    while i < len(body):
        if i + 3 > len(body):
            raise bad
        t, ln = body[i], body[i + 1] * 32 + body[i + 2]
        i += 3
        if i + ln > len(body):
            raise bad
        fields.append((t, body[i:i + ln]))
        i += ln
    sig, _, _ = _to_bytes(sig_groups)
    if len(sig) != 65:
        raise bad
    r, s_, recid = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:64], "big"), sig[64]
    # Pack: data bits zero-padded to a byte boundary (BOLT #11 signature preimage).
    bits = "".join(format(g, "05b") for g in body)
    bits += "0" * ((8 - len(bits) % 8) % 8)
    msg_bytes = bytes(int(bits[k:k + 8], 2) for k in range(0, len(bits), 8))
    z = int.from_bytes(hashlib.sha256(hrp.encode("utf-8") + msg_bytes).digest(), "big")
    out = {"currency": currency, "msat": msat, "timestamp": ts, "expiry": 3600, "payment_hash": None,
           "description_hashes": [], "descriptions": 0, "payee": None}
    for t, d in fields:
        if t == 1:  # p
            if len(d) == 52:
                if out["payment_hash"] is not None:
                    raise bad  # P3: a second valid p field
                out["payment_hash"] = _to_bytes(d)[0][:32].hex()
        elif t == 23:  # h
            if len(d) == 52:
                out["description_hashes"].append(_to_bytes(d)[0][:32].hex())
        elif t == 13:  # d
            out["descriptions"] += 1
        elif t == 19:  # n
            if len(d) == 53:
                out["payee"] = _to_bytes(d)[0][:33].hex()
        elif t == 6:  # x
            out["expiry"] = _int(d)
    if out["payment_hash"] is None:
        raise bad  # BOLT #11: a payment hash is required
    if out["payee"] is not None:
        pt = pubkey_from_hex(out["payee"])
        if pt is None or not ecdsa_verify(pt, z, r, s_):
            raise bad
        out["signer"] = out["payee"]
    else:
        q = ecdsa_recover(z, r, s_, recid)
        if q is None or not ecdsa_verify(q, z, r, s_):
            raise bad
        out["signer"] = compress(q)
    return out


# ------------------------------------------------------------------ JSON Patch (RFC 6902, objects only)
def _ptr(path):
    if path == "":
        return []
    if not path.startswith("/"):
        raise ValueError(path)
    return [p.replace("~1", "/").replace("~0", "~") for p in path[1:].split("/")]


def apply_patch(doc, patch):
    doc = copy.deepcopy(doc)
    for op in patch:
        parts = _ptr(op["path"])
        parent = doc
        for p in parts[:-1]:
            parent = parent[int(p)] if isinstance(parent, list) else parent[p]
        key = parts[-1]
        if isinstance(parent, list):
            key = int(key)
        if op["op"] in ("add", "replace"):
            parent[key] = copy.deepcopy(op["value"])
        elif op["op"] == "remove":
            del parent[key]
        else:
            raise ValueError(op["op"])
    return doc


# ------------------------------------------------------------------ shared checks
def pos_int_str(v):
    return isinstance(v, str) and bool(DEC.match(v)) and int(v) > 0  # P4: leading zeros allowed ("encodes")


def pos_int(v):
    return isinstance(v, int) and not isinstance(v, bool) and v > 0  # P5: a JSON integer, not 300.0


def check_params(profile, params):
    """Syntax of requestBindingParams for the profile; raises Fail(request_binding)."""
    rb = Fail("invalid_exact_lnbtc_request_binding")
    if not isinstance(params, dict):
        raise rb
    try:
        if profile == "http:1":
            if set(params) != {"headers"}:
                raise rb
            B.check_bound_headers(params["headers"])
        elif profile == "mcp:1":
            if set(params) != {"server", "metadata"}:
                raise rb
            B.mcp_binding({"server": params["server"], "bound_metadata": params["metadata"],
                           "params": {"name": "x"}})
        else:
            raise rb
    except B.Reject:
        raise rb


# ------------------------------------------------------------------ facilitator /settle
def settle_step(store, doc, now, skew):
    req, payload = doc.get("requirements"), doc.get("payload")
    if not isinstance(req, dict) or not isinstance(payload, dict):
        raise Fail("invalid_exact_lnbtc_request_binding", 1)
    acc = payload.get("accepted") if isinstance(payload.get("accepted"), dict) else {}
    # 1. equality of accepted and requirements
    if acc.get("scheme") != req.get("scheme"):
        raise Fail("unsupported_scheme", 1)
    if acc.get("network") != req.get("network"):
        raise Fail("network_mismatch", 1)
    if acc.get("amount") != req.get("amount"):
        raise Fail("invalid_exact_lnbtc_amount_mismatch", 1)
    if acc.get("asset") != req.get("asset"):
        raise Fail("invalid_exact_lnbtc_asset", 1)
    if acc.get("payTo") != req.get("payTo"):
        raise Fail("invalid_exact_lnbtc_pay_to_mismatch", 1)
    if acc.get("maxTimeoutSeconds") != req.get("maxTimeoutSeconds") or \
            type(acc.get("maxTimeoutSeconds")) is not type(req.get("maxTimeoutSeconds")):
        raise Fail("invalid_exact_lnbtc_max_timeout_mismatch", 1)
    # 2. values
    if req.get("scheme") != "exact":
        raise Fail("unsupported_scheme", 2)
    if req.get("network") not in NETWORKS:
        raise Fail("unsupported_network", 2)
    if req.get("asset") != "BTC":
        raise Fail("invalid_exact_lnbtc_asset", 2)
    if not pos_int_str(req.get("amount")):
        raise Fail("invalid_exact_lnbtc_amount", 2)
    if not pos_int(req.get("maxTimeoutSeconds")):
        raise Fail("invalid_exact_lnbtc_max_timeout", 2)
    if pubkey_from_hex(req.get("payTo")) is None:
        raise Fail("invalid_exact_lnbtc_pay_to_malformed", 2)
    # 3. extra
    rx = req.get("extra") if isinstance(req.get("extra"), dict) else {}
    ax = acc.get("extra") if isinstance(acc.get("extra"), dict) else {}
    for x in (rx, ax):
        if x.get("assetTransferMethod", "bolt11") != "bolt11":
            raise Fail("invalid_exact_lnbtc_asset_transfer_method", 3)
    for x in (rx, ax):
        if x.get("paymentFlow") != "upfront":
            raise Fail("invalid_exact_lnbtc_payment_flow", 3)
    for x in (rx, ax):
        if not isinstance(x.get("requestHash"), str) or not HEX64.match(x["requestHash"]):
            raise Fail("invalid_exact_lnbtc_request_binding", 3)
    for x in (rx, ax):
        if x.get("requestBindingProfile") not in ("http:1", "mcp:1"):
            raise Fail("invalid_exact_lnbtc_request_binding", 3)
    for x in (rx, ax):
        if "requestBindingParams" not in x:
            raise Fail("invalid_exact_lnbtc_request_binding", 3)
        try:
            check_params(x["requestBindingProfile"], x["requestBindingParams"])
        except Fail as f:
            raise Fail(f.reason, 3)
    if rx["requestHash"] != ax["requestHash"] or rx["requestBindingProfile"] != ax["requestBindingProfile"]:
        raise Fail("invalid_exact_lnbtc_request_mismatch", 3)
    try:
        if B.jcs(rx["requestBindingParams"]) != B.jcs(ax["requestBindingParams"]):
            raise Fail("invalid_exact_lnbtc_request_mismatch", 3)
    except B.Reject:
        raise Fail("invalid_exact_lnbtc_request_binding", 3)
    binding_keys = {"invoice", "requestHash", "requestBindingProfile", "requestBindingParams"}
    for k, v in rx.items():
        if k in binding_keys:
            continue
        if k == "assetTransferMethod":
            continue  # P6: a missing method resolves to bolt11 on both sides, so presence may differ
        if k not in ax or ax[k] != v:
            raise Fail("invalid_exact_lnbtc_extra_mismatch", 3)
    # 4. invoices present
    for x in (rx, ax):
        if not isinstance(x.get("invoice"), str) or x["invoice"] == "":
            raise Fail("invalid_exact_lnbtc_invoice_missing", 4)
    # 5. accepted invoice
    try:
        inv = decode_bolt11(ax["invoice"])
    except Fail as f:
        raise Fail(f.reason, 5)
    if len(inv["description_hashes"]) != 1 or inv["descriptions"]:
        raise Fail("invalid_exact_lnbtc_invoice_description", 5)
    if inv["description_hashes"][0] != rx["requestHash"]:
        raise Fail("invalid_exact_lnbtc_invoice_request_mismatch", 5)
    if inv["signer"] != req["payTo"]:
        raise Fail("invalid_exact_lnbtc_invoice_payee_mismatch", 5)
    if inv["currency"] != NETWORKS[req["network"]]:
        raise Fail("invalid_exact_lnbtc_invoice_currency_mismatch", 5)
    if inv["msat"] is None:
        raise Fail("invalid_exact_lnbtc_invoice_decode_failed", 5)
    if inv["msat"] != int(req["amount"]):
        raise Fail("invalid_exact_lnbtc_invoice_amount_mismatch", 5)
    if inv["expiry"] != req["maxTimeoutSeconds"]:
        raise Fail("invalid_exact_lnbtc_invoice_expiry_mismatch", 5)
    if inv["timestamp"] > now + skew:
        raise Fail("invalid_exact_lnbtc_invoice_created_in_future", 5)
    # 6. preimage
    pl = payload.get("payload") if isinstance(payload.get("payload"), dict) else {}
    if "preimage" not in pl:
        raise Fail("invalid_exact_lnbtc_preimage_missing", 6)
    pre = pl["preimage"]
    if not isinstance(pre, str) or not re.match(r"^[0-9a-f]*$", pre):
        raise Fail("invalid_exact_lnbtc_preimage_malformed", 6)
    if len(pre) != 64:
        raise Fail("invalid_exact_lnbtc_preimage_length", 6)
    if hashlib.sha256(bytes.fromhex(pre)).hexdigest() != inv["payment_hash"]:
        raise Fail("invalid_exact_lnbtc_preimage_hash_mismatch", 6)
    # 7. paid-but-expired
    end = inv["timestamp"] + inv["expiry"]
    if now > end + skew:
        raise Fail("invalid_exact_lnbtc_invoice_expired", 7)
    key = req["network"] + ":" + inv["payment_hash"]
    if key in store:
        raise Fail("duplicate_settlement", "replay")
    store.add(key)
    return {"success": True, "transaction": inv["payment_hash"], "network": req["network"],
            "replay_key": key, "retain_until_at_least": end + skew + 3600}


def run_settle(base, case):
    store, results = set(), []
    for st in case["steps"]:
        try:
            doc = apply_patch(base, st.get("patch", []))
            results.append(settle_step(store, doc, st["now"], st.get("skew", 60)))
        except Fail as f:
            results.append({"success": False, "error_reason": f.reason, "step": f.step})
    return results


# ------------------------------------------------------------------ client
def run_client(base, case):
    doc = apply_patch(base, case.get("patch", []))
    now, skew = case["now"], case.get("skew", 60)
    called = False
    try:
        pr = doc["payment_required"]
        accepts = pr.get("accepts") or []
        req = next((a for a in accepts if isinstance(a, dict) and a.get("scheme") == "exact"
                    and isinstance(a.get("network"), str) and a["network"].startswith("lnbtc:")),
                   accepts[0] if accepts else {})  # P7
        # 1
        if req.get("scheme") != "exact":
            raise Fail("unsupported_scheme")
        if req.get("network") not in NETWORKS:
            raise Fail("unsupported_network")
        if req.get("asset") != "BTC":
            raise Fail("invalid_exact_lnbtc_asset")
        if not pos_int_str(req.get("amount")):
            raise Fail("invalid_exact_lnbtc_amount")
        if not pos_int(req.get("maxTimeoutSeconds")):
            raise Fail("invalid_exact_lnbtc_max_timeout")
        if pubkey_from_hex(req.get("payTo")) is None:
            raise Fail("invalid_exact_lnbtc_pay_to_malformed")
        x = req.get("extra") if isinstance(req.get("extra"), dict) else {}
        # 2
        if x.get("paymentFlow") != "upfront":
            raise Fail("invalid_exact_lnbtc_payment_flow")
        if not isinstance(x.get("invoice"), str) or x["invoice"] == "":
            raise Fail("invalid_exact_lnbtc_invoice_missing")
        if x.get("assetTransferMethod", "bolt11") != "bolt11":
            raise Fail("invalid_exact_lnbtc_asset_transfer_method")
        # 3
        inv = decode_bolt11(x["invoice"])
        # 4
        if not isinstance(x.get("requestHash"), str) or not HEX64.match(x["requestHash"]):
            raise Fail("invalid_exact_lnbtc_request_binding")
        prof = x.get("requestBindingProfile")
        if prof not in ("http:1", "mcp:1") or "requestBindingParams" not in x:
            raise Fail("invalid_exact_lnbtc_request_binding")
        check_params(prof, x["requestBindingParams"])
        intended = doc["intended_request"]
        if prof != intended.get("profile"):
            raise Fail("invalid_exact_lnbtc_request_mismatch")  # P8: profile for another transport
        try:
            if prof == "http:1":
                h = intended["http"]
                if (pr.get("resource") or {}).get("url") != h.get("url"):
                    raise Fail("invalid_exact_lnbtc_request_mismatch")  # P9
                b = B.http_binding(dict(h, bound_headers=x["requestBindingParams"]["headers"]))
            else:
                mm = intended["mcp"]
                if x["requestBindingParams"]["server"] != mm.get("server"):
                    raise Fail("invalid_exact_lnbtc_request_mismatch")  # P10: server identity
                b = B.mcp_binding(dict(mm, bound_metadata=x["requestBindingParams"]["metadata"]))
            digest, _ = B.request_hash(b)
        except B.Reject:
            raise Fail("invalid_exact_lnbtc_request_binding")
        if len(inv["description_hashes"]) != 1 or inv["descriptions"]:
            raise Fail("invalid_exact_lnbtc_invoice_description")
        if x["requestHash"] != digest:
            raise Fail("invalid_exact_lnbtc_request_mismatch")
        if inv["description_hashes"][0] != digest:
            raise Fail("invalid_exact_lnbtc_invoice_request_mismatch")
        # 5..9
        if inv["signer"] != req["payTo"]:
            raise Fail("invalid_exact_lnbtc_invoice_payee_mismatch")
        if inv["currency"] != NETWORKS[req["network"]]:
            raise Fail("invalid_exact_lnbtc_invoice_currency_mismatch")
        if inv["msat"] is None:
            raise Fail("invalid_exact_lnbtc_invoice_decode_failed")
        if inv["msat"] != int(req["amount"]):
            raise Fail("invalid_exact_lnbtc_invoice_amount_mismatch")
        if inv["expiry"] != req["maxTimeoutSeconds"]:
            raise Fail("invalid_exact_lnbtc_invoice_expiry_mismatch")
        if inv["timestamp"] > now + skew:
            raise Fail("invalid_exact_lnbtc_invoice_created_in_future")
        if now > inv["timestamp"] + inv["expiry"]:
            raise Fail("invalid_exact_lnbtc_invoice_expired")  # P11: no skew here; the end itself is unexpired
        # 10
        called = True
        res = doc.get("payer_result") or {}
        st = res.get("status")
        if st == "in_flight":
            raise Fail("exact_lnbtc_payment_in_flight")
        if st != "paid":
            raise Fail("exact_lnbtc_payment_not_paid")
        if res.get("invoice") != x["invoice"]:
            raise Fail("invalid_exact_lnbtc_payer_invoice_mismatch")
        if res.get("payment_hash") != inv["payment_hash"]:
            raise Fail("invalid_exact_lnbtc_payer_payment_hash_mismatch")
        am = res.get("amount_msat")
        if not isinstance(am, str) or not DEC.match(am) or int(am) != inv["msat"]:
            raise Fail("invalid_exact_lnbtc_payer_amount_mismatch")
        if "preimage" not in res or res["preimage"] is None:
            raise Fail("invalid_exact_lnbtc_payer_preimage_required")
        pre = res["preimage"]
        if not isinstance(pre, str) or not HEX64.match(pre):
            raise Fail("invalid_exact_lnbtc_payer_preimage_malformed")
        if hashlib.sha256(bytes.fromhex(pre)).hexdigest() != inv["payment_hash"]:
            raise Fail("invalid_exact_lnbtc_payer_preimage_hash_mismatch")
        return {"preimage": pre}
    except Fail as f:
        return {"error": f.reason, "payer_called": called}
