#!/usr/bin/env python3
"""acp_dispute_check_089d8f9 — the db04871 reader (sha256 2a5f878e...) brought to the RFC text at 089d8f9.

Five edits, each named below (E-R3, E-R5, E-R6, E-4.5a, E-4.5b); everything else is the frozen db04871 reader.
  E-R3   §4.5/§7.5: `opened_at` is now a required field of the determination; `missing:opened_at` is a problem.
  E-R5   §7.5: a disputed line with neither `subtotal` nor `unit_price` makes the record ineligible
         (`not_eligible: line_amount_missing`); the single-line fallback to payment_amount is removed.
  E-R6   §7.4(1): only a completed adjustment of type refund, credit or price_adjustment counts; other types
         and unrecognized values do not, for rule 1 and for "without a completed adjustment" in rule 3 (a reading:
         rule 3 does not restate the list; this reader takes the rule-1 kinds, the ones that return money).
  E-4.5a §4.5: `factors` must carry all five considerations (the schema now requires them): absent is a problem.
  E-4.5b when the record is not eligible, the determination check reports that and does not compare lines or fee.

The original header follows.

Written 2026-10-27 from agentic-commerce-protocol PR #316 at head db048718 (maximusrufus fork; unmerged,
SEP #303) only: rfcs/rfc.dispute_resolution.md, spec/unreleased/json-schema/schema.dispute_resolution.json,
the Order / OrderLineItem / Adjustment / Fulfillment definitions of schema.agentic_checkout.json, and
examples/unreleased/examples.dispute_resolution.json. Not opened: scripts/validate-consistency.js, the
reference implementation described in SEP #303, the AP2 sample in google-agentic-commerce/AP2#352.

Standard library only. The readings R1-R9 are where the text leaves a choice; each is stated where it is
used, and `spec_open` in a result names the readings it relied on.

  R1 §4.4  chain: payment_mandate.transaction_id, checkout_receipt.reference and payment_receipt.reference
           must each equal checkout_hash as strings. Otherwise not_eligible: authorization_chain_broken.
  R2 §7.5  receipt status: both receipts must have status "success" (the only value the examples use).
  R3 §7.5  window: opened_at minus payment_receipt.iat, in whole UTC calendar days, is at most window_days
           (default 120 when not given). Without opened_at the window is not evaluated.
  R4 §4.4a approval is bound only when SHA-256 of the RFC 8785 form of {items, approved_at} equals
           approval_digest AND equals the digest the merchant received on complete. Without that digest
           the approval is not bound.
  R5 §7.4  line amount: OrderLineItem.subtotal; else unit_price x quantity.ordered; else, when the order
           has exactly one line, payment_mandate.payment_amount. Otherwise the line is undecided.
  R6 §7.4(1) a completed adjustment that names the line counts in full; one with no line_items is
           allocated pro rata by line amount over all lines with a known amount. Adjustment type is
           not restricted (the text says "refund or credit"; the schema has no enum).
  R7 §7.4(2) execution after exp: the UTC date of execution_date is later than the UTC date of exp.
           The same day is not "after". Charge over the mandate: the order total (totals type "total")
           exceeds payment_amount; the excess is overturned on the claimed line when one line is claimed.
           Mandate reuse has no field and is not evaluated.
  R8 §7.4(3) canceled: order.status == "canceled" with no completed adjustment on that line (R6).
           Unfulfilled after estimated_delivery: as_of is after order.estimated_delivery.latest and
           quantity.fulfilled < quantity.current (or ordered); overturn the unfulfilled share of the amount.
  R9 §7.4(4) intent: with a bound approval, a claimed line whose item.id / sku and variant match no approved
           item is a finding against the agent platform; the outcome stays uphold.
Rules are applied in the RFC's order; the first that decides a line wins.
"""
from __future__ import annotations

import hashlib
import json
from datetime import date, datetime, timezone
from typing import Any

DEFAULT_WINDOW_DAYS = 120
COUNTED_ADJUSTMENT_TYPES = ("refund", "credit", "price_adjustment")  # E-R6, §7.4(1) at 089d8f9
FACTORS = ("mandate_scope", "intent_fidelity", "merchant_performance", "adjustments_already_made",
           "agent_platform_conduct")


def _obj(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def jcs(value: Any) -> str:
    """RFC 8785 for the shapes UserApproval allows (objects, arrays, strings, integers, booleans, null)."""
    if isinstance(value, bool) or value is None:
        return json.dumps(value)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        raise ValueError("non-integer number")
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(jcs(v) for v in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + jcs(value[k]) for k in keys) + "}"
    raise ValueError(f"unsupported type {type(value).__name__}")


def _utc_date(value: Any) -> date | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc).date()
    if isinstance(value, str) and value:
        try:
            if len(value) == 10:
                return date.fromisoformat(value)
            moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        if moment.tzinfo is None:
            return None
        return moment.astimezone(timezone.utc).date()
    return None


def _moment(value: Any) -> datetime | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if isinstance(value, str) and value:
        try:
            moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return moment if moment.tzinfo else None
    return None


def chain_ok(record: dict) -> bool:
    h = record.get("checkout_hash")
    if not isinstance(h, str) or not h:
        return False
    pm = _obj(record.get("payment_mandate"))
    cr = _obj(record.get("checkout_receipt"))
    pr = _obj(record.get("payment_receipt"))
    return pm.get("transaction_id") == h and cr.get("reference") == h and pr.get("reference") == h


def approval_bound(record: dict, complete_digest: str | None) -> bool:
    ua = record.get("user_approval")
    if not isinstance(ua, dict) or not isinstance(complete_digest, str):
        return False
    try:
        recomputed = hashlib.sha256(jcs({"items": ua.get("items"), "approved_at": ua.get("approved_at")})
                                    .encode("utf-8")).hexdigest()
    except ValueError:
        return False
    return recomputed == ua.get("approval_digest") == complete_digest


def _lines(order: dict) -> list[dict]:
    return [li for li in (order.get("line_items") or []) if isinstance(li, dict)]


def line_amount(order: dict, line: dict, mandate: dict) -> int | None:
    sub = line.get("subtotal")
    if isinstance(sub, int) and not isinstance(sub, bool):
        return sub
    unit = line.get("unit_price")
    qty = line.get("quantity")
    ordered = qty.get("ordered") if isinstance(qty, dict) else None
    if isinstance(unit, int) and isinstance(ordered, int) and not isinstance(unit, bool):
        return unit * ordered
    return None  # E-R5: no fallback; §7.5 makes such a line's record ineligible


def credited(order: dict, line_id: str, amounts: dict[str, int]) -> tuple[int, bool]:
    """(credit toward the line, whether any completed adjustment touched it)."""
    total = 0
    touched = False
    known = sum(amounts.values())
    for adj in order.get("adjustments") or []:
        if not isinstance(adj, dict) or adj.get("status") != "completed":
            continue
        if adj.get("type") not in COUNTED_ADJUSTMENT_TYPES:  # E-R6
            continue
        amt = adj.get("amount")
        if not isinstance(amt, int) or isinstance(amt, bool):
            continue
        refs = adj.get("line_items")
        if refs:
            if any(isinstance(r, dict) and r.get("id") == line_id for r in refs):
                total += amt
                touched = True
        elif known > 0 and line_id in amounts:
            total += amt * amounts[line_id] // known
            touched = True
    return total, touched


def _order_total(order: dict) -> int | None:
    for t in order.get("totals") or []:
        if isinstance(t, dict) and t.get("type") == "total" and isinstance(t.get("amount"), int):
            return t["amount"]
    return None


def _item_key(line: dict) -> tuple[str | None, str | None]:
    item = _obj(line.get("item"))
    sku = line.get("sku") or item.get("sku") or item.get("id") or line.get("product_id")
    variant = line.get("variant") or item.get("variant") or line.get("variant_id")
    return sku, variant


def decide(record: dict, *, complete_digest: str | None = None, opened_at: Any = None, as_of: Any = None,
           window_days: int | None = None) -> dict:
    out: dict[str, Any] = {"eligible": False, "not_eligible": None, "approval_bound": False, "per_line": [],
                           "window_evaluated": opened_at is not None}
    if not chain_ok(record):
        out["not_eligible"] = "authorization_chain_broken"
        return out
    for key in ("checkout_receipt", "payment_receipt"):
        if _obj(record.get(key)).get("status") != "success":
            out["not_eligible"] = "receipt_status"
            return out
    if opened_at is not None:
        start = _utc_date(_obj(record.get("payment_receipt")).get("iat"))
        opened = _utc_date(opened_at)
        days = window_days if window_days is not None else DEFAULT_WINDOW_DAYS
        if start is None or opened is None or (opened - start).days > days or opened < start:
            out["not_eligible"] = "outside_window"
            return out
    order = _obj(record.get("order"))
    mandate = _obj(record.get("payment_mandate"))
    lines: dict[str, dict] = {li["id"]: li for li in _lines(order) if isinstance(li.get("id"), str)}
    amounts = {lid: a for lid, li in lines.items() if (a := line_amount(order, li, mandate)) is not None}
    claimed = [x for x in (_obj(record.get("claim")).get("line_ids") or []) if isinstance(x, str)]
    if any(lid in lines and lid not in amounts for lid in claimed):  # E-R5, §7.5 at 089d8f9
        out["not_eligible"] = "line_amount_missing"
        return out
    out["eligible"] = True
    bound = approval_bound(record, complete_digest)
    out["approval_bound"] = bound
    exp_day = _utc_date(mandate.get("exp"))
    exec_day = _utc_date(mandate.get("execution_date"))
    charge = _order_total(order)
    cap = mandate.get("payment_amount")
    approved = _obj(record.get("user_approval")).get("items") or []
    as_of_m = _moment(as_of)
    latest = _moment(_obj(order.get("estimated_delivery")).get("latest"))

    for lid in claimed:
        row: dict[str, Any] = {"line_id": lid, "outcome": None, "amount": None, "rule": None, "finding": None}
        out["per_line"].append(row)
        line = lines.get(lid)
        amount = amounts.get(lid)
        if line is None or amount is None:
            row["rule"] = "line_unresolved"
            continue
        credit, touched = credited(order, lid, amounts)
        if touched and credit >= amount:
            row.update(outcome="uphold", amount=0, rule="1_moot")
            continue
        if exp_day is not None and exec_day is not None and exec_day > exp_day:
            row.update(outcome="overturn", amount=amount, rule="2_after_exp")
            continue
        if (isinstance(charge, int) and isinstance(cap, int) and charge > cap and len(claimed) == 1):
            row.update(outcome="overturn", amount=charge - cap, rule="2_over_mandate")
            continue
        if order.get("status") == "canceled" and not touched:
            row.update(outcome="overturn", amount=amount, rule="3_canceled")
            continue
        qty = _obj(line.get("quantity"))
        if qty and as_of_m and latest and as_of_m > latest:
            base = qty.get("current", qty.get("ordered"))
            done = qty.get("fulfilled", 0)
            if isinstance(base, int) and isinstance(done, int) and base > 0 and done < base:
                row.update(outcome="overturn", amount=amount * (base - done) // base, rule="3_unfulfilled")
                continue
        if bound:
            sku, variant = _item_key(line)
            match = any(isinstance(a, dict) and a.get("sku") == sku
                        and (a.get("variant") is None or a.get("variant") == variant) for a in approved)
            if not match:
                row.update(outcome="uphold", amount=0, rule="4_intent", finding="agent_platform")
                continue
        row.update(outcome="uphold", amount=0, rule="5_default")
    return out


def check_determination(det: dict, record: dict, decision: dict) -> dict:
    """Problems with a determination against the record and the recomputed decision."""
    problems: list[str] = []
    warnings: list[str] = []
    for key in ("determination_id", "dispute_id", "policy_version", "per_line", "factors",
                "prohibited_screened", "signer", "opened_at", "issued_at", "seal", "fee_disposition"):  # E-R3
        if key not in det:
            problems.append(f"missing:{key}")
    if det.get("dispute_id") != record.get("dispute_id"):
        problems.append("dispute_id_mismatch")
    if det.get("policy_version") != record.get("policy_version"):
        problems.append("policy_version_mismatch")
    if det.get("prohibited_screened") is not True:
        problems.append("prohibited_not_screened")
    signer = _obj(det.get("signer"))
    if not signer.get("name") or not signer.get("credential"):
        problems.append("signer_incomplete")
    factors = _obj(det.get("factors"))
    extra = sorted(set(factors) - set(FACTORS))
    if extra:
        problems.append("factor_not_permitted:" + ",".join(extra))
    absent = [f for f in FACTORS if f not in factors]
    if absent:
        problems.append("factors_absent:" + ",".join(absent))  # E-4.5a
    if not decision.get("eligible"):  # E-4.5b: report and stop; lines and fee are not compared
        problems.append(f"record_not_eligible:{decision.get('not_eligible')}")
        return {"ok": False, "problems": problems, "warnings": warnings, "rules": []}
    want = {r["line_id"]: r for r in decision.get("per_line", [])}
    got = {r.get("line_id"): r for r in det.get("per_line") or [] if isinstance(r, dict)}
    for lid, r in want.items():
        g = got.get(lid)
        if g is None:
            problems.append(f"line_missing:{lid}")
            continue
        if r["outcome"] is None:
            warnings.append(f"line_undecided:{lid}")
            continue
        if g.get("outcome") != r["outcome"]:
            problems.append(f"outcome_differs:{lid}")
        amt = _obj(g.get("amount")).get("amount")
        if r["outcome"] == "overturn" and amt != r["amount"]:
            problems.append(f"amount_differs:{lid}")
    for lid in got:
        if lid not in want:
            problems.append(f"line_not_claimed:{lid}")
    outcomes = {r["outcome"] for r in decision.get("per_line", []) if r["outcome"]}
    paid_by = _obj(det.get("fee_disposition")).get("paid_by")
    if outcomes == {"overturn"} and paid_by != "merchant":
        problems.append("fee_paid_by_differs")
    if outcomes == {"uphold"} and paid_by != "payer":
        problems.append("fee_paid_by_differs")
    rules = sorted({r["rule"] for r in decision.get("per_line", []) if r["rule"]})
    return {"ok": not problems, "problems": problems, "warnings": warnings, "rules": rules}


def main(argv: list[str]) -> int:
    """Usage: acp_dispute_check_089d8f9.py <case.json>  (case = {record, determination?, complete_digest?, opened_at?, as_of?})"""
    case = json.load(open(argv[1], encoding="utf-8"))
    decision = decide(case["record"], complete_digest=case.get("complete_digest"), opened_at=case.get("opened_at"),
                      as_of=case.get("as_of"), window_days=case.get("window_days"))
    result: dict[str, Any] = {"decision": decision}
    if "determination" in case:
        result["determination"] = check_determination(case["determination"], case["record"], decision)
    print(json.dumps(result, indent=1, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    import sys
    raise SystemExit(main(sys.argv))
