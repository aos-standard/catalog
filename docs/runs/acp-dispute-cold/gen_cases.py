#!/usr/bin/env python3
"""Cases D*/T* for acp_dispute_check.py. Written 2026-10-27 after the reader was frozen (2a5f878e...).
Each expectation is fixed here from the RFC text (rule order of §7.4, §4.4, §4.4a, §7.5) before any scored run.
`spec_open` names the reading (R1-R9 in the reader) a case depends on where the text does not decide it.
Usage: python3 -I gen_cases.py <examples.dispute_resolution.json> <out_dir>
"""
import copy, hashlib, json, sys
from pathlib import Path

ex = json.load(open(sys.argv[1], encoding="utf-8"))
out = Path(sys.argv[2]); (out / "cases").mkdir(parents=True, exist_ok=True)

# Base: the upstream dispute_record with the mandate times moved to 2026-11-01 so that execution is inside
# iat..exp (the upstream example executes 41 days after exp; that case is kept as-is in U1).
base = copy.deepcopy(ex["dispute_record"])
base["payment_mandate"].update(iat=1793491200, exp=1793577599)        # 2026-11-01T00:00Z .. 23:59:59Z
base["checkout_receipt"]["iat"] = 1793491300
base["payment_receipt"]["iat"] = 1793491400
base["order"].update(status="completed", line_items=[{"id": "line_item_123", "title": "Tee", "quantity": {"ordered": 1, "current": 1, "fulfilled": 1}, "subtotal": 330}],
                     fulfillments=[{"id": "f1", "type": "shipping", "status": "delivered"}], adjustments=[])

def rec(**kw):
    r = copy.deepcopy(base)
    for path, v in kw.items():
        cur = r; keys = path.split("__")
        for k in keys[:-1]: cur = cur[k]
        cur[keys[-1]] = v
    return r

def line(outcome, amount, rule, finding=None, lid="line_item_123"):
    return {"line_id": lid, "outcome": outcome, "amount": amount, "rule": rule, "finding": finding}

det_ok = copy.deepcopy(ex["dispute_determination"])
det_ok["factors"] = {f: {"finding": "n/a"} for f in ("mandate_scope", "intent_fidelity", "merchant_performance", "adjustments_already_made", "agent_platform_conduct")}

two = [{"id": "a", "title": "A", "quantity": {"ordered": 1, "current": 1, "fulfilled": 0}, "subtotal": 200},
       {"id": "b", "title": "B", "quantity": {"ordered": 1, "current": 1, "fulfilled": 0}, "subtotal": 100}]

ua = copy.deepcopy(ex["dispute_record_approval_mismatch"]["user_approval"])
D = ua["approval_digest"]
intent = rec(claim__ground="intent", user_approval=ua)
intent["order"]["line_items"][0]["item"] = {"id": "TEE-01", "variant": "black"}
intent_ok = copy.deepcopy(intent); intent_ok["order"]["line_items"][0]["item"]["variant"] = "green"

cases = [
 ("D0", {"record": base}, {"eligible": True, "per_line": [line("uphold", 0, "5_default")]}, [], "control: delivered, no adjustment"),
 ("D1a", {"record": rec(payment_mandate__transaction_id="h_other")}, {"eligible": False, "not_eligible": "authorization_chain_broken"}, [], "§4.4 mandate transaction_id != checkout_hash"),
 ("D1b", {"record": rec(checkout_receipt__reference="h_other")}, {"eligible": False, "not_eligible": "authorization_chain_broken"}, [], "§4.4 checkout receipt reference differs"),
 ("D1c", {"record": rec(payment_receipt__reference="h_other")}, {"eligible": False, "not_eligible": "authorization_chain_broken"}, [], "§4.4 payment receipt reference differs"),
 ("D1d", {"record": rec(checkout_hash="H_7F3A", payment_mandate__transaction_id="H_7F3A", checkout_receipt__reference="h_7f3a", payment_receipt__reference="H_7F3A")}, {"eligible": False, "not_eligible": "authorization_chain_broken"}, ["R1"], "§4.4 equality is exact (case differs on one receipt)"),
 ("D2", {"record": rec(payment_receipt__status="failed")}, {"eligible": False, "not_eligible": "receipt_status"}, ["R2"], "§7.5 receipt status in eligibility"),
 ("D3a", {"record": base, "opened_at": "2027-03-01T12:00:00Z"}, {"eligible": True, "per_line": [line("uphold", 0, "5_default")]}, ["R3"], "§7.5 opened day 120 after payment_receipt.iat"),
 ("D3b", {"record": base, "opened_at": "2027-03-02T00:00:00Z"}, {"eligible": False, "not_eligible": "outside_window"}, ["R3"], "§7.5 opened day 121"),
 ("D4", {"record": rec(order__status="canceled")}, {"eligible": True, "per_line": [line("overturn", 330, "3_canceled")]}, [], "§7.4(3) canceled without completed adjustment"),
 ("D4b", {"record": rec(order__status="canceled", order__adjustments=[{"id": "adj1", "type": "refund", "status": "completed", "occurred_at": "2026-11-02T00:00:00Z", "amount": 330, "currency": "usd", "line_items": [{"id": "line_item_123", "quantity": 1}]}])}, {"eligible": True, "per_line": [line("uphold", 0, "1_moot")]}, [], "§7.4(1) completed line refund >= amount: moot"),
 ("D4c", {"record": rec(order__status="canceled", order__adjustments=[{"id": "adj1", "type": "refund", "status": "pending", "occurred_at": "2026-11-02T00:00:00Z", "amount": 330, "currency": "usd", "line_items": [{"id": "line_item_123", "quantity": 1}]}])}, {"eligible": True, "per_line": [line("overturn", 330, "3_canceled")]}, [], "§7.4(1)/(3) a pending refund is not completed"),
 ("D4d", {"record": rec(order__status="canceled", order__line_items=two, claim__line_ids=["a"], order__adjustments=[{"id": "adj1", "type": "refund", "status": "completed", "occurred_at": "2026-11-02T00:00:00Z", "amount": 200, "currency": "usd"}])}, {"eligible": True, "per_line": [line("uphold", 0, "5_default", lid="a")]}, ["R6", "R8"], "§7.4(1) order-level 200 allocated pro rata: 133 to line a (< 200, not moot); rule 3 needs no completed adjustment, so it does not fire"),
 ("D5", {"record": rec(order__status="canceled", payment_mandate__execution_date="2026-11-02")}, {"eligible": True, "per_line": [line("overturn", 330, "2_after_exp")]}, ["R7"], "§7.4(2) before (3): executed the day after exp"),
 ("D5b", {"record": rec(order__status="canceled", payment_mandate__execution_date="2026-11-01")}, {"eligible": True, "per_line": [line("overturn", 330, "3_canceled")]}, ["R7"], "§7.4(2) same UTC day as exp is not after"),
 ("D6", {"record": rec(order__totals=[{"type": "total", "display_text": "Total", "amount": 400}])}, {"eligible": True, "per_line": [line("overturn", 70, "2_over_mandate")]}, ["R7"], "§7.4(2) charge 400 over mandate 330: overturn the excess"),
 ("D7", {"record": rec(order__estimated_delivery={"earliest": "2026-11-03T00:00:00Z", "latest": "2026-11-05T00:00:00Z"}, order__line_items=[{"id": "line_item_123", "title": "Tee", "quantity": {"ordered": 2, "current": 2, "fulfilled": 1}, "subtotal": 330}]), "as_of": "2026-11-20T00:00:00Z"}, {"eligible": True, "per_line": [line("overturn", 165, "3_unfulfilled")]}, ["R8"], "§7.4(3) one of two units unfulfilled after estimated_delivery.latest"),
 ("D8", {"record": intent, "complete_digest": D}, {"eligible": True, "approval_bound": True, "per_line": [line("uphold", 0, "4_intent", "agent_platform")]}, ["R9"], "§4.4a bound approval, variant black not approved: finding against platform, charge stands"),
 ("D8b", {"record": intent, "complete_digest": "0" * 64}, {"eligible": True, "approval_bound": False, "per_line": [line("uphold", 0, "5_default")]}, [], "§4.4a merchant-received digest differs: not bound, no finding"),
 ("D8c", {"record": intent_ok, "complete_digest": D}, {"eligible": True, "approval_bound": True, "per_line": [line("uphold", 0, "5_default")]}, ["R9"], "§4.4a bound approval matches the ordered item"),
 ("D8d", {"record": (lambda r: (r["user_approval"].update(approved_at="2026-11-01T09:59:00Z"), r)[1])(copy.deepcopy(intent)), "complete_digest": D}, {"eligible": True, "approval_bound": False, "per_line": [line("uphold", 0, "5_default")]}, [], "§4.4a approved_at altered: recomputed digest differs"),
 ("T0", {"record": rec(order__status="canceled"), "determination": det_ok}, {"eligible": True, "per_line": [line("overturn", 330, "3_canceled")], "det_ok": True, "det_problems": []}, [], "determination matches the recomputed decision"),
 ("T1", {"record": rec(order__status="canceled"), "determination": (lambda d: (d.update(prohibited_screened=False), d)[1])(copy.deepcopy(det_ok))}, {"det_ok": False, "det_problems": ["prohibited_not_screened"]}, [], "§7.3 prohibited_screened false"),
 ("T2", {"record": base, "determination": det_ok}, {"det_ok": False, "det_problems": ["outcome_differs:line_item_123", "fee_paid_by_differs"]}, [], "determination overturns a line the rule upholds; merchant pays although the merchant prevailed"),
 ("T3", {"record": rec(order__status="canceled"), "determination": (lambda d: (d["factors"].update(party_reputation={}), d)[1])(copy.deepcopy(det_ok))}, {"det_ok": False, "det_problems": ["factor_not_permitted:party_reputation"]}, [], "§7.2/§7.3 a sixth factor"),
 ("T4", {"record": rec(order__status="canceled"), "determination": (lambda d: (d["signer"].update(credential=""), d)[1])(copy.deepcopy(det_ok))}, {"det_ok": False, "det_problems": ["signer_incomplete"]}, [], "§7.7 signer without credential"),
 ("U1", {"record": ex["dispute_record"], "determination": ex["dispute_determination"]}, {"eligible": True, "per_line": [line("overturn", 330, "2_after_exp")], "det_ok": True, "det_problems": [], "det_warnings": ["factors_absent:intent_fidelity,agent_platform_conduct"]}, ["R5", "R7"], "upstream example pair as published: execution_date 2026-11-01 is after exp 2026-09-21, so rule 2 decides before rule 3 (the example's reason names rule 3); factors carry 3 of 5"),
]
idx = []
for cid, case, expect, spec_open, note in cases:
    (out / "cases" / f"{cid}.json").write_text(json.dumps(case, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    idx.append({"id": cid, "expect": expect, "spec_open": spec_open, "note": note})
(out / "cases.json").write_text(json.dumps({"source_examples_sha256": hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest(), "cases": idx}, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
print(len(idx), "cases")
