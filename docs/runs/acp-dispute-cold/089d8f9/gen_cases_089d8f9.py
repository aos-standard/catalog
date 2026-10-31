#!/usr/bin/env python3
"""Cases for acp_dispute_check_089d8f9.py: the 26 cases of the db04871 record (same inputs, built from the 089d8f9
example the same way, except U1 which keeps the db04871 example pair as published), plus E1-E7 for what the text at
089d8f9 decided, and U2, the example pair as published at 089d8f9. Written 2026-10-31 after the reader was frozen
(b519d178...). Expectations are fixed from the RFC text at 089d8f9 (§4.5, §7.4, §7.5) before any scored run.
Usage: python3 -I gen_cases_089d8f9.py <examples.dispute_resolution.json @089d8f9> <examples @db04871> <out_dir>
"""
import copy, hashlib, json, sys
from pathlib import Path

ex = json.load(open(sys.argv[1], encoding="utf-8"))
ex_old = json.load(open(sys.argv[2], encoding="utf-8"))
out = Path(sys.argv[3]); (out / "cases").mkdir(parents=True, exist_ok=True)

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

def adj(type_, amount, status="completed", lines=None, id_="adj1"):
    a = {"id": id_, "type": type_, "status": status, "occurred_at": "2026-11-02T00:00:00Z", "amount": amount, "currency": "usd"}
    if lines: a["line_items"] = [{"id": l, "quantity": 1} for l in lines]
    return a

det_ok = copy.deepcopy(ex["dispute_determination"])   # at 089d8f9 it carries opened_at and the five factors
det_ok["factors"] = {f: {"finding": "n/a"} for f in ("mandate_scope", "intent_fidelity", "merchant_performance", "adjustments_already_made", "agent_platform_conduct")}
assert "opened_at" in det_ok
det_3of5 = copy.deepcopy(det_ok); det_3of5["factors"] = {f: det_ok["factors"][f] for f in ("mandate_scope", "merchant_performance", "adjustments_already_made")}
det_no_opened = copy.deepcopy(det_ok); del det_no_opened["opened_at"]

two = [{"id": "a", "title": "A", "quantity": {"ordered": 1, "current": 1, "fulfilled": 0}, "subtotal": 200},
       {"id": "b", "title": "B", "quantity": {"ordered": 1, "current": 1, "fulfilled": 0}, "subtotal": 100}]

ua = copy.deepcopy(ex["dispute_record_approval_mismatch"]["user_approval"])
D = ua["approval_digest"]
intent = rec(claim__ground="intent", user_approval=ua)
intent["order"]["line_items"][0]["item"] = {"id": "TEE-01", "variant": "black"}
intent_ok = copy.deepcopy(intent); intent_ok["order"]["line_items"][0]["item"]["variant"] = "green"

CANCEL = "3_canceled"
cases = [
 # --- the 26 of the db04871 record (expectations unchanged except U1) ---
 ("D0", {"record": base}, {"eligible": True, "per_line": [line("uphold", 0, "5_default")]}, [], "control: delivered, no adjustment"),
 ("D1a", {"record": rec(payment_mandate__transaction_id="h_other")}, {"eligible": False, "not_eligible": "authorization_chain_broken"}, [], "§4.4 mandate transaction_id != checkout_hash"),
 ("D1b", {"record": rec(checkout_receipt__reference="h_other")}, {"eligible": False, "not_eligible": "authorization_chain_broken"}, [], "§4.4 checkout receipt reference differs"),
 ("D1c", {"record": rec(payment_receipt__reference="h_other")}, {"eligible": False, "not_eligible": "authorization_chain_broken"}, [], "§4.4 payment receipt reference differs"),
 ("D1d", {"record": rec(checkout_hash="H_7F3A", payment_mandate__transaction_id="H_7F3A", checkout_receipt__reference="h_7f3a", payment_receipt__reference="H_7F3A")}, {"eligible": False, "not_eligible": "authorization_chain_broken"}, [], "§4.4 equality is exact string equality (now stated in the text)"),
 ("D2", {"record": rec(payment_receipt__status="failed")}, {"eligible": False, "not_eligible": "receipt_status"}, [], "§7.5 a receipt is eligible only when status is success (now stated)"),
 ("D3a", {"record": base, "opened_at": "2027-03-01T12:00:00Z"}, {"eligible": True, "per_line": [line("uphold", 0, "5_default")]}, [], "§7.5 opened day 120 after payment_receipt.iat (whole UTC days, now stated)"),
 ("D3b", {"record": base, "opened_at": "2027-03-02T00:00:00Z"}, {"eligible": False, "not_eligible": "outside_window"}, [], "§7.5 opened day 121"),
 ("D4", {"record": rec(order__status="canceled")}, {"eligible": True, "per_line": [line("overturn", 330, CANCEL)]}, [], "§7.4(3) canceled without completed adjustment"),
 ("D4b", {"record": rec(order__status="canceled", order__adjustments=[adj("refund", 330, lines=["line_item_123"])])}, {"eligible": True, "per_line": [line("uphold", 0, "1_moot")]}, [], "§7.4(1) completed line refund >= amount: moot"),
 ("D4c", {"record": rec(order__status="canceled", order__adjustments=[adj("refund", 330, status="pending", lines=["line_item_123"])])}, {"eligible": True, "per_line": [line("overturn", 330, CANCEL)]}, [], "§7.4(1)/(3) a pending refund is not completed"),
 ("D4d", {"record": rec(order__status="canceled", order__line_items=two, claim__line_ids=["a"], order__adjustments=[adj("refund", 200)])}, {"eligible": True, "per_line": [line("uphold", 0, "5_default", lid="a")]}, ["R8"], "§7.4(1) order-level 200 allocated pro rata over the lines with a known amount: 133 to line a (< 200, not moot); rule 3 needs no completed adjustment, so it does not fire (still a reading)"),
 ("D5", {"record": rec(order__status="canceled", payment_mandate__execution_date="2026-11-02")}, {"eligible": True, "per_line": [line("overturn", 330, "2_after_exp")]}, [], "§7.4(2) before (3): executed the UTC day after exp (now stated)"),
 ("D5b", {"record": rec(order__status="canceled", payment_mandate__execution_date="2026-11-01")}, {"eligible": True, "per_line": [line("overturn", 330, CANCEL)]}, [], "§7.4(2) the same day is not after (now stated)"),
 ("D6", {"record": rec(order__totals=[{"type": "total", "display_text": "Total", "amount": 400}])}, {"eligible": True, "per_line": [line("overturn", 70, "2_over_mandate")]}, [], "§7.4(2) the charge is the order total, compared with payment_amount (now stated)"),
 ("D7", {"record": rec(order__estimated_delivery={"earliest": "2026-11-03T00:00:00Z", "latest": "2026-11-05T00:00:00Z"}, order__line_items=[{"id": "line_item_123", "title": "Tee", "quantity": {"ordered": 2, "current": 2, "fulfilled": 1}, "subtotal": 330}]), "as_of": "2026-11-20T00:00:00Z"}, {"eligible": True, "per_line": [line("overturn", 165, "3_unfulfilled")]}, [], "§7.4(3) unfulfilled = current minus fulfilled after estimated_delivery.latest (now stated)"),
 ("D8", {"record": intent, "complete_digest": D}, {"eligible": True, "approval_bound": True, "per_line": [line("uphold", 0, "4_intent", "agent_platform")]}, ["R9"], "§4.4a bound approval, variant black not approved: finding against platform, charge stands"),
 ("D8b", {"record": intent, "complete_digest": "0" * 64}, {"eligible": True, "approval_bound": False, "per_line": [line("uphold", 0, "5_default")]}, ["R4"], "§4.4a merchant-received digest differs: not bound, no finding (R4 not restated at 089d8f9)"),
 ("D8c", {"record": intent_ok, "complete_digest": D}, {"eligible": True, "approval_bound": True, "per_line": [line("uphold", 0, "5_default")]}, ["R9"], "§4.4a bound approval matches the ordered item"),
 ("D8d", {"record": (lambda r: (r["user_approval"].update(approved_at="2026-11-01T09:59:00Z"), r)[1])(copy.deepcopy(intent)), "complete_digest": D}, {"eligible": True, "approval_bound": False, "per_line": [line("uphold", 0, "5_default")]}, ["R4"], "§4.4a approved_at altered: recomputed digest differs"),
 ("T0", {"record": rec(order__status="canceled"), "determination": det_ok}, {"eligible": True, "per_line": [line("overturn", 330, CANCEL)], "det_ok": True, "det_problems": []}, [], "determination matches the recomputed decision"),
 ("T1", {"record": rec(order__status="canceled"), "determination": (lambda d: (d.update(prohibited_screened=False), d)[1])(copy.deepcopy(det_ok))}, {"det_ok": False, "det_problems": ["prohibited_not_screened"]}, [], "§7.3 prohibited_screened false"),
 ("T2", {"record": base, "determination": det_ok}, {"det_ok": False, "det_problems": ["outcome_differs:line_item_123", "fee_paid_by_differs"]}, [], "determination overturns a line the rule upholds; merchant pays although the merchant prevailed"),
 ("T3", {"record": rec(order__status="canceled"), "determination": (lambda d: (d["factors"].update(party_reputation={}), d)[1])(copy.deepcopy(det_ok))}, {"det_ok": False, "det_problems": ["factor_not_permitted:party_reputation"]}, [], "§7.2/§7.3 a sixth factor"),
 ("T4", {"record": rec(order__status="canceled"), "determination": (lambda d: (d["signer"].update(credential=""), d)[1])(copy.deepcopy(det_ok))}, {"det_ok": False, "det_problems": ["signer_incomplete"]}, [], "§7.7 signer without credential"),
 ("U1", {"record": ex_old["dispute_record"], "determination": ex_old["dispute_determination"]}, {"eligible": False, "not_eligible": "line_amount_missing", "det_ok": False, "det_problems": ["missing:opened_at", "factors_absent:intent_fidelity,agent_platform_conduct", "record_not_eligible:line_amount_missing"]}, [], "the db04871 example pair under the 089d8f9 text: its line item has neither subtotal nor unit_price (§7.5 line_amount_missing); the determination lacks opened_at and two factors"),
 # --- E: what the text at 089d8f9 decided ---
 ("E1", {"record": rec(order__status="canceled", order__adjustments=[adj("return", 330, lines=["line_item_123"])])}, {"eligible": True, "per_line": [line("overturn", 330, CANCEL)]}, ["R6b"], "§7.4(1) a completed return of 330 naming the line does not count; canceled without a counted adjustment: overturn (db04871 reader: moot)"),
 ("E2", {"record": rec(order__status="canceled", order__adjustments=[adj("cancellation", 330)])}, {"eligible": True, "per_line": [line("overturn", 330, CANCEL)]}, ["R6b"], "§7.4(1) a completed order-level cancellation does not count (db04871 reader: moot)"),
 ("E3", {"record": rec(order__status="canceled", order__adjustments=[adj("price_adjustment", 330, lines=["line_item_123"])])}, {"eligible": True, "per_line": [line("uphold", 0, "1_moot")]}, [], "§7.4(1) a completed price_adjustment counts: moot (both readers)"),
 ("E4", {"record": rec(order__line_items=[{"id": "line_item_123", "title": "Tee", "quantity": {"ordered": 1, "current": 1, "fulfilled": 1}}])}, {"eligible": False, "not_eligible": "line_amount_missing"}, [], "§7.5 a disputed line with neither subtotal nor unit_price: ineligible (db04871 reader: decided from payment_amount, R5)"),
 ("E5", {"record": rec(order__status="canceled"), "determination": det_3of5}, {"det_ok": False, "det_problems": ["factors_absent:intent_fidelity,agent_platform_conduct"]}, [], "§4.5 factors with 3 of 5: a problem (db04871 reader: a warning)"),
 ("E6", {"record": rec(order__status="canceled"), "determination": det_no_opened}, {"det_ok": False, "det_problems": ["missing:opened_at"]}, [], "§4.5 opened_at is required on the determination"),
 ("E7", {"record": rec(order__status="canceled", order__line_items=two, claim__line_ids=["a"], order__adjustments=[adj("exchange", 300)])}, {"eligible": True, "per_line": [line("overturn", 200, CANCEL, lid="a")]}, ["R6b", "R8"], "§7.4(1)/(3) a completed order-level exchange counts for nothing, so the line is canceled without a counted adjustment: overturn 200 (db04871 reader: the exchange counts, 300 allocated pro rata gives 200 to a, equal to the line amount, so moot)"),
 ("U2", {"record": ex["dispute_record"], "determination": ex["dispute_determination"], "opened_at": ex["dispute_determination"]["opened_at"]}, {"eligible": False, "not_eligible": "line_amount_missing", "det_ok": False, "det_problems": ["record_not_eligible:line_amount_missing"]}, [], "the 089d8f9 example pair as published: opened_at 2026-11-12 is 52 days after payment_receipt.iat (in window), the mandate now expires after execution, factors carry all five; but the order's line item is {id} only, neither subtotal nor unit_price, so under the new §7.5 sentence the record is ineligible while the determination overturns 330"),
]
idx = []
for cid, case, expect, spec_open, note in cases:
    (out / "cases" / f"{cid}.json").write_text(json.dumps(case, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    idx.append({"id": cid, "expect": expect, "spec_open": spec_open, "note": note})
(out / "cases.json").write_text(json.dumps({"source_examples_sha256_089d8f9": hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest(),
                                            "source_examples_sha256_db04871": hashlib.sha256(open(sys.argv[2], "rb").read()).hexdigest(),
                                            "cases": idx}, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
print(len(idx), "cases")
