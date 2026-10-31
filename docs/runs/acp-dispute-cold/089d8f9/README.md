# ACP Dispute Resolution Extension, PR #316 at `089d8f9`: the reader brought to the stated readings, rerun

The record in [`../`](../) read the extension at `db04871` and listed nine places where the text left a choice (R1–R9).
At `089d8f9` (2026-10-29T15:08:02Z) the RFC states readings for those places. This directory is the rerun that record
promised: the reader is changed only where the new text decides something the old reader read otherwise, every edit is
named, and both readers are scored on one case set so the difference is visible case by case.

## What the text at `089d8f9` decided, and what the reader did about it

| Reading | At `db04871` the reader took | At `089d8f9` the RFC says | Edit |
| --- | --- | --- | --- |
| R1 chain equality | exact strings | "exact string equality, with no normalization of case or encoding" (§4.4) | none |
| R2 receipt status | `success` only | "eligible only when its `status` is `success`" (§7.5) | none |
| R3 window | whole UTC days from `payment_receipt.iat` to the day the provider received the record | the same, and the received time is the new required field `opened_at` on the determination (§4.5, §7.5) | E-R3: `opened_at` required on the determination |
| R5 line amount | `subtotal`, else `unit_price` × `quantity.ordered`, else (one line) `payment_amount` | `subtotal`, else `unit_price` × `quantity.ordered`; a disputed line with neither is `not_eligible: line_amount_missing` (§7.4, §7.5) | E-R5: fallback removed, eligibility code added |
| R6 adjustments | any completed type counts; order-level allocated pro rata | only completed `refund`, `credit`, `price_adjustment` count; `return`, `exchange`, `cancellation`, `dispute` and unrecognized do not; an adjustment naming no line is allocated pro rata over the lines with a known amount (§7.4 rule 1) | E-R6: type filter |
| R7 expiry and charge | UTC date granularity; charge = order total | the same, stated (§7.4 rule 2) | none |
| R8 unfulfilled share | `current` else `ordered` minus `fulfilled`, after `estimated_delivery.latest` | the same, stated; "a fulfillment's own estimate does not extend it" (§7.4 rule 3) | none |
| R9 intent | finding, outcome unchanged | unchanged text | none |
| R4 approval binding | RFC 8785 digest of `{items, approved_at}` equal to `approval_digest` and to the merchant's digest | not restated in this change | none; still a reading |
| §4.5 `factors` | 3 of 5 reported as a warning (schema had no `required`) | the five are required in the schema, the examples and the checkout copies | E-4.5a: absent is a problem |
| mandate reuse | not evaluated (no field) | Open Question 12 | none |

One new reading, **R6b**: rule 3 says "canceled without a completed adjustment" and does not restate rule 1's list of
types. This reader takes the rule-1 kinds (the ones that return money) for rule 3 as well, so a completed `return` or
`cancellation` with no refund leaves the line "without a completed adjustment". Cases E1, E2 and E7 depend on it.
E-4.5b is a reporting choice: when the record is not eligible, the determination check says so and does not compare
lines or the fee.

## Files and results

| File | What | Result |
| --- | --- | --- |
| `acp_dispute_check_089d8f9.py` | the `db04871` reader (`2a5f878e…`) with the five named edits; frozen before the cases were written (`FROZEN.txt`, sha256 `b519d178…`) | |
| `gen_cases_089d8f9.py`, `cases.json`, `cases/` | 34 cases: the 26 of the first record (same inputs; U1 keeps the `db04871` example pair), E1–E7 for what the new text decides, U2 the example pair as published at `089d8f9`. Expectations fixed from the `089d8f9` text after the freeze and before any scored run; one note corrected after scoring, logged | |
| `run_089d8f9.json` | the `089d8f9` reader on the 34 | **34/34** |
| `run_db04871_reader.json` | the frozen `db04871` reader on the same 34 | **26/34**; differs on U1, E1, E2, E4, E5, E6, E7, U2, each the case written for an edit |
| `upstream_pins_089d8f9.txt` | what was fetched, opened, not opened | |

Same author for the reader and the expectations, as before: 34/34 shows that the reader does what the table says the
text now says, not that the table is right.

## The published example at `089d8f9` (case U2)

The two notes of the first record are closed: the mandate's `exp` (1794096000, 2026-11-08) is now after
`execution_date` (2026-11-01), so rule 3 decides the line as the determination says; `factors` carries all five;
`opened_at` (2026-11-12T09:00:00Z) is 52 days after `payment_receipt.iat` (2026-09-21), inside the window.

One thing the new §7.5 sentence does to its own example: `dispute_record.order.line_items` is `[{"id": "line_item_123"}]`,
with neither `subtotal` nor `unit_price`. Under "A record whose disputed line has neither `subtotal` nor `unit_price` is
ineligible: `not_eligible: line_amount_missing`" the provider would return that code, while `dispute_determination`
overturns 330. The `db04871` reader decided the same record from `payment_amount` (R5, the fallback the new text removes).
A `subtotal` of 330 on the example's line item would make the pair consistent again; so would a sentence saying that for
a single-line order `payment_amount` is the line amount, if that is the intended reading.

## Not covered

As in the first record: no second reader of this draft; the AP2 side taken as given; no mutation battery. The
`validate-consistency.js` script and the reference implementation were not opened, so nothing here says what they do
with `line_amount_missing`. CC0.
