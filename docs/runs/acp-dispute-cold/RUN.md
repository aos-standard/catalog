# ACP Dispute Resolution Extension (PR #316 @ db04871) — clean-room cold run (2026-10-27, not published)

- Reader: acp_dispute_check.py sha256 2a5f878e… frozen 2026-10-26T23:33:43Z (FROZEN.txt). Sources: RFC, schema.dispute_resolution.json,
  Order/LineItem/Adjustment/Fulfillment of schema.agentic_checkout.json, examples.dispute_resolution.json (SHA256SUMS in downloads/acp316_db04871).
  Not opened: validate-consistency.js, SEP #303 reference implementation, AP2#352 sample.
- Cases: 26, expectations fixed from the RFC text after the reader was frozen (gen_cases.py; one pre-scoring correction of base epochs, logged).
- First scored run: 26/26 (first_run.json). Same author for reader and expectations: this shows the reader does what the readings say, not that the readings are right.

## Findings on the published example (U1) — NOT public; route via resident PM (upstream channel undecided)
1. examples.dispute_resolution.json `dispute_record`: payment_mandate.exp = 1790003600 (2026-09-21T15:13:20Z) but execution_date = 2026-11-01.
   Under §7.4 the rules apply in order, so rule 2 ("Execution after exp … overturn the line") decides the line before rule 3 (canceled).
   The example determination's reason is `merchant_canceled_without_completed_adjustment` (rule 3). Outcome and amount (overturn 330) are the same either way.
   Likely the epoch values are placeholders (iat/receipts also 2026-09-21 while the approval example is 2026-11-01).
2. `dispute_determination.factors` has 3 of the 5 names (no intent_fidelity, agent_platform_conduct). §4.5 marks `factors` Required and
   "the five factor names are fixed" (§12 Q5), but the schema has no `required` inside factors, so 3/5 validates. Spec-open, reported as a warning.

## Where the text leaves a choice (R1–R9, in the reader's docstring)
Line amount source (R5), pro-rata allocation and which adjustment types count (R6), "after exp" at date granularity and "charge" = order total (R7),
"canceled without a completed adjustment" when a partial completed adjustment exists (R8, case D4d), receipt status value (R2), window in UTC calendar days (R3).
