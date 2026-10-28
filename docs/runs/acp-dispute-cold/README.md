# ACP Dispute Resolution Extension (SEP #303, PR #316 at `db04871`) — a cold reader, 26 cases, two notes on the example

**Date:** 2026-10-29 (run 2026-10-27). CC0 for the files here. The input is an **unmerged** pull request on
agentic-commerce-protocol/agentic-commerce-protocol (#316, head `db04871`, maximusrufus's fork; SEP #303 awaiting a
sponsor), so everything below is about a draft, pinned by commit and by the file digests in
`upstream_pins_db04871.txt`.

## What was read

`rfcs/rfc.dispute_resolution.md`, `spec/unreleased/json-schema/schema.dispute_resolution.json`, the Order /
OrderLineItem / Adjustment / Fulfillment definitions of `schema.agentic_checkout.json`, and
`examples/unreleased/examples.dispute_resolution.json`, all at `db04871`. Not opened: `scripts/validate-consistency.js`,
the reference implementation SEP #303 describes, and the AP2 sample in google-agentic-commerce/AP2#352.

## The reader and the cases

`acp_dispute_check.py` (sha256 `2a5f878e…`, standard library) decides a dispute record under §7.4 and checks a
determination under §4.5. It was frozen before the cases were written (`FROZEN.txt`). The 26 cases (`cases/`,
`cases.json`, built by `gen_cases.py`) and their expected results were written from the RFC text after the freeze and
before any scored run; one correction of base epochs was made before scoring and is logged in `FROZEN.txt`.
`first_run.json`: **26/26**. Same author for reader and expectations, so 26/26 shows that the reader does what the
readings below say, not that the readings are the author's intent.

Nine places where the text leaves a choice, each stated in the reader's docstring and named in a result's
`spec_open`: R1 chain equality as strings; R2 receipt status `success` only; R3 the dispute window in whole UTC calendar
days; R4 approval binding by the RFC 8785 digest of `{items, approved_at}`; R5 the line amount source; R6 pro-rata
allocation of an adjustment that names no line, any adjustment type; R7 "after exp" at UTC date granularity and
"charge" as the order total; R8 "canceled without a completed adjustment" and the unfulfilled share after
`estimated_delivery.latest`; R9 intent as a finding against the platform with the outcome unchanged.

## Two notes on the published example (not defects of an implementation; the file is a draft's example)

1. `examples.dispute_resolution.json`, `dispute_record`: `payment_mandate.exp` is 1790003600 (2026-09-21T15:13:20Z) while
   `execution_date` is 2026-11-01. Under §7.4 the rules apply in order, so rule 2 (execution after `exp`) decides the line
   before rule 3 (canceled). The example's determination gives `merchant_canceled_without_completed_adjustment` (rule 3).
   Outcome and amount are the same either way (overturn 330). The epochs look like placeholders: `iat` and the receipts
   are also 2026-09-21 while the approval example is 2026-11-01.
2. `dispute_determination.factors` in the example has 3 of the 5 names (no `intent_fidelity`, no
   `agent_platform_conduct`). §4.5 marks `factors` Required and §12 Q5 says the five names are fixed, but the schema
   has no `required` inside `factors`, so 3/5 validates. The reader reports it as a warning.

## Not covered

No independent reader of this draft exists; the AP2 side (mandates, receipts) was taken as given and not verified
cryptographically; no mutation battery. The dispute window and rule 2 depend on readings R3 and R7.
