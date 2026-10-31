# Addendum to the `db04871` record: the extension at `089d8f9`

Written beside the record, not over it. The record above is the reading of PR #316 at `db04871` (2026-10-27, 26/26).
On 2026-10-29 the RFC author took the two notes on the example (`b7bb15d`) and stated the nine readings in the RFC
(`089d8f9`), one of them differently from the record's reader (R6: only `refund`, `credit` and `price_adjustment`
adjustments count) and one with a new field (R3: `opened_at` on the determination) and a new eligibility code
(`line_amount_missing`).

The rerun is in [`089d8f9/`](089d8f9/): the same reader with five named edits (frozen `b519d178…`), 34 cases (the
26 of this record plus 8 for the new text), **34/34** for the edited reader and **26/34** for this record's frozen
reader on the same cases, differing exactly on the 8 cases written for the edits. One new reading (R6b: rule 3's
"completed adjustment" taken as the rule-1 kinds) and one note on the `089d8f9` example (its line item has neither
`subtotal` nor `unit_price`, which the new §7.5 sentence makes ineligible) are stated there.

Nothing in the record above is changed: `acp_dispute_check.py`, `cases/`, `first_run.json` and `SHA256SUMS` are as
published at `8258150`.
