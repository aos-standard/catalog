# ACP Dispute Resolution Extension, PR #316 at `ddc2871`: the 089d8f9 reader, unchanged, on the example as fixed

The [`089d8f9/`](../089d8f9/) record left two points for the text: rule 3 did not say which adjustments count (reading R6b),
and the example's line item had no amount, so under the new §7.5 the example record was ineligible while its determination
overturned 330. At `ddc2871` (2026-10-31T03:30:43Z) the RFC author took both:

| Point | At `089d8f9` | At `ddc2871` |
| --- | --- | --- |
| R6b | rule 3: "canceled without a completed adjustment" | "without a completed adjustment of a type counted in rule 1" (§7.4 rule 3) |
| example | `line_items: [{"id": "line_item_123"}]` | the same line with `"subtotal": 330`, in the record and in the checkout copy |

The schema is byte-identical to `089d8f9`. The reader already took R6b, so it is **not edited**: the frozen `089d8f9`
reader (sha256 `b519d178…`) is rerun as is.

## Files and results

| File | What | Result |
| --- | --- | --- |
| `gen_cases_ddc2871.py`, `cases.json`, `cases/` | the 34 cases of `089d8f9/`, same bytes, plus U3: the example pair as published at `ddc2871`. U3's expectation written from the `ddc2871` text before any scored run (`FROZEN.txt`) | |
| `run_ddc2871.json` | the frozen `089d8f9` reader on the 35 | **35/35** |
| `run_db04871_reader.json` | the frozen `db04871` reader on the same 35 | **27/35**; differs on the same eight as before (U1, E1, E2, E4, E5, E6, E7, U2) and agrees on U3 |
| `upstream_pins_ddc2871.txt` | what was fetched, opened, not opened | |

U3: the record is eligible (`subtotal` 330, receipt `success`, `opened_at` 52 days after `payment_receipt.iat`), the merchant
canceled with no completed `refund`, `credit` or `price_adjustment`, so rule 3 overturns 330, which is what
`dispute_determination` says; the five factors are present. The example pair is consistent again under the text.

That the older reader also agrees on U3 is expected: the example has no adjustment at all, and with a `subtotal` its line
amount no longer depends on the `payment_amount` fallback. The cases that separate the two readings are E1, E2 and E7.

Answer exposure: R6b and the example note are this record's own earlier findings, and U3's expectation is the outcome the
author's comment states. 35/35 shows that the reader, the text and the published example now agree, not that the reading
is the only one possible. `validate-consistency.js` was not opened. CC0.
