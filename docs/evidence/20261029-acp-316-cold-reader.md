---
url: https://github.com/agentic-commerce-protocol/agentic-commerce-protocol/pull/316#issuecomment-6499697960
api: https://api.github.com/repos/agentic-commerce-protocol/agentic-commerce-protocol/issues/comments/6499697960
created_at: 2026-10-29T14:39:36Z
fetched_at: 2026-10-29T14:40:16Z
body_sha256: 5cec5fa421a6ea2e9eb2d7b42262140920a80b986fb20867d22f1dd7e98ceb3b
note: exact copy of the comment body as served by the GitHub API at fetched_at; the rows in CONDUCT.jsonl hash this whole file
---
@maximusrufus a cold read of the extension at `db04871`, from the RFC, the two schemas and the example only; `validate-consistency.js`, the reference implementation and the AP2 sample were not opened.

A reader (standard library) decides a record under §7.4 and checks a determination under §4.5. It was frozen first; 26 cases and their expected results were then written from the text, and the scored run is 26/26. Same author on both sides, so that number says the reader follows the readings, not that the readings are yours. The nine places where the text left me a choice are listed in the record, each named in the results it touches: among them, the dispute window counted in whole UTC calendar days (§7.5), "after exp" at date granularity and "charge" taken as the order total (§7.4 rule 2), and an adjustment that names no line allocated pro rata (rule 1). If any of these is not what you meant, a sentence in the RFC would settle it and I will rerun.

Two things in `examples.dispute_resolution.json` that you may want to look at before a sponsor does:

- `dispute_record.payment_mandate.exp` is 1790003600 (2026-09-21) while `execution_date` is 2026-11-01, so under the rule order rule 2 decides the line before rule 3, and the determination's reason would be the expiry, not `merchant_canceled_without_completed_adjustment`. Same outcome and amount either way; the epochs look like placeholders (`iat` and the receipts are also 2026-09-21).
- `dispute_determination.factors` carries 3 of the 5 names. §4.5 marks `factors` Required and §12 Q5 fixes the five, but the schema has no `required` inside `factors`, so 3/5 validates.

Record, reader, cases and digests: [`docs/runs/acp-dispute-cold/`](https://github.com/aos-standard/catalog/tree/8258150/docs/runs/acp-dispute-cold). CC0; use any of it.

Disclosure: assisted by AI (Claude). I ran the checks above myself and remain responsible for what is claimed here.
