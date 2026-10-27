---
url: https://github.com/x402-foundation/tsc/issues/4#issuecomment-6455792222
api: https://api.github.com/repos/x402-foundation/tsc/issues/comments/6455792222
created_at: 2026-10-27T23:06:45Z
fetched_at: 2026-10-27T23:07:02Z
body_sha256: 54f1b1715ee050e83138ae7bf23c6857c802de04959be5f481d0a9b573b6a191
note: exact copy of the comment body as served by the GitHub API at fetched_at; the rows in CONDUCT.jsonl hash this whole file
---
@maximusrufus thank you for taking 58 and 59. A rerun of the 87 at `85a310d`, two steps, the first of which is against us:

1. **The verifier frozen for 1.4.1 (v141.3, the 57/57 one), unchanged: 68/87.** 01–59 all agree. The 18 disagreements are each on a rule 1.4.2 introduces (canonical base64, `genTime` form and rounding, independence by key, repeated `key_id`, RFC 3339 stated times). And **76 crashes it**: `committed_at` `2026-13-01T00:00:00Z` reached an unguarded time parse. A verifier that raises on a stranger's input is our defect, whatever the profile says about that input, and it is recorded as such on our side.
2. **v142.1, written from the step-10 rule text (reference not opened): 87/87** on every compared field, and still 57/57 on `bc5a138`. Answer-exposed: v141.3 had been scored on the 87 first, so I knew which vectors each rule touched. A first cut (v142) got 84/87: it compared `committed_at` with the millisecond-rounded `genTime` (66, 68; the vector text says "to the second") and reported a wrongly typed result `id` as `CRITERIA_RESULTS_MISMATCH` instead of the step-1 refusal (77). Both fixed after seeing them, and the addendum says so.

Two readings I fixed that the text leaves open, in case they are worth a sentence: a non-canonical token or criteria file "matches nothing" is reported as the corresponding mismatch, never as a refusal; and `RECEIPT_TIME_UNREADABLE` is raised only for the stated time step 5 actually uses (`issued_utc` always, `committed_at` only when it is the fallback).

Verifiers, runs and hashes beside the earlier ones: [`ADDENDUM-profile142.md`](https://github.com/aos-standard/catalog/blob/9cc7362/docs/runs/work-acceptance-record-cold/ADDENDUM-profile142.md).

Disclosure: assisted by AI (Claude). I ran the checks above myself and remain responsible for what is claimed here.

