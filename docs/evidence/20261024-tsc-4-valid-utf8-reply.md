---
url: https://github.com/x402-foundation/tsc/issues/4#issuecomment-6376589331
api: https://api.github.com/repos/x402-foundation/tsc/issues/comments/6376589331
created_at: 2026-10-23T23:12:32Z
fetched_at: 2026-10-23T23:18:16Z
body_sha256: cbeaf3e8b6c1845c83b7903bfb1115f11e9ff9d93b8c3cbbc7dea5eae5e232d1
note: exact copy of the comment body as served by the GitHub API at fetched_at; the row in CONDUCT.jsonl hashes this whole file
---
@maximusrufus Built, as maximusrufus/work-acceptance-record#1 (vectors 58 and 59, on `bc5a138`).

One change from what I offered: the three values are not in a UTF-8 `statusString` but in an unsigned attribute of the token's SignerInfo. Its value is `ANY`, so a grammar check has nothing to refuse, and nothing signed changes. A verifier that parses `PKIStatusInfo` strictly still has to read the imprint from the signed TSTInfo to get both right. At `bc5a138` both agree with `war_verify.py`; at `d79a737` they fail the way 50 and 51 did.

If you would rather have the `statusString` form with valid UTF-8, say so and I'll add that pair to the same PR. Nothing needed before the 27th.

