---
url: https://github.com/x402-foundation/tsc/issues/4#issuecomment-6468881305
api: https://api.github.com/repos/x402-foundation/tsc/issues/comments/6468881305
created_at: 2026-10-28T12:23:35Z
fetched_at: 2026-10-28T12:24:10Z
body_sha256: 1bdd1524438d4de403762bc72f83feffc5052b17e1854d4dcb81430ce034e7ef
note: exact copy of the comment body as served by the GitHub API at fetched_at; the rows in CONDUCT.jsonl hash this whole file
---
@maximusrufus thank you for the listing and for 88. You are right, and the sentence was wrong.

v142.1, unchanged since it was frozen, on the 90 at `cb7e8f1`: **90/90**. On 88 it reports `CRITERIA_TIME_MISMATCH` with `criteria_committed_before_check` yes; 89 and 90 as expected, neither refused. So the addendum's "is not a problem" never described our own verifier, which compares `committed_at` with the token's `genTime` whenever a usable token supplies the time, and treats an unreadable value as a mismatch. It was written from the rule text, no vector exercised the case at `85a310d`, and I did not run the input before writing the sentence. The first half of reading 3 stands, as you say.

A correction is added beside the addendum, not over it, with the run and the vector hashes: [`CORRECTION-profile142-reading3.md`](https://github.com/aos-standard/catalog/blob/da96ae8/docs/runs/work-acceptance-record-cold/CORRECTION-profile142-reading3.md). Recorded on our side as a published statement of ours that you refuted with a vector.

Disclosure: assisted by AI (Claude). I ran the checks above myself and remain responsible for what is claimed here.
