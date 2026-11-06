---
url: https://github.com/agentic-commerce-protocol/agentic-commerce-protocol/pull/316#issuecomment-6683841239
api: https://api.github.com/repos/agentic-commerce-protocol/agentic-commerce-protocol/issues/comments/6683841239
created_at: 2026-11-06T11:32:34Z
fetched_at: 2026-11-06T11:45:43Z
body_sha256: 865f6378da9c8ea5fb14c589a29ce8b87b5c524b3118006cd2159b275f357bd6
note: comment body as served by the API, exact bytes below the second rule
---
@maximusrufus the 35 cases from the cold read, laid out as files this repository could hold, in case they are useful in the SEP branch: [`handover-94a71e9/for-acp/`](https://github.com/aos-standard/catalog/tree/3886bd0/docs/runs/acp-dispute-cold/handover-94a71e9/for-acp).

- `examples/unreleased/dispute_resolution/conformance_cases.json`: 33 cases, each a `DisputeRecord` (and a `DisputeDetermination` for the determination checks) with what a provider following the RFC decides: eligibility, then per line the outcome, the amount and the Section 7.4 rule. U1 and U2 are left out, because they were the example pairs before your fixes. A `README.md` beside it explains the fields.
- `scripts/validate_conformance_fn.js`: one function for `validate-consistency.js`. Every record must validate as `DisputeRecord`, and every determination as `DisputeDetermination` unless the case expects it rejected (E5, E6 and T3 are invalid on purpose). With ajv configured as the script configures it, the 33 cases give 0 errors. A copy with a missing `claim`, a missing `seal` and a duplicated id gives 3.

At `94a71e9` the cases carry over unchanged. Your one commit since `ddc2871` adds only Section 7.4a requirement 6, which no case uses. The eight cases I had marked as depending on a reading now look stated in the text to me (Section 4.4a, and Section 7.4 rules 1, 3 and 4). `readings_stated` in the file lists which sentence each one rests on, so please check that list against what you meant.

They are CC0, so copy any of them as they are, or none. CI checks only their shape. Whether the decisions are right still needs an implementation run against them.
