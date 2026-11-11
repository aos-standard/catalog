---
url: https://github.com/agentic-commerce-protocol/agentic-commerce-protocol/pull/316#issuecomment-6809800426
api: https://api.github.com/repos/agentic-commerce-protocol/agentic-commerce-protocol/issues/comments/6809800426
created_at: 2026-11-11T23:35:15Z
fetched_at: 2026-11-11T23:39:04Z
body_sha256: 3c6008a4431222b14f0c82e93ad6c5c1c4da0aa7f2634fcb04b102d9595f2993
note: comment body as served by the API, exact bytes below the second rule. Record: docs/runs/acp-dispute-cold/harness-7cab286/ (e5fbe9c)
---
@maximusrufus a possible next step for the cases, only if you and the maintainers want one. `validate-consistency.js` checks that each case has the right shape. It cannot check the decisions, because the repository holds no implementation to run them against.

I wrote a harness for that, so this is something to look at rather than an offer: [`harness-7cab286/`](https://github.com/aos-standard/catalog/tree/e5fbe9c/docs/runs/acp-dispute-cold/harness-7cab286). `scripts/run_dispute_conformance.js` gives each case's `input` to a command named in `DISPUTE_PROVIDER_CMD`, reads the JSON it prints, and compares only the keys the case's `expect` names. It holds no reference implementation. It uses the Node standard library only, like `validate-consistency.js`.

Run on `conformance_cases.json` exactly as it is in your branch at `7cab286`:

- the cold-read reader written against the RFC at `089d8f9`: **33 of 33**
- the same author's earlier reader, written against `db04871`: **27 of 33**. It fails E1, E2, E4, E5, E6 and E7, the cases for the text added at `089d8f9` (rule 3's adjustment types, `line_amount_missing`, all five factors, `opened_at`), and passes the rest.

So an implementation that follows older text fails the cases tied to the sentences that changed. Both readers and the expectations have the same author, so these runs show that the harness works, not that the expectations are right.

Two ways it could sit in the repository:

1. **Harness only.** CI keeps running only the shape check. An implementer runs the harness against their own provider and reports "N of 33 at commit X". Nothing in the repository claims to be right.
2. **Harness plus a reference evaluator in CI.** A change to Section 7.4 or 4.4a then fails CI until the cases or the text agree. The cost is a second reading of the RFC in code, which someone has to keep in step with the text.

I would lean to 1 while the SEP is in review, and leave 2 to the maintainers. The script is CC0, so take it as is, change it, or leave it.

Disclosure: assisted by AI (Claude). I ran the checks above myself and remain responsible for what is claimed here.
