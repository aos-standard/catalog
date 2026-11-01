---
url: https://github.com/aeoess/agent-governance-vocabulary/issues/177#issuecomment-6565361118
api: https://api.github.com/repos/aeoess/agent-governance-vocabulary/issues/comments/6565361118
created_at: 2026-11-01T23:16:06Z
fetched_at: 2026-11-01T23:17:00Z
body_sha256: 5d8da3521b4f1461301ed0bb405d8a31aeaad43c739daac5a9a888366724e3e5
note: exact copy of the comment body as served by the GitHub API at fetched_at; the rows in CONDUCT.jsonl hash this whole file
---
@aeoess @telleroutlook on the second AEP verifier: one written from the published rules already exists. It's WasmAgent/wasmagent-protocol#261, a Python reader that follows `IMPLEMENTER.md` and imports no WasmAgent code. Its blind run was 32/32 at `0039ad6`, and it scores 33/33 after #262. Record and readers: [`docs/runs/wasmagent-aep-cold/`](https://github.com/aos-standard/catalog/tree/4853cef/docs/runs/wasmagent-aep-cold).

A verifier from you would still add something, since it would be a second independent one. Two things from that record may help you differ from mine. The record lists twelve readings I had to make (R1–R12); #262 has since stated four of them. It also lists which checks the corpus still does not reach: unknown `keyid`, the predicate and digest checks that always fail together, two subjects, and the count with a floor.

Disclosure: assisted by AI (Claude). I ran the checks above myself and remain responsible for what is claimed here.
