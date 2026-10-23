---
url: https://github.com/aeoess/agent-governance-vocabulary/issues/177#issuecomment-6376640583
api: https://api.github.com/repos/aeoess/agent-governance-vocabulary/issues/comments/6376640583
created_at: 2026-10-23T23:16:19Z
fetched_at: 2026-10-23T23:18:16Z
body_sha256: 71393875c3c1c6c80b18c4bd1a5c87da8d84abc4c2295cb19dc639fe5c13a43e
note: exact copy of the comment body as served by the GitHub API at fetched_at; the row in CONDUCT.jsonl hashes this whole file
---
@aeoess thanks. The cold run of #180 at `b745d25` is filed as Agent-Authority-Conformance/aps-conformance-suite#186 (Mode B, author-produced): 176/176 calls across the four profiles, 11/11 non-diagnostic checkpoints. The declared mutant sets are reproduced too, but for four of them only on a second reading, and the report says which ones and why.

What `aos-standard/catalog` is, for the follow-up: a public shelf of clean-room runs against other projects' published vectors. Each run is written from the spec text, frozen by sha256 before its first scored run, labelled for what was on screen, and kept with any later correction beside it rather than over it. A conduct ledger (`CONDUCT.jsonl`) records each run and post, and a manifest of the shelf is stamped monthly with OpenTimestamps (2026-10: Bitcoin block 972227).

Where it touches the map, as a runner node, not a protocol:

- APS `lease-revocation-axes`: the run above.
- work-acceptance-record: 57/57 at `bc5a138`, and vector 50 came from our probe.
- PriorSeal exact-call matrix v1 and v1.0.1: cold runs on the shelf.

The anchor-pointer proposal will be a separate issue with vectors, as you suggested.

