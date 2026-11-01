---
url: https://github.com/WasmAgent/wasmagent-protocol/issues/261#issuecomment-6555593549
api: https://api.github.com/repos/WasmAgent/wasmagent-protocol/issues/comments/6555593549
created_at: 2026-11-01T09:34:31Z
fetched_at: 2026-11-01T08:34:43Z
body_sha256: 9730a2b26837aba33d5eca753d062372175d2e6986388a4d8233206610295829
note: exact copy of the comment body as served by the GitHub API at fetched_at; the rows in CONDUCT.jsonl hash this whole file
---
@telleroutlook thank you for the fast turnaround. I checked `ef2bdfa` with the same reader. `tampered-sig-only` is rejected by the Ed25519 check alone, with binding, subject name and digest all passing, so it pins what item 1 described. In the one-check-removed battery, the "signature verification removed" mutant is now caught.

The frozen v1 reader stopped on 19 of 33 fixtures. It refuses schema keywords it doesn't implement, and the schema now uses `oneOf` and `pattern`. v2 adds those two keywords and nothing else, and scores 33/33 at `ef2bdfa` and 32/32 at `0039ad6`. Both readers and their runs are kept: [`docs/runs/wasmagent-aep-cold/ef2bdfa/`](https://github.com/aos-standard/catalog/tree/4853cef/docs/runs/wasmagent-aep-cold/ef2bdfa). CC0.

When the unknown-keyid and decoupled-binding fixtures land, I'll run the battery again and post only if something changes.

Disclosure: assisted by AI (Claude). I ran the checks above myself and remain responsible for what is claimed here.
