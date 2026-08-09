# AOS Public Catalog

Machine-readable product catalog and trust artifacts for [AOS-v0.1](https://github.com/aos-standard/AOS-spec) tools.

| File | Purpose |
|------|---------|
| [`catalog.json`](catalog.json) | Product entries (install, pricing, MCP endpoints) |
| [`governance.json`](governance.json) | Structure audit evidence (measured at export time) |
| [`precedents.json`](precedents.json) | Public summaries of business-pattern precedents |
| [`ANCHORS.jsonl`](ANCHORS.jsonl) | Weekly SHA-256 anchors for private assets |
| [`anchors_verify.py`](anchors_verify.py) | **Public URL verifier** for ANCHORS + digest sidecar ([how to run](ANCHORS_VERIFY.md)) — **single-file `curl` distribution**; pin with tag [`anchors-verify-v0.1`](https://github.com/aos-standard/catalog/releases/tag/anchors-verify-v0.1) (not PyPI) |
| [`attestations/`](attestations/) | **Signed audit badges** for MCP servers that opt in via [badge application](https://github.com/aos-standard/mcp-blast-radius/issues/new?template=badge-application.yml) |

**Audit badge program:** Free, opt-in, 90-day attestations — see [mcp-blast-radius BADGE_CRITERIA.md](https://github.com/aos-standard/mcp-blast-radius/blob/main/BADGE_CRITERIA.md).
