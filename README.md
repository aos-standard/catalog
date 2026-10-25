# aos-standard/catalog — independent runs of agent-economy specs

This repository publishes **clean-room runs of other projects' published vectors and specifications**. Each run
uses a reader written from the text alone, states what was on screen, freezes the reader before scoring and pins
every input. Corrections are added beside a run, never over it. How it is done: [`docs/runs/METHOD.md`](docs/runs/METHOD.md).

## Runs

| run | target | result |
|---|---|---|
| [`aps-lease-revocation-axes-cold`](docs/runs/aps-lease-revocation-axes-cold/) | APS conformance suite, `lease-revocation-axes` revision 2 | 176/176 calls × profiles; declared variant sets reproduced in three published steps |
| [`work-acceptance-record-cold`](docs/runs/work-acceptance-record-cold/) | work-acceptance-record (x402-foundation/tsc#4), profiles 1.2.1–1.4.1 | 57/57 at `bc5a138`; probes adopted as upstream vectors |
| [`ap2-evidence-pack-cold`](docs/runs/ap2-evidence-pack-cold/) | ap2-evidence-pack (google-agentic-commerce/AP2#338) | 26/26 at 1.5.3; later versions in its addenda |
| [`x402-offer-receipt-cold`](docs/runs/x402-offer-receipt-cold/) | x402 Offer and Receipt extension: JWS vectors (x402#3207) and EIP-712 vectors (x402#3533) | 26/26; OpenSSL 20/20 |
| [`x402-delivery-receipt-cold`](docs/runs/x402-delivery-receipt-cold/) | x402 `delivery-receipt` v0.2.1 | 14/14 |
| [`e6-receipt-to-bill-cold`](docs/runs/e6-receipt-to-bill-cold/) | VeritasActa E6 receipt-to-bill fixture v1.1.0 | 12/12 |
| [`anchor-pointer-evm-log-cold`](docs/runs/anchor-pointer-evm-log-cold/) | giskard09's `evm-log` anchor vectors | 14/14, live RPC |
| [`priorseal-exact-call-matrix-v1`](docs/runs/priorseal-exact-call-matrix-v1/) · [`v1.0.1`](docs/runs/priorseal-exact-call-matrix-v1.0.1-cold-run/) · [`g9–g11`](docs/runs/priorseal-g9-g11-seams-2ff89d8/) | PriorSeal exact-call matrix | see each run |
| [`acceptance-record-cold-27`](docs/runs/acceptance-record-cold-27/) | acceptance-record vectors | 27 vectors |

**Proposals with vectors** (CC0):
- [`anchor-pointer-draft0`](docs/runs/anchor-pointer-draft0/) and [`draft1`](docs/runs/anchor-pointer-draft1/): one form
  for "this record was anchored here", run by other projects on their own anchors (aeoess/agent-governance-vocabulary#217).
- [`jcs-number-vectors`](docs/runs/jcs-number-vectors/): 1001 RFC 8785 number vectors.

## Where other projects took these in

Each line links to the other project's own file or record, pinned to a commit.

| project | what it took in | where |
|---|---|---|
| Agent-Authority-Conformance/aps-conformance-suite | the lease-revocation-axes run, as an interop record (Mode B, author-produced, answer-exposed); README rules added from the run | [`interop/aos-catalog-lra-cold-3e882bc/run-report.md`](https://github.com/Agent-Authority-Conformance/aps-conformance-suite/blob/7141c61/interop/aos-catalog-lra-cold-3e882bc/run-report.md) (PR #188) |
| maximusrufus/work-acceptance-record | first row of the implementations table (57/57); vectors 12b–16 and 50 contributed, CC0; profile 1.3 and 1.4.1 readings | [`README.md`](https://github.com/maximusrufus/work-acceptance-record/blob/8e00300/README.md) |
| robertolocatelli81-dev/ap2-evidence-pack | the clean-room run listed in the README; CHANGELOG points 2–5 from it | [`README.md`](https://github.com/robertolocatelli81-dev/ap2-evidence-pack/blob/fffadff/README.md) · [`CHANGELOG.md`](https://github.com/robertolocatelli81-dev/ap2-evidence-pack/blob/fffadff/CHANGELOG.md) |
| robertolocatelli81-dev/work-acceptance-check-omega | our proposed vectors carried and run; probe cited | [`README.md`](https://github.com/robertolocatelli81-dev/work-acceptance-check-omega/blob/21b2c3c/README.md) |
| maximusrufus/agentic-commerce-protocol (ACP SEP #303) | §7.4a requirement 5, the time-anchor fields, credited to nmatt1 and Tetsurohhori | [`rfcs/rfc.dispute_resolution.md`](https://github.com/maximusrufus/agentic-commerce-protocol/blob/4c05598/rfcs/rfc.dispute_resolution.md) (agentic-commerce-protocol#316) |
| CNSLabs/x402-acceptance-record | probes behind its header, timestamp-form and completeness-input rules | [`NOTICE.md`](https://github.com/CNSLabs/x402-acceptance-record/blob/ad53b54/NOTICE.md) |
| probityai/agent-evidence-vectors | `anchors_verify.py` vendored for its anchor-stream vectors | [`vectors-anchor-stream/README.md`](https://github.com/probityai/agent-evidence-vectors/blob/afe537e/vectors-anchor-stream/README.md) |
| LembaGang/receipt-verify | a vector citing the binding rule from modelcontextprotocol#3004 | [`n25-boundary-prefix-only-no-position.json`](https://github.com/LembaGang/receipt-verify/blob/6434245/fixtures/tersign-evidence-record-conformance/1075ca65b4495212cf49a891e63e07f2cf48acf8/vectors/n25-boundary-prefix-only-no-position.json) |

Being listed by another project is not an endorsement by it, and agreement between two readers is not a
certification.

## Records

| file | what it is |
|---|---|
| [`CONDUCT.jsonl`](CONDUCT.jsonl) | **Verification conduct ledger:** an append-only record of our runs, our self-found defects, and the breaks and refutations others found. Free. **Not a KPI**: the row count is not a score. How to read it: [`CONDUCT.md`](CONDUCT.md) |
| [`docs/runs/ledger-timestamps/`](docs/runs/ledger-timestamps/) | a monthly manifest of this shelf, stamped with OpenTimestamps (2026-10: Bitcoin block 972227) |
| [`docs/evidence/`](docs/evidence/) | an exact copy of each public comment the runs were reported in, with the body's sha256 |
| [`ANCHORS.jsonl`](ANCHORS.jsonl) | weekly SHA-256 anchors for private assets, with the public verifier [`anchors_verify.py`](anchors_verify.py) ([how to run](ANCHORS_VERIFY.md)); single-file `curl` distribution, pinned with tag [`anchors-verify-v0.12`](https://github.com/aos-standard/catalog/releases/tag/anchors-verify-v0.12). Runnable cases: [`docs/cases/`](docs/cases/) |
| [`t2_constructions.py`](t2_constructions.py) | **T2 construction set:** ten mutations plus a baseline (not "nine"; the miscount is corrected), with regenerated sidecars. See [`T2_CONSTRUCTIONS.md`](T2_CONSTRUCTIONS.md); pinned with tag [`anchors-verify-v0.6`](https://github.com/aos-standard/catalog/releases/tag/anchors-verify-v0.6) |

## Catalog files

| file | purpose |
|---|---|
| [`catalog.json`](catalog.json) | product entries (install, pricing, MCP endpoints); payment instructions in `products[].payment` are a locator only, not a call to action |
| [`governance.json`](governance.json) | structure audit evidence, measured at export time |
| [`precedents.json`](precedents.json) | public summaries of business-pattern precedents |
| [`attestations/`](attestations/) | signed audit badges for MCP servers that opt in via [badge application](https://github.com/aos-standard/mcp-blast-radius/issues/new?template=badge-application.yml); free, opt-in, 90-day ([criteria](https://github.com/aos-standard/mcp-blast-radius/blob/main/BADGE_CRITERIA.md)) |

Maintainer: Tetsuroh Hori (Tetsurohhori)
