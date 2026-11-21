# Independent runs and where they stand

One row per clean-room run in this folder that was reported in a public thread. Thread state, and whether anyone
replied after our last post, were measured with the GitHub API at **2026-11-21T12:24:18Z** (`STATUS_20261121.json`,
made by `status_measure.py`). "Taken in" lists only what the other project put in its own files, and says whether that
change is merged there or still proposed. Being listed is not an endorsement. Agreement between two readers is not a
certification.

| Record | Target (spec, version) | Result | Thread | State (2026-11-21) | Reply after our last post | Taken in |
| --- | --- | --- | --- | --- | --- | --- |
| [`x402-delivery-receipt-cold`](x402-delivery-receipt-cold/) | x402 `delivery-receipt` v0.2.1; vectors at `d9027a5` | 14/14; rerun 25/25 | [x402#3758](https://github.com/x402-foundation/x402/issues/3758), [x402#4298](https://github.com/x402-foundation/x402/pull/4298) | issue open; PR open, not merged | #4298: yes (2026-11-18) | **proposed**: 7 negative vectors in #4298, credited in its Appendix B |
| [`x402-lnbtc-cold`](x402-lnbtc-cold/) | x402 `exact` on `lnbtc`, shared vectors (PR #3727 at `63d5640`; #4266 at `dc77b23`) | blind 194/199; reader v2 203/206 | [x402#3727](https://github.com/x402-foundation/x402/pull/3727), [x402#4266](https://github.com/x402-foundation/x402/pull/4266) | both PRs open, not merged | #3727: yes (2026-11-13); #4266: none | **proposed**: #4266 (draft, stacked on #3727) is a follow-up written from our run, as its description says |
| [`x402-http-headers-cold`](x402-http-headers-cold/) | x402 HTTP header vectors (PR #4066 at `c3e23c9`) | blind 16/16 | [x402#4066](https://github.com/x402-foundation/x402/pull/4066) | PR open, not merged | yes (2026-11-18) | **proposed**: five candidate vectors adopted into the PR branch |
| [`work-acceptance-record-cold`](work-acceptance-record-cold/) | work-acceptance-record, profiles 1.2.1–1.4.1 | 57/57 at `bc5a138` | [tsc#4](https://github.com/x402-foundation/tsc/issues/4), [work-acceptance-record#8](https://github.com/maximusrufus/work-acceptance-record/issues/8) | both issues open | tsc#4: yes (2026-11-15); #8: yes (2026-11-15) | **merged** in maximusrufus/work-acceptance-record: implementations table row, vectors 12b–16 and 50 ([`README.md`](https://github.com/maximusrufus/work-acceptance-record/blob/8e00300/README.md)) |
| [`acp-dispute-cold`](acp-dispute-cold/) | ACP Dispute Resolution Extension (SEP #303, PR #316 at `db04871`) | 26 cases; two notes | [ACP#316](https://github.com/agentic-commerce-protocol/agentic-commerce-protocol/pull/316) | PR open, not merged | yes (2026-11-15) | **proposed**: §7.4a requirement 5 credited in the PR branch ([`rfc.dispute_resolution.md`](https://github.com/maximusrufus/agentic-commerce-protocol/blob/4c05598/rfcs/rfc.dispute_resolution.md)) |
| [`ap2-evidence-pack-cold`](ap2-evidence-pack-cold/) | ap2-evidence-pack 1.5.3 (AP2#338) | 26/26 | [AP2#338](https://github.com/google-agentic-commerce/AP2/issues/338) | issue open | yes (2026-10-25) | **merged** in robertolocatelli81-dev/ap2-evidence-pack: README and CHANGELOG ([`README.md`](https://github.com/robertolocatelli81-dev/ap2-evidence-pack/blob/fffadff/README.md)) |
| [`aps-lease-revocation-axes-cold`](aps-lease-revocation-axes-cold/) | APS conformance suite, `lease-revocation-axes` revision 2 | 176/176 | [aps-conformance-suite#186](https://github.com/Agent-Authority-Conformance/aps-conformance-suite/issues/186) | issue closed 2026-10-27 | yes (2026-10-27) | **merged**: interop record, PR #188 merged 2026-10-24 ([`run-report.md`](https://github.com/Agent-Authority-Conformance/aps-conformance-suite/blob/7141c61/interop/aos-catalog-lra-cold-3e882bc/run-report.md)) |
| [`iab-web-bot-auth-cold`](iab-web-bot-auth-cold/) | IAB Web Bot Auth profile (PR #4 at `3bcfb96`) | 91/91; 3 proposed vectors | [iab-agentic-primitives#4](https://github.com/IABTechLab/iab-agentic-primitives/pull/4) | PR open, not merged | none | — |
| [`w3c-atp-did-cold`](w3c-atp-did-cold/) | W3C ATP `did:atp` identifier rules, vectors at `8e4f7ac` | 11/11; 4 proposed additions | [atp#8](https://github.com/w3c-cg/atp/issues/8) | issue open | yes (2026-11-18) | — (additions to go through the CG's contribution process) |
| [`a2c-smcp-conformance-cold`](a2c-smcp-conformance-cold/) | A2C-SMCP conformance vectors at `1a81dee` | blind 81/81 | [a2c-smcp-protocol#78](https://github.com/A2C-SMCP/a2c-smcp-protocol/issues/78) | issue open (ours) | none | — |
| [`agent-custody-receipt-v0.2-cold`](agent-custody-receipt-v0.2-cold/) | agent-custody receipt v0.2, published conformance vectors | 97/97 on the verdict; 4/4 audit | [agent-custody#185](https://github.com/svayatta/agent-custody/issues/185) | issue open | yes (2026-11-02) | — |
| [`agent-did-rfc001-cold`](agent-did-rfc001-cold/) | Agent-DID RFC-001 fixtures at `37a3190` | blind 46/46 | [agent-did#127](https://github.com/edisonduran/agent-did/issues/127) | issue open (ours) | none | — |
| [`openab-computer-conformance-cold`](openab-computer-conformance-cold/) | openab-computer conformance vectors at `8094277` | third reader; see record for per-file results | [openab-computer#24](https://github.com/openabdev/openab-computer/issues/24) | issue closed 2026-11-07 | yes (2026-11-07) | — |
| [`otc-effect-evidence-cold`](otc-effect-evidence-cold/) | autonomous-ot-control federation fixtures v2 | 12/12, 10/10; 21-mutant battery | [autonomous-ot-control#39](https://github.com/darklordVirtual/autonomous-ot-control/pull/39) | PR open, not merged | none | **proposed**: a row for this catalog in the PR |
| [`wasmagent-aep-cold`](wasmagent-aep-cold/) | AEP conformance corpus at `0039ad6` | blind 32/32 | [wasmagent-protocol#261](https://github.com/WasmAgent/wasmagent-protocol/issues/261) | issue closed 2026-11-01 | yes (2026-11-01) | — |
| [`e6-receipt-to-bill-cold`](e6-receipt-to-bill-cold/) | VeritasActa E6 receipt-to-bill fixture v1.1.0 | 12/12 | [agent-governance-vocabulary#177](https://github.com/aeoess/agent-governance-vocabulary/issues/177) | issue open (active) | yes (2026-11-18) | — |
| [`anchor-pointer-evm-log-cold`](anchor-pointer-evm-log-cold/) | giskard09's `evm-log` anchor vectors | 14/14, live RPC | [agent-governance-vocabulary#217](https://github.com/aeoess/agent-governance-vocabulary/issues/217) | issue open | yes (2026-10-29) | — |
| [`wimse-http-signature-cold`](wimse-http-signature-cold/) | IETF WIMSE HTTP signature test vectors (draft-miao-…-00) | 26/26 applicable of 29; 10 proposed vectors | [FG-TIDA/themes#66](https://github.com/FG-TIDA/themes/issues/66) | issue open | not yet posted | — |

"Reply after our last post" counts any human comment after our last comment, or after our opening post when the
thread is ours. It does not say the reply was addressed to us. Each row's record has the details.

**Proposed** means the change is in the other project's open PR or branch, and not yet in its default branch.
**Merged** means it is in the default branch of the repository named.

This table does not cover every folder. Records without a thread of their own (PriorSeal runs,
`acceptance-record-cold-27`, the anchor-pointer drafts, `jcs-number-vectors`, `ledger-timestamps`) are left out. The
README's Runs table lists every folder.
