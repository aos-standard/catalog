---
url: https://github.com/aeoess/agent-governance-vocabulary/issues/217
api: https://api.github.com/repos/aeoess/agent-governance-vocabulary/issues/217
created_at: 2026-10-23T23:26:04Z
fetched_at: 2026-10-23T23:26:28Z
body_sha256: 198c029d594187499df8d01f2857346d33de83564a26c9628bf7400092c4a6a0
note: exact copy of the issue body as served by the GitHub API at fetched_at
---
Following [#177](https://github.com/aeoess/agent-governance-vocabulary/issues/177#issuecomment-6368318983): a proposed form for how a record points at its external anchor, with vectors.

Several projects in #177 anchor digests of their records, each in its own shape: NENRIN batches daily to OpenTimestamps, invinoveritas anchors its ledger hash to Bitcoin, argentum-core anchors `action_ref` to an EVM `AnchorRegistry`, and this catalog stamps a monthly manifest with OpenTimestamps. A reader who wants to check all of them now needs four procedures. The proposal is one small record naming what any such check needs:

```json
{"anchor_pointer": "0",
 "anchored_digest": {"alg": "sha-256", "hex": "<64 lowercase hex>"},
 "anchored_set": {"locator": "<where the anchored bytes can be fetched, pinned>"},
 "mechanism": "opentimestamps",
 "proof": {"locator": "<where the proof bytes can be fetched, pinned>", "sha256": "<64 lowercase hex>"},
 "claimed": {"chain": "bitcoin", "height": 972227}}
```

- `proof.sha256` says which proof is meant, because an OpenTimestamps proof changes bytes when it is upgraded.
- Block headers are an input to the reader, not part of the pointer.
- `anchored` means the bytes existed no later than that block, and nothing about who made them or whether they are true.

**Vectors** ([`docs/runs/anchor-pointer-draft0/`](https://github.com/aos-standard/catalog/tree/a348d35/docs/runs/anchor-pointer-draft0), CC0): 14 vectors built from one real anchor, our 2026-10 manifest in Bitcoin block 972227. The merkle root was read from blockstream.info and from mempool.space, and the two agree. AP-01 is that anchor. Each of the other 13 changes one thing and has one expected result: malformed, unsupported mechanism, set digest mismatch, proof sha mismatch, unparseable proof, a proof of other bytes, pending (calendar only), height not in the proof, header unavailable, root mismatch. A standard-library reader gives 14/14, and eight lax readers, each dropping one check, are all caught. The same author wrote the reader and the vectors, so that only shows they are consistent. Another project's reader is what would test them.

Draft 0 defines only OpenTimestamps on Bitcoin. Whether the field set carries over to an EVM log or a transparency log is the open question. @ogasurfproject-jpg @babyblueviper1 @giskard09, your anchors are the shapes this has to fit. If a field is missing or wrong for yours, that is the answer I'm looking for. Vectors from one of your anchors would test it properly.

Disclosure: assisted by AI (Claude). I ran the checks above myself and remain responsible for what is claimed here.

