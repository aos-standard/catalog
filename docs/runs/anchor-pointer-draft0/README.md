# Anchor pointer, draft 0 — a shared form for "this record was anchored here", with vectors

**Date:** 2026-10-24. **Status:** a proposal, not a standard. CC0.

Several projects anchor a digest of their records to Bitcoin or another append-only store, each in its own shape. An
anchor pointer is a small record that names the five things a reader needs to check any of them:

```json
{"anchor_pointer": "0",
 "anchored_digest": {"alg": "sha-256", "hex": "<64 lowercase hex>"},
 "anchored_set": {"locator": "<where the anchored bytes can be fetched, pinned>"},
 "mechanism": "opentimestamps",
 "proof": {"locator": "<where the proof bytes can be fetched, pinned>", "sha256": "<64 lowercase hex>"},
 "claimed": {"chain": "bitcoin", "height": 972227}}
```

- `anchored_digest` is the value the proof commits to, and the anchored bytes must hash to it.
- `proof.sha256` names which proof is meant: an OpenTimestamps proof changes bytes when it is upgraded from calendar
  commitments to a Bitcoin attestation.
- `claimed` is the block the pointer says the proof reaches. Block headers are an input to the reader, not part of the
  pointer: the reader takes merkle roots from a source it trusts.

`anchored` means the bytes existed no later than that block. It does not say who made them, or whether their content is
true.

## Reader and result codes

`anchor_pointer_check.py` (standard library only) implements draft 0 for `opentimestamps` with Bitcoin. It runs the checks
in a fixed order and returns the first failure. The order and codes are in its docstring: `malformed`,
`unsupported_mechanism`, `set_digest_mismatch`, `proof_sha_mismatch`, `proof_unparseable`, `proof_for_other_digest`,
`pending`, `height_not_in_proof`, `header_unavailable`, `root_mismatch`, `anchored`.

## Vectors — `vectors.json`, 14

Built by `build_vectors.py` from one real anchor: this catalog's 2026-10 manifest
(`docs/runs/ledger-timestamps/2026-10/`, at commit `64b52df`), sha256 `f046ca25…57c`, in Bitcoin block 972227.
The block's merkle root (`14bc2bbf…fc7b`) was read from blockstream.info and from mempool.space, and the two agree.
`AP-01` is that anchor. Each of `AP-02`…`AP-14` changes one thing, and its `expected` is fixed by construction. The
anchored bytes and the proofs travel as base64 in `blobs`, with their sha256 values in `blob_sha256`.

| result | vectors |
|---|---|
| anchored | AP-01 |
| malformed | AP-02 uppercase hex, AP-03 `claimed` missing, AP-04 height as a string |
| unsupported_mechanism | AP-05 |
| set_digest_mismatch | AP-06 one hex digit of the manifest changed |
| proof_sha_mismatch | AP-07 pointer names the pending proof, the upgraded one is supplied |
| proof_unparseable | AP-08 proof truncated |
| proof_for_other_digest | AP-09 a valid proof of the manifest, offered for other bytes |
| pending | AP-10 the proof before upgrade |
| height_not_in_proof | AP-11 claimed one block later |
| header_unavailable | AP-12 |
| root_mismatch | AP-13 wrong header, AP-14 one byte of the proof's path flipped |

## Runs here

- `run_output.txt`: 14/14 (`run.json`). **The same author wrote the reader and the vectors**, so this shows only that the two
  are consistent. Another project's reader is what would test them.
- `lax_battery_output.txt`: eight lax readers, each dropping one check, and every one is caught by at least one vector.
  `lax_battery.py` says how a dropped check is modelled.
- `FROZEN.txt`: the reader and the builder were frozen before the first scored run.

## Not covered

Other mechanisms (EVM logs, transparency logs) and other chains. Only the field set is meant to carry over. Neither
inclusion of the anchored bytes in a larger published set nor locators that are not pinned is checked. Header retrieval
is left to the reader.
