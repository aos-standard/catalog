# Anchor pointer, draft 1 — the selector, an EVM form, and the tight bound

**Date:** 2026-10-25. **Status:** a proposal, not a standard. CC0. Follows
[`anchor-pointer-draft0/`](../anchor-pointer-draft0/) and the replies on aeoess/agent-governance-vocabulary#217.
Draft 0 stays as published.

## What changed from draft 0

| | draft 0 | draft 1 | from |
|---|---|---|---|
| anchored bytes inside a larger resource | not expressible | optional `anchored_set.select`; one kind, `line` | babyblueviper1 |
| EVM logs | not defined | `mechanism: "evm-log"`, `claimed` locates the log, no `proof` | giskard09 |
| proof reaching more than one block | not said | `claimed.height` may be any of them; the reader reports `earliest_height`, the tight bound | ogasurfproject-jpg |
| `proof.sha256` | stated | also explained: it pins the bytes when the served proof is upgraded at the same URL; bytes off the branch the reader walks are not read | babyblueviper1, ogasurfproject-jpg |
| member of a batch (inclusion) | — | **open**, left out of the pointer; a separate optional field later | ogasurfproject-jpg |
| finality on EVM chains | — | not in the pointer; the reader returns `not_final` above the chain's `finalized` block | giskard09 |

```json
{"anchor_pointer": "1",
 "anchored_digest": {"alg": "sha-256", "hex": "<64 lowercase hex>"},
 "anchored_set": {"locator": "<pinned>", "select": {"kind": "line", "index": 0}},
 "mechanism": "opentimestamps",
 "proof": {"locator": "<pinned>", "sha256": "<64 lowercase hex>"},
 "claimed": {"chain": "bitcoin", "height": 972677}}
```

```json
{"anchor_pointer": "1",
 "anchored_digest": {"alg": "sha-256", "hex": "<64 lowercase hex>"},
 "mechanism": "evm-log",
 "claimed": {"chain": "eip155:8453", "contract": "0x49fEcA52bC634a9Ab773226D16619deC547794aa",
             "tx": "0x<64 hex>", "log_index": 59, "height": 52987624}}
```

- **`select`, kind `line`:** lines are separated by LF (0x0A). A line's bytes exclude its LF, and nothing else is
  stripped. `index` counts from 0, and an empty segment after a final LF is not a line. With no `select`, the whole
  resource is the anchored bytes.
- **`anchored_set` is optional.** When it is absent, or the reader is not given its bytes, the result says
  `set_checked: false`. That is the EVM vectors' case: they name a digest and no resource.
- **Trust inputs are the reader's:** block headers for Bitcoin, RPC endpoints for EVM chains. `anchored` means the bytes
  existed no later than that block. It says nothing about who made them or whether they are true.

Result codes and their order are in the docstring of `anchor_pointer_check_d1.py`. The new ones are
`unsupported_select` and `select_out_of_range`, plus the `evm-log` codes.

## Vectors here — `vectors.json`, 22, offline

- **AP-01…14:** draft 0's, moved to version `"1"`. AP-05 now names `registry-x`, since `evm-log` is defined.
- **AP-15…19:** babyblueviper1's decision-receipt slot log of 2026-10-22 and its `.ots`, carried as fetched under CC0
  with its owner's permission. 15 is `select` line 0, anchored in block 972677, with the merkle root read from two
  explorers. 16 has no `select`, 17 selects line 1, 18 selects past the last line, and 19 uses an unknown kind.
- **AP-20…22:** the `evm-log` shape, checked offline: a proof present, a chain not in CAIP-2 form, `log_index`
  missing.

## Runs

| file | what | result |
|---|---|---|
| `run_output.txt`, `run.json` | the draft 1 reader on the 22 vectors here | 22/22 |
| `run_nenrin_output.txt`, `run_nenrin.json` | on ogasurfproject-jpg's 3 vectors (horizon-shield `ea658bd`, `workers/hs-ledger/nenrin/anchor-pointer-draft0/vectors.json`, sha256 `14ad86d9…42ea`), draft 0 pointers unchanged | 3/3; entry 120 reports `earliest_height` 972141 under both claimed heights |
| `run_evm_output.txt`, `run_evm.json` | on giskard09's 14 `evm-log` vectors (argentum-core `63711d8`, sha256 `632a3c83…d00d3`), each `input` rewritten as a draft 1 pointer, live RPC `mainnet.base.org` and `arb1.arbitrum.io/rpc` | 14/14 on pass/fail; all four positives final |
| `lax_battery_output.txt` | twelve lax readers, each dropping one check | 12/12 caught. One of them, reporting the claimed height as `earliest_height`, is caught only by NENRIN's entry 120, not by the vectors here |

The other projects' vectors are not copied here: fetch them at those commits. The draft 0 vectors also run unchanged
through the draft 1 reader, 14/14.

**Same author, and order:** the reader and the vectors here are by the same author, so 22/22 only shows they are
consistent. The runs on the other projects' vectors are what test them. `FROZEN.txt` records the reader's sha256. It
was frozen after one run over draft 0's vectors (14/14) and before every run listed above. The builder, the
external runner and the battery were frozen before their runs.

## Open

- **Inclusion of one member in an anchored batch:** the reverse of `select`.
- **Other `select` kinds,** such as a JSON pointer.
- **Other mechanisms,** such as transparency logs, and other EVM events.
- **A finality vector:** a static file cannot encode chain state at read time.
