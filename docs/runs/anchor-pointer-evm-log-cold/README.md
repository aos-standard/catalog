# Anchor pointer, `evm-log` — a reader written from the vectors' text, run on giskard09's 14 vectors

**Date:** 2026-10-24. CC0. Follows [`anchor-pointer-draft0/`](../anchor-pointer-draft0/) and
aeoess/agent-governance-vocabulary#217.

giskard09 published 14 vectors for an EVM-log anchor (`argentum-core`, `examples/conformance/anchor-pointer-evm-log-v1/`
at `63711d8722aaff2dfb4c26aea64d02d2e0deaf2b`, CC0). `evm_log_pointer_check.py` was written from the `mechanism` block of
that `vectors.json` and the event signature alone. No code from that repository was read. The vectors are not copied here: fetch `vectors.json` at that commit
(sha256 `632a3c8337be990630737a35d1216eb15888097c5ce62d433d806973c2ed00d3`) and run
`python3 -I evm_log_pointer_check.py vectors.json run.json`.

| file | what it is |
|---|---|
| `evm_log_pointer_check.py` | the reader (standard library only). Check order and result codes are in its docstring |
| `keccak_topic0.py` | recomputes the event's topic0, `keccak256("Anchored(bytes32,address,uint256)")`, instead of taking it from the vectors |
| `run_output.txt`, `run.json` | the run, 2026-10-24 04:17Z |

**Result:** pass/fail agrees with the vectors on **14/14**. The recomputed topic0 equals the one in the vectors
(`0xfe2289…8734`).

**RPCs trusted:** `https://mainnet.base.org` (eip155:8453) and `https://arb1.arbitrum.io/rpc` (eip155:42161). For this
mechanism the evidence is a query against the chain, so the result is only as good as those endpoints, the same way the
Bitcoin reader depends on where it took block headers.

**Where the result codes differ from the vectors' `failure_mode`** (pass/fail is the same in every case):

- `destination-001` and `logindex-001` both come out `log_not_found` (no log at the declared `log_index`). The reader does
  not check the transaction's `to`: if `anchor()` is called through another contract, the log is real and `to` is not the
  registry.
- `chain-001` comes out `tx_not_found` on the declared chain.

**Finality.** After the other checks, the reader asks the chain for its `finalized` block and returns `not_final` if the
anchor's block is above it, the role `pending` has for OpenTimestamps. In this run block 52987624 was final (finalized
53012531). A static vector cannot test this.

**What this run does not establish.** That the anchored digest means anything: the vectors test the pointer, not the
digest's preimage. The same author wrote this reader and ran it, so another reader would test it further.
