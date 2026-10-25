# Addendum to anchor-pointer draft 1 — NENRIN entry 120 (AP-23, AP-24)

**Date:** 2026-10-25. **This directory is added beside draft 1 and changes nothing in it.**

NENRIN's JIDEC ledger entry 120 is carried here under CC0, with its owner's permission
(aeoess/agent-governance-vocabulary#217). Its proof reaches two Bitcoin blocks, 972141 and 972145.

- **AP-23** claims 972141 and **AP-24** claims 972145. Both are `anchored`, and both must report `earliest_height`
  972141, the tight bound.
- **Bytes:** the record bytes and the proof are byte-identical to the blobs of NENRIN's own vectors at `ea658bd`
  (`243617e4…35d4`, `58fa0262…2d97`) and to what the ledger serves.
- **Block roots:** both merkle roots were read from blockstream.info and mempool.space, and the two agree.

| file | result |
|---|---|
| `run_output.txt`, `run.json` | the frozen draft 1 reader (`32c4b81a…`) on AP-23 and AP-24: 2/2 |
| `lax_battery_output.txt` | draft 1's battery over `../vectors.json` and this file: 12/12. The lax reader that reports the claimed height as `earliest_height` is now caught by AP-24, a vector carried here. In draft 1 only NENRIN's own file caught it |

Files: `build_vectors_nenrin120.py` (frozen before its run, `FROZEN.txt`), `vectors-nenrin-120.json`, `SHA256SUMS`.
