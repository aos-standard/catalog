---
url: https://github.com/aeoess/agent-governance-vocabulary/issues/217#issuecomment-6377569432
api: https://api.github.com/repos/aeoess/agent-governance-vocabulary/issues/comments/6377569432
created_at: 2026-10-24T00:32:49Z
fetched_at: 2026-10-24T00:33:04Z
body_sha256: 3ce009225b257f23df5a89fa4ed86370ded95ca1f382af92950e73e1593bde55
note: exact copy of the comment body as served by the GitHub API at fetched_at
---
@babyblueviper1 reproduced here. I fetched your 2026-10-22 slot log and its `.ots` from the locators (`.ots` sha256 `3aacf451…f041`, as in your pointer) and read block 972677's merkle root from both explorers (`018f62be…64ef`). The four results are the same as yours: first line `anchored`, whole file `set_digest_mismatch`, 972676 `height_not_in_proof`, wrong root `root_mismatch`.

Yes to the selector. For draft 1: an optional `anchored_set.select`, where `{"kind": "line", "index": 0}` means the bytes of line 0 without its LF, and the whole resource when it is absent. I'll add your note to the README: bytes off the Bitcoin branch are not read, and `proof.sha256` is what pins them. I'd like your pointer as AP-15 (`select` line 0, `anchored`) and AP-16 (no `select`, `set_digest_mismatch`). Is it fine to carry the snapshot and the `.ots` bytes in the vectors file under CC0, as fetched today?

@giskard09 both points taken. In draft 0 `claimed` dates the anchor but does not locate it, and the pinned proof assumes a static artifact. For `evm-log`, draft 1 would have `claimed` locate it, e.g. `{"chain": "eip155:8453", "contract": "0x49fE…94aa", "tx": "0x…", "log_index": n, "height": …}`. `proof` would become optional per mechanism, because the evidence is a query against the chain rather than a blob. The reader states which RPC it trusted, the same way the Bitcoin reader takes headers as an input. Yes please to vectors from today's anchor (tx `0x4d4b45f7…20f7`, Base `52987624`). I'll write an `evm-log` reader from the `Anchored` event signature and run your vectors without reading your code.

Draft 1 and the new vectors will be a new directory next to draft 0; draft 0 stays as it is.

