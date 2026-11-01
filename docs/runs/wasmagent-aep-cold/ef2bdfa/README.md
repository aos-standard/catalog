# Addendum: the corpus after PR #262 (`ef2bdfa`)

The blind run in [`../`](../) (reader v1, 32/32 at `0039ad6`) reported four readings the text left open and five things
the corpus did not pin. The maintainer answered on #261 (comment 6555314789) and merged PR #262 at `ef2bdfa` the same day:

| From the record | In `ef2bdfa` |
| --- | --- |
| R1 predicate, subject digest, canonical JSON | stated in `IMPLEMENTER.md`; canonical JSON is RFC 8785 |
| R2 subject name | stated |
| R3 `prev_record_hash` | stated, and added to `aep-record.schema.json` (`oneOf`: 64-hex string or null) |
| 1. no fixture fails on the signature itself | `dsse/tampered-sig-only.json` (last signature byte flipped, own key `sig-tampered-verify-key-01`), adequacy label `L2-sig-only` |
| historical path in the manifest | fixed |
| 2.–5. | noted on #261 to be tracked separately; not in this PR |

## Rerun

The frozen v1 reader raises on schema keywords it does not implement, by design, and it stopped on 19 of 33 fixtures
because the schema now uses `oneOf` and `pattern` (`runs/run_ef2bdfa_v1.json`). Reader v2 adds those two keywords and
nothing else (edit E1 in `FROZEN.txt`).

| Run | Result |
| --- | --- |
| v2 on `ef2bdfa` (33 fixtures) | **33/33**; structural 33/33, semantic 33/33, authenticity 17/17, chain 7/7 |
| v2 on `0039ad6` (32 fixtures) | 32/32, the same as v1 |
| `tampered-sig-only` | rejected by the Ed25519 check alone (`signature:ed25519`); binding, subject name and digest pass |
| mutant battery on `ef2bdfa` | 13 of 32 survive (15 at `0039ad6`): A3, signature verification removed, is now caught by the new fixture; S5, schema `type` not checked, is now caught through the `oneOf` branches |

The other survivors are the items the maintainer listed for later fixtures (unknown keyid, the coupled binding checks,
the legacy field on the re-signed fixtures, two subjects, the count with a floor). The maintainer's reply says item 4
is intentional (the re-signed fixtures test legacy-field handling) and that a corpus note will say so. CC0.
