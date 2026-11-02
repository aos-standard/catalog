# A2C-SMCP conformance vectors at `1a81dee`: an independent reader from the spec text, blind 81/81

The protocol repository hosts byte-exact data vectors that every SDK must pass (`conformance-tests.md` §2.7, §2.8 and the
BundleID section of `data-structures.md`). The two SDKs that run them are the reference implementations. This record
is a third reader, written from the normative text without opening either SDK, and then scored once on the vectors.

Text used: `data-structures.md` (BundleID model, connection-identity), `guides/computer-mcp-config-guide.md`
(environment variable naming), `blob-transfer.md` (`canonical_path`), `conformance-tests.md` §2.7/§2.8, and each fixture's
`algorithm` block, which the spec says must agree with the body.

## First blind run (reader v1, frozen before scoring)

| Vector file | Agreement |
| --- | --- |
| `bundle_id_conformance_vectors.json` | **16/16** |
| `env_segment_conformance_vectors.json` | **16/16** |
| `canonical_path_conformance_vectors.json` | **49/49** |

The mismatch list is empty. `auth_error_conformance_vectors.json` is not scored: §4.8 requires a real MCP server over a real
transport. Answer exposure: none of the expected values, ids or descriptions was seen before the freeze. The inputs and
the `algorithm` blocks were. Readings the text left open are named A1–A3 in the reader.

## What the vectors do not pin: one rule changed at a time

`reader/mutants.py` changes one rule of the frozen reader and reruns the vectors (`runs/mutants_1a81dee_v1.json`).
34 of 42 mutants are caught. The 8 that keep 81/81 fall into two groups.

**Rules no vector reaches** (a different SDK could get them wrong and still pass):

1. **Trimming a leading or trailing `-` in `normalize_name`.** Step 1.3 trims `[_-]`. No vector name begins or ends with `-`,
   so an implementation that trims only `_` passes. `-lead`, `trail-` or `-_x_-` would pin it.
2. **Argument order in the connection identity.** The text says `args` keep their order. Every fallback vector has at
   most two arguments, and the two-argument one (`["-y", "everything"]`) is already sorted, so an implementation that
   sorts `args` passes. `["b", "a"]` under an empty name would pin it.
3. **Five of the seven reserved characters in Windows components.** The vectors cover `?` and `:` (the stream form).
   An implementation that rejects only those two passes. `<`, `>`, `|`, `"` and `*` are not reached.
4. **An explicit `bundle_id` is taken as is.** The only explicit value, `custom_id`, is unchanged by normalization, so an
   implementation that normalizes explicit values passes. This is minor, since the text makes an invalid explicit
   value a configuration error, outside the vectors.

**Rules whose outcome a later step always decides** (not a gap in the vectors; noted so nobody adds a vector expecting
them to matter):

5. **Iterating by code point in `normalize_name`.** Iterating UTF-8 bytes gives the same `bundle_id` for every input,
   because every non-ASCII byte becomes `_` and runs of `_` are then folded. The code-point MUST is observable in
   `ENV_SEGMENT` (which does not fold, and the CJK and astral vectors pin it) but not in `normalize_name`.
6. **Rejecting `\\.\` and `\\?\UNC\` (and the case-insensitive `UNC`) on Windows.** Without these checks the remainder
   still fails step ④, because `//./C:/…` and `UNC/server/…` never begin with `X:/`. The result is `invalid_path` either way.

## One wording note

`data-structures.md` (connection-identity) says the exact frame ("TLV 长度前缀、空值表示、分隔符常量") is fixed by the
vectors. The fixture's `algorithm` block defines length prefixes and key order, but no null representation and no
separator constant, and none is needed, since missing collections are empty and the frame has no separators. Either
the body sentence predates the final frame, or something is meant that the fixture does not say.

## Files

| File | What |
| --- | --- |
| `reader/a2c_check_v1.py` | the reader, frozen before scoring |
| `reader/score.py` | scores a reader on the three files |
| `reader/mutants.py` | the one-rule-changed battery |
| `runs/run_1a81dee_v1.json` | the blind run, every vector with expected and got |
| `runs/mutants_1a81dee_v1.json` | the battery |
| `upstream_pins_1a81dee.txt` | what was fetched, opened and not opened |

The same author wrote the reader and the readings. No SDK code was opened or run. CC0.
