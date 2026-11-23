# Rerun on A2C-SMCP `develop` at `e811757` (PR #85): the four uncovered rules are now pinned

On [a2c-smcp-protocol#78](https://github.com/A2C-SMCP/a2c-smcp-protocol/issues/78#issuecomment-7080992119), JIAQIA added
vectors for the four rules the first run found uncovered, plus three more, and merged them into `develop` as PR #85
(`e811757`). This reruns the frozen first reader (`../reader/a2c_check_v1.py`, sha256 `9e7b99c6…`, 2026-11-02) and
its battery, both unchanged, on those files.

| Vector file | At `1a81dee` | At `e811757` |
| --- | --- | --- |
| `bundle_id_conformance_vectors.json` | 16/16 | **25/25** |
| `env_segment_conformance_vectors.json` | 16/16 | **16/16** (file unchanged) |
| `canonical_path_conformance_vectors.json` | 49/49 | **56/56** |

**Battery: 38 of 42 mutants caught** (34 before). All four gaps from the first run are now caught:

| Mutant | Caught by |
| --- | --- |
| B4: `normalize_name` trims only `_` | `-lead`, `trail-` |
| T7: `args` sorted in the connection identity | the unnamed `["b","a"]` vector |
| T8: an explicit `bundle_id` normalized | the explicit `-custom` / `_custom` vectors |
| P16: `<` `>` `\|` `"` `*` allowed in Windows components | `win-reserved-lt`, `win-reserved-gt`, … |

The four survivors are the ones the first run already marked as rules whose outcome a later step always decides, so
they are not gaps: B7 (iterating UTF-8 bytes in `normalize_name`, which folding hides), and P5–P7 (the `\\.\` and
`\\?\UNC\` checks, which step ④ catches anyway). No new gap was found.

Reproduce from the parent folder:

```
python3 -I -B reader/score.py reader/a2c_check_v1.py <fixtures at e811757> run.json
python3 -I -B reader/mutants.py reader/a2c_check_v1.py <fixtures at e811757> mutants.json
```

The fixture hashes are in `upstream_pins_e811757.txt`. Standard library only. CC0.
