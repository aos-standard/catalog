# Seven more proposed samples: scopes, origins, external signatures, symbols (2026-11-27)

This folder adds to the record one level up. That record left seven of the unpinned rules without proposals because
they need new multi-block tokens. These tokens are built from scratch with the samples' root key and deterministic
ephemeral and third-party keys. All blocks use signature payload v1. Ed25519 is deterministic, so
`build_multiblock.py` rebuilds every file byte for byte.

| id | Rule (spec) | Token | Authorizer | Expected |
| --- | --- | --- | --- | --- |
| `proposed_previous_covers_all_earlier_blocks` | `previous`: "the previous blocks (including the authority)" | block 2: `check if right("file1", "read"), user("alice") trusting previous` | `allow if true;` | `Ok(0)` |
| `proposed_block_level_trusting_previous` | block-level scope annotations | block 2 declares `trusting previous` at block level; its check `user("alice")` has no scope | `allow if true;` | `Ok(0)` |
| `proposed_previous_ignored_in_authorizer` | "`previous` ... is ignored when used in the authorizer" | block 1: `user("alice")` | `check if user("alice") trusting previous;` | authorizer check 0 fails |
| `proposed_origin_includes_matched_facts` | origin = rule block ∪ matched facts' origins | authority: `admin($u) <- member($u) trusting ed25519/<third-party>`; third-party block 1: `member("alice")` | `check if admin("alice");` | authorizer check 0 fails (origin {0, 1}) |
| `proposed_bad_external_signature` | verifying external signatures | third-party block 1 with one bit of its external signature flipped (the regular signature covers the flipped bytes) | `allow if true;` | format error |
| `proposed_duplicate_symbol` | "different blocks do not contain the same symbol" | block 1's `symbols` repeats `file1` from block 0 (appended, so no index moves) | `allow if true;` | format error |
| `proposed_third_party_below_v3_2` | third-party blocks must be at least v3.2 | third-party block 1 at datalog version 4 | `allow if true;` | format error |

For each one, the frozen reader one level up gives the expected result, and the same reader with the named rule
removed does not (**7/7**, `check_multiblock.py`). The expected results come from the text quoted above. These tokens
have not been run against any Biscuit implementation.

One reading the third case does not depend on: when the only scope annotation in the authorizer is `previous` and it
is ignored, the text doesn't say whether the default (`authority`) then applies. Block 1 is untrusted under either
reading, so the expected failure holds both ways.

```
python3 -I -B build_multiblock.py <samples/current/samples.json> out
python3 -I -B check_multiblock.py .
```

CC0.
