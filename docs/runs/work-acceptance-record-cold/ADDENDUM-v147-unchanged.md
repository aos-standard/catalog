# Addendum, 2026-11-07: v142.1, unchanged since 2026-10-27, on profile 1.4.7 (`6f7a075`): 108/115

**This file sits beside the earlier addenda and changes nothing in them.** It records one run of the reader this
record froze for profile 1.4.2 against the vectors at tag `v1.4.7`. The reader was not edited for this run.

| | |
|---|---|
| Subject | `maximusrufus/work-acceptance-record` tag `v1.4.7` (`6f7a075`), vectors 01 to 115 (`upstream_pins_6f7a075.txt`) |
| Reader | `war_cold_verifier_v1421.py` (`a0575614…80d22`) with `run_vectors_v1421.py` (`be3a2abb…c0a61`), both as frozen in `FROZEN_V1421.txt` at 2026-10-27T23:00:37Z, and `tsa_check_141.py` (`3b51efa5…39949`), as at the `cb7e8f1` run |
| Run date | 2026-11-07, once |
| Environment | Ubuntu 22.04, CPython 3.10.12, `cryptography` 46.0.3 |
| Answer exposure | Vectors 91 to 115 were added after the reader was frozen, so the reader could not have been fitted to them. Their file names were listed before the run. Their descriptions and expectations were read after scoring, to explain the seven disagreements |

`run_v1421_6f7a075.json` carries `"readme_pin": "85a310d"`. That value is a constant in the frozen runner, not the
commit scored here. The commit scored here is `6f7a075`.

## Vectors 01 to 90 did not change

Between `cb7e8f1` (scored 90/90 on 2026-10-28) and `v1.4.7`, the vectors directory gained 25 files (91 to 115). No
earlier vector was modified or removed. The reader agrees with all 90 again.

## The seven disagreements are the profile changes after 1.4.2

| Vector | Added in | What the reader does instead |
| --- | --- | --- |
| 95 `issued-utc-fraction-one-digit` | 1.4.3 (`3a5b909`) | reads a one-digit fraction as unreadable (`RECEIPT_TIME_UNREADABLE`). The profile now reads one to three digits |
| 105 `gentime-fraction-not-digits` | 1.4.3 (`3a5b909`) | reports the authority signature as `no_signer`, where the profile now has it `failed`, because genTime is read by step 5's form rule |
| 107 `gentime-without-z` | 1.4.3 (`a89cf90`) | the same, for a genTime without `Z` |
| 110 `producer-key-only-in-issuer-keys` | 1.4.5 (`c4b4bd4`) | has no `relying_party_keys` input, so it accepts a producer key found only in the issuer's response |
| 112 `relying-party-key-non-canonical-base64` | 1.4.5 (`066315f`) | the same input is absent, so the canonical-base64 rule for its entries is not applied |
| 114 `producer-key-neutral-point` | 1.4.7 (`6f7a075`) | does not apply step 2's point rule to the producer's key |
| 115 `neutral-point-from-unrelated-list` | 1.4.7 (`6f7a075`) | the same, with the neutral point under an unrelated `key_id` |

Each row is one rule that the profile added or made explicit after the reader was frozen. None of them is a
disagreement on a vector that existed at the freeze.

## What this shows and what it does not

The vectors have been append-only from 1.4.2 to 1.4.7. A reader written for an earlier profile keeps its earlier
results, and the vectors it misses name the rules it lacks, by profile version. That is the property a conformance
suite needs, if implementations are to state which vectors they agree with.

It does not show that this reader conforms to 1.4.7. It does not. No reader for 1.4.7 was written here.

## Files

| File | What |
| --- | --- |
| `run_v1421_6f7a075.json`, `run_v1421_6f7a075.stdout` | the run, as written by the frozen runner |
| `upstream_pins_6f7a075.txt` | the tag, the commit, the vector diff since `cb7e8f1`, and the sha256 of the README and of each added vector |

CC0.
