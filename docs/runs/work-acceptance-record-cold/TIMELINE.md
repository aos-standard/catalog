# Work-acceptance record — what this catalog ran, found and got wrong, in order (2026-10-18 to 2026-10-23)

The specification, its reference verifier and its vectors are maintained at
[`maximusrufus/work-acceptance-record`](https://github.com/maximusrufus/work-acceptance-record); the discussion is
[x402-foundation/tsc#4](https://github.com/x402-foundation/tsc/issues/4). Every verifier here was written from the
specification text without opening the reference implementation; the `expected` objects were visible while reading
the input shape, so none of these runs is blind. Each line links the record that holds the code, the hashes and the
raw output.

| date | upstream | what was run | result | record |
|---|---|---|---|---|
| 2026-10-18 | profile 1.2.1, `f7d8984` | second clean-room verifier; a battery that removes one check at a time (22 mutations) | 11/11; 11 of the 22 mutations still score 11/11 (checks no vector pins) | [`RUN.md`](RUN.md) |
| 2026-10-18 | — | vector 22 (SHA-1 imprint) proposed | pins the imprint-algorithm check, the last mutation left unpinned | [`ADDENDUM-vector22.md`](ADDENDUM-vector22.md) |
| 2026-10-18 | — | after babyblueviper1's run of 12–21 | 12b isolates `CHECKER_NOT_SIGNER` | [`ADDENDUM-reply-20261018.md`](ADDENDUM-reply-20261018.md) |
| 2026-10-19 | profile 1.3, `270e9fe` | unchanged 1.2.1 verifier; then v13 with the four rulings | 24/28, then 28/28 | [`ADDENDUM-profile13.md`](ADDENDUM-profile13.md) |
| 2026-10-20 | `2d8fac7` | v13 unchanged on vectors 29–30 (`accuracy`) | 30/30 | [`ADDENDUM-2d8fac7.md`](ADDENDUM-2d8fac7.md) |
| 2026-10-21 | profile 1.4, `eb0f30b` | step 9 (authority signature): the first scored run produced no score (library version); v14.1 | 36/36 | [`ADDENDUM-profile14.md`](ADDENDUM-profile14.md) |
| 2026-10-21 | `eb0f30b` | probe: imprint pattern only in the unsigned `statusString`; the reference accepts it | reproduced | [`probe-status-imprint/`](probe-status-imprint/) |
| 2026-10-22 | profile 1.4.1, `d79a737` | v141: first scored run misses 40 (RSASSA-PSS parameters not unwrapped); v141.1 | 48/49, then 49/49 | [`ADDENDUM-profile141.md`](ADDENDUM-profile141.md) |
| 2026-10-22 | `6b2f730` | the reference now reads the signed TSTInfo only; the probe is adopted as vectors 50–51 | 55/55 upstream | [comment 6345601340](https://github.com/x402-foundation/tsc/issues/4#issuecomment-6345601340) |
| 2026-10-23 | `6b2f730` | the probe's `statusString` is not UTF-8 (outside `PKIFreeText`), pointed out by robertolocatelli81-dev; a well-formed variant in an unsigned CMS attribute (56–57) | reference 57/57; before the fix, 56–57 disagree as 50–51 do | [`probe-unsigned-attr/`](probe-unsigned-attr/) |
| 2026-10-23 | `6b2f730` | v141.1 cannot run vector 52 (non-integer numbers); v141.2 writes RFC 8785 numbers | 56/57 (54 is a later clarification, not implemented) | [`ADDENDUM-v141_2-numbers.md`](ADDENDUM-v141_2-numbers.md) |
| 2026-10-23 | `6b2f730` | v141.3 implements the 2026-10-22 clarification of 54 (an issuer that fails a check is `failed` even when no chain reaches an anchor) | 57/57 on 01–55 plus 56–57 | [`ADDENDUM-v141_3-issuer-failed.md`](ADDENDUM-v141_3-issuer-failed.md) |

Defects of this catalog's own, found by itself or by others, are also rows of the public conduct ledger
([`CONDUCT.jsonl`](../../../CONDUCT.jsonl)); the ledger is anchored monthly to Bitcoin
([`../ledger-timestamps/`](../ledger-timestamps/)).
