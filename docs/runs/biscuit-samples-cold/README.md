# Eclipse Biscuit samples at `b3d3fe2`: an independent verifier from the text, 45/50 and 50/50 revocation ids

The Biscuit repository publishes 38 sample tokens with 50 expected authorization results (`samples/current/samples.json`).
The specification says these are the expected result of verification. This record is an outside reader of them. A
verifier and authorizer were written from `SPECIFICATIONS.md` and `schema.proto` alone. No implementation and no
`samples/current/README.md` were opened. The verifier covers the protobuf format, Ed25519 and secp256r1 signatures (v0
and v1 payloads, third-party, sealed), symbol and public-key tables, the Datalog engine with origins and scopes, the
expression VM with closures, and a parser for the authorizer's text code. It was frozen before any expected value was
read, then scored once.

## Result

| What | Agreement |
| --- | --- |
| outcome class and detail (allow with policy index, or the failed checks and policy, or the error kind) | **45/50** |
| revocation ids | **50/50** |
| allow or deny only | 49/50 |

The five differences group into three text points:

1. **Expression errors (3 cases: `test027` overflow, `test032` shadowing, `test038` an uncaught error on the right-hand
   side of `try_or`).** The text says "If it overflows, the expression fails", "Strict equality fails with a type
   error", and that shadowing "should be rejected before starting the evaluation". This reader took a failing
   expression as a rule that does not match (R8). The samples expect the whole authorization to stop with an execution
   error. Both readings reject in all three cases, but the error class differs. The text could say that an expression
   error aborts authorization.
2. **Unsafe rules (`test018`).** The text defines a safe rule, but not what an unsafe rule in a token does. The samples
   expect `FailedLogic/InvalidBlockRule` with the rule. This reader returned a format error. Both reject.
3. **External calls (`test035`).** The sample expects `true.extern::test()` to succeed and
   `"a".extern::test("a") == "equal strings"`. The text says external calls are implementation-defined and names no
   `test` function, so a verifier written from the text cannot pass this case. A line saying which host function the
   sample assumes would make it checkable.

One more text point turned up while reading:

4. **The v0 signature payload order.** The text lists the v0 payload as data, then `pk`, then `alg`. Its sealing
   formula (`data_n + alg_n+1 + pk_n+1 + sig_n`) puts `alg` first. The sample tokens' block signatures verify only
   with `alg` before `pk`, and this reader uses that order. This was settled against the sample tokens' own signatures,
   not against any expected result, and it is disclosed in `FREEZE.txt` as R12. The width of "the little endian
   representation" is also unstated. 32 bits works for every sample.

## What the samples do not pin: one rule changed at a time

`reader/mutants.py` changes one rule of the frozen reader and reruns all 50 cases. A mutant is caught when a case the
frozen reader agreed on stops agreeing. **23 of 41 mutants are caught.** Three survivors only change cases the frozen
reader already disagrees on (overflow wrap, shadowing, unsafe rules), so they say nothing. The other 15 survive because
no sample reaches the rule:

- **Policies:** a matching `deny` policy treated as `allow`. No sample has a deny policy that matches.
- **Cryptography:** the proof's `nextSecret` not checked against the last public key; a sealed token's
  `finalSignature` not checked; external (third-party) signatures not checked.
- **Versions and tables:** datalog versions outside v3.0–v3.3 accepted; third-party blocks below v3.2 accepted;
  the same symbol defined in two blocks accepted.
- **Scopes:** `previous` meaning only the previous block; `previous` honoured in the authorizer; block-level `trusting`
  ignored; a generated fact's origin not including the facts it was derived from.
- **Values:** set `contains(set)` as overlap instead of superset; mixed-type sets accepted; dates compared with
  integers; floor instead of truncating division (the text does not say which, so that one is also a text point).

## Proposed samples (6)

`proposed/proposed.json` and the `.bc` files. They are built from `samples/current` tokens with the samples' own root
key and are byte-reproducible. Each one gives the expected class under the frozen reader and not under the reader
without the named rule (**6/6**, `reader/check_proposed.py`).

| id | Gap | Built from | Expected |
| --- | --- | --- | --- |
| `proposed_deny_policy` | deny policy | `test012` with `deny if true;` before its authorizer | `Unauthorized`, policy `Deny(0)` |
| `proposed_set_contains_is_superset` | set superset | `test012` with `check if !{1, 2}.contains({1, 3});` | `Ok(0)` |
| `proposed_wrong_proof_secret` | proof secret | `test012`, `nextSecret` replaced | format error |
| `proposed_sealed_bad_final_signature` | sealed signature | `test020`, last bit of `finalSignature` flipped | format error |
| `proposed_datalog_version_above_range` | version range | `test012` authority block at version 7, re-signed | format error |
| `proposed_datalog_version_below_range` | version range | `test012` authority block at version 2, re-signed | format error |

The scope, external-signature, symbol and remaining value gaps need new multi-block tokens with fresh keys, and are
not proposed here.

## Reproduce

Fetch `SPECIFICATIONS.md`, `schema.proto` and `samples/current/` at `b3d3fe2` into `upstream/`, and check the hashes in
`upstream_pins_b3d3fe2.txt`. Then:

```
python3 -I -B reader/split.py upstream/samples/current/samples.json blind
python3 -I -B reader/run_blind.py reader/biscuit_reader_v1.py blind/inputs.json upstream/samples/current run.json
python3 -I -B reader/score.py run.json blind/expected_SEALED.json
python3 -I -B reader/mutants.py reader/biscuit_reader_v1.py blind/inputs.json upstream/samples/current blind/expected_SEALED.json m.json
python3 -I -B reader/build_proposed.py upstream/samples/current upstream/samples/current/samples.json blind/inputs.json proposed
python3 -I -B reader/check_proposed.py proposed upstream/samples/current
```

You need Python 3 and `cryptography` (tested with 3.4.8). `FREEZE.txt` lists what was read before the freeze,
including the sample filenames, each case's authorizer code (an input), and the R12 calibration.

The same author wrote the reader, the readings and the proposed samples. Agreement between two readers is not a
certification. CC0.
