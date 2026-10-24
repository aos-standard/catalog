# E6 receipt-to-bill fixture, `v1.1.0`: a consumer written from the README, run on all 12 cases

**Date:** 2026-10-24 (run 11:45Z). CC0 for the files in this directory. Requested by the fixture's author on
aeoess/agent-governance-vocabulary#177.

**Fixture:** `VeritasActa/e6-fixture` at `8d8fc50ae2b4fdb498fcbb65b4f2268683a79a41` (tag `v1.1.0`), Apache-2.0, by
Tom Farley. sha256 of `SHA256SUMS`: `08731bb75416e588a2a0269387731c6643dfbded76ef98b738e0097a99c2ebc3`. All 89 files
were checked against `SHA256SUMS` before the run. The fixture is not copied here; fetch it at that commit.

**Who:** the reader was written and run by the operator of `aos-standard/catalog`, with an AI assistant (Claude). We
wrote none of the format, the verifier, the fixture or its reference consumer.

## Result

Agreement with `expected` on **12/12** cases under the fixture's own rule: the verdict, all eight claims, every code,
and `payment_ready` false. Codes are compared as sets (order ignored).

| file | what it is |
|---|---|
| `e6_bill_check.py` | the consumer, standard library only. Its docstring lists the checks and codes |
| `run_output.txt`, `run.json` | the run: file check, one line per case, every result beside `expected` |
| `xcheck_openssl.py`, `xcheck_openssl_output.txt` | every signature the run decides, verified again by OpenSSL |
| `control_no_signature_check.py`, `control_output.txt` | the same consumer with signature checks replaced by `true` |
| `SHA256SUMS` | the files above |

`e6_bill_check.py` (sha256 `f1f67778e5abbda4130bac40bd21a16769e44169ea6cc906b76ac2c548e128af`) was frozen before its
first scored run (11:43:48Z). The first run gave 12/12, and the file was not changed after it.

## How it was written

- From the fixture `README.md` only. `consumer/`, `producer/` and `test/` were not opened, and neither was the text
  of draft-farley-acta-signed-receipts-03 (the README's "Constructions" section was enough for this fixture).
- **Not `@veritasacta/verify`.** Ed25519 verification is written in the file from RFC 8032 5.1.7 (cofactorless,
  `s < L`, canonical encodings), and checked against RFC 8032 test vectors 1 and 2 before the run. JCS (RFC 8785) is
  written in the file for the value types this fixture has. There are no floats in any fixture file, and the code
  raises on one. So the `keys` and `signatures` claims rest on this file, not on the published verifier.
- **Cross-check.** OpenSSL 3.6.1 (`pkeyutl -verify -rawin`) re-verified 157 signatures over the same JCS bytes: the
  51 receipts, the manifest and the meter key's certificate, and the altered records of cases 07, 08 and 12. It
  disagrees with this file on none (103 valid, 54 invalid).
- **Environment:** Linux 6.8, Python 3.14.3, OpenSSL 3.6.1.
- **On screen before the reader was written:** the `case.json` of cases 01, 04, 08, 10 and 12, including their
  `expected` blocks, which were opened to learn the input shape. So the claim and code layout of those five cases
  (for example `keys: ABSTAIN` in case 10, and `invalid_signature` beside `manifest_signature_invalid` in case 08) was
  known while writing. The `expected` blocks of the other seven cases were not seen before the scored run.

## Control

With every signature check replaced by `true`, case 12 turns into a PASS, as the fixture says it should. Under the
fixture's full agreement rule, cases 07 and 08 also catch that consumer: in 07 the `signatures` codes lose
`invalid_signature` (the link still breaks), and in 08 `signatures` becomes PASS. The README says a consumer that
never checks a signature "matches both in all eleven". That holds for the verdict and the decisive claim, which is
the comparison that sentence is about. Under the codes rule, it does not hold for 07 and 08.

## Where the README leaves a choice (this reader's answer; the cases do not test it)

1. **No verifier, plus a failure decidable without one.** Case 10 makes `keys` ABSTAIN because the certificate cannot
   be checked. If a record also named an unknown key, the failure needs no verifier. This reader returns `keys: FAIL`
   (`unexpected_signer`) then and abstains only when nothing else failed.
2. **Validity window boundaries.** "Issued inside its validity window": this reader takes `valid_from` as inclusive and
   `valid_until` as exclusive. The meter key's `valid_until` is null, so no case reaches the end.
3. **`quantities` when a line names an unknown receipt** (case 02): the line count still has to equal `quantity`, and
   the unknown ID is left to `coverage_bill_to_receipts`. The `expected` of case 02 agrees.
4. **Which key is "the pinned meter key"** when the keys document has more than one meter entry: this fixture has one,
   and this reader fails `signatures` if there is not exactly one.

## What this run does not establish

The keys are demo keys and the outcomes are simulated. There is no contract, so `amount` is not evaluated and
`payment_ready` is false in every case. Agreement shows that this consumer and the fixture's `expected` read the
README the same way on these 12 cases. It says nothing about work quality, price, or any real party.
