# Addendum — after babyblueviper1's run of vectors 12–21 (tsc#4, 2026-10-18)

babyblueviper1 ran their checker (now at profile 1.2.1, `431525f`) over the ten proposed
vectors as data only: 9/10 agree, the three reading choices (15, 19, 21) adopted, 18 confirmed
against the reference's fallback to `issued_utc`. Two things came back; both are taken.

## 1. Vector 12 tested two things at once → `12b`

In 12 the signature envelope names `hori-cold-test-2` while the signed `receipt.key_id` names
`hori-cold-test-1`. This verifier verifies with the envelope's key and raises
`CHECKER_NOT_SIGNER`; babyblueviper1's verifies with the key the *signed bytes* name and requires
the envelope to agree, so it reports `SIGNATURE_INVALID`. Step 2 says "the key identified by
`key_id`" without saying which `key_id`; both readings fit.

`proposed_vectors/12b-signer-is-not-the-checker.json` rebuilds the case so that `receipt.key_id`
and `signature.key_id` both name test-2 and only `parties.checker.key_id` names test-1. It
isolates `CHECKER_NOT_SIGNER`: this verifier reports exactly that and nothing else. 12 is left in
place as the record of the ambiguity, not as a conformance case.

## 2. Their proposed 22 and 23, run here (data only; `war_check.py` not opened)

| vector | this verifier (1.2.1 as written) | their expectation | agree |
|---|---|---|---|
| 22 — record token covers this record and says 13:00; `issued_utc` 12:00; criteria token 12:30 | `criteria_committed_before_check: yes`, no problems | `no`, `CRITERIA_COMMITTED_AFTER_CHECK` | **no** — by design: they propose a rule change |
| 23 — criteria token imprint algorithm SHA-384, same DER length, same 32 bytes | `CRITERIA_TIMESTAMP_MISMATCH` + fallback with `CRITERIA_COMMITMENT_UNVERIFIED` | same | yes |

**On 22.** Profile 1.2.1 step 5 takes the reference time from the covering token's genTime when
one is supplied. Here that is 13:00, later than the criteria commitment (12:30), so the profile as
written says the criteria were committed first — although the record's own signed `issued_utc`
says the check ran at 12:00, before the criteria existed. The covering token proves the record
existed *by* 13:00; it bounds the check from above, not below. babyblueviper1's proposed rule —
reference time = the **earlier** of `issued_utc` and the covering token's genTime — gives `no`
here and changes nothing on 01–21 (checked: every covering token in those vectors has a genTime
after its `issued_utc`, and the criteria times are far from both). This verifier agrees with the
rule and keeps reporting 1.2.1 as written until the profile says so; the two readings are the
same sentence with one word changed.

**On 23.** SHA-384's OID differs from SHA-256's in one byte and encodes to the same length, so the
token carries the right 32 bytes under the wrong algorithm. This is the cleaner pin for the
imprint-algorithm mutation than my SHA-1 vector 22 (`ADDENDUM-vector22.md`), whose 20-byte imprint
also fails on length. If Trilatic takes 23, my 22 can be dropped; the numbers collide only because
both were proposed the same day.

Files: `proposed_vectors/12b-signer-is-not-the-checker.json`, `run_babyblueviper1_22_23.json`,
`FROZEN-reply.txt` (sha256; the verifier is unchanged, `897b5648…e9aa`).
