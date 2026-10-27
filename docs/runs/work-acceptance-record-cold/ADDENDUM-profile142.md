# Addendum, 2026-10-28 — profile 1.4.2 (87 vectors at `85a310d`): v141.3 68/87 with one crash, v142.1 87/87

**This file is added beside `RUN.md` and the earlier addenda and changes nothing in them.** Files listed here are in
`SHA256SUMS-profile142`; every earlier `SHA256SUMS*` is unchanged.

Profile 1.4.2 (maximusrufus/work-acceptance-record, README at `85a310d`, README sha256 `21a8a5d2…1456`) adds vectors
58–87. 58 and 59 are this catalog's (PR #1, merged 2026-10-27); 60–87 exercise the 1.4.2 rules: canonical base64,
lowercase digests, the form of `genTime` and millisecond rounding, RFC 3339 stated times, independence by key, the
signed `key_id` for the checker comparison, unsigned attributes not read, and wrong types refused. Vectors 01–57 and
their outcomes are unchanged.

## 1. The frozen 1.4.1 verifier on the 87 — 68/87, and one crash (self-found)

`war_cold_verifier_v141.py` (v141.3, `cee9537d…82da`, with `tsa_check_141.py` `3b51efa5…9949`), run unchanged
through its 0012 port (identical but for a three-line docstring): `run_v1413port_85a310d.json`.

- 01–59 all agree (01–57 as before; 58 and 59 are ours).
- 60–87: 18 disagree, each on a rule 1.4.2 introduces (60–62, 65, 66, 68–75, 78–81, 87).
- **76 crashes the verifier**: `committed_at` `2026-13-01T00:00:00Z` reaches `datetime.fromisoformat` unguarded
  (`ValueError: month must be in 1..12`). A verifier that raises on a stranger's input is a defect of ours, whatever
  the profile says about that input; 1.4.2's types rule says the same ("never makes a verifier fail"). Recorded as
  `self_found`.

## 2. v142 — written from the 1.4.2 rule text; 84/87

`war_cold_verifier_v142.py` (`011168ac…de5d`, `FROZEN_V142.txt`, frozen before its run): v141.3 with the nine rules of
README step 10 applied, as listed in its docstring. The reference verifier was not opened. **Answer-exposed:** v141.3 had
been scored on these vectors before v142 was written, so which vectors a rule touches was known.
`run_v142_85a310d.json`: 84/87. Three disagreements:

- 66, 68: v142 compared `committed_at` with the millisecond-rounded `genTime` and added `CRITERIA_TIME_MISMATCH`; the
  vectors say `committed_at` is compared to the second.
- 77: a result `id` that is an object. v142 guarded against raising and then reported `CRITERIA_RESULTS_MISMATCH`; the
  rule is the step-1 refusal.

## 3. v142.1 — 87/87, and 57/57 on `bc5a138`

`war_cold_verifier_v1421.py` (`a0575614…80d22`, `FROZEN_V1421.txt`), v142 with those two corrections, written after
seeing them (post hoc for 66, 68 and 77). `run_v1421_85a310d.json`: **87/87** on every compared field (seven outcome
fields, the two code sets, `tsa_signature` where expected). `run_v1421_bc5a138.json`: **57/57** on the 1.4.1 set, so
the 1.4.2 rules change no earlier outcome in this reader either.

Readings fixed in v142 that the text leaves open, and consistent with the 87:

1. A non-canonical token or criteria file "matches nothing": reported as `CRITERIA_TIMESTAMP_MISMATCH` /
   `imprint_mismatch` / `CRITERIA_HASH_MISMATCH` respectively, never as a refusal.
2. A `genTime` in a non-DER form leaves the token covering its imprint (`imprint_match`) but giving no time; for the
   record token that means no reference adjustment, for the criteria token the `committed_at` fallback with
   `CRITERIA_COMMITMENT_UNVERIFIED`.
3. `RECEIPT_TIME_UNREADABLE` is raised when the stated time step 5 actually uses is unreadable: `issued_utc` always,
   `committed_at` only when it is the fallback. An unreadable `committed_at` beside a usable criteria token is not
   a problem.
4. The types rule is applied as a list of the fields the README names (`_types_ok`); a field the README does not
   name is not type-checked.

## 4. Not covered

No new mutation battery for the 1.4.2 rules (v141's `lax_battery_v141.py` covers the 1.4.1 rules only). The 0012 port
still carries v141.3; moving v142.1 into it is a separate step. CC0 for the files here.
