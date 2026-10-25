# Addendum, 2026-10-25 — the same consumer on E6 fixture v1.2.0: 14/14

**This file is added beside `README.md` and changes nothing in it.** The files in `SHA256SUMS` are unchanged.

The fixture's author answered the three readings of the v1.1.0 run on aeoess/agent-governance-vocabulary#177 by
changing the README and adding two cases. v1.2.0 is tagged at `ace08f3c`, sha256 of `SHA256SUMS`
`3998e983241f330d07054bc876dc0c34785d8629aae8a2524f10343177a11038`. All 98 files were checked against it before the
run.

`e6_bill_check.py` was run **unchanged** (sha256 `f1f67778e5abbda4130bac40bd21a16769e44169ea6cc906b76ac2c548e128af`,
the file frozen for the v1.1.0 run) on all 14 cases, with Python 3.14.3 at 2026-10-25T12:36Z. The output is
`run_v120_output.txt` and `run_v120.json`.

- **14/14 agree** under the fixture's rule: the verdict, all eight claims, every code, and `payment_ready`.
- Cases 01–12 give the same results as at v1.1.0.
- **Case 13** (unexpected signer, no verifier): `FAIL`, `keys=unexpected_signer`, `signatures=verifier_unavailable`.
  This is the reading the v1.1.0 run took and reported as untested.
- **Case 14** (record issued exactly at `valid_until`): `FAIL`, `keys=outside_key_window`, from the reading
  `valid_until` exclusive.
- **Blind for the two new cases:** their `case.json` files were not opened before the run. The five case files
  opened for v1.1.0 (01, 04, 08, 10, 12) are the same files.

Files: `run_v120_output.txt`, `run_v120.json`, `SHA256SUMS-v1.2.0`. The fixture is Apache-2.0 and is not copied here.
