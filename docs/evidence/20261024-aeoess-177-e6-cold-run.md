---
url: https://github.com/aeoess/agent-governance-vocabulary/issues/177#issuecomment-6384314057
api: https://api.github.com/repos/aeoess/agent-governance-vocabulary/issues/comments/6384314057
created_at: 2026-10-24T12:39:05Z
fetched_at: 2026-10-24T12:39:20Z
body_sha256: 232dca34d2ca9e1aad920a9280d3c864bc2e2b1f5b1ce0c352a233713dea0498
note: exact copy of the comment body as served by the GitHub API at fetched_at; the row in CONDUCT.jsonl hashes this whole file
---
@tomjwxf thanks, it was a good fixture to read. I ran all 12 cases of `v1.1.0` (`8d8fc50`, `SHA256SUMS` sha256 `08731bb7…2ebc3`, all 89 files checked) with a consumer written from the README alone, without opening `consumer/`, `producer/` or `test/`. It agrees on **12/12** under your rule: the verdict, all eight claims, every code, and `payment_ready` false.

It does not call `@veritasacta/verify`. Ed25519 is written from RFC 8032 (checked against its test vectors first) and JCS for the value types the fixture has (Python 3.14 standard library). OpenSSL 3.6.1 then re-verified the 157 signatures the run decides over the same bytes, with no disagreement. The consumer was frozen by sha256 before its first scored run, and that run is the published one. One limit on independence: I had opened the `case.json` of cases 01, 04, 08, 10 and 12, expected blocks included, to learn the input shape before writing it.

Run, reader and outputs: [`docs/runs/e6-receipt-to-bill-cold/`](https://github.com/aos-standard/catalog/tree/f90ec2f/docs/runs/e6-receipt-to-bill-cold)

Three things from reading it:

1. **The no-signature control.** With signature checks replaced by `true`, case 12 becomes a PASS, as intended. Under the full agreement rule, cases 07 and 08 catch that consumer too: 07 loses `invalid_signature` from the codes, and in 08 `signatures` turns PASS. So the README sentence "matches both in all eleven" holds for the verdict and the decisive claim. It does not hold under the codes rule.
2. **No verifier, plus a failure that needs none.** Case 10 makes `keys` ABSTAIN. If a record also named an unknown key, I return `keys: FAIL` (`unexpected_signer`) and abstain only when nothing else failed. The README doesn't say which, and no case tests it.
3. **The validity window.** I took `valid_from` as inclusive and `valid_until` as exclusive. With `valid_until` null, no case reaches the end.

Authorship, kept separate: you wrote the format, verifier, fixture and reference consumer. I wrote this consumer and ran it, on Linux 6.8.

Disclosure: assisted by AI (Claude). I ran the checks above myself and remain responsible for what is claimed here.

