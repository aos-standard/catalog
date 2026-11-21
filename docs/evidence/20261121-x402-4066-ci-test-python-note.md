---
url: https://github.com/x402-foundation/x402/pull/4066#issuecomment-7063901472
api: https://api.github.com/repos/x402-foundation/x402/issues/comments/7063901472
created_at: 2026-11-21T14:12:09Z
fetched_at: 2026-11-21T14:13:02Z
body_sha256: 0a60ee0a8bd5ccf279693ca0363595247363c06612b12baad43519848979d6b8
note: comment body as served by the API, exact bytes below the second rule. The one failing check on #4066 (test-python, run 44296464438) is an unrelated cardano test; the PR touches no Python. Re-run or merging main suggested.
---
@MajorTal On the one unchecked box: the `test-python` failure on `895e6f2` ([run 44296464438](https://github.com/x402-foundation/x402/actions/runs/44296464438)) is a single test, `tests/unit/mechanisms/cardano/test_signers.py::test_full_core_flow_verifies_and_reconciles_each_transfer_method[lovelace-default]` (1 failed, 3818 passed). This PR touches only `specs/` and `typescript/packages/core/test/unit/http/headerVectors.test.ts`, no Python. `Check Python` passes on other PRs today, for example #4372, so re-running the job or merging `main` will probably clear it.

Disclosure: assisted by AI (Claude). I read the CI log myself.
