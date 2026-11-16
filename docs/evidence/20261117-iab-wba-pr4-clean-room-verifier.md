---
url: https://github.com/IABTechLab/iab-agentic-primitives/pull/4#issuecomment-6931773929
api: https://api.github.com/repos/IABTechLab/iab-agentic-primitives/issues/comments/6931773929
created_at: 2026-11-16T22:51:14Z
fetched_at: 2026-11-16T22:51:57Z
body_sha256: ad0ae72228ff4a7b6f479f02584a34d3bcbd8d61c6fb7b1a80c9384d749f3487
note: comment body as served by the API, exact bytes below the second rule. Comment on IABTechLab/iab-agentic-primitives PR #4 (Web Bot Auth profile): clean-room verifier 91/91 on the vectors and scenarios at 3bcfb96, three proposed negative vectors. First contact with this repository. Record: docs/runs/iab-web-bot-auth-cold/ (c5abde5)
---
I wrote an independent verifier for this profile from `WEB_BOT_AUTH.md` and the vectors README alone, without opening the module's code, and ran it on the conformance files at `3bcfb96`. **91/91 agree on the first run**: the 20 committed vectors and all 71 scenarios. I signed the scenarios myself from the published seeds, following the README's "Scenarios" section, and hid their expected outcomes until the verifier and harness were frozen. Record: [`docs/runs/iab-web-bot-auth-cold/`](https://github.com/aos-standard/catalog/tree/c5abde5/docs/runs/iab-web-bot-auth-cold).

- All 19 `expected_signature_base` values match my base byte for byte, and re-signing each one with its seed reproduces the committed `Signature`. The "diff your base first" design made this a one-step check.
- The `target_uris` GETs are signed over the stated `wire` and verified from the `url`, so the target-URI rule is checked against the file, not against my own code. 8/8.

**Three rules no shared file exercises.** I turned off one check of my verifier at a time and reran all 91 cases. 26 of the 29 mutants are caught. This confirms the README's note about `negative/001`, `003`, `004`, `006` and `007`. Three are not caught:

| Check removed | Rule |
| --- | --- |
| the response signer's origin is not compared with `expected_origin` | `origin-mismatch` |
| a directory `kid` is not compared with the key's thumbprint | `directory-kid` |
| a directory signature's `tag` is not checked | `directory-tag` |

Your unit tests do cover all three (`test_wba_response.py`, and `test_wba_directory.py` lines 218 and 276). So this only matters for another implementation graded through the adapter, which cannot fail on them today.

I made one negative vector per rule, in the committed format and signed with the published seeds at the same clock: [`proposed/`](https://github.com/aos-standard/catalog/tree/c5abde5/docs/runs/iab-web-bot-auth-cold/proposed). In each, everything else is valid. For example, `x01` is answered by other.example.com with a valid key, directory and request binding. The mutant that drops exactly that rule accepts the vector, so no other check refuses it. Take or edit them under this repository's Apache-2.0 license. The `tier` value is my guess, since I did not run Cloudflare's library.

Exposure: the README names each negative vector's status and rule, so the 20 committed vectors are not a blind read. The 71 scenarios are.

Disclosure: assisted by AI (Claude). I ran the verifier and the harness myself and remain responsible for what is claimed here.
