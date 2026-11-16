---
url: https://github.com/x402-foundation/x402/issues/3758#issuecomment-6931060850
api: https://api.github.com/repos/x402-foundation/x402/issues/comments/6931060850
created_at: 2026-11-16T22:17:43Z
fetched_at: 2026-11-16T22:18:06Z
body_sha256: 6c5b696e1c6979e7d7e429fe418fc1928f31d5ffc0b621c041d97266ab9a1a3f
note: comment body as served by the API, exact bytes below the second rule. Reply to johnInarti 6928565438, who ran the seven proposed vectors (proposed/delivery-receipt.proposed-vectors.json, e376c64b, 036e9ab) through the TypeScript reference and asked to take them into a follow-up PR on #3783. Consent under Apache-2.0 and credit given here. Record: docs/runs/x402-delivery-receipt-cold/ (036e9ab)
---
@johnInarti thanks for running them. I checked `run-out.json` at `0c65c66` against my side: 11/11 decisive and 5/11 strict, and the six strict misses are all on levels after the first non-passing one, as you say.

**Yes to all of it.** You may take the seven vectors into the follow-up PR on #3783 under this repository's Apache-2.0 license. I wrote them, and I hold the copyright in them (the catalog copy is MIT). Please credit them as "Tetsuroh Hori (@Tetsurohhori)", with a link to the record they came from: https://github.com/aos-standard/catalog/blob/036e9ab/docs/runs/x402-delivery-receipt-cold/RUN.md. Edit them as you need. If a change alters a verdict, tell me here and I will rerun my verifier on the new file.

**A.7: your rule, not a mandate.** Compare up to and including the first non-passing level, and treat the later levels as informative. Please don't mandate `not-evaluated`. One reason from your own output: the reference already stops after `integrity` (`mlDsa65Stripped` and `framingUnregistered` match on all five levels), but it keeps going after `authentic`, `trusted` and `settlement`. So a `not-evaluated` mandate would change the reference as well as the text. The point of A.7 is that verdicts agree, and your rule says exactly that. If you take it, the `not-evaluated` values after the first non-passing level in my seven files should become informative, or be dropped, so that no vector asserts them.

**§8.1.** Your sentence works for me. It is the reading under which my verifier went from 12/14 to 14/14 on the `endToEnd/stream/*` runs.

Disclosure: assisted by AI (Claude). I compared the run output above myself and remain responsible for what is claimed here.
