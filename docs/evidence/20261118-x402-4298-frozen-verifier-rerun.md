---
url: https://github.com/x402-foundation/x402/pull/4298#issuecomment-6963736353
api: https://api.github.com/repos/x402-foundation/x402/issues/comments/6963736353
created_at: 2026-11-17T23:11:44Z
fetched_at: 2026-11-17T23:12:08Z
body_sha256: 385e83a42258a4961846554229be5724321c645db86e35d83a34054abaca03ba
note: comment body as served by the API, exact bytes below the second rule. Rerun asked for by johnInarti in #3758 (6937265029): the frozen delivery-receipt verifier on #4298 at d9027a5, 25/25; the contributed fixtures checked unchanged. #4298 takes the seven vectors of this catalog, credited in Appendix B. Record: docs/runs/x402-delivery-receipt-cold/rerun-4298-d9027a5/ (856cde4)
---
Rerun, as asked in #3758: the frozen verifier, unchanged since 2026-10-18 (`dr_cold_verifier.py`, sha256 `006eda9f…`), on `specs/extensions/delivery-receipt.vectors.json` at `d9027a5`. **25/25 agree**: the 14 earlier runs and the 11 new ones, on `path`, the listed levels, `valid`, `longTermEvidence`, `reason.level` and the compared codes. Appendix A.1–A.6 all reproduce. The runner has the one change you named: it compares only the levels a run lists. Record: [`rerun-4298-d9027a5/`](https://github.com/aos-standard/catalog/tree/856cde4/docs/runs/x402-delivery-receipt-cold/rerun-4298-d9027a5).

I also checked the description of the edits against the files. Compared with `e82f684` and with my proposed file (`e376c64b`):

- every earlier member, including the 14 runs, is unchanged, and `negative` is the only new member;
- the seven fixtures are identical apart from the `/negative/fixtures/` prefix on the `$ref`s;
- each of the 11 runs only lost the levels after its first non-passing one.

It is exactly as stated, and the credit in Appendix B is as I asked.

Disclosure: assisted by AI (Claude). I ran the verifier and the comparison myself and remain responsible for what is claimed here.
