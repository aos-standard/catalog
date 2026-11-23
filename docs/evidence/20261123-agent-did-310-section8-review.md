---
url: https://github.com/edisonduran/agent-did/issues/310#issuecomment-7096220103
api: https://api.github.com/repos/edisonduran/agent-did/issues/comments/7096220103
created_at: 2026-11-23T09:06:12Z
fetched_at: 2026-11-23T09:06:32Z
body_sha256: 7cd667c0a65b8ff9117fc2c2293416c00999eff2af01513e54a1fba42992a891
note: comment body as served by the API, exact bytes below the second rule. Review of RFC-001 section 8 at 76015096 for the v1.0.0 criterion C-SPEC-3, asked for by the maintainer in #310: text findings only (no vulnerability); conditional sign-off (1.1 and 1.2 resolved). Materials pinned: RFC 1daec23f, Threat-Model 29b60bfd, SECURITY 56611e84.
---
@edisonduran Review of RFC-001 §8 for `v1.0.0` (C-SPEC-3).

**What I reviewed.** §8, §8.1 and §8.2 at `76015096` (the RFC file's sha256 is `1daec23f…`, the same bytes as at `d09ca9f`). I checked each statement against the rule it points to: §4.3, §4.4, §6.1, §6.2, §6.2.2, §6.5, §6.6 (items 4, 7 and 8), §6.7 and §6.8. I also read `Threat-Model.md` at the same commit, which §8.1 summarizes, and `SECURITY.md`.

**How.** Claude (AI) read the texts with me, drafted the comparisons and pointed out the passages below. I checked each finding against the cited text myself, and the sign-off decision is my own. No code was run for this review, and the SDKs were not opened. Nothing below is a vulnerability in the protocol or the SDKs. These are all text points.

## 1. Wrong, or stronger than the normative rules

1.1 **§8.1 is marked informative but carries requirements that exist nowhere else.** Item 4 says verifiers MUST keep `(keyid, nonce)` "in a store shared by all verifier instances". §6.5 item 6, the normative rule, says to record the pair until `expires` and says nothing about instances. The shared store appears only in §8.1 and in the Threat Model ("mandatory for multi-instance verifiers"). If it is a requirement, it belongs in §6.5 item 6, where a conformance claim is made. If not, §8.1 should not say MUST.

1.2 **§6.1 takes its requirement from the informative section.** §6.1 says "A resolver in this RFC's sense MUST verify the whole log as required by §8.1 item 2", and §8.1 item 2 is where the list (SCID, `entryHash` chain, proofs, `updateKeys` authorization) and the no-fallback rule are stated. A normative MUST that depends on an informative section is easy to lose in a later edit. I suggest stating the whole-log rule in §6.1 or §6.2 and having §8.1 item 2 restate it with a reference.

1.3 **§8 item 3, "Immediate revocation: critical requirement",** says more than the protocol gives. §8.1 item 3 explains that a log host can withhold the deactivating entry, and that only cache bounds and the A2A propagation window limit how long a verifier keeps accepting the key. A wording such as "Revocation takes effect for a verifier when it fetches the deactivating entry; bound resolver caching (§8.1 item 3)" would match the rules. The other short principles in §8 (items 2, 4 and 5) do not point to the rule that carries them, so a reader cannot tell which are requirements. A section reference on each would fix that.

## 2. Threats an implementer or verifier needs and §8.1 omits

2.1 **Headers outside the covered set are not authenticated.** The Threat Model lists this as a residual ("Headers outside the covered set are not protected"), and §8.1 does not. The covered set has no `Content-Type`, no `Authorization` and no other header, so a party that can alter the request in transit can change how a correctly digested body is interpreted. A verifier that reads anything outside the seven components should know that the signature does not cover it. One line in §8.1 would do it, for example "only the covered components are signed; treat every other field as unauthenticated, or cover it as an additional component (§6.5 item 2)".

2.2 **Resolution is driven by an unauthenticated header, before the signature is checked.** A verifier has to resolve the DID named in `Agent-DID` before it can verify anything, so any sender can make it fetch from a host it chooses. The Threat Model covers this in Flow 3 (SSRF guard, no redirects, deadlines and size caps) and as cross-cutting finding 6 ("a sender can name unknown DIDs to force fetches"). §8.1 does not mention it, and §6.1 refers to "the same fetch limits as the log" without saying anywhere what those limits are. For an independent implementation this is the consideration with the most practical weight. I suggest an §8.1 item covering at least: refusing non-globally-routable targets, not following redirects, a deadline and a size cap per fetch, and rate-limiting per sender.

2.3 **A holder of a valid key can fill the replay store.** This is in the Threat Model (Flow 4, D) with "rate-limit per `keyid`". It belongs next to §8.1 item 4, because a shared store makes it a cross-instance problem.

2.4 **Rollback, against a verifier that already holds a log.** §8.1 item 3 is right that freshness is not authenticated. But §6.6 item 4 already has a normative defence it does not mention: a client that holds a log never accepts an older prefix or a diverging history. A pointer would show that rollback works only against a verifier with no copy, which is useful when choosing cache lifetimes.

## 3. MUST and SHOULD levels in §8.1

Given 1.1 and 1.2, I would make §8.1 carry no new requirements. Each MUST there would either move to the normative section it belongs to (whole-log verification to §6.1 or §6.2, the shared replay store to §6.5 item 6 if intended) or become a restatement with a reference. Item 1, "Verifiers MUST authorize DIDs themselves", cannot be tested as written, because the RFC defines no authorization decision. It reads better as a statement of scope: "a valid signature is authentication only; authorization is the verifier's decision (§6.2.1.2)". The SHOULDs (reading the Threat Model, bounding cache lifetime) are at the right level.

## 4. Parties §8.2 leaves out

4.1 **The signer's key service.** §8.1 item 6 recommends an HSM or KMS, and §6.6 item 2 allows a KMS behind the signer. Whoever operates it receives every signature base, so it learns when the agent signs, which `@authority`, `@path` and `@query` it calls, and the body digest. For a remote KMS that is a full record of whom the agent calls. It belongs in the table.

4.2 **did:webvh witnesses.** A witness approves each governed log entry (§6.1), so it sees every change to the document, and possibly before the entry is published. The table lists the log host but not the witnesses.

4.3 **The operator of a shared replay store.** If item 4 of §8.1 stays, a shared store, often a separate service, sees each accepted `keyid` and when. §8.2 item 4 covers what a verifier records, but not a store operated by another party.

## Smaller points

- `Threat-Model.md` §6 (A2A), row "Privilege escalation across delegation chains", says "Not covered … Open; belongs to the RFC-001 delegation model". §6.7 now defines attenuation along the chain, so the row looks older than §6.7.
- §8.2 item 4 says a replay store "MUST keep [the pair] until then, §6.5 item 6". The Anti-Replay guide's store contract keeps it through `expires` inclusive, which `reject-replayed-at-expires` now pins. "Until `expires` inclusive" in §6.5 item 6 would make the text match the vector.

## Sign-off

I sign off on §8 for `v1.0.0` on the condition that 1.1 and 1.2 are resolved, by moving the two requirements into the normative sections or by dropping MUST from §8.1. The other points are recommendations and do not block.
