# AuthZEN Authorization API 1.0 certification scenario at `aab761f`: an independent PDP from the text, 53/55

The OpenID Foundation AuthZEN working group publishes a certification scenario for PDPs
(`certification/authorization-api-1_0-scenario.md`). This record checks the scenario from the outside. A minimal PDP was
written from the Authorization API 1.0 text and the scenario's fixture section only. It was frozen before any test
section was read, then run on every test the scenario defines, transcribed as executable checks. A one-rule-at-a-time
battery then shows what the scenario does not pin.

## Result: 53 of 55 checks pass; both failures are cases that open PR #793 changes

| Level | Checks | Pass |
| --- | --- | --- |
| Basic (Core and Properties), response format, errors, headers, idempotency | 24 | 24 |
| Batch (Core and Properties), response format, errors | 10 | 9 |
| Search (Core and Properties), pagination, empty results, errors | 20 | 19 |
| Discovery | 1 | 1 |

The two failures are places where the scenario at `aab761f` asks for more than the API text, and where this PDP
follows the text:

- **`c-3-4-1`:** a batch item with no `resource` at any level must give HTTP 200 with that item `false`. The PDP
  returns 400, because Section 10.1.1 requires a Bad Request when a required attribute is omitted. Issue #763 raised
  this, and PR #793 changes `c-3-4-1` to a 400.
- **`c-4-5-2`:** the page-token follow-up request leaves out the `limit` of the first request. §8.2 requires every
  parameter except the token to be identical, and says a PDP SHOULD return an error otherwise. #792 makes that a MUST.
  The PDP returns 400. Issue #764(c) raised this, and PR #793 makes the follow-up repeat `limit`.

So this run is an independent data point for both changes in #793: a PDP written from the text alone fails exactly
those two cases at `aab761f`.

## What the scenario does not pin: one rule changed at a time

`reader/mutants.py` changes one rule of the frozen PDP and reruns the 55 checks (`runs/mutants_v1.json`). 7 of 21
mutants are caught. Some survivors are out of scope by design (the short-circuit evaluation semantics, which `c-3-4-1`
excludes) or make no difference to this PDP. Three groups are real gaps:

1. **Request properties versus identifiers.** `c-2-2-4` says the deny "is based on `properties.status` being
   `"archived"`, not on the resource identifier". But it sends `record-2`, whose fixture status is already `archived`.
   A PDP that ignores the request's `properties` for subject and resource, lets stored values win, or decides by the
   identifier alone passes every check.
2. **Whole-object override in batch defaults.** `c-3-2-7` says it "validates entity-level default inheritance and
   whole-object override". But its overriding `resource` carries `type`, `id` and `properties`, so a PDP that merges
   sub-fields gets the same result. (Issue #640 found the opposite problem in the conformance suite.)
3. **Invalid field types.** `c-2-4-6` covers an entity given as a string and `action.name` given as a number.
   Nothing sends a non-string `type`, a non-object `properties`, or a non-object `context`.

One question about the fixture itself: rules 5 and 6 overlap when `alice` sends `properties.role` = `"admin"` for a
write to an archived resource. Rule 5 says that decision MUST be `false`, and rule 6 says it MUST be `true`. No test
sends that request, but a PDP's policy has to choose.

## Proposed cases (5)

`proposed/proposed_cases.json`: each case passes the frozen PDP, and fails the mutant that drops its rule (5/5).

| id | Gap | Request | Expected |
| --- | --- | --- | --- |
| `proposed-basic-props-status-not-id` | 1 | alice `write` on `record-1` with `properties.status` = `"archived"` | 200, `false` (rule 5) |
| `proposed-batch-whole-object-override` | 2 | top-level `resource` = archived `record-2`; the evaluation gives `{type, id: record-1}` with no properties | 200, `[true]` (rule 2) |
| `proposed-invalid-type-subject-type-number` | 3 | `subject.type` = 7 | 400 |
| `proposed-invalid-type-properties-string` | 3 | `resource.properties` = `"active"` | 400 |
| `proposed-invalid-type-context-string` | 3 | `context` = `"2025-06-27"` | 400 |

## Readings the PDP took

R1–R12 in `reader/authzen_pdp_v1.py`. The ones that matter here are: R1, request `properties` take precedence over
stored values; R7, a per-evaluation key replaces the default whole; R8, an evaluation missing a required entity is a
400 for the whole payload; R10, a page token bound to an unchanged request; and R12, 400 (not 415) for a wrong
`Content-Type`.

## Reproduce

```
python3 -I -B reader/smoke.py reader/authzen_pdp_v1.py
python3 -I -B reader/scenario_cases.py reader/authzen_pdp_v1.py run.json
python3 -I -B reader/mutants.py reader/authzen_pdp_v1.py mutants.json
python3 -I -B reader/proposed_cases.py reader/authzen_pdp_v1.py proposed.json
```

You need Python 3 and the standard library only. The PDP runs in-process, with no network. `FREEZE.txt` has the
PDP's hash, the freeze time, and what was read before the freeze.

## Limits

The scenario's checks were transcribed by the same author who wrote the PDP, from the scenario's own "Expected" and
"The harness validates" text. The OIDF conformance suite was not run, and its modules may check more or less than
the text says. Agreement here is not a certification. CC0.
