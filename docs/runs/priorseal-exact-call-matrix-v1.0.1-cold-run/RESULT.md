# External cold-run result — PriorSeal exact-call matrix v1.0.1

Filled from `RESULT-TEMPLATE.md` (PriorSeal `d90e5d3`, PR #27). Raw command
output is in `run.log`; the captured runner output is `report.json`.

## Operator and independence

- Operator GitHub handle or chosen attribution: the maintainer of aos-standard/catalog (same operator as the v1.0.0 run in atlas#49)
- Relationship to PriorSeal / fixture author (if any): none; third party. Ran the v1.0.0 fixture independently on 2026-10-11 (atlas#49, `docs/runs/priorseal-exact-call-matrix-v1/`).
- Did you run this on a separate machine or environment from the author? `yes`
- Did you start from a fresh clone at the commit below? `yes`
- Was the expected output visible before the run? `yes` (it is published)
- Runner used: `published verify.mjs`
- Independent reader implementation used: `no` for this run. The v1.0.0 reader (`oel_exact_call_reader.py`) was not updated to the v1.0.1 contract and was not run here.

## Pinned input and environment

- Repository commit: `2ff89d86611257b4440232e5c2793926b3d52043`
- Contract version: `1.0.1`
- `git rev-parse HEAD` output: `2ff89d86611257b4440232e5c2793926b3d52043`
- Operating system and architecture: Ubuntu 22.04.5 LTS, Linux 6.8.0-111-generic, x86_64
- Node.js version: `v20.20.2` — **below the Node 22 the packet asks for**; reported as run, not adjusted
- npm version: `10.8.2`
- Exact commands run: the packet's block verbatim (`git clone` → `git checkout --detach 2ff89d8…` → `test` → `npm ci` → `node examples/open-evidence-lab-exact-call-matrix-v1/verify.mjs > report.json` → `cmp` → sha256), see `run.log`
- `npm ci` result: exit 0 (npm printed an audit notice; no install error)

## Observed result

- Runner exit code: `0`
- `summary.result`: `PASS`
- Cases passing / total: 6 / 6 (`envelopeBindingCases: 5`, `evidenceAvailabilityCases: 1`)
- Authorizer recovery matched declared signer: `yes` (per report)
- Acceptance signature valid: `yes` (per report)
- Authorization check passed: `yes` (per report)
- Output byte-identical to committed `report.json`: `yes` (`cmp` silent)
- SHA-256 of the captured runner output: `223db1554639f242eae559b1f010dcabe3e9466e610cfa95aefe2e1ce564a363` (equals the packet's listed value)
- Case 04 observed: reader `bound: true`, `mismatchCodes: []`, `availabilityCodes: ["EXECUTION_UNAVAILABLE"]`; profile `rawBinding.bound: false` with `EXECUTION_UNAVAILABLE` in `reasonCodes`, `partitionedBinding.bound: true`; `complianceStatus: NOT_ASSESSABLE`; `outcome: UNDETERMINED`
- Case 05 observed: `mismatchCodes: ["OUTSIDE_AUTHORIZATION_WINDOW", "OUTSIDE_TIME_WINDOW"]` (reader and profile); `complianceStatus: NON_COMPLIANT`
- Differences, warnings, or failure output: none. Working tree clean after the run (`git status --porcelain` empty).

## Disclosure and limits

- Local changes made before or during the run: none
- AI assistance used to prepare or interpret the run, if any: yes (Claude) — the commands were run and the result reviewed by the operator
- Anything that limits another operator's ability to reproduce it: `npm ci` needs registry access; Node version differs from the packet's stated minimum

This result concerns the pinned synthetic artifact and the environment
reported above. It does not establish real-chain behavior, production use,
adoption, integration, pilot, or endorsement.
