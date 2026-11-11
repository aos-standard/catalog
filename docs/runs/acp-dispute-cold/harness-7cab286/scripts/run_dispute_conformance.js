#!/usr/bin/env node
/*
 * Runs examples/unreleased/dispute_resolution/conformance_cases.json against an implementation.
 *
 * The implementation is any command named in DISPUTE_PROVIDER_CMD. For each case, the harness writes the
 * case's `input` as one JSON object to the command's stdin and reads one JSON object from its stdout.
 * Only the keys that the case's `expect` names are compared, by deep equality; other keys are ignored.
 * Nothing here is a reference implementation: the harness decides nothing itself.
 *
 *   DISPUTE_PROVIDER_CMD="python3 my_provider.py" node scripts/run_dispute_conformance.js [cases.json]
 *
 * Exit code: 0 if every case agrees, 1 otherwise, 2 on a usage error. Add --json for a machine-readable report.
 * CC0.
 */
'use strict';
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const args = process.argv.slice(2);
const asJson = args.includes('--json');
const casesPath = args.find((a) => !a.startsWith('--')) ||
  path.join(__dirname, '..', 'examples', 'unreleased', 'dispute_resolution', 'conformance_cases.json');
const cmd = process.env.DISPUTE_PROVIDER_CMD;
if (!cmd) {
  console.error('Set DISPUTE_PROVIDER_CMD to the command that decides one case (input on stdin, JSON on stdout).');
  process.exit(2);
}

function canonical(v) {
  if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
  if (v && typeof v === 'object') {
    return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canonical(v[k])).join(',') + '}';
  }
  return JSON.stringify(v);
}

const file = JSON.parse(fs.readFileSync(casesPath, 'utf8'));
const rows = [];
for (const c of file.cases) {
  const r = spawnSync(cmd, { shell: true, input: JSON.stringify(c.input), encoding: 'utf8', timeout: 30000 });
  let got = null;
  let error = null;
  if (r.error) error = String(r.error);
  else if (r.status !== 0) error = `exit ${r.status}: ${(r.stderr || '').trim().slice(0, 200)}`;
  else {
    try { got = JSON.parse(r.stdout); } catch (e) { error = 'stdout is not one JSON object'; }
  }
  const diffs = {};
  if (!error) {
    for (const [k, v] of Object.entries(c.expect)) {
      if (canonical(got[k]) !== canonical(v)) diffs[k] = { expected: v, got: got[k] === undefined ? null : got[k] };
    }
  }
  rows.push({ id: c.id, agree: !error && Object.keys(diffs).length === 0, error, diffs });
}

const agree = rows.filter((r) => r.agree).length;
if (asJson) {
  console.log(JSON.stringify({ cases: path.basename(casesPath), n: rows.length, agree, rows }, null, 1));
} else {
  for (const r of rows.filter((x) => !x.agree)) {
    console.log(`DIFFER ${r.id}: ${r.error || JSON.stringify(r.diffs)}`);
  }
  console.log(`${agree} of ${rows.length} cases agree`);
}
process.exit(agree === rows.length ? 0 : 1);
