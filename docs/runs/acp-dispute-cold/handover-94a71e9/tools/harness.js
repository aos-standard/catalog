// Runs validateDisputeConformanceCases() alone, with the same error()/success() shape as validate-consistency.js.
// Usage: NODE_PATH=<dir with ajv, ajv-formats> node harness.js <repo-like root> <fn.js>
const fs = require('fs');
const path = require('path');
const Ajv = require('ajv');
const addFormats = require('ajv-formats');
const root = process.argv[2];
const errors = [];
function error(msg, ctx) { errors.push(msg); console.log('❌ ' + msg + (ctx && ctx.errors ? ' ' + JSON.stringify(ctx.errors).slice(0, 300) : '')); }
function success(msg) { console.log('✅ ' + msg); }
const __dirname_fake = path.join(root, 'scripts');
const src = fs.readFileSync(process.argv[3], 'utf8');
new Function('fs', 'path', 'Ajv', 'addFormats', 'error', 'success', '__dirname', src + '\nvalidateDisputeConformanceCases();')(
  fs, path, Ajv, addFormats, error, success, __dirname_fake);
console.log('errors', errors.length);
process.exit(errors.length ? 1 : 0);
