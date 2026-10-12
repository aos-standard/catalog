// Feeds mutated observed envelopes (built by probe.py, not part of the fixture)
// to the two paths the fixture ships: the Lab reader and the PriorSeal profile.
// Usage: node probe.mjs <repo-root> <mutations.json>
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const [repo, mutationsPath] = process.argv.slice(2);
const dir = join(repo, "examples/open-evidence-lab-exact-call-matrix-v1");
const { bindEnvelope } = await import(pathToFileURL(join(dir, "reader.mjs")).href);
const { buildAuthorizedReceipt } = await import(pathToFileURL(join(repo, "src/index.mjs")).href);
const source = JSON.parse(readFileSync(join(dir, "fixture/signed-authorization.json"), "utf8"));
const mutations = JSON.parse(readFileSync(mutationsPath, "utf8"));
const sorted = (v) => [...new Set(v)].sort();
const out = {};
for (const [name, observed] of Object.entries(mutations)) {
  const entry = {};
  try {
    const r = bindEnvelope(source.authorization.intent, observed);
    entry.labReader = { bound: r.bound, reasonCodes: sorted(r.reasonCodes) };
  } catch (e) {
    entry.labReader = { error: String(e?.message ?? e) };
  }
  try {
    const receipt = buildAuthorizedReceipt({
      authorization: source.authorization,
      acceptance: source.acceptance,
      execution: observed,
      issuer: source.acceptance.issuer,
      keyId: source.acceptance.keyId,
      issuedAt: observed.observedAt ?? observed.executedAt ?? 1100,
    });
    entry.profile = {
      bound: receipt.binding.bound,
      reasonCodes: sorted(receipt.binding.reasonCodes),
      complianceStatus: receipt.compliance?.status ?? null,
      complianceReasonCodes: sorted(receipt.compliance?.reasonCodes ?? []),
      outcome: receipt.outcome,
    };
  } catch (e) {
    entry.profile = { error: String(e?.message ?? e).slice(0, 200) };
  }
  out[name] = entry;
}
console.log(JSON.stringify(out, null, 1));
