#!/usr/bin/env python3
"""Proposed additions to test-vectors.json for four rules the text states and no vector exercises (mutation_battery.py
N2, N4, N5, N7). The e1_/pq1_ values are those of pathIdentifiers[0], which the reader reproduces."""
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__)); W = os.path.dirname(HERE)
run = json.load(open(os.path.join(W, "runs", "run_v2.json")))
p0 = next(x for x in run["pathIdentifiers"] if x["i"] == 0)
E1, PQ1 = p0["e1"], p0["pq1"]
bad_e1 = "e1_+" + E1[4:]  # same length, one character outside base64url
add = {
 "$comment": "Proposed additions, not part of the upstream file. Each value or input MUST be refused.",
 "invalidIdentifiers": [
  {"description": "uppercase method name (Method Name: the prefix MUST be lowercase did:atp:)", "value": "did:ATP:agents.example.com"},
  {"description": "e1_ fingerprint with a character outside base64url (ABNF base64url-char)", "value": f"did:atp:agents.example.com:billing:{bad_e1}:{PQ1}"},
  {"description": "path-type DID with no path segment before the bindings (ABNF 1*(\":\" path-segment))", "value": f"did:atp:agents.example.com:{E1}:{PQ1}"},
 ],
 "invalidPairwiseInputs": [
  {"description": "master secret of 31 bytes (Recommended Derivation: MUST be at least 32 bytes)", "domain": "agents.example.com",
   "masterSecretHex": "09" * 31, "peerId": "did:example:relying-party-1"},
 ],
}
with open(os.path.join(W, "proposed", "test-vectors-additions.json"), "w", encoding="utf-8") as f:
    json.dump(add, f, indent=2); f.write("\n")
