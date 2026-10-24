#!/usr/bin/env python3
"""Cross-check: every Ed25519 signature the run decides, verified again by OpenSSL.

Usage: python3 -I xcheck_openssl.py <fixture_dir> <work_dir>
The signed bytes are e6_bill_check.jcs_bytes(payload); only the signature
arithmetic is replaced (openssl pkeyutl -verify -rawin).
"""
import base64
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

here = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('e6', here / 'e6_bill_check.py')
e6 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(e6)

F, W = Path(sys.argv[1]), Path(sys.argv[2])
W.mkdir(parents=True, exist_ok=True)


def pem(pub_hex, name):
    der = bytes.fromhex('302a300506032b6570032100' + pub_hex)
    p = W / (name + '.pem')
    p.write_text('-----BEGIN PUBLIC KEY-----\n' + base64.b64encode(der).decode() + '\n-----END PUBLIC KEY-----\n')
    return p


def openssl_ok(pem_path, env):
    (W / 'msg').write_bytes(e6.jcs_bytes(env['payload']))
    (W / 'sig').write_bytes(bytes.fromhex(env['signature']['sig']))
    r = subprocess.run(['openssl', 'pkeyutl', '-verify', '-pubin', '-inkey', str(pem_path), '-rawin',
                        '-in', str(W / 'msg'), '-sigfile', str(W / 'sig')], capture_output=True)
    return r.returncode == 0


def jsonl(p):
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()]


keys = json.loads((F / 'keys.json').read_text())
meter, root = keys['keys'][0]['public_key_hex'], keys['root']['public_key_hex']
pm, pr = pem(meter, 'meter'), pem(root, 'root')
items = [('receipt %d' % e['payload']['sequence'], pm, meter, e) for e in jsonl(F / 'receipts/chain.jsonl')]
items.append(('manifest', pm, meter, json.loads((F / 'manifest.json').read_text())))
items.append(('meter key certificate (root key)', pr, root, keys['keys'][0]['certificate']))
items.append(('case 12 manifest', pm, meter, json.loads((F / 'cases/12-manifest-signature-altered/manifest.json').read_text())))
items += [('case 07 receipt %d' % e['payload']['sequence'], pm, meter, e) for e in jsonl(F / 'cases/07-altered-receipt/chain.jsonl')]
items += [('case 08 receipt %d (pinned key)' % e['payload']['sequence'], pm, meter, e) for e in jsonl(F / 'cases/08-unexpected-signer/chain.jsonl')]
items.append(('case 08 manifest (pinned key)', pm, meter, json.loads((F / 'cases/08-unexpected-signer/manifest.json').read_text())))
tally, dis = {}, 0
for tag, pp, ph, env in items:
    a, b = e6.verify_envelope(ph, env), openssl_ok(pp, env)
    tally[(a, b)] = tally.get((a, b), 0) + 1
    if a != b:
        dis += 1
    if not (a and b):
        print('%-40s this reader=%s openssl=%s' % (tag, a, b))
print('signatures checked %d, disagreements %d, both valid %d, both invalid %d' % (
    len(items), dis, tally.get((True, True), 0), tally.get((False, False), 0)))
sys.exit(1 if dis else 0)
