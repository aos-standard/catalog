#!/usr/bin/env python3
"""E6 receipt-to-bill consumer, written from the fixture README (v1.1.0) alone.

Not read: consumer/, producer/, test/, draft-farley-acta-signed-receipts-03 itself.
Standard library only. Ed25519 verification is written here from RFC 8032 5.1.7
(cofactorless, s < L, canonical point encodings required); JCS is written here
for the inputs this fixture has (objects, arrays, strings, integers, booleans, null;
a float raises). It does not call @veritasacta/verify, so the `keys` and
`signatures` claims rest on this file, not on that verifier.

Usage:
  python3 -I e6_bill_check.py <fixture_dir>            # all cases, compare with expected
  python3 -I e6_bill_check.py <fixture_dir> --json OUT # also write every result

Checks, per README "Claims" (codes are this reader's; where the README names a
reference code, that name is used):
  keys        root_fingerprint_mismatch | certificate_invalid | certificate_subject_mismatch
              | unexpected_signer | outside_key_window | verifier_unavailable
  signatures  invalid_signature | missing_link | chain_break | manifest_signature_invalid
              | verifier_unavailable
  scope       period_mismatch | manifest_mismatch | count_mismatch | sequence_mismatch
              | head_mismatch | root_mismatch | receipt_period_mismatch
  coverage_bill_to_receipts   unknown_receipt
  coverage_receipts_to_bill   unaccounted_receipt
  uniqueness  listed_twice_in_bill | billed_on_earlier_bill
  quantities  quantity_mismatch | not_billable | billing_class_mismatch
The four bill claims are NOT_EVALUATED unless keys, signatures and scope all PASS.
"""
import hashlib
import json
import sys
from pathlib import Path

# ---------- JCS (RFC 8785), for this fixture's value types ----------

def _jcs_str(s):
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == '\\':
            out.append('\\\\')
        elif o < 0x20:
            out.append({8: '\\b', 9: '\\t', 10: '\\n', 12: '\\f', 13: '\\r'}.get(o, '\\u%04x' % o))
        else:
            out.append(ch)
    out.append('"')
    return ''.join(out)


def _utf16_key(k):
    return k.encode('utf-16-be')


def jcs(v):
    if v is None:
        return 'null'
    if v is True:
        return 'true'
    if v is False:
        return 'false'
    if isinstance(v, int):
        if abs(v) > 2 ** 53:
            raise ValueError('integer beyond IEEE-754 exact range')
        return str(v)
    if isinstance(v, float):
        raise ValueError('float in input: this reader does not serialize floats')
    if isinstance(v, str):
        return _jcs_str(v)
    if isinstance(v, list):
        return '[' + ','.join(jcs(x) for x in v) + ']'
    if isinstance(v, dict):
        return '{' + ','.join(_jcs_str(k) + ':' + jcs(v[k]) for k in sorted(v, key=_utf16_key)) + '}'
    raise TypeError(type(v))


def jcs_bytes(v):
    return jcs(v).encode('utf-8')


def record_id(envelope):
    """README: sha256: + hex SHA-256 of the UTF-8 JCS of the whole envelope, signature included."""
    return 'sha256:' + hashlib.sha256(jcs_bytes(envelope)).hexdigest()


def key_fingerprint(pub_hex):
    return 'sha256:' + hashlib.sha256(bytes.fromhex(pub_hex)).hexdigest()

# ---------- Ed25519 verify (RFC 8032 5.1.7) ----------

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _recover_x(y, sign):
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _I % _P
    if (x * x - x2) % _P != 0:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


def _decode_point(b):
    if len(b) != 32:
        return None
    y = int.from_bytes(b, 'little')
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def _add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(s, p):
    q = (0, 1, 1, 0)
    while s:
        if s & 1:
            q = _add(q, p)
        p = _add(p, p)
        s >>= 1
    return q


def _eq(p, q):
    return (p[0] * q[2] - q[0] * p[2]) % _P == 0 and (p[1] * q[2] - q[1] * p[2]) % _P == 0


_GY = 4 * pow(5, _P - 2, _P) % _P
_G = (_recover_x(_GY, 0), _GY, 1, _recover_x(_GY, 0) * _GY % _P)


def ed25519_verify(pub, msg, sig):
    if len(pub) != 32 or len(sig) != 64:
        return False
    a = _decode_point(pub)
    r = _decode_point(sig[:32])
    if a is None or r is None:
        return False
    s = int.from_bytes(sig[32:], 'little')
    if s >= _L:
        return False
    k = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(), 'little') % _L
    return _eq(_mul(s, _G), _add(r, _mul(k, a)))


def verify_envelope(pub_hex, env):
    """README: Ed25519 over the JCS bytes of the payload alone, no pre-hash."""
    try:
        sig = bytes.fromhex(env['signature']['sig'])
    except (KeyError, TypeError, ValueError):
        return False
    return ed25519_verify(bytes.fromhex(pub_hex), jcs_bytes(env['payload']), sig)

# ---------- Merkle range root (RFC 6962) ----------

def _mth(leaves):
    n = len(leaves)
    if n == 1:
        return hashlib.sha256(b'\x00' + leaves[0]).digest()
    k = 1
    while k * 2 < n:
        k *= 2
    return hashlib.sha256(b'\x01' + _mth(leaves[:k]) + _mth(leaves[k:])).digest()


def range_root(ids):
    if not ids:
        return None
    return 'sha256:' + _mth([bytes.fromhex(i.split(':', 1)[1]) for i in ids]).hex()

# ---------- the consumer ----------

def _uniq(xs):
    out = []
    for x in xs:
        if x not in out:
            out.append(x)
    return out


def _in_window(ts, start, end):
    # All times in this fixture are ISO-8601 UTC with the same width, so string order is time order.
    return (start is None or ts >= start) and (end is None or ts < end)


def check(receipts, manifest, bill, keys, root_fingerprint, earlier_bills, verifier_available=True):
    claims, codes = {}, {}

    def put(name, cs, abstain=False):
        cs = _uniq(cs)
        claims[name] = 'ABSTAIN' if abstain else ('FAIL' if cs else 'PASS')
        if cs:
            codes[name] = cs

    records = receipts + [manifest]

    # keys
    kc = []
    root = keys.get('root', {})
    if not (key_fingerprint(root.get('public_key_hex', '')) == root_fingerprint == root.get('fingerprint')):
        kc.append('root_fingerprint_mismatch')
    meters = [k for k in keys.get('keys', []) if k.get('role') == 'meter']
    by_kid = {k['kid']: k for k in meters}
    if verifier_available:
        for k in meters:
            cert = k.get('certificate') or {}
            if not (cert.get('signature', {}).get('kid') == root.get('kid')
                    and verify_envelope(root.get('public_key_hex', ''), cert)):
                kc.append('certificate_invalid')
            subj = cert.get('payload', {}).get('subject', {})
            for f in ('kid', 'public_key_hex', 'fingerprint', 'valid_from', 'valid_until'):
                if subj.get(f) != k.get(f):
                    kc.append('certificate_subject_mismatch')
            if key_fingerprint(k['public_key_hex']) != k.get('fingerprint'):
                kc.append('certificate_subject_mismatch')
    for env in records:
        kid = env.get('signature', {}).get('kid')
        k = by_kid.get(kid)
        if k is None or env['payload'].get('issuer_id') != kid:
            kc.append('unexpected_signer')
        elif not _in_window(env['payload'].get('issued_at', ''), k.get('valid_from'), k.get('valid_until')):
            kc.append('outside_key_window')
    if not verifier_available and not kc:
        put('keys', ['verifier_unavailable'], abstain=True)
    else:
        put('keys', kc)

    # signatures: under the pinned meter key, whatever kid a record names
    sc = []
    if verifier_available:
        pinned = meters[0]['public_key_hex'] if len(meters) == 1 else None
        for i, env in enumerate(receipts):
            if pinned is None or not verify_envelope(pinned, env):
                sc.append('invalid_signature')
            if i > 0:
                link = env['payload'].get('previousReceiptHash')
                if link is None:
                    sc.append('missing_link')
                elif link != record_id(receipts[i - 1]):
                    sc.append('chain_break')
        if pinned is None or not verify_envelope(pinned, manifest):
            sc.append('manifest_signature_invalid')
        put('signatures', sc)
    else:
        put('signatures', ['verifier_unavailable'], abstain=True)

    # scope
    pc = []
    mp = manifest['payload']
    rng = mp.get('range', {})
    pid = mp.get('period', {}).get('id')
    if bill.get('period') != pid:
        pc.append('period_mismatch')
    if bill.get('manifest') != record_id(manifest):
        pc.append('manifest_mismatch')
    ids = [record_id(r) for r in receipts]
    if len(receipts) != rng.get('outcome_receipts', -1) + rng.get('correction_receipts', -1):
        pc.append('count_mismatch')
    seqs = [r['payload'].get('sequence') for r in receipts]
    if seqs != list(range(rng.get('first_sequence', 0), rng.get('last_sequence', -1) + 1)):
        pc.append('sequence_mismatch')
    head = ids[-1] if ids else None
    if rng.get('head') != head or mp.get('previousReceiptHash') != head:
        pc.append('head_mismatch')
    if rng.get('root') != range_root(ids):
        pc.append('root_mismatch')
    if any(r['payload'].get('period') != pid for r in receipts):
        pc.append('receipt_period_mismatch')
    put('scope', pc)

    bill_claims = ('coverage_bill_to_receipts', 'coverage_receipts_to_bill', 'uniqueness', 'quantities')
    if all(claims[c] == 'PASS' for c in ('keys', 'signatures', 'scope')):
        idset = set(ids)
        by_id = dict(zip(ids, receipts))
        lines = bill.get('lines', [])
        line_ids = [x for ln in lines for x in ln.get('receipts', [])]
        excl_ids = [e.get('receipt') for e in bill.get('exclusions', [])]
        named = line_ids + excl_ids
        put('coverage_bill_to_receipts', ['unknown_receipt' for x in named if x not in idset])
        nset = set(named)
        put('coverage_receipts_to_bill', ['unaccounted_receipt' for x in ids if x not in nset])
        uc = []
        if len(named) != len(nset):
            uc.append('listed_twice_in_bill')
        earlier = {x for b in earlier_bills for ln in b.get('lines', []) for x in ln.get('receipts', [])}
        if any(x in earlier for x in line_ids):
            uc.append('billed_on_earlier_bill')
        put('uniqueness', uc)
        qc = []
        for ln in lines:
            rs = ln.get('receipts', [])
            if ln.get('quantity') != len(rs):
                qc.append('quantity_mismatch')
            for x in rs:
                r = by_id.get(x)
                if r is None:
                    continue  # an unknown receipt is coverage_bill_to_receipts' finding
                oc = r['payload'].get('outcome', {})
                if oc.get('billable') is not True:
                    qc.append('not_billable')
                if oc.get('billing_class') != ln.get('billing_class'):
                    qc.append('billing_class_mismatch')
        put('quantities', qc)
    else:
        for c in bill_claims:
            claims[c] = 'NOT_EVALUATED'
    claims['amount'] = 'NOT_EVALUATED'

    ev = [claims[c] for c in ('keys', 'signatures', 'scope') + bill_claims]
    verdict = 'FAIL' if 'FAIL' in ev else ('PASS' if all(x == 'PASS' for x in ev) else 'ABSTAIN')
    order = ('keys', 'signatures', 'scope') + bill_claims + ('amount',)
    return {'verdict': verdict, 'claims': {c: claims[c] for c in order}, 'codes': codes, 'payment_ready': False}

# ---------- case runner ----------

def _read_json(p):
    return json.loads(Path(p).read_bytes().decode('utf-8'))


def _read_jsonl(p):
    return [json.loads(l) for l in Path(p).read_bytes().decode('utf-8').splitlines() if l.strip()]


def run_case(case_dir):
    case = _read_json(case_dir / 'case.json')
    inp = case['inputs']
    at = lambda rel: (case_dir / rel).resolve()
    got = check(
        receipts=_read_jsonl(at(inp['receipts'])),
        manifest=_read_json(at(inp['manifest'])),
        bill=_read_json(at(inp['bill'])),
        keys=_read_json(at(inp['keys'])),
        root_fingerprint=inp['root_fingerprint'],
        earlier_bills=[_read_json(at(p)) for p in inp.get('earlier_bills', [])],
        verifier_available=(inp.get('verifier') != 'unavailable'),
    )
    exp = case['expected']
    diff = []
    if got['verdict'] != exp['verdict']:
        diff.append('verdict')
    for c, v in exp['claims'].items():
        if got['claims'].get(c) != v:
            diff.append('claim:' + c)
    for c in set(exp.get('codes', {})) | set(got['codes']):
        if sorted(exp.get('codes', {}).get(c, [])) != sorted(got['codes'].get(c, [])):
            diff.append('codes:' + c)
    if got['payment_ready'] is not False or exp.get('payment_ready') is not False:
        diff.append('payment_ready')
    return case['case'], got, exp, diff


def main(argv):
    root = Path(argv[1])
    out = argv[argv.index('--json') + 1] if '--json' in argv else None
    results, agree = [], 0
    for d in sorted((root / 'cases').iterdir()):
        name, got, exp, diff = run_case(d)
        agree += not diff
        results.append({'case': name, 'got': got, 'expected': exp, 'differences': diff})
        codes = ';'.join('%s=%s' % (c, ','.join(v)) for c, v in got['codes'].items()) or '-'
        print('%-44s %-7s %s  %s' % (name, got['verdict'], 'AGREE' if not diff else 'DIFFER ' + ' '.join(diff), codes))
    print('agree %d/%d' % (agree, len(results)))
    if out:
        Path(out).write_text(json.dumps({'agree': agree, 'total': len(results), 'results': results}, indent=1) + '\n')
    return 0 if agree == len(results) else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv))
