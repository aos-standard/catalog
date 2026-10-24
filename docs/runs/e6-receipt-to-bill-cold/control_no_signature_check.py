#!/usr/bin/env python3
"""Control: the same reader with every signature check replaced by True.

Usage: python3 -I control_no_signature_check.py <fixture_dir>
Expected: case 12 turns into PASS (the case only a signature check catches).
"""
import importlib.util
import sys
from pathlib import Path

here = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('e6', here / 'e6_bill_check.py')
e6 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(e6)
e6.verify_envelope = lambda pub_hex, env: True
for d in sorted((Path(sys.argv[1]) / 'cases').iterdir()):
    name, got, exp, diff = e6.run_case(d)
    print('%-44s %-7s %s' % (name, got['verdict'], 'AGREE' if not diff else 'DIFFER ' + ' '.join(diff)))
