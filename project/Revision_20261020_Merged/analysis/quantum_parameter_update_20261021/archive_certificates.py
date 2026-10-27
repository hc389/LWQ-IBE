"""Recompute and preserve the two already selected certificates; no attack search.

Generated JSON contains the full frozen-index lists, exact parameters and budgets.
The original parameter generator and certificate implementation are read-only.
"""
import sys
sys.dont_write_bytecode = True
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path('/Users/Admin/Desktop/IBE')
SOURCE = ROOT / 'Revision_20261014_Polar/analysis/abla_borrowing_round2_20261016/experiments/round2_search_frozen_mixed.py'
OUT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('frozen_parameter_source', SOURCE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
for label, n, r, b, kp, raw, short, mpk in [
    ('Q-MPK', 10848, '8192', 64, 6, 27993630, 14091177, 8199213791040),
    ('Q-CT', 12480, '4096', 1024, 9, 26545026, 13595498, 8944600927080),
]:
    p = mod.candidate(n, r, b, 80, 'higher', kp, 'folded_rs8192', mixed=True)
    c = mod.old.certify(p, 256)
    assert c['raw_bytes'] == raw and c['compressed_bytes'] == short
    assert p['MPK_bytes'] == mpk
    assert c['DFR_pass'] and c['savings_pass'] and c['lattice_layout_pass']
    assert 'frozen_sets' in c and c['frozen_sets']
    record = {
        'scope': 'Reproduction of the already selected parameter/certificate calculation, not a new attack run or encryption execution',
        'source': str(SOURCE),
        'source_sha256': hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        'parameters': p, 'certificate': c,
    }
    target = OUT / (label + '-full-certificate.json')
    target.write_text(json.dumps(record, indent=2, ensure_ascii=False) + '\n')
    print(label, 'PASS', 'bytes', short, 'full_certificate', target.name,
          'sha256', hashlib.sha256(target.read_bytes()).hexdigest())
