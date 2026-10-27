"""Read-only validation of exact search outputs; generated QA is written locally."""
from decimal import Decimal
import argparse
import hashlib
import json
import math
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def ceilroot(x):
    y = math.isqrt(x)
    return y+(y*y < x)


def check_row(row):
    c, cfg = row['selected'], row['configuration']
    n, r, a, m, D = (c[k] for k in ('n', 'r', 'q_bits', 'm', 'D'))
    q, S, sig, rho = (int(c[k]) for k in ('q', 'S', 'sigma', 'rho'))
    kH, kP, b, w, bar = (c[k] for k in ('honest_entropy_k', 'proof_entropy_k', 'gadget_b', 'w', 'bar'))
    ledger = row['ledger']
    assert [r['q_bits'] for r in ledger] == list(range(1, a+1))
    assert all(x['status'] == 'DOMAIN_EXCLUDED' for x in ledger[:79])
    assert all(x['status'] == 'REJECT' and x['failures'] == ['modulus'] for x in ledger[79:-1])
    assert all(c['checks'].values()) and c['status'] == 'FINITE_PASS'
    assert D == 2*m and q == 2**a and bar == m-w and D % 256 == 0
    assert w == n*((a+cfg['g']-1)//cfg['g'])
    assert b**(c['gadget_digit_length']-1)*c['gadget_last_radix'] == q
    assert bar >= n+c['honest_B'] and kH*bar >= n*a+c['honest_B']
    assert m >= n+1+c['proof_B']+1 and kP*m >= (n+1)*a+c['proof_B']
    assert S == math.isqrt(4*r*r*(1+rho*rho))+1
    assert sig == c['key_h']*max(int(c['honest_GS_bound']), int(c['simulated_GS_bound']))
    if 'honest_column_bound' in c:
        H = 1 << (kH-1)
        CH = H*ceilroot(bar)
        sparse = ceilroot((b+1)**2*CH*CH+b*b+1)
        full = ceilroot((b*b+1)*(1+H*H*bar*w))
        assert int(c['honest_column_bound']) == CH
        assert int(c['honest_GS_sparse_bound']) == sparse
        assert int(c['honest_GS_full_matrix_bound']) == full
        assert int(c['honest_GS_bound']) == min(sparse, full)
    assert c['key_h'] == 8
    t = c['key_theta_bits']
    assert 3140*8**2 > 694*(t+2) and 3140*7**2 <= 694*(t+2)
    keyK = (D+2*ceilroot(D*202)+404+5)//6
    V = r*r+S*S*sig*sig*keyK
    assert V == int(c['W2']) and q*q >= 652*V
    assert c['raw_complete_ciphertext_bytes'] == ((D+1)*a+7)//8
    assert c['MPK_bytes'] == ((54*n*m+n)*a+7)//8
    p = row['polar']
    expected = ((D+1)*a-(D//256)*p['frozen_bits_per_block']+256+7)//8
    assert expected == p['compressed_bytes']
    assert Decimal(p['combined_DFR_upper']) < Decimal(2)**(-160)
    assert Decimal(p['global_tv_upper']) < Decimal(2)**(-170)
    assert p['DFR_pass'] and p['savings_pass'] and p['lattice_layout_pass']
    assert row['precision_crosscheck']['frozen_sets_equal']
    assert row['precision_crosscheck']['complete_bytes_equal']
    return dict(name=row['name'], exhaustive_modulus_ledger=True,
                independently_checked_gates=True, exact_sizes=True, polar_reference_pass=True,
                previous_a=a-1, previous_ratio=ledger[-2]['decryption_ratio'],
                selected_a=a, selected_ratio=c['decryption_ratio'])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--shared', action='store_true')
    args = ap.parse_args()
    source = HERE/('ours_shared_column_audit.json' if args.shared else 'ours_modulus_audit.json')
    doc = json.loads(source.read_text())
    reuse = []
    qa = []
    for row in doc['rows']:
        qa.append(check_row(row))
        ev = row['saved_estimator_evidence']
        assert sha(ev['source']) == ev['source_sha256']
        c = row['selected']
        for attack in ev['attacks']:
            parsed = re.search(r'LWEParameters\(n=(\d+), q=(\d+),.*?, m=(\d+),', attack['input_repr'])
            assert parsed and tuple(map(int, parsed.groups())) == (c['n'], int(c['q']), c['m']+1)
            assert attack['status'] == 'ok' and attack['bits'] >= 128
        assert len(ev['attacks']) == 6
        assert min(x['bits'] for x in ev['attacks']) == ev['minimum_finite_bits']
        reuse.append(dict(name=row['name'], exact_input=dict(n=c['n'], q=c['q'], r=c['r'], m_samples=c['m']+1),
                          status='REUSED_VERIFIED_IDENTICAL_INPUT', evidence=ev))
    reuse_doc = dict(scope='Classical saved six-attack evidence reused only at identical narrow-source LWE inputs; no new attack execution',
                     source=str(source), source_sha256=sha(source),
                     estimator_commit='53da5982597709ba0fdf94ea37a84d822310fd84', rows=reuse)
    (HERE/'security-reuse.json').write_text(json.dumps(reuse_doc, indent=2, ensure_ascii=False)+'\n')
    qfile = HERE/('ours_shared_column_quantum_audit.json' if args.shared else 'ours_quantum_formula_audit.json')
    if qfile.exists():
        qdata = json.loads(qfile.read_text())
        for row in qdata['rows']:
            if row['name'].startswith('Q-'):
                qa.append(check_row(row))
    summary = dict(status='PASS', checks=qa, classical_reused_attack_count=18,
                   no_new_attacks_executed=True, verification_script_sha256=sha(__file__),
                   source_script_sha256_match=doc['script_sha256'] == sha(HERE/('search_shared_column.py' if args.shared else 'search_ours.py')))
    assert summary['source_script_sha256_match']
    (HERE/('shared-qa.json' if args.shared else 'qa.json')).write_text(json.dumps(summary, indent=2, ensure_ascii=False)+'\n')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
