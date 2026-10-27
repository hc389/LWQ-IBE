"""Unified sparse-column GS protocol, layered on the frozen legacy audit.

Uses a deterministic honest mask column bound H_H ceil(sqrt(bar m)); the
two-coordinate gadget lift bound applies to the honest and simulated sides.
This tightens a sufficient analysis without changing masks or distributions.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import sys
import time

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('frozen_ours_audit', HERE/'search_ours.py')
legacy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(legacy)


def at_a(cfg, a):
    c = legacy.candidate_at_a(cfg, a)
    if c['status'] == 'DOMAIN_EXCLUDED':
        return c
    b = c['gadget_b']
    H = 1 << (c['honest_entropy_k']-1)
    C_H = H*legacy.cs(c['bar'])
    honest_sparse = legacy.cs((b+1)**2*C_H*C_H+b*b+1)
    honest_old = int(c['honest_GS_bound'])
    honest = min(honest_old, honest_sparse)
    sigma = c['key_h']*max(honest, int(c['simulated_GS_bound']))
    V = c['r']**2+int(c['S'])**2*sigma*sigma*c['key_norm_factor']
    lhs, rhs = 1 << (2*a), 652*V
    c.update(honest_GS_bound=str(honest), honest_GS_full_matrix_bound=str(honest_old),
             honest_column_bound=str(C_H), honest_GS_sparse_bound=str(honest_sparse),
             shared_protocol='sparse gadget-column GS on both trapdoor sides; min with valid full-matrix bound',
             sigma=str(sigma), sigma_log2=math.log2(sigma), W2=str(V),
             decryption_lhs=str(lhs), decryption_rhs=str(rhs), decryption_ratio=lhs/rhs,
             exact_reference_DFR_bits=lhs//(4*V)-1)
    c['checks']['modulus'] = lhs >= rhs
    c['margins']['decryption'] = lhs-rhs
    c['failures'] = [name for name, value in c['checks'].items() if not value]
    c['status'] = 'FINITE_PASS' if not c['failures'] else 'REJECT'
    return c


def audit(name, cfg, oldrow):
    rows = []
    for a in range(1, cfg['old_a']+1):
        c = at_a(cfg, a)
        rows.append(c)
        if c['status'] == 'FINITE_PASS':
            break
    else:
        raise RuntimeError(f'No passing point: {name}')
    c = rows[-1]
    pol = legacy.old.certify_safe(c, 256)
    from polar_certificate import certify_frozen_sets
    second = certify_frozen_sets(c['q_bits'], 256, c['S'], 170, c['D'], 256, 150)
    assert pol['frozen_sets'] == second['frozen_sets'] and pol['compressed_bytes'] == second['compressed_bytes']
    source_same = {key: str(c[key]) == str(oldrow['selected'][key]) for key in ('n', 'r', 'q_bits', 'm')}
    row = dict(name=name, configuration=cfg, selected=c, old_point=oldrow['selected'], ledger=rows,
               claim='minimum power-of-two modulus exponent for fixed design under shared-column finite analysis',
               source_estimator_input_changed=not all(source_same.values()),
               estimator_status='NOT_REEXECUTED_SUPPLEMENTAL_QUANTUM' if name.startswith('Q-') else 'NEW_ESTIMATE_REQUIRED',
               finite_legacy_vs_shared_input_equality=source_same, polar=pol,
               precision_crosscheck=dict(decimal_digits=[110,150], frozen_sets_equal=True,
                                        complete_bytes_equal=True, certificate150=second))
    if name.startswith('C-') and all(source_same.values()):
        row['saved_estimator_evidence'] = oldrow['saved_estimator_evidence']
        row['estimator_status'] = 'REUSED_VERIFIED_IDENTICAL_INPUT'
    return row


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--quantum', action='store_true')
    args = ap.parse_args()
    oldpath = HERE/('ours_quantum_formula_audit.json' if args.quantum else 'ours_modulus_audit.json')
    old = json.loads(oldpath.read_text())
    rows = []
    for oldrow in old['rows']:
        row = audit(oldrow['name'], oldrow['configuration'], oldrow)
        rows.append(row)
        c = row['selected']
        print(json.dumps(dict(name=row['name'], a=c['q_bits'], m=c['m'],
                              CT_bytes=row['polar']['compressed_bytes'], MPK_TiB=c['MPK_bytes']/2**40,
                              estimator_status=row['estimator_status'])), flush=True)
    doc = dict(created_unix=time.time(), scope='shared finite-bound deterministic search and reference polar certificates; no full IBE execution',
               shared_protocol='same MGF/key-tail/smoothing/ReRand budgets, sparse gadget columns on both trapdoor sides',
               fixed=old['common'], script_sha256=legacy.sha(__file__),
               frozen_legacy_script_sha256=legacy.sha(HERE/'search_ours.py'),
               legacy_result_source=str(oldpath), legacy_result_sha256=legacy.sha(oldpath), rows=rows)
    dest = HERE/('ours_shared_column_quantum_audit.json' if args.quantum else 'ours_shared_column_audit.json')
    dest.write_text(json.dumps(doc, indent=2, ensure_ascii=False)+'\n')


if __name__ == '__main__':
    main()
