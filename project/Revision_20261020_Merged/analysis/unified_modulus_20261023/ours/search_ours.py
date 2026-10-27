"""Exact fixed-design minimum-modulus audit. No manuscript or old artifact writes.

Shared transferable gates: a smoothing multiplier derived from the same theta
inequality, a discrete-Gaussian MGF phase tail, source D_Z,r, and original ReRand
factor two. Scheme-specific evaluator, entropy and sparse gadget conditions are
retained. No estimator is run here; selected points need separate cost coverage.
"""
from __future__ import annotations
import argparse
from decimal import Decimal
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import platform
import sys
import time

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SOURCE = Path('/Users/Admin/Desktop/IBE/Revision_20261014_Polar/analysis/abla_borrowing_round2_20261016/experiments/round2_search_frozen_mixed.py')
spec = importlib.util.spec_from_file_location('read_only_round2', SOURCE)
old = importlib.util.module_from_spec(spec)
spec.loader.exec_module(old)
cs, cl = old.cs, old.cl
CONFIGS = {
    'C-MPK': dict(n=10072, r=8192, g=6, kH=80, kP=6, old_a=239),
    'C-Mid': dict(n=10864, r=8192, g=8, kH=80, kP=8, old_a=256),
    'C-CT': dict(n=11600, r=4096, g=10, kH=80, kP=9, old_a=270),
    'Q-MPK': dict(n=10848, r=8192, g=6, kH=80, kP=6, old_a=240),
    'Q-CT': dict(n=12480, r=4096, g=10, kH=80, kP=9, old_a=271),
}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def candidate_at_a(cfg, a):
    n, r, g, k, kp = (cfg[x] for x in ('n', 'r', 'g', 'kH', 'kP'))
    lower = max(16, k, kp, cl(r)+1)
    if a < lower:
        return dict(q_bits=a, status='DOMAIN_EXCLUDED', reasons=[
            reason for test, reason in [
                (a < 16, 'declared minimum exponent 16'),
                (a < k, 'honest entropy alphabet requires a >= kH'),
                (a < kp, 'proof entropy alphabet requires a >= kP'),
                (a < cl(r)+1, 'declared source-width domain a >= ceil_log2(r)+1')]
            if test])
    b, d, amp = 1 << g, (1 << g)-1, 1 << (k-1)
    T, u = 232, 52
    digits = (a+g-1)//g
    last = 1 << (a-g*(digits-1))
    w = n*digits
    Bh = 2*(T+8)+2*cl(w)+cl(k)+2
    barmin = max(n+Bh, (n*a+Bh+k-1)//k)
    m = old.align(w+barmin)
    fixed_point_steps = 0
    while True:
        Bp = 2*(T+8+cl(2*(u+1)*m))
        proofmin = max(n+1+Bp+1, ((n+1)*a+Bp+kp-1)//kp)
        newm = old.align(max(m, proofmin))
        fixed_point_steps += 1
        if newm == m:
            break
        m = newm
    bar, D, L = m-w, 2*m, d*w
    delta = 79848*L**3+79850*L**2+2*L

    def netK(p, cols):
        x = (3045*cols+694*(T+cl(2*(u+1))+2)+999)//1000
        return cs((50*(p+2*cs(p*x)+2*x)+80)//81)

    proof_amp = (1 << kp)-1
    var = (1 << (2*kp))-1
    KA0, KF0 = netK(m, w), netK(m, m)
    KA, KF = cs((var*KA0*KA0+2)//3), cs((var*KF0*KF0+2)//3)
    kap = max(KF, cs((m*KA*KA+w-1)//w))
    rho = kap*(delta+1)
    CR = proof_amp*cs(m)+cs((KA*KA*delta*delta+w-1)//w)
    Lsim = cs((b+1)**2*CR*CR+b*b+1)
    Lhon = cs((b*b+1)*(1+amp*amp*bar*w))
    theta = T+16+2+cl(D)+4
    h = 1
    while 3140*h*h <= 694*(theta+2):
        h += 1
    sigma = h*max(Lsim, Lhon)
    threshold = 4*r*r*(1+rho*rho)
    S = math.isqrt(threshold)+1
    keyK = (D+2*cs(D*202)+404+5)//6
    W2 = r*r+S*S*sigma*sigma*keyK
    lhs, rhs = 1 << (2*a), 652*W2
    checks = dict(
        source_floor=r*r >= 9*n, strict_worstcase_floor=r*r > 8*n,
        gadget_product_modulus=b**(digits-1)*last == 1 << a,
        mixed_last_radix_range=1 < last <= b,
        a_at_least_entropy_k=a >= max(k, kp),
        honest_first_term=bar >= n+Bh,
        honest_source_entropy=k*bar >= n*a+Bh,
        active_rows=m >= w,
        starting_column=KA*KA*L*L >= proof_amp*proof_amp*m*w,
        higher_first_term=m >= n+1+Bp+1,
        higher_collision_entropy=kp*m >= (n+1)*a+Bp,
        strict_rerand=S*S > threshold,
        finite_rerand=2*r*r >= T+cl(D)+8,
        modulus=lhs >= rhs,
        block_alignment=D % 256 == 0,
        theta=3140*h*h > 694*(theta+2),
    )
    return dict(
        status='FINITE_PASS' if all(checks.values()) else 'REJECT',
        failures=[k for k, v in checks.items() if not v],
        n=n, r=r, q_bits=a, q=str(1 << a), m=m, D=D, w=w, bar=bar,
        u=u, gadget_b=b, gadget_t=g, gadget_digit_length=digits,
        gadget_last_radix=last, mixed_last_radix=True,
        honest_entropy_k=k, proof_entropy_k=kp, honest_B=Bh, proof_B=Bp,
        honest_bar_threshold=barmin, proof_m_threshold=proofmin,
        fixed_point_steps=fixed_point_steps,
        L=str(L), delta=str(delta), KA=KA, KF=KF, kappa=kap,
        rho=str(rho), column_bound=str(CR), simulated_GS_bound=str(Lsim),
        honest_GS_bound=str(Lhon), sigma=str(sigma), S=str(S),
        key_h=h, key_theta_bits=theta, key_norm_factor=keyK, W2=str(W2),
        decryption_lhs=str(lhs), decryption_rhs=str(rhs),
        decryption_ratio=lhs/rhs,
        exact_reference_DFR_bits=lhs//(4*W2)-1,
        raw_complete_ciphertext_bytes=((D+1)*a+7)//8,
        MPK_bytes=(((u+2)*n*m+n)*a+7)//8,
        rho_log2=math.log2(rho), S_log2=math.log2(S), sigma_log2=math.log2(sigma),
        checks=checks,
        margins=dict(honest_first=bar-(n+Bh), honest_entropy=k*bar-(n*a+Bh),
                     proof_first=m-(n+1+Bp+1), proof_entropy=kp*m-((n+1)*a+Bp),
                     rerand=S*S-threshold, finite_rerand=2*r*r-(T+cl(D)+8),
                     smoothing=3140*h*h-694*(theta+2), decryption=lhs-rhs),
    )


def audit(name, cfg, certificate):
    ledger = []
    for a in range(1, cfg['old_a']+1):
        c = candidate_at_a(cfg, a)
        ledger.append(c)
        if c['status'] == 'FINITE_PASS':
            break
    else:
        raise RuntimeError(f'No passing modulus up to old exponent: {name}')
    selected = ledger[-1]
    reference = old.candidate(cfg['n'], str(cfg['r']), 1 << cfg['g'], cfg['kH'],
                              'higher', cfg['kP'], 'folded_rs8192', mixed=True)
    fields = ['n', 'r', 'q_bits', 'm', 'D', 'w', 'bar', 'rho', 'sigma', 'S',
              'KA', 'KF', 'kappa', 'honest_GS_bound', 'simulated_GS_bound', 'MPK_bytes']
    equality = {key: str(selected[key]) == str(reference[key]) for key in fields}
    assert all(equality.values()), equality
    old_point = candidate_at_a(cfg, cfg['old_a'])
    result = dict(name=name, configuration=cfg, selected=selected,
                  old_point=old_point, ledger=ledger,
                  independently_reimplemented_source_agreement=equality,
                  claim='minimum exponent among all admitted powers of two for this fixed design and these sufficient conditions',
                  estimator_status='NOT_RUN_NEW_POINT' if selected['q_bits'] != cfg['old_a'] else 'UNCHANGED_INPUT_REUSE_REQUIRES_SOURCE_HASH',
                  source_estimator_input_changed=any(selected[k] != old_point[k] for k in ['n', 'r', 'q_bits', 'm']))
    if name.startswith('C-'):
        saved_path = SOURCE.parent/('folded-rs8192-final-verified.json' if name == 'C-Mid' else 'selected-results.json')
        saved_data = json.loads(saved_path.read_text())
        selector = 'rows[0]' if name == 'C-Mid' else ('selected.MPK-priority' if name == 'C-MPK' else 'selected.CT-priority')
        saved = saved_data['rows'][0] if name == 'C-Mid' else saved_data['selected']['MPK-priority' if name == 'C-MPK' else 'CT-priority']
        same_input = {k: str(selected[k]) == str(saved['parameters'][k]) for k in ['n', 'r', 'q_bits', 'm']}
        if all(same_input.values()):
            assert saved['six_attack_status'] == 'PASS'
            assert len(saved['attacks']) == 6 and all(x['status'] == 'ok' and x['bits'] >= 128 for x in saved['attacks'])
            result['estimator_status'] = 'REUSED_VERIFIED_IDENTICAL_INPUT'
            result['saved_estimator_evidence'] = dict(source=str(saved_path), selector=selector,
                source_sha256=sha(saved_path), identical_input_fields=same_input,
                estimator_commit='53da5982597709ba0fdf94ea37a84d822310fd84',
                model='ADPS16 classical Core-SVP; primal GSA',
                distributions='UniformMod(q) secret; D_Z,r with sd r/sqrt(2pi); m+1 samples',
                minimum_finite_bits=saved['minimum_finite_bits'], attacks=saved['attacks'],
                note='Six saved finite attack results reused, not re-executed; BKW/Arora historical model-bound coverage is separate.')
    if certificate:
        pol = old.certify_safe(selected, 256)
        result['polar'] = pol
        from polar_certificate import certify_frozen_sets
        second = certify_frozen_sets(selected['q_bits'], 256, selected['S'], 170, selected['D'], 256, 150)
        assert pol['frozen_sets'] == second['frozen_sets']
        assert pol['compressed_bytes'] == second['compressed_bytes']
        result['precision_crosscheck'] = dict(decimal_digits=[110, 150], frozen_sets_equal=True,
                                              complete_bytes_equal=True, certificate150=second)
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--quantum', action='store_true')
    ap.add_argument('--no-certificates', action='store_true')
    args = ap.parse_args()
    rows = []
    for name, cfg in CONFIGS.items():
        if name.startswith('Q-') and not args.quantum:
            continue
        row = audit(name, cfg, not args.no_certificates)
        rows.append(row)
        c = row['selected']
        print(json.dumps(dict(name=name, old_a=cfg['old_a'], new_a=c['q_bits'], m=c['m'],
                              MPK_TiB=c['MPK_bytes']/2**40,
                              CT_bytes=row.get('polar', {}).get('compressed_bytes'),
                              lower_a_count=len(row['ledger'])-1)), flush=True)
    doc = dict(created_unix=time.time(), scope='deterministic finite-parameter and polar-reference-certificate audit; no IBE execution',
               common=dict(T=232, tail_bits=200, TG=162, reference_DFR_target_bits=160,
                           N=256, global_SC_budget_bits=170, seed_bits=256, query_log2=16,
                           ReRand_factor=2, target_base_LWE_bits=128),
               environment=dict(python=sys.version, platform=platform.platform()),
               source=dict(path=str(SOURCE), sha256=sha(SOURCE)), script_sha256=sha(__file__), rows=rows)
    outfile = HERE/('ours_quantum_formula_audit.json' if args.quantum else 'ours_modulus_audit.json')
    outfile.write_text(json.dumps(doc, indent=2, ensure_ascii=False)+'\n')


if __name__ == '__main__':
    main()
