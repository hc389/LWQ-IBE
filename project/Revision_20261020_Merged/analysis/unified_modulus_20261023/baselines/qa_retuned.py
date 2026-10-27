"""Independent integer recomputation, no imports from the search generator."""
from __future__ import annotations
import functools
import hashlib
import json
import math
from pathlib import Path
import sys
from sage.all import ZZ, previous_prime

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent

def cs(x):return math.isqrt(x-1)+1 if x else 0
def cl(x):return (x-1).bit_length()
def align(x):return (x+127)//128*128
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()

@functools.lru_cache(None)
def prime(a):return int(previous_prime(ZZ(2)**a))

def inspect(c):
    n,r,a,m,q=c['n'],int(c['r']),c['q_bits'],c['m'],int(c['q'])
    issues=[]
    def equal(name,expected):
        if int(c[name])!=int(expected):issues.append(dict(field=name,expected=str(expected),actual=str(c[name])))
    equal('q',prime(a))
    isj=c['scheme']=='JKN21'
    if isj:
        count,b,mask=12,2,1
        expected_m=align(6*n*a+1)
        w=n*a;bar=m-w;beta=1+9*m;rho=m*(beta+1)
        C=(beta+1)*cs(m)
        equal('beta',beta)
        Gsim=min(5*(1+rho*rho),9*C*C+5)
        Ghon=min(5*(1+bar*w),9*cs(bar)**2+5)
        # Covers twelve public matrix blocks plus the public vector; extra
        # constants include T+8, the union count, and an additional 8-bit slack.
        joint_rhs=(n+1)*a+2*(232+8)+2*cl(12*m+1)+8
        joint_slack=m-joint_rhs
        structural=dict(source_dimension=n>=259,strict_m_gt_6na=m>6*n*a,
                        honest_entropy=bar>=n*a+480+2*cl(w))
    else:
        b=c['b'];mask=1 if b==2 else b;count=41
        k=(a+2) if b==2 else ((a+3)//4+2)
        w=n*k
        entropy=n*a+480+2*cl(w)
        bar0=(50*entropy+78)//79 if b==2 else (entropy+4)//5
        expected_m=align(w+bar0);bar=m-w
        B=(b-1)*cs(w*m);J=k*(b-1)
        nu=232+cl(40)+4
        x=(3045*m+694*nu+999)//1000
        K0=mask*cs((100*(m+2*cs(m*x)+2*x)+80)//81)
        E0=J;Eeq=E0*(1+6*B);Esel=128*J*Eeq
        delta=5*(B+65536)*(Esel+1);rho=K0*delta
        d=(b-1)*cs(w);C0=mask*cs(m)
        Ceq=K0*E0*(1+6*d);Csel=128*J*Ceq
        CR=5*(K0*(Esel+1)*d+65536*(Csel+C0));C=min(rho,CR)
        CH=mask*cs(bar)
        Gsim=min((b*b+1)*(1+rho*rho),(b+1)**2*C*C+b*b+1)
        Ghon=min((b*b+1)*(1+mask*mask*bar*w),(b+1)**2*CH*CH+b*b+1)
        for key,val in [('gadget_k',k),('entropy_target',entropy),('B',B),('J',J),
                        ('initial_K0',K0),('initial_x',x),('initial_nu',nu),
                        ('E0',E0),('Eeq',Eeq),('Esel',Esel),('delta',delta),
                        ('digit_column_bound',d),('starting_column_bound',C0),
                        ('equality_column_bound',Ceq),('selector_column_bound',Csel),
                        ('derived_column_bound',CR)]:equal(key,val)
        joint_rhs=(n+1)*a+480+2*cl(40*m)
        joint_slack=(79*m-50*joint_rhs) if b==2 else 5*m-joint_rhs
        structural=dict(eta_range=q>2,no_wrap_partition=q>5*65537**2,
                        partition_balance=12*(1<<16)*7**5<=128**5,
                        honest_entropy=(79*bar>=50*entropy if b==2 else 5*bar>=entropy))
        if b!=2:
            structural.update(mask_range=q>4*n*mask*mask,
                              gadget_digit_range=b**(k-3)<q<=b**(k-2))
    equal('m',expected_m);equal('w',w);equal('bar',bar);equal('rho',rho)
    equal('simulated_column_bound',C)
    equal('honest_column_bound',mask*cs(bar))
    equal('simulated_GS2',Gsim);equal('honest_GS2',Ghon)
    D=2*m;theta=232+16+2+cl(D)+4
    h=next(h for h in range(1,100) if 3140*h*h>694*(theta+2))
    sigma=h*cs(max(Gsim,Ghon));S=math.isqrt(4*r*r*(1+rho*rho))+1
    K=(D+2*cs(D*202)+404+5)//6
    W2=r*r+S*S*sigma*sigma*K
    lhs=(q-8)**2;rhs=652*W2
    for key,val in [('D',D),('key_theta_bits',theta),('key_h',h),('sigma',sigma),('S',S),
                    ('GS_squared_bound',max(Gsim,Ghon)),('key_norm_K',K),('W2',W2),
                    ('MGF_lhs',lhs),('MGF_rhs',rhs),('source_samples',m+1),
                    ('matrix_count',count),('raw_ciphertext_bytes',((D+1)*a+7)//8),
                    ('complete_ciphertext_bytes',((D+1)*a+7)//8),
                    ('MPK_bytes',(a*(count*n*m+n)+7)//8)]:equal(key,val)
    strengthened=dict(source_floor=r*r>=9*n,exact_ReRand=S*S>4*r*r*(1+rho*rho),
                      smoothing=3140*h*h>694*(theta+2),
                      finite_rerand=2*r*r>=232+cl(D)+8,
                      joint_LHL_strengthened=joint_slack>=0,
                      common_MGF=q>8 and lhs>=rhs,
                      actual_prime=q==prime(a))
    strengthened.update(structural)
    # Failing candidates are expected to violate MGF; the integer formulas
    # themselves must still match, and the strengthened LHL is tested for all a.
    return dict(formula_equalities_pass=not issues,issues=issues,
                joint_LHL_rhs=str(joint_rhs),joint_LHL_margin=str(joint_slack),
                joint_LHL_unit=('binary entropy bits' if isj else
                                ('79m-50rhs, scaled entropy bits' if b==2 else '5m-rhs, entropy bits')),
                strengthened_checks=strengthened)


def main():
    source=HERE.parent/'dimension_screen.json'
    d=json.loads(source.read_text())
    outputs=[]
    for c in d['selected']:
        kind='jkn' if c['scheme']=='JKN21' else ('ablaI' if c['variant']=='Type I' else 'ablaII')
        path=HERE/f'{kind}_retuned_common-ledger.json'
        led=json.loads(path.read_text());rows=led['rows']
        checks=[inspect(row) for row in rows]
        passed=inspect(c)
        assertions=dict(selected_matches_ledger=c==led['selected'],
                        contiguous_a=[z['q_bits'] for z in rows]==list(range(2,c['q_bits']+1)),
                        all_formulas_independently_match=all(z['formula_equalities_pass'] for z in checks),
                        all_lower_candidates_rejected=all(z['failures'] for z in rows[:-1]),
                        every_smaller_MGF_fails=all(not z['strengthened_checks']['common_MGF'] for z in checks[:-1]),
                        strengthened_joint_LHL_all_rows=all(z['strengthened_checks']['joint_LHL_strengthened'] for z in checks),
                        selected_all_finite_checks=all(c['finite_checks'].values()),
                        selected_all_strengthened_checks=all(passed['strengthened_checks'].values()))
        outputs.append(dict(profile=c['profile_id'],n=c['n'],r=c['r'],a=c['q_bits'],m=c['m'],
                            CT_bytes=c['raw_ciphertext_bytes'],MPK_bytes=c['MPK_bytes'],
                            CT_MiB=c['CT_MiB'],MPK_TiB=c['MPK_TiB'],
                            ledger_path=str(path),ledger_sha256=sha(path),
                            candidate_count=len(rows),selected_audit=passed,
                            previous_a=rows[-2]['q_bits'],previous_MGF_ratio=rows[-2]['MGF_ratio'],
                            previous_failures=rows[-2]['failures'],checks=assertions,
                            issues=[(rows[i]['q_bits'],x['issues']) for i,x in enumerate(checks) if x['issues']]))
    result=dict(status='PASS' if all(all(x['checks'].values()) for x in outputs) else 'FAIL',
                scope='Independent exact arithmetic QA; does not rerun lattice attacks or prove source lemmas',
                skill='Claude-Scholar/results-analysis reproducibility',
                inputs=dict(dimension_screen=str(source),dimension_screen_sha256=sha(source)),
                qa_script_sha256=sha(Path(__file__)),
                jkn_strengthened_union='m >= (n+1)a + 2(T+8) + 2ceil_log2(12m+1) + 8',
                note='Stronger union-margin check does not change q,m,n,r or ciphertext/MPK sizes; frozen search data retained.',
                selected=outputs)
    (HERE/'final-retuned-qa.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
