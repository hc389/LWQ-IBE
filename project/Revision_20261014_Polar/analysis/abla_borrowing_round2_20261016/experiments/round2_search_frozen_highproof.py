"""Claude-Scholar round-2 bounded experiments; ARS LHL interfaces supplied upstream.

Only honest TrapGen source entropy and gadget radix vary. Yamada FMAH, u360,
proof-side binary-difference masks, original ReRand factor2 and q=2^a remain.
"""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor,as_completed
from decimal import Decimal
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import time

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
ORIGINAL=ROOT/'analysis/baseline_mpk_128_20261015/ours/continuous_width_search.py'
spec=importlib.util.spec_from_file_location('readonly_round1',ORIGINAL)
old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
cs,cl=old.ceil_sqrt,old.ceil_log2
BASES=[4,8,16,32,64]
K_GRID=[1,2,3,4,5]
R_GRID=['floor','512','1384','4096']
assert 2**1585>3**1000  # log2(8/3)>1.415, exact integer check.

def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def save(d,name):(HERE/name).write_text(json.dumps(d,indent=2,ensure_ascii=False)+'\n')
def align(x):return ((x+127)//128)*128


def candidate(n,r_policy,b,k,profile='exact',proof_k=1):
    if b not in BASES or k not in K_GRID:raise ValueError('Outside recorded base/entropy grid')
    if profile not in ['old','exact','higher']:raise ValueError(profile)
    if profile!='higher' and proof_k!=1:raise ValueError('Old/exact profiles keep binary differences')
    if profile=='higher' and proof_k not in [2,3,4,5]:raise ValueError(proof_k)
    n=int(n);r=cs(9*n) if str(r_policy)=='floor' else int(r_policy)
    if r*r<9*n:return None
    g=b.bit_length()-1;d=b-1;amp=1<<(k-1)
    T,u,eta,ell,zeta=232,360,30,2047,12
    for a in range(max(16,k,cl(r)+1),cl(r)+450):
        if a%g:continue
        w=n*(a//g)
        Bh=2*(T+8)+2*cl(w)+cl(k)+2
        barmin=max(n+Bh,(n*a+Bh+k-1)//k)
        m=align(w+barmin)
        while True:
            M=(u+1)*m
            Bp=2*(T+8)+2*cl(M)+4
            if profile=='old':proofmin=(n+1)*a+2*T+2*cl(M)+8
            elif profile=='exact':proofmin=max(n+1+Bp,(1000*((n+1)*a+Bp)+1414)//1415)
            else:
                Bp=2*(T+8+cl(2*(u+1)*m))
                proofmin=max(n+1+Bp+1,((n+1)*a+Bp+proof_k-1)//proof_k)
            newm=align(max(m,proofmin))
            if newm==m:break
            m=newm
        bar,D=m-w,2*m
        L=d*w
        delta=171931*L**3+6197*L**2+2*L
        def netK(p,cols):
            x=(3045*cols+694*(T+cl(2*(u+1))+2)+999)//1000
            return cs((50*(p+2*cs(p*x)+2*x)+80)//81)
        proof_amp=(1<<proof_k)-1
        KA,KF=proof_amp*netK(m,w),proof_amp*netK(m,m)
        # General b: digit vector length <=(b-1)sqrt(w), all starting columns
        # length <=sqrt(m); this is the exact condition used by the old proof.
        assert KA*KA*L*L>=proof_amp*proof_amp*m*w
        kap=max(KF,cs((m*KA*KA+w-1)//w))
        rho=kap*(delta+1)
        CR=proof_amp*cs(m)+cs((KA*KA*delta*delta+w-1)//w)
        Lsim=cs((b+1)**2*CR*CR+b*b+1)
        Lhonest=cs((b*b+1)*(1+amp*amp*bar*w))
        theta=T+16+2+cl(D)+4
        h=1
        while 3140*h*h<=694*(theta+2):h+=1
        sigma=h*max(Lsim,Lhonest)
        threshold=4*r*r*(1+rho*rho)
        S=math.isqrt(threshold)+1
        keyK=(D+2*cs(D*202)+404+5)//6
        W2=r*r+S*S*sigma*sigma*keyK
        if 1<<(2*a)<4*163*W2:continue
        checks=dict(source_floor=r*r>=9*n,strict_worstcase_floor=r*r>8*n,
                    q_base_alignment=a%g==0,a_at_least_entropy_k=a>=k,
                    honest_first_term=bar>=n+Bh,honest_source_entropy=k*bar>=n*a+Bh,
                    active_rows=m>=w,starting_column=KA*KA*L*L>=proof_amp*proof_amp*m*w,
                    full_old_clamp=m>=(n+1)*a+2*T+2*cl((u+1)*m)+8,
                    exact_first_term=m>=n+1+Bp,
                    exact_collision_entropy=1415*m>=1000*((n+1)*a+Bp),
                    higher_first_term=m>=n+1+Bp+1,
                    higher_collision_entropy=proof_k*m>=(n+1)*a+Bp,
                    strict_rerand=S*S>threshold,finite_rerand=2*r*r>=T+cl(D)+8,
                    modulus=(1<<(2*a))>=4*163*W2,
                    block_alignment=D%256==0,theta=3140*h*h>694*(theta+2))
        gate_names={'full_old_clamp','exact_first_term','exact_collision_entropy','higher_first_term','higher_collision_entropy'}
        applicable={'old':{'full_old_clamp'},'exact':{'exact_first_term','exact_collision_entropy'},
                    'higher':{'higher_first_term','higher_collision_entropy'}}[profile]
        diagnostics={key:checks[key] for key in gate_names}
        checks={key:value for key,value in checks.items() if key not in gate_names or key in applicable}
        assert all(checks.values()),checks
        mpk=((362*n*m+n)*a+7)//8
        return dict(n=n,r=r,r_policy=str(r_policy),gadget_b=b,gadget_t=g,
                    honest_entropy_k=k,honest_mask_min=-(1<<(k-1)),
                    honest_mask_max=(1<<(k-1))-1,honest_mask_maxabs=amp,
                    honest_trapgen=f'uniform centered {1<<k}-point integers',
                    proof_mask=('unchanged independent binary difference' if proof_k==1 else
                                f'difference of independent uniform {1<<proof_k}-point integers'),
                    proof_entropy_k=proof_k,proof_mask_maxabs=proof_amp,proof_entropy_profile=profile,
                    honest_B=Bh,proof_B=Bp,honest_bar_threshold=barmin,proof_m_threshold=proofmin,
                    q_bits=a,q=str(1<<a),m=m,D=D,w=w,bar=bar,u=u,eta=eta,ell=ell,zeta=zeta,
                    L=str(L),delta=str(delta),KA=KA,KF=KF,kappa=kap,rho=str(rho),
                    sigma=str(sigma),S=str(S),Smin=str(S),s_policy='integer',h_policy='theta',
                    norm_policy='one_net',column_bound=str(CR),simulated_GS_bound=str(Lsim),
                    honest_GS_bound=str(Lhonest),key_h=h,key_theta_bits=theta,
                    inside_stat_budget_bits=T,query_log2=16,keynorm_tail_bits=200,
                    checks=checks,alternative_gate_diagnostics=diagnostics,
                    exact_reference_DFR_bits=(1<<(2*a))//(4*W2)-1,
                    raw_complete_ciphertext_bytes=((D+1)*a+7)//8,
                    MPK_bytes=mpk,MPK_TiB=mpk/2**40,S_log2=math.log2(S),
                    sigma_log2=math.log2(sigma),r_log2=math.log2(r),
                    honest_GS_dominates=Lhonest>=Lsim)
    raise RuntimeError('No modulus')


def metadata():
    return dict(date='2026-10-16',scope='Deterministic finite parameter screen, no full IBE execution',
                skill='Claude-Scholar results-analysis and reproducibility',command=sys.argv,
                script_sha256=sha(__file__),readonly_dependency=str(ORIGINAL),dependency_sha256=sha(ORIGINAL),
                estimator_commit=subprocess.check_output(['git','-C',str(old.EST),'rev-parse','HEAD'],text=True).strip(),
                sage_version=subprocess.check_output(['/usr/local/bin/sage','--version'],text=True).strip(),
                environment=dict(python=sys.version,platform=platform.platform(),randomness='none'),
                exact_rational_constant=dict(log2_8over3_lower='1415/1000',integer_verified=2**1585>3**1000),
                fixed=dict(ell=2047,eta=30,zeta=12,u=360,Q=65536,T=232,keytail_bits=200,
                           reference_DFR_target=160,base_LWE_target=128,ReRand_factor=2,
                           cost_model='ADPS16 classical Core-SVP',shape='GSA',polar_N=256),rows=[],gates=[])


def screen(quick=False,higher_quick=False):
    doc=metadata();cache={}
    name='higher-quick-screen.json' if higher_quick else ('quick-screen.json' if quick else 'screen.json')
    seed=HERE/'quick-screen.json'
    if not quick and not higher_quick and seed.exists():
        seeddata=json.loads(seed.read_text());doc['seed_sha256']=sha(seed)
        for c in seeddata['rows']:
            cache[c['n'],c['r_policy'],c['gadget_b'],c['honest_entropy_k'],c['proof_entropy_profile'],c.get('proof_entropy_k',1)]=c
            doc['rows'].append(c)
    def ev(n,r,b,k,profile,proof_k):
        key=n,str(r),b,k,profile,proof_k
        if key not in cache:
            c=candidate(n,r,b,k,profile,proof_k)
            if c is None:return None
            c['usvp']=old.attack(c,'usvp');cache[key]=c;doc['rows'].append(c)
        return cache[key]
    if higher_quick:configs=[('higher',b,5,'512',kp) for b in [16,32,64] for kp in [3,4]]
    elif quick:configs=[('exact',4,5,r,1) for r in ['512','1384','4096']]
    else:
        configs=[('exact',b,k,r,1) for b in BASES for k in K_GRID for r in ['floor','512','1384']]
        configs += [('old',b,k,'512',1) for b in BASES for k in K_GRID]
        configs += [('higher',b,k,r,kp) for b in BASES for k in [3,5] for r in ['512','1384'] for kp in [2,3,4]]
    doc['config_grid']=[dict(profile=p,b=b,k=k,r=r,proof_k=kp) for p,b,k,r,kp in configs]
    for ix,(profile,b,k,r,proof_k) in enumerate(configs):
        lo,hi=6000,15000
        if r!='floor':hi=min(hi,int(r)**2//9)
        upper=ev(hi,r,b,k,profile,proof_k)
        if not upper or upper['usvp'].get('status')!='ok' or upper['usvp'].get('bits',0)<128:
            doc['gates'].append(dict(profile=profile,b=b,k=k,r=r,status='NO_PASSING_UPPER'))
            save(doc,name);continue
        while hi-lo>16:
            mid=((hi+lo)//32)*16
            if mid<=lo:mid=lo+1
            c=ev(mid,r,b,k,profile,proof_k)
            if not c or c['usvp'].get('status')!='ok':raise RuntimeError('Bad in-process attack screen')
            if c['usvp']['bits']>=128:hi=mid
            else:lo=mid
        near=[ev(n,r,b,k,profile,proof_k) for n in range(max(6000,lo-8),hi+17,8)]
        good=[c for c in near if c and c['usvp'].get('status')=='ok' and c['usvp']['bits']>=128]
        best=min(good,key=lambda c:c['MPK_bytes']);doc['gates'].append(best)
        passing=[c for c in doc['rows'] if c['usvp'].get('status')=='ok' and c['usvp'].get('bits',0)>=128]
        doc['best_screened']=sorted(passing,key=lambda c:c['MPK_bytes'])[:20]
        if ix%10==0 or quick:save(doc,name)
        print(json.dumps(dict(i=ix,total=len(configs),profile=profile,b=b,k=k,proof_k=proof_k,r=r,n=best['n'],
                              a=best['q_bits'],m=best['m'],MPK_TiB=best['MPK_TiB'],bits=best['usvp']['bits'])),flush=True)
    doc['finished_unix']=time.time();save(doc,name)


def job(c,name,case,timeout):
    cf=case/'candidate.json'
    assert json.loads(cf.read_text())==c
    cmd=['/usr/local/bin/sage','-python',str(Path(__file__).resolve()),'--worker',name,str(cf)]
    began=time.time();proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
    try:
        out,err=proc.communicate(timeout=timeout)
        lines=[x for x in out.splitlines() if x.startswith('RESULT_JSON=')]
        result=json.loads(lines[-1].split('=',1)[1]) if lines else dict(status='worker_failed')
        if proc.returncode!=0:result['status']='worker_failed'
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid,signal.SIGTERM)
        try:out,err=proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:os.killpg(proc.pid,signal.SIGKILL);out,err=proc.communicate()
        result=dict(status='timeout')
    sf,ef=case/f'{name}.stdout.txt',case/f'{name}.stderr.txt'
    sf.write_text(out);ef.write_text(err)
    result.update(attack=name,wall_seconds=time.time()-began,command=cmd,exit_code=proc.returncode,
                  stdout_path=str(sf),stderr_path=str(ef),stdout_sha256=sha(sf),stderr_sha256=sha(ef),
                  candidate_sha256=sha(cf))
    return result


def battery(source,output,limit,timeout):
    ss=json.loads(source.read_text());good=[c for c in ss['rows'] if c.get('usvp',{}).get('status')=='ok' and c['usvp']['bits']>=128]
    if limit==1:chosen=[min(good,key=lambda c:c['MPK_bytes'])]
    else:
        chosen=[]
        for profile in ['exact','old']:
            sub=[c for c in good if c['proof_entropy_profile']==profile]
            if sub:chosen.append(min(sub,key=lambda c:c['MPK_bytes']))
        for c in sorted(good,key=lambda c:c['MPK_bytes']):
            if len(chosen)>=limit:break
            if not any(c['gadget_b']==x['gadget_b'] and c['proof_entropy_profile']==x['proof_entropy_profile'] for x in chosen):chosen.append(c)
    dest=HERE/output
    if dest.exists():raise RuntimeError('Refuse to overwrite existing completed/partial battery; choose a new output name')
    doc=metadata();doc['source_screen_sha256']=sha(source);doc['rows']=[]
    work=[]
    for i,c in enumerate(chosen):
        case=HERE/'logs'/Path(output).stem/f'point-{i:02d}';case.mkdir(parents=True,exist_ok=True)
        cf=case/'candidate.json';cf.write_text(json.dumps(c,indent=2)+'\n')
        row=dict(parameters=c,attacks=[],polar=old.certify(c),frozen_candidate_sha256=sha(cf));doc['rows'].append(row)
        work += [(i,c,name,case) for name in ['usvp','bdd','dual','dual_hybrid','bdd_hybrid','mitm']]
    save(doc,output)
    with ThreadPoolExecutor(max_workers=2) as pool:
        fs={pool.submit(job,c,name,case,timeout):i for i,c,name,case in work}
        for f in as_completed(fs):
            i=fs[f];rr=f.result();doc['rows'][i]['attacks'].append(rr);save(doc,output)
            print(json.dumps(dict(row=i,attack=rr['attack'],status=rr.get('status'),bits=rr.get('bits'))),flush=True)
    for row in doc['rows']:
        finite=[a['bits'] for a in row['attacks'] if a.get('status')=='ok' and math.isfinite(a.get('bits',math.nan))]
        row['minimum_finite_bits']=min(finite) if finite else None
        row['six_attack_status']='PASS' if len(finite)==6 and min(finite)>=128 else 'PARTIAL_OR_FAIL'
    save(doc,output)


def quantizers(verified,out):
    ss=json.loads(verified.read_text());good=[r for r in ss['rows'] if r.get('six_attack_status')=='PASS' and r['polar']['DFR_pass'] and r['polar']['savings_pass']]
    best=min(good,key=lambda r:r['parameters']['MPK_bytes']);c=best['parameters']
    doc=metadata();doc['parameters']=c;doc['source_verified_sha256']=sha(verified);doc['rows']=[]
    for N in [1,16,64,256,1024]:
        if c['D']%N:doc['rows'].append(dict(N=N,status='UNALIGNED'));continue
        pol=old.certify(c,N);doc['rows'].append(dict(N=N,status='PASS' if pol['DFR_pass'] and pol['savings_pass'] else 'FAIL',polar=pol))
    sys.path.insert(0,str(old.CERT))
    from polar_certificate import certify_frozen_sets
    cert150=certify_frozen_sets(c['q_bits'],256,c['S'],170,c['D'],256,150)
    assert cert150['frozen_sets']==best['polar']['frozen_sets']
    assert cert150['compressed_bytes']==best['polar']['compressed_bytes']
    doc['precision150']=dict(frozen_and_bytes_identical=True,certificate=cert150)
    save(doc,out)


if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--stage',choices=['quick','higher-quick','scan','battery','quantizers'],default='quick')
    ap.add_argument('--worker',nargs=2);ap.add_argument('--source',type=Path,default=HERE/'quick-screen.json')
    ap.add_argument('--output',default='quick-verified.json');ap.add_argument('--limit',type=int,default=1);ap.add_argument('--timeout',type=int,default=300)
    args=ap.parse_args()
    if args.worker:
        cc=json.loads(Path(args.worker[1]).read_text());print('RESULT_JSON='+json.dumps(old.attack(cc,args.worker[0])),flush=True)
    elif args.stage=='quick':screen(True)
    elif args.stage=='higher-quick':screen(False,True)
    elif args.stage=='scan':screen(False)
    elif args.stage=='battery':battery(args.source,args.output,args.limit,args.timeout)
    else:quantizers(args.source,args.output)
