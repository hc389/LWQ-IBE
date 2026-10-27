"""Reproducible bounded scan removing gratuitous power-of-two width rounding.

ARS derivation, Claude-Scholar deterministic parameter experiments. No Paper edits.
Fixed partition/query budgets and original factor-two proof-side ReRand retained.
"""
from __future__ import annotations
import argparse
from decimal import Decimal
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import time

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
EST = ROOT.parent / 'Revision_20261012/experiments/A3_lattice-estimator'
CERT = ROOT.parent / 'Revision_20261013_Native/analysis/polar_validation_20261014'
POLICIES = ['floor', 'floor+1', 'floor+4', 'floor+8', '1.25floor', '1.5floor',
            '512', '600', '640', '700', '768', '1024', '2048']
CTX = {}
NORM = 'old_net'


def scan_name():
    return 'scan.json' if NORM=='old_net' else 'scan-one_net.json'


def battery_name():
    return 'battery.json' if NORM=='old_net' else 'battery-one_net.json'


def ceil_sqrt(x):
    k = math.isqrt(x)
    return k + (k*k < x)


def ceil_log2(x):
    return (x-1).bit_length()


def r_value(n, policy):
    base = ceil_sqrt(9*n)
    if policy.isdecimal():
        return int(policy)
    if policy.startswith('floor+'):
        return base + int(policy.split('+')[1])
    return {'floor': base, '1.25floor': (5*base+3)//4,
            '1.5floor': (3*base+1)//2, '512': 512}[policy]


def candidate(n, policy, s_policy='integer', h_policy='theta', norm_policy=None):
    norm_policy=NORM if norm_policy is None else norm_policy
    r = r_value(n, policy)
    if r*r < 9*n:
        return None
    T, eta, ell, zeta, u = 232, 30, 2047, 12, 360
    for a in range(max(16, ceil_log2(r)+1), ceil_log2(r)+400):
        w = n*a
        m = ((2*w + 2*ceil_log2(w) + 2*T + 127)//128)*128
        bar, D = m-w, 2*m
        C = lambda d: 1+(d-1)*w
        Ns = [min(ell+1, (2*ell+1+(1<<j)-1)//(1<<j)) for j in range(zeta)]
        H = w*(Ns[-1]+w*sum(Ns[:-1]))
        H0 = w*C(zeta)
        delta = C(eta-1)*H+w*H0
        assert delta == 171931*w**3 + 6197*w*w + 2*w
        nu = T+ceil_log2(2*(u+1))+2
        KA = 2*ceil_sqrt(3*(m+w)+nu)
        KF = 2*ceil_sqrt(5*m+nu)
        if norm_policy=='one_net':
            def net_K(p,d):
                x=(3045*d+694*(T+ceil_log2(2*(u+1))+2)+999)//1000
                num=50*(p+2*ceil_sqrt(p*x)+2*x)
                return ceil_sqrt((num+80)//81)
            KA,KF=net_K(m,w),net_K(m,m)
        assert KA*KA*w>=m
        kappa = max(KF, ceil_sqrt((m*KA*KA+w-1)//w))
        rho = kappa*(delta+1)
        CR = ceil_sqrt(m)+ceil_sqrt((KA*KA*delta*delta+w-1)//w)
        Lsim, Lhonest = ceil_sqrt(9*CR*CR+5), 2*ceil_sqrt(1+bar*w)
        theta = T+16+2+ceil_log2(D)+4
        h = 1
        while 3140*h*h <= 694*(theta+2):
            h += 1
        if h_policy == 'original':
            h = ceil_sqrt((theta+5)//4)
        sigma = h*max(Lsim,Lhonest)
        threshold = 4*r*r*(1+rho*rho)
        Smin = math.isqrt(threshold)+1
        S = Smin if s_policy == 'integer' else 1 << ceil_log2(Smin)
        K = (D+2*ceil_sqrt(D*202)+404+5)//6
        W2 = r*r+S*S*sigma*sigma*K
        if 1 << (2*a) < 4*163*W2:
            continue
        checks = dict(r_floor=(r*r>=9*n), worst_case_floor=(r*r>8*n),
                      strict_rerand=(S*S>threshold),
                      finite_rerand=(2*r*r>=T+ceil_log2(D)+8),
                      modulus=(1 << (2*a) >=4*163*W2),
                      block_alignment=(D%256==0),
                      theta=(3140*h*h>694*(theta+2)))
        assert all(checks.values()), checks
        mpk = ((362*n*m+n)*a+7)//8
        return dict(n=n,r=r,r_policy=policy,S=str(S),Smin=str(Smin),
                    s_policy=s_policy,h_policy=h_policy,norm_policy=norm_policy,q_bits=a,m=m,D=D,w=w,
                    bar=bar,u=u,ell=ell,eta=eta,zeta=zeta,inside_stat_budget_bits=T,
                    query_log2=16,keynorm_tail_bits=200,key_h=h,key_theta_bits=theta,
                    rho=str(rho),sigma=str(sigma),delta=str(delta),
                    column_bound=str(CR),simulated_GS_bound=str(Lsim),
                    honest_GS_bound=str(Lhonest),checks=checks,
                    strict_rerand_margin_log2=math.log2(S*S)-math.log2(threshold),
                    S_log2=math.log2(S),r_log2=math.log2(r),sigma_log2=math.log2(sigma),
                    exact_reference_DFR_bits=(1 << (2*a))//(4*W2)-1,
                    raw_complete_ciphertext_bytes=((D+1)*a+7)//8,
                    MPK_bytes=mpk,MPK_TiB=mpk/2**40)
    raise RuntimeError('No modulus found')


def estimator_context():
    if not CTX:
        sys.path.insert(0,str(EST))
        from estimator import LWE, ND
        from estimator.reduction import RC
        from sage.all import ZZ, RR, pi, sqrt, log
        CTX.update(LWE=LWE,ND=ND,RC=RC,ZZ=ZZ,RR=RR,pi=pi,sqrt=sqrt,log=log)
    return CTX


def attack(c,name):
    x=estimator_context()
    LWE,ND,RC=x['LWE'],x['ND'],x['RC']
    q=x['ZZ'](2)**c['q_bits']
    p=LWE.Parameters(n=c['n'],q=q,Xs=ND.UniformMod(q),
                     Xe=ND.DiscreteGaussian(x['RR'](c['r'])/x['sqrt'](2*x['pi'])),m=c['m']+1)
    kw=dict(red_cost_model=RC.ADPS16,red_shape_model='gsa')
    fs={'usvp':lambda:LWE.primal_usvp(p,**kw),
        'bdd':lambda:LWE.primal_bdd(p,**kw),
        'dual':lambda:LWE.dual(p,red_cost_model=RC.ADPS16),
        'dual_hybrid':lambda:LWE.dual_hybrid(p,red_cost_model=RC.ADPS16),
        'bdd_hybrid':lambda:LWE.primal_hybrid(p,mitm=False,babai=False,**kw),
        'mitm':lambda:LWE.primal_hybrid(p,mitm=True,babai=True,**kw)}
    t=time.time()
    try:
        cost=fs[name]()
        return dict(status='ok',attack=name,bits=float(x['log'](cost['rop'],2)),
                    raw_repr=repr(cost),input_repr=repr(p),seconds=time.time()-t)
    except Exception as exc:
        return dict(status='error',attack=name,error=repr(exc),input_repr=repr(p),seconds=time.time()-t)


def certify(c,N=256):
    sys.path.insert(0,str(CERT))
    sys.path.insert(0,str(ROOT/'Code'))
    from polar_certificate import certify_frozen_sets,completion_tail_upper,Outward
    from integer_polar_codec import validate_lattice_layout
    S=int(c['S']); D=c['D']; a=c['q_bits']
    pol=certify_frozen_sets(a,N,S,170,D,256)
    validate_lattice_layout(a,pol['frozen_sets'],N)
    ar=Outward(110)
    stop=min(a,ceil_log2(S)+6)
    draws=(D//N)*sum(N-len(f) for f in pol['frozen_sets'][:stop])
    numerical=ar.up.add(ar.up.divide(Decimal(draws),Decimal(1<<256)),
                       ar.up.divide(Decimal(draws),Decimal(1<<300)))
    tail=Decimal(completion_tail_upper(D,S,stop))
    matching=ar.up.add(ar.up.add(ar.up.multiply(Decimal(2),Decimal(pol['global_tv_upper'])),tail),numerical)
    ref=ar.up.divide(Decimal(1),Decimal(1<<c['exact_reference_DFR_bits']))
    kt=ar.up.divide(Decimal(1),Decimal(1<<200))
    gpv=ar.up.divide(Decimal(1),Decimal(1<<(232+16+5)))
    total=ar.up.add(ar.up.add(ar.up.add(ref,kt),gpv),matching)
    pol.update(stop_bits=stop,matching_TV_upper=str(matching),tail_upper=str(tail),
               finite_grid_TV_upper=str(numerical),reference_DFR_upper=str(ref),
               combined_DFR_upper=str(total),DFR_pass=(total<ar.down.divide(Decimal(1),Decimal(1<<160))),
               savings_pass=(pol['complete_byte_saving_fraction']>=.30),lattice_layout_pass=True,
               actual_GPV_sampler_TV_excluded=True,full_dim_execution=False)
    return pol


def save(doc,name):
    (HERE/name).write_text(json.dumps(doc,indent=2,ensure_ascii=False)+'\n')


def scan():
    doc=dict(scope='deterministic parameter arithmetic and estimator screening; no full IBE execution',
             command=sys.argv,script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
             environment=dict(python=sys.version,platform=platform.platform(),randomness='none'),
             estimator_commit=subprocess.check_output(['git','-C',str(EST),'rev-parse','HEAD'],text=True).strip(),
             fixed=dict(ell=2047,eta=30,zeta=12,u=360,stat_bits=232,QE=65536,keytail_bits=200,N=256,
                        security_target=128,cost='ADPS16 classical',shape='GSA',norm_policy=NORM),rows=[],gates=[])
    cache={}
    previous=HERE/scan_name()
    if previous.exists():
        old=json.loads(previous.read_text())
        # Resume only records with identical fixed assumptions and cost model.
        if old.get('fixed')==doc['fixed']:
            doc['rows']=old['rows']
            for c in doc['rows']:
                cache[c['n'],c['r_policy'],c['s_policy']]=c
    def evalpoint(n,rp,sp):
        key=(n,rp,sp)
        if key not in cache:
            c=candidate(n,rp,sp)
            c['usvp']=attack(c,'usvp')
            cache[key]=c
            doc['rows'].append(c)
            save(doc,scan_name())
        return cache[key]
    for sp in ['integer','power2']:
        for rp in POLICIES:
            lo,hi=7600,10000
            while hi-lo>8:
                mid=((hi+lo)//16)*8
                c=evalpoint(mid,rp,sp)
                if c['usvp']['status']!='ok':
                    raise RuntimeError(c['usvp'])
                if c['usvp']['bits']>=128:
                    hi=mid
                else:
                    lo=mid
            neighborhood=[evalpoint(n,rp,sp) for n in range(max(7600,lo-32),min(10000,hi+32)+1,8)]
            good=[c for c in neighborhood if c['usvp']['status']=='ok' and c['usvp']['bits']>=128]
            best=min(good,key=lambda c:c['MPK_bytes'])
            doc['gates'].append(best)
            save(doc,scan_name())
            print(json.dumps({k:best[k] for k in ['n','r','r_policy','s_policy','q_bits','m','key_h','MPK_TiB','S_log2']}|{'bits':best['usvp']['bits']}),flush=True)
    best=min(doc['gates'],key=lambda c:c['MPK_bytes'])
    # Fine actual local n/r grid rather than asserting smallest r is best.
    for n in range(best['n']-16,best['n']+17,2):
        evalpoint(n,best['r_policy'],'integer')
        base=ceil_sqrt(9*n)
        for extra in range(0,17,2):
            evalpoint(n,'floor+'+str(extra),'integer')
    # Joint local r/n check around the best resolved fixed-width strategy.
    for n in range(best['n']-12,best['n']+13,4):
        for r in range(max(ceil_sqrt(9*n),best['r']-24),best['r']+25,8):
            evalpoint(n,str(r),'integer')
    good=[c for c in doc['rows'] if c['usvp']['status']=='ok' and c['usvp']['bits']>=128]
    unique={(c['n'],c['r'],c['q_bits'],c['S']):c for c in good}
    doc['best_screened']=sorted(unique.values(),key=lambda c:c['MPK_bytes'])[:8]
    save(doc,scan_name())
    print('BEST='+json.dumps({k:doc['best_screened'][0][k] for k in ['n','r','q_bits','m','MPK_TiB']}),flush=True)


def batteries(timeout,input_file=None,output_name=None,limit=3):
    doc=json.loads((Path(input_file) if input_file else HERE/scan_name()).read_text())
    out_name=output_name or battery_name()
    top=[];seen=set()
    for c in doc['best_screened']+sorted(doc['gates'],key=lambda c:c['MPK_bytes']):
        key=(c['n'],c['r'],c['q_bits'])
        if key not in seen:
            top.append(c);seen.add(key)
        if len(top)==limit:
            break
    out=dict(rows=[],scope='six finite estimator attacks plus independently checked two model lower bounds')
    for i,c in enumerate(top):
        cf=HERE/f'point-{NORM}-{c["n"]}-{c["r"]}-{i}.json';cf.write_text(json.dumps(c)+'\n')
        rec=dict(parameters=c,attacks=[],polar=certify(c))
        out['rows'].append(rec)
        for name in ['usvp','bdd','dual','dual_hybrid','bdd_hybrid','mitm']:
            cmd=[sys.executable,str(Path(__file__).resolve()),'--worker',name,str(cf)]
            t=time.time();p=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
            try:
                stdout,stderr=p.communicate(timeout=timeout)
                lines=[x for x in stdout.splitlines() if x.startswith('RESULT_JSON=')]
                result=json.loads(lines[-1].split('=',1)[1]) if lines else dict(status='worker_failed',stderr=stderr[-3000:])
            except subprocess.TimeoutExpired:
                os.killpg(p.pid,signal.SIGTERM);stdout,stderr=p.communicate()
                result=dict(status='timeout',timeout=timeout)
            result.update(attack=name,wall_seconds=time.time()-t)
            rec['attacks'].append(result)
            save(out,out_name)
            print(f"POINT{i} n={c['n']} r={c['r']} a={c['q_bits']} {name}: {result.get('bits',result['status'])}",flush=True)
        finite=[x['bits'] for x in rec['attacks'] if x['status']=='ok']
        rec['min_finite_bits']=min(finite) if finite else None
        rec['six_attack_status']='PASS' if len(finite)==6 and min(finite)>=128 else 'PARTIAL_OR_FAIL'
        # Same fixed implementation model: q is unchanged by normalize/amplify.
        # Arora: n-159>8192 and Gaussian minimum equation degree >=8.
        rec['model_bounds']=dict(coded_BKW_bits_lower=2*c['q_bits']+math.log2(2*c['q_bits']+1),
                                 arora_GB_bits_lower=160 if c['n']-159>8192 and c['r']/math.sqrt(2*math.pi)>4 else None,
                                 status='COVERED_BY_MODEL_BOUND',numerical_success_claimed=False)
        save(out,out_name)


def boundary_scan():
    """Resolve potential optima just before q increments, missed by r powers."""
    doc=json.loads((HERE/scan_name()).read_text())
    rows=[]
    for r in range(280,1409,16):
        lo,hi=8500,9000
        hi=min(hi,(r*r)//9)
        hi-=hi%2
        if hi<=lo:
            continue
        upper=candidate(hi,str(r));upper['usvp']=attack(upper,'usvp');rows.append(upper)
        if upper['usvp']['status']!='ok' or upper['usvp']['bits']<128:
            continue
        while hi-lo>2:
            n=((lo+hi)//4)*2
            c=candidate(n,str(r))
            if c is None:
                raise AssertionError('smoothing-floor domain must be bounded above')
            c['usvp']=attack(c,'usvp')
            rows.append(c)
            if c['usvp']['status']=='ok' and c['usvp']['bits']>=128:
                hi=n
            else:lo=n
        c=candidate(hi,str(r));c['usvp']=attack(c,'usvp');rows.append(c)
    doc['rows'].extend(rows)
    good=[c for c in doc['rows'] if c['usvp']['status']=='ok' and c['usvp']['bits']>=128]
    unique={(c['n'],c['r'],c['q_bits'],c['S']):c for c in good}
    best=min(unique.values(),key=lambda c:c['MPK_bytes'])
    for r in range(max(1,best['r']-16),best['r']+17):
        for n in range(best['n']-8,best['n']+9,2):
            c=candidate(n,str(r))
            if c is None:continue
            c['usvp']=attack(c,'usvp');doc['rows'].append(c)
    good=[c for c in doc['rows'] if c['usvp']['status']=='ok' and c['usvp']['bits']>=128]
    unique={(c['n'],c['r'],c['q_bits'],c['S']):c for c in good}
    doc['best_screened']=sorted(unique.values(),key=lambda c:c['MPK_bytes'])[:8]
    save(doc,'boundary-'+scan_name())
    print('BOUNDARY_BEST='+json.dumps({k:doc['best_screened'][0][k] for k in ['n','r','q_bits','m','MPK_TiB']}),flush=True)


if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--worker',nargs=2);ap.add_argument('--stage',choices=['scan','battery','boundary'],default='scan');ap.add_argument('--timeout',type=float,default=300);ap.add_argument('--norm',choices=['old_net','one_net'],default='old_net');ap.add_argument('--input');ap.add_argument('--output-name');ap.add_argument('--limit',type=int,default=3)
    args=ap.parse_args()
    NORM=args.norm
    if args.worker:
        print('RESULT_JSON='+json.dumps(attack(json.loads(Path(args.worker[1]).read_text()),args.worker[0])),flush=True)
    elif args.stage=='scan':scan()
    elif args.stage=='boundary':boundary_scan()
    else:batteries(args.timeout,args.input,args.output_name,args.limit)
