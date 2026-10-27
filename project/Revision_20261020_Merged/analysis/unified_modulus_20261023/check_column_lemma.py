"""Exact rational arithmetic checks of the graph-lift GS argument (not a proof)."""
from fractions import Fraction as F
from pathlib import Path
import hashlib
import json

def dot(u,v):
    return sum(x*y for x,y in zip(u,v))

def gs_squared(cols):
    star=[]
    for col in cols:
        v=list(map(F,col))
        for prev in star:
            c=dot(v,prev)/dot(prev,prev)
            v=[x-c*y for x,y in zip(v,prev)]
        assert dot(v,v)>0
        star.append(v)
    return [dot(v,v) for v in star]

def check(b,q,rows):
    s=1
    while b**s<q:s+=1
    g=[b**i for i in range(s)]
    # q=b^s allowed: final column b*e_last rather than a truncated digit string.
    digits=[(q//b**i)%b for i in range(s)] if q<b**s else [0]*(s-1)+[b]
    R=[[((i+2)*(j+3)%11)-5 for j in range(s)] for i in range(rows)]
    def lift(z):return [-dot(r,z) for r in R]+list(z)
    cols=[]
    for j in range(s-1):
        z=[0]*s;z[j]=b;z[j+1]=-1;cols.append(lift(z))
    cols.append(lift(digits))
    A=[i+2 for i in range(rows)]
    # Matrix [A | A*R+g]; graph (-Rz,z).
    for i in range(rows):
        z=[-A[i]]+[0]*(s-1)
        col=lift(z);col[i]+=1;cols.append(col)
    matrix=A+[sum(A[i]*R[i][j] for i in range(rows))+g[j] for j in range(s)]
    assert all(dot(matrix,c)%q==0 for c in cols)
    C2=max(sum(R[i][j]**2 for i in range(rows)) for j in range(s))
    bound=(b+1)**2*C2+b*b+1
    norms=gs_squared(cols)
    assert max(norms[:s])<=bound
    assert max(norms[s:])<=1
    v=[F(q*x,dot(g,g)) for x in g]
    assert sum(abs(x) for x in v)<=b+1 and dot(v,v)<=b*b
    return dict(b=b,q=q,rectangular_rows=rows,gadget_length=s,
                max_GS_squared=str(max(norms)),column_bound_squared=C2,
                certified_bound_squared=bound,pass_exact=True)

if __name__=='__main__':
    cases=[check(b,q,rows) for b in [2,4,16]
           for q in [3,5,11,31,61,127,256] for rows in [1,3]]
    out=dict(scope='42 exact small-matrix consistency tests; proof is in audit.md; no inference from sampling',
             source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),cases=cases)
    Path(__file__).with_name('column_lemma_exact_tests.json').write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'cases':len(cases),'all_pass':all(c['pass_exact'] for c in cases)}))
