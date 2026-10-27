"""Finite polar screen of already uSVP-qualified folded profile gate points."""
import hashlib,json,time
from pathlib import Path
import round2_search as R
P=Path(__file__).resolve().parent
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
sources=['folded_rs8192-large-screen.json','folded_rs8192-refine-screen.json','folded_rs8192-final-screen.json']
d=dict(scope='Deterministic finite polar certificate; no six-attack inference',
       script_sha256=sha(__file__),candidate_dependency_sha256=sha(R.__file__),
       sources={f:sha(P/f) for f in sources},rows=[])
seen=set()
for f in sources:
    for c in json.loads((P/f).read_text())['gates']:
        if 'n' not in c:continue
        key=(c['n'],c['r'],c['q_bits'],c['m'],c['gadget_b'],c['honest_entropy_k'],c['proof_entropy_k'])
        if key in seen:continue
        seen.add(key)
        pol=R.certify_safe(c)
        d['rows'].append(dict(parameters=c,polar=pol,source=f))
        print(json.dumps(dict(b=c['gadget_b'],kh=c['honest_entropy_k'],kp=c['proof_entropy_k'],r=c['r'],
              MPK_TiB=c['MPK_TiB'],compressed_bytes=pol['compressed_bytes'],saving=pol['complete_byte_saving_fraction'])),flush=True)
d['best_mpk_index']=min(range(len(d['rows'])),key=lambda i:d['rows'][i]['parameters']['MPK_bytes'])
d['best_complete_ct_index']=min(range(len(d['rows'])),key=lambda i:d['rows'][i]['polar']['compressed_bytes'])
d['finished_unix']=time.time()
(P/'candidate-polar-screen.json').write_text(json.dumps(d,indent=2)+'\n')
best=d['rows'][d['best_complete_ct_index']]['parameters']
(P/'size-priority-selected-screen.json').write_text(json.dumps(dict(rows=[best],selection_source_sha256=sha(P/'candidate-polar-screen.json'),
    scope='Selected smallest certified complete polar ciphertext among finite gate points; six attacks still required'),indent=2)+'\n')
