"""Final six-point mixed-radix polar check, independent of prior frozen screen."""
import hashlib,json,time
from pathlib import Path
import round2_search_frozen_mixed as R
P=Path(__file__).resolve().parent
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
source=P/'folded_rs8192-mixed-screen.json'
d=dict(script_sha256=sha(__file__),candidate_dependency_sha256=sha(R.__file__),
       source_screen_sha256=sha(source),rows=[],scope='Six finite uSVP gates with certified polar CT; full attacks separate')
for c in json.loads(source.read_text())['gates']:
    pol=R.certify_safe(c)
    d['rows'].append(dict(parameters=c,polar=pol))
    print(json.dumps(dict(b=c['gadget_b'],r=c['r'],n=c['n'],a=c['q_bits'],MPK_TiB=c['MPK_TiB'],
          raw=c['raw_complete_ciphertext_bytes'],compressed=pol['compressed_bytes'],saving=pol['complete_byte_saving_fraction'])),flush=True)
(P/'mixed-polar-screen.json').write_text(json.dumps(d,indent=2)+'\n')
