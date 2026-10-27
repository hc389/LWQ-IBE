"""Replay the six bundled small diagnostic ciphertexts; not a full IBE test."""
from pathlib import Path
import hashlib
import json
import sys

ROOT=Path(__file__).resolve().parents[1]
CODE=ROOT/'project/Revision_20261014_Polar/Code'
sys.path.insert(0,str(CODE))
from integer_polar_codec import sample_vector, pack_ciphertext, unpack_ciphertext
from run_integer_polar_validation import source_vector

results=[]
for folder in sorted(CODE.glob('validation*/')):
    record=json.loads((folder/'validation.json').read_text())
    frozen=record['inherited_polar_certificate']['frozen_sets']
    for row in record['pilots']:
        kind=row['source_kind'];case=folder/kind
        a=row['q_bits'];s=row['S_bits'];D=row['executed_dimension'];B=row['block_dimension']
        seed=bytes.fromhex(row['public_seed']);source_seed=bytes.fromhex(row['source_seed'])
        tape=(case/'private_random_tape.bin').read_bytes()
        expected=(case/'ciphertext.bin').read_bytes()
        assert hashlib.sha256(tape).hexdigest()==row['tape_sha256']
        assert hashlib.sha256(expected).hexdigest()==row['sha256']
        y=source_vector(kind,a,D,source_seed)
        scalar=int.from_bytes(hashlib.shake_256(b'scalar/'+source_seed).digest((a+7)//8),'big')%(1<<a)
        x,details=sample_vector(y,a,s,frozen,seed,tape,B)
        actual=pack_ciphertext(scalar,x,seed,a,frozen,B)
        assert actual==expected,(folder.name,kind)
        assert unpack_ciphertext(actual,D,a,frozen,B)==(scalar,x,seed)
        assert details==row['details']
        results.append({'record':str(case.relative_to(ROOT)),
                        'ciphertext_bytes':len(actual),'sha256':hashlib.sha256(actual).hexdigest(),
                        'byte_identical':True})
assert len(results)==6
print(json.dumps({'scope':'Saved small-instance replay, not Extract or full IBE',
                  'replayed_cases':len(results),'cases':results},indent=2))
