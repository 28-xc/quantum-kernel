"""Validate exact checked sparse NEON test/header identities and finite records."""
from pathlib import Path
# Shared typed XML persistence; transport JSON remains in memory.
import sys as _record_sys
from pathlib import Path as _RecordPath
for _record_parent in _RecordPath(__file__).resolve().parents:
    _record_candidate = _record_parent / 'record_io.py'
    if not _record_candidate.is_file():
        _record_candidate = _record_parent / '01_源代码/可参数化格运算内核/record_io.py'
    if _record_candidate.is_file():
        _record_sys.path.insert(0, str(_record_candidate.parent))
        break
import argparse, hashlib, record_io as json
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);p.add_argument('--data',type=Path);a=p.parse_args();d=a.data or Path(__file__).resolve().parent;r=json.loads((d/'result.xml').read_text());assert r['status']=='PASS'
 for name,path,key in [('lc_sparse8_neon.h','src/dsa_packed/lc_sparse8_neon.h','helper_sha256'),('lc_dsa_keycheck.h','src/common/lc_dsa_keycheck.h','gate_sha256'),('checked_sparse_oracle.c','tests/representation/checked_sparse_oracle.c','original_public_test_sha256')]:assert sha(d/name)==sha(a.source/path)==r[key]
 assert sha(d/'checked_sparse_neon_oracle.c')==r['adapted_test_sha256']
 for record in r['records']:
  w=record['wide'];actual=json.loads((d/f'run-{w}.out').read_text());assert not (d/f'run-{w}.err').read_text().strip()
  assert sha(d/f'probe-wide{w}')==record['executable_sha256']
  assert actual==record['result']==dict(status='PASS',cases=24576,canonical_cases=14592,malformed_fallback_cases=9984,coefficients=6291456)
 print(json.dumps(dict(status='PASS',widths=2,cases_per_width=24576,coefficients_per_width=6291456,scope='Compiled finite-domain oracle under both width choices. This consumer verifies source and execution record identity; the included C oracle supports fresh execution.')))
if __name__=='__main__':main()
