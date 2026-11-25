"""Validate complete-operation timing datasets; raw measurements stay immutable."""
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
import argparse, record_io as json
from .shared_keccak_v1 import schema_check,need,safe_file,sha
HERE=Path(__file__).resolve().parent
def validate(data):
 schema_check(data,json.loads((HERE/'timing_attribution.schema.xml').read_text()))
 need(data['retained_samples']==17600000,'Timing observation count differs')
 need([s['id'] for s in data['studies']]==['complete-key-factorial','portable-rho-factorial','shared-screen'],'Study omitted or reordered')
 need([s['retained_samples'] for s in data['studies']]==[2480000,7320000,7800000],'Study observation counts differ')
 return True
def check_files(path):
 path=Path(path);data=json.loads(path.read_text());validate(data);root=path.parent;count=0
 for study in data['studies']:
  for job in study['jobs']:
   for r in job['files'].values() if 'files' in job else [job['raw']]:safe_file(root,r);count+=1
 for r in data['measured_sources']:safe_file(root,r);count+=1
 return dict(status='PASS',files=count,retained_samples=data['retained_samples'],observations_sha256=sha(path))
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('observations',type=Path);a=p.parse_args();print(json.dumps(check_files(a.observations),indent=2))
