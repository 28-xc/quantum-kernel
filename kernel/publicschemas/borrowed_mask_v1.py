"""Check production bindings and immediate rejected-mask destruction records."""
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
from pathlib import Path
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):return json.loads(p.read_text(encoding='utf8'))
def main():
 p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);p.add_argument('--data',type=Path);a=p.parse_args();d=a.data or Path(__file__).resolve().parent;doc=read(d/'records.xml');prov={x['path']:x for x in read(d.parent/'projection-provenance.xml')['records']};count=0;erased=0
 for row in doc['records']:
  root=d/row['platform'];q=root/row['profile'];ann=read(root/'annotation.xml')
  assert row['annotation_sha256']==prov[(root/'annotation.xml').relative_to(d.parent).as_posix()]['original_sha256']
  assert row['status']=='PASS' and row['positive_control_detected'] is True and row['accepted_signatures']==900
  for unit in ann['changed_files']:
   assert sha(a.source/unit['path'])==unit['production_sha256']
   assert sha(root/'observed-source'/unit['path'])==unit['observed_sha256']
  build=read(q/'build.xml');assert build['binary']['sha256']==row['observed_library_sha256']
  eq=read(q/'equivalence.xml');assert eq['status']=='PASS'
  assert [v['sha256'] for v in eq['libraries']]==[row['production_library_sha256'],row['observed_library_sha256']]
  assert prov[(q/'equivalence.xml').relative_to(d.parent).as_posix()]['original_sha256']==row['byte_equivalence_sha256']
  assert sum(v['count'] for v in eq['records'])==900 and all(v['complete_signatures_byte_equal'] for v in eq['records'])
  raw=[json.loads(line) for line in (q/'observations.stdout').read_text().splitlines()];assert raw==row['observations']
  assert not (q/'observations.stderr').read_text().strip()
  active=row.get('borrowed_parameters',[44,65,87])
  for z in raw:
   n=z['parameter'];assert n in [44,65,87] and z['nonzero_failed_bytes']==0
   if n in active:
    assert z['attempts']==z['failed_attempts']+300
    assert z['erased_bytes_observed']==z['failed_attempts']*{44:2304,65:3200,87:4480}[n]
   else:assert all(z[k]==0 for k in ['attempts','failed_attempts','erased_bytes_observed'])
   count+=z['failed_attempts'];erased+=z['erased_bytes_observed']
 print(json.dumps(dict(status='PASS',production_profiles=len(doc['records']),complete_signature_pairs=900*len(doc['records']),observed_rejections=count,observed_erased_bytes=erased,scope='Recorded rejected attempts, observed after production wipe; conditional on stated source annotations and finite inputs.')))
if __name__=='__main__':main()
