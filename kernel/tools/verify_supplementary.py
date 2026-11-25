"""Verify source-bound component, pruning and linked-entity records."""
from pathlib import Path,PurePosixPath
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
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--input',type=Path,required=True);p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 root=a.input.resolve();source=a.source.resolve();m=json.loads((root/'observations.xml').read_text(encoding='utf8'))
 if m['schema']!='lattice.supplementary_records.v1':raise ValueError('Unexpected schema')
 seen=set()
 for row in m['files']:
  rel=PurePosixPath(row['path']);q=(root/rel).resolve()
  if rel.is_absolute()or not q.is_relative_to(root)or row['path']in seen:raise ValueError('Invalid evidence path')
  seen.add(row['path'])
  if sha(q)!=row['sha256']or q.stat().st_size!=row['bytes']:raise ValueError('Evidence differs: '+row['path'])
 for row in m['source_bindings']:
  q=(source/row['path']).resolve()
  if not q.is_relative_to(source)or sha(q)!=row['sha256']:raise ValueError('Bound source differs: '+row['path'])
 rows=[]
 for r in m['records']:
  d=json.loads((root/r['result']).read_text(encoding='utf8'))
  if d.get('status') not in ['PASS','BUILT_FUNCTIONALLY_CHECKED','READ_ONLY_LINKED_IMAGE_INSPECTED']:raise ValueError('Result is incomplete: '+r['id'])
  if r['kind']=='pruning':
   if d['unselected_named_entities']or d['unselected_operation_entities']or d['unsupported_status']!=-8:raise ValueError('Pruned interface differs')
   for item in d['public_checks'].values():
    if item['exit_code']!=0 or not any(x.get('status')=='PASS'for x in item['rows']):raise ValueError('Pruned public checks failed')
  if r['kind']=='fused-keygen'and d['coefficients']!=16761088:raise ValueError('Fused-domain coverage differs')
  rows.append(dict(id=r['id'],kind=r['kind'],status=d['status'],result_sha256=sha(root/r['result'])))
 result=dict(schema='lattice.supplementary_reconstruction.v1',status='PASS',files_verified=len(seen),source_files_verified=len(m['source_bindings']),records=rows)
 a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf8');print(json.dumps(dict(status='PASS',records=len(rows),files=len(seen),source_files=len(m['source_bindings']))))
if __name__=='__main__':main()
