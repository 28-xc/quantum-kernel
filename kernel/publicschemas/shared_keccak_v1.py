"""Strict scientific schema and raw-data replay for the shared Keccak profile."""
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
import argparse, csv, hashlib, record_io as json, math, re, statistics
HERE=Path(__file__).resolve().parent
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def need(c,m):
 if not c:raise ValueError(m)
def schema_check(value,schema,where='$'):
 if schema is False:raise ValueError(where+': unexpected item')
 if 'const' in schema:need(value==schema['const'],where+': wrong constant');return
 if 'anyOf' in schema:
  for option in schema['anyOf']:
   try:schema_check(value,option,where);return
   except ValueError:pass
  raise ValueError(where+': no allowed scientific record shape')
 t=schema['type'];valid={'object':type(value)is dict,'array':type(value)is list,'integer':type(value)is int,
  'number':type(value)in (int,float) and math.isfinite(value),'boolean':type(value)is bool,'string':type(value)is str,'null':value is None}
 need(valid[t],where+': wrong value type')
 if t=='object':
  need(set(value)==set(schema['properties']),where+': unexpected or missing scientific fields')
  for k,v in value.items():schema_check(v,schema['properties'][k],where+'.'+k)
 elif t=='array':
  for i,v in enumerate(value):schema_check(v,schema['items'],where+'[]')
 elif t=='string':need(re.search(r'(?<![A-Za-z])[A-Za-z]:[\\/]|/home/|a127-private|BEGIN .*PRIVATE KEY',value)is None,where+': local execution material')
def validate(data):
 schema_check(data,json.loads((HERE/'shared_keccak.schema.xml').read_text()))
 need(data['profile']['id']=='compact-shared','Profile differs')
 need(data['profile']['parameters']==[512,768,1024,44,65,87],'Parameters differ')
 m=data['measurements'];need(len(m['jobs'])==180 and len(m['cells'])==18,'Incomplete operation matrix')
 need(m['retained_samples']==72000 and m['blocks']==5 and m['samples_per_job']==400,'Changed sample design')
 need(len(data['comparisons'])==4,'A candidate was omitted')
 need(data['common_context']['full_reserved_core_budget_bytes']==14672,'Resource identity differs')
 return True
def safe_file(root,row):
 p=(root/row['path']).resolve();need(p.is_relative_to(root.resolve()),'Raw path escapes dataset')
 need(p.stat().st_size==row['bytes'] and sha(p)==row['sha256'],'Raw identity differs: '+row['path']);return p
def close(a,b):need(math.isclose(a,b,rel_tol=1e-12,abs_tol=1e-9),'Numerical replay differs')
def recompute(path):
 path=Path(path);root=path.parent;d=json.loads(path.read_text());validate(d);m=d['measurements'];jobs=[]
 for row in m['jobs']:
  p=safe_file(root,row['raw'])
  with p.open(newline='') as f:
   reader=csv.DictReader(f);need(reader.fieldnames==['iteration','operation_elapsed_ns'],'Changed raw columns');samples=list(reader)
  need(len(samples)==400 and [int(x['iteration']) for x in samples]==list(range(400)),'Sample count/order differs')
  values=[float(x['operation_elapsed_ns']) for x in samples];need(all(math.isfinite(x) and x>0 for x in values),'Invalid samples')
  value=statistics.median(values);close(value,row['median_ns']);jobs.append(dict(**row,recomputed_median=value))
 for c in m['cells']:
  rows=[r for r in jobs if r['pair']==c['pair'] and r['parameter']==c['parameter'] and r['operation']==c['operation']]
  ratios=[]
  for block in range(5):
   pair=[r for r in rows if r['round']==block];need(len(pair)==2,'Incomplete block')
   ratios.append(next(r for r in pair if r['arm']=='control')['recomputed_median']/next(r for r in pair if r['arm']=='candidate')['recomputed_median'])
  for a,b in zip(ratios,c['paired_block_ratios']):close(a,b)
  close(math.exp(statistics.mean(map(math.log,ratios))),c['geomean_paired_ratio'])
 close(math.exp(statistics.mean(math.log(c['geomean_paired_ratio']) for c in m['cells'])),m['geomean_control_over_candidate'])
 for row in d['resource_trials']:
  p=safe_file(root,row);lines=p.read_text().splitlines();need(len(lines)==row['trials'],'Resource trial count differs')
  for line in lines:
   trial=json.loads(line);need('argv' not in trial and 'events' in trial,'Non-scientific resource record')
 return dict(status='PASS',operation_cells=18,raw_samples=72000,resource_trials=sum(x['trials'] for x in d['resource_trials']),observations_sha256=sha(path))
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('observations',type=Path);a=p.parse_args();print(json.dumps(recompute(a.observations),indent=2))
