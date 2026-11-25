"""Recompute complete-operation statistics with an audited cross-platform float comparison."""
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
import argparse, hashlib, record_io as json, math, sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'analysis'))
import pooled_statistics as shared
import mean_tail_statistics as mean_tail
import equal_frequency_statistics as equal_frequency

def need(ok,message):
 if not ok:raise ValueError(message)
def compare(expected,actual):
 result=dict(relative_tolerance=3e-13,absolute_tolerance=1e-9,float_fields=0,unequal_float_fields=0,
  maximum_absolute_difference=0.0,maximum_relative_difference=0.0,
  archived_replicate_values_sha256=expected['method']['replicate_values_sha256'],
  recomputed_replicate_values_sha256=actual['method']['replicate_values_sha256'])
 def walk(a,b,path=()):
  if path==('runtime',):
   result['archived_runtime']=a;result['recomputed_runtime']=b;return
  if path==('method','replicate_values_sha256'):
   mean_tail.model.digest(a);mean_tail.model.digest(b);return
  need(type(a)is type(b),'Type differs: '+ '/'.join(path))
  if isinstance(a,dict):
   need(a.keys()==b.keys(),'Fields differ: '+ '/'.join(path))
   for k in a:walk(a[k],b[k],path+(k,))
  elif isinstance(a,list):
   need(len(a)==len(b),'Length differs: '+ '/'.join(path))
   for i,(x,y) in enumerate(zip(a,b)):walk(x,y,path+(str(i),))
  elif isinstance(a,float):
   need(math.isfinite(a) and math.isfinite(b),'Nonfinite statistic')
   need(math.isclose(a,b,rel_tol=result['relative_tolerance'],abs_tol=result['absolute_tolerance']),'Numerical result differs: '+ '/'.join(path))
   delta=abs(a-b);relative=delta/max(abs(a),abs(b)) if a or b else 0.0
   result['float_fields']+=1;result['unequal_float_fields']+=a!=b
   result['maximum_absolute_difference']=max(result['maximum_absolute_difference'],delta)
   result['maximum_relative_difference']=max(result['maximum_relative_difference'],relative)
  else:need(a==b,'Exact field differs: '+ '/'.join(path))
 walk(expected,actual)
 result['replicate_bytes_equal']=result['archived_replicate_values_sha256']==result['recomputed_replicate_values_sha256']
 return result

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--kind',choices=['mean-tail','equal-frequency'],required=True)
 p.add_argument('--observations',type=Path,required=True);p.add_argument('--summary',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
 a=p.parse_args();need(not a.output.exists(),'Fresh output required')
 module=mean_tail if a.kind=='mean-tail' else equal_frequency
 observations=shared.read_observations(a.observations);summary=shared.read(a.summary);identity=shared.sha(a.observations)
 module.model.validate(summary,observations)
 need(summary['observations_sha256']==identity,'Raw observation identity changed')
 need(summary['source_code_hashes']==module.sources(),'Statistical implementation identity changed')
 pairs=[{k:r[k] for k in ('id','candidate','reference')} for r in summary['comparisons']]
 computed=module.analyze(observations,pairs,identity,summary['method']['resamples'],summary['method']['bootstrap_seed'],a.observations.resolve().parent)
 actual=computed[0] if a.kind=='mean-tail' else computed
 numerical=compare(summary,actual)
 a.output.mkdir(parents=True)
 shared.write(a.output/'recomputed-summary.xml',actual)
 result=dict(schema='lattice.operation_statistics_reproduction.v1',status='PASS',kind=a.kind,dataset_id=observations['dataset_id'],
  observations_sha256=identity,summary_sha256=shared.sha(a.summary),source_code_hashes=module.sources(),
  sample_rows=summary['counts']['raw_rows'],block_draws_sha256=summary['method']['block_draws_sha256'],
  recomputed_summary_sha256=shared.sha(a.output/'recomputed-summary.xml'),numerical_comparison=numerical,
  raw_samples_changed=False,formal_timing_collected=False)
 shared.write(a.output/'result.xml',result)
 print(shared.json.dumps(result))
if __name__=='__main__':main()
