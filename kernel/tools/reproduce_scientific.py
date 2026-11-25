"""Recompute released scientific records and regenerate report figures/tables."""
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
import argparse, hashlib, importlib.util, record_io as json, os, shutil, subprocess, sys, time
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def read(p):return json.loads(Path(p).read_text(encoding='utf-8'))
def save(p,x):Path(p).write_text(json.dumps(x,ensure_ascii=False,indent=2,allow_nan=False)+'\n',encoding='utf-8')
def same(a,b):
 if isinstance(a,dict):
  if not isinstance(b,dict)or set(a)!=set(b):raise ValueError('Recomputed field mismatch')
  for k in a:same(a[k],b[k])
 elif isinstance(a,list):
  if not isinstance(b,list)or len(a)!=len(b):raise ValueError('Recomputed row mismatch')
  for x,y in zip(a,b):same(x,y)
 elif isinstance(a,(int,float))and not isinstance(a,bool):
  import math
  if not isinstance(b,(int,float))or not math.isclose(a,b,rel_tol=3e-13,abs_tol=1e-9):raise ValueError('Recomputed number mismatch')
 elif a!=b:raise ValueError('Recomputed value mismatch')
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--bundle',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--mode',choices=['quick','full'],default='full');p.add_argument('--data-only',action='store_true');p.add_argument('--figures-only',action='store_true');p.add_argument('--objdump',type=Path,help='GNU objdump for independently decoding the released machine-code correspondence; defaults to PATH');a=p.parse_args();B=a.bundle.resolve();O=a.output.resolve()
 if O.exists()or O.is_relative_to(B):raise ValueError('Use a fresh output outside the delivered bundle')
 O.mkdir(parents=True);(O/'logs').mkdir();D=B/'data';F=B/'report/figures/source';env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',PYTHONUTF8='1',MPLCONFIGDIR=str(O/'matplotlib'),TEMP=str(O),TMP=str(O));result=dict(schema='lattice.scientific_reproduction.v1',status='RUNNING',mode=a.mode,records=[])
 def check(name,value,expected):
  same(read(expected),value);save(O/(name+'.xml'),value);result['records'].append(dict(name=name,expected_sha256=sha(expected),recomputed_sha256=sha(O/(name+'.xml')),status='PASS'));save(O/'result.xml',result)
 def run(name,script,args,timeout=1800):
  start=time.monotonic();q=subprocess.run([sys.executable,'-X','utf8','-B',str(script),*map(str,args)],capture_output=True,text=True,encoding='utf-8',env=env,timeout=timeout);log=O/'logs'/(name+'.log');log.write_text(json.capture_text(q.stdout+q.stderr),encoding='utf-8');result['records'].append(dict(name=name,script_sha256=sha(script),exit_code=q.returncode,seconds=time.monotonic()-start,log_sha256=sha(log)));save(O/'result.xml',result)
  if q.returncode:raise RuntimeError(name+' failed; inspect logs/'+log.name)
  print(name+' PASS',flush=True)
 def regenerate():
  report=O/'report';shutil.copytree(F,report/'figures/source')
  (report/'tables').mkdir()
  run('final-report-figures',F/'regenerate_report.py',['--data-root',D,'--report-root',report,'--qa-dir',O/'report-qa'])
 if a.figures_only:
  if a.data_only:raise ValueError('Choose data-only or figures-only')
  try:regenerate();result.update(status='PASS',formal_timing_collected=False)
  except BaseException as e:result.update(status='FAILED_OR_INCOMPLETE',error=str(e));raise
  finally:save(O/'result.xml',result)
  print(json.dumps(dict(status='PASS',checks=len(result['records']),output=str(O/'result.xml'))));return
 try:
  from publicschemas.application_owner_v1 import recompute as application
  from publicschemas.primitive_samples_v1 import recompute as primitive
  from publicschemas.profiling_v1 import recompute as profiling
  from publicschemas.application_budget_v1 import recompute as budget
  from publicschemas.signing_qualification import recompute as qualification
  for platform in ['windows','arm']:
   folder=D/(platform+'-application-owner');check(platform+'-application',application(folder/'observations.xml'),folder/'summary.xml')
   folder=D/(platform+'-polynomial-operations');check(platform+'-primitives',primitive(folder/'observations.xml'),folder/'statistics.xml')
   folder=D/('application-budget-'+platform);check(platform+'-application-budget',budget(folder/'observations.xml'),folder/'summary.xml')
  folder=D/'windows-instruction-samples';check('instruction-samples',profiling(folder/'observations.xml'),folder/'summary.xml')
  folder=D/'verification-signing-pipeline'
  run('qualification',folder/'recompute.py',['--root',folder,'--output',O/'qualification.xml'])
  same(read(O/'qualification.xml'),read(folder/'summary.xml'))
  if a.mode=='full':
   for platform in ['windows','arm']:
    folder=D/('signing-pipeline-'+platform)
    run(platform+'-pipeline-mean-tail',ROOT/'tools/recompute_operation_statistics.py',['--kind','mean-tail','--observations',folder/'observations.xml','--summary',folder/'mean-tail-summary.xml','--output',O/(platform+'-pipeline-mean-tail')])
    run(platform+'-pipeline-equal-frequency',ROOT/'tools/recompute_operation_statistics.py',['--kind','equal-frequency','--observations',folder/'observations.xml','--summary',folder/'equal-frequency-summary.xml','--output',O/(platform+'-pipeline-equal-frequency')])
   registry=read(D/'supplementary-records.xml')
   assert registry['schema']=='lattice.supplementary_records.v1' and registry['records']
   objdump=a.objdump or shutil.which('objdump')
   if any('{objdump}' in str(x) for rec in registry['records'] for x in rec['args']):
    if objdump is None or not Path(objdump).is_file():raise ValueError('Full machine-code replay requires GNU objdump on PATH or --objdump <executable>')
   for record in registry['records']:
    script=(B/record['script']).resolve()
    assert script.is_relative_to(B) and sha(script)==record['script_sha256']
    args=[str(x).replace('{bundle}',str(B)).replace('{source}',str(ROOT)).replace('{data}',str(D)).replace('{output}',str(O)).replace('{objdump}',str(objdump)) for x in record['args']]
    run(record['name'],script,args,record.get('timeout_seconds',1800))
    for comparison in record.get('comparisons',[]):
     same(read(B/comparison['released']),read(O/comparison['recomputed']))
   if not a.data_only:regenerate()
  result['status']='PASS';result['formal_timing_collected']=False
 except BaseException as e:result.update(status='FAILED_OR_INCOMPLETE',error=str(e));raise
 finally:save(O/'result.xml',result)
 print(json.dumps(dict(status='PASS',checks=len(result['records']),output=str(O/'result.xml'))))
if __name__=='__main__':main()
