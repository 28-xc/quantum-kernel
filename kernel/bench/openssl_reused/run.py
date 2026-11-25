"""Build and run a common serialized-boundary driver, preserving all samples.

Default mode checks correctness without collecting time. Sanity timings are
labelled separately; collect emits raw data and never declares a formal result.
"""
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
import argparse, csv, hashlib, record_io as json, math, os, platform, shutil, subprocess, time
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def dump(p,x):p.write_text(json.dumps(x,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
def validate_csv(path,summary):
 with path.open(newline='',encoding='utf-8') as f:rows=list(csv.DictReader(f))
 n=summary['samples'];w=summary['warmups'];measure=summary['mode']=='measure'
 if len(rows)!=n+w or summary['raw_rows']!=n+w:raise ValueError('Raw sample count mismatch')
 for i,row in enumerate(rows):
  if row['case_id']!=f"{summary['seed']:016x}-{summary['parameter']}-{summary['operation']}-{i}":raise ValueError('Case identity mismatch/duplication')
  if int(row['iteration'])!=i-w or int(row['warmup'])!=(i<w) or int(row['status'])!=0:raise ValueError('Missing/out-of-order/failing sample')
  for k in ('entropy_sha256','message_sha256','context_sha256'):
   if len(row[k])!=64 or any(c not in '0123456789abcdef' for c in row[k]):raise ValueError('Invalid input identity')
  if measure:
   ns=float(row['elapsed_ns']);ticks=int(row['elapsed_ticks']);freq=int(row['tick_frequency'])
   if not math.isfinite(ns) or ns<0 or ticks<0 or freq!=summary['frequency'] or abs(ns-ticks*1e9/freq)>0.001:raise ValueError('Invalid elapsed time')
  elif any(row[k] for k in ('elapsed_ns','elapsed_ticks','tick_frequency')):raise ValueError('Unexpected timing in verification mode')
 return rows
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--crypto-library',type=Path,required=True);p.add_argument('--crypto-prefix',type=Path,required=True);p.add_argument('--expected-version',choices=['3.6.0','3.6.4'],required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--cc',default='gcc');p.add_argument('--cpu',type=int,required=True);p.add_argument('--mode',choices=['verify','sanity','collect'],default='verify');p.add_argument('--count',type=int,default=100);p.add_argument('--warmups',type=int,default=0);p.add_argument('--seed',type=int,default=20260924);p.add_argument('--workspace',type=int,default=262144);p.add_argument('--message-bytes',type=int,default=1024);p.add_argument('--context-bytes',type=int,default=0);p.add_argument('--pct',nargs='+',choices=['none','random'],default=['none','random']);p.add_argument('--parameters',type=int,nargs='+',choices=[512,768,1024,44,65,87],default=[512,768,1024,44,65,87]);p.add_argument('--operations',type=int,nargs='+',choices=[0,1,2],default=[0,1,2]);a=p.parse_args()
 if not 1<=a.count<=1000000 or not 0<=a.warmups<=10000 or not 0<a.seed<2**64 or not 32<=a.workspace<=262144 or not 0<=a.message_bytes<=16384 or not 0<=a.context_bytes<=255 or a.cpu<0:raise ValueError('Invalid numerical argument')
 if any(len(x)!=len(set(x)) for x in (a.pct,a.parameters,a.operations)):raise ValueError('Duplicate requested cell')
 out=a.output.resolve();library=a.library.resolve();crypto=a.crypto_library.resolve();prefix=a.crypto_prefix.resolve();cc=shutil.which(a.cc)
 if out.exists() or out==ROOT or out in ROOT.parents:raise ValueError('Output must be a new dedicated directory')
 if os.name=='nt' and out.drive.upper()!='D:':raise ValueError('Windows output must stay on D:')
 if not cc or not library.is_file() or not crypto.is_file() or not (prefix/'include/openssl/evp.h').is_file():raise ValueError('Missing explicit tool/library/header input')
 out.mkdir(parents=True);(out/'tmp').mkdir();env=os.environ.copy();env.update(TEMP=str(out/'tmp'),TMP=str(out/'tmp'),PYTHONUTF8='1',PYTHONDONTWRITEBYTECODE='1')
 if os.name=='nt':env['PATH']=str(crypto.parent)+os.pathsep+env.get('PATH','')
 else:env['LD_LIBRARY_PATH']=str(crypto.parent)+os.pathsep+env.get('LD_LIBRARY_PATH','')
 source_files=(HERE/'driver.c',HERE/'run.py',HERE/'method.md',ROOT/'include/latticecore.h')
 for source in source_files:
  dest=out/'source_snapshot'/source.relative_to(ROOT);dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,dest)
 identity={'library':{'path':str(library),'sha256':sha(library)},'crypto_library':{'path':str(crypto),'sha256':sha(crypto)},'sources':{p.relative_to(ROOT).as_posix():sha(p) for p in source_files},'host':platform.platform(),'machine':platform.machine(),'cpu':a.cpu,'mode':a.mode,'thread_count':1,'seed':a.seed,'requested_parameters':a.parameters,'requested_operations':a.operations,'import_pct_modes':a.pct,'cpu_capability_overrides':{k:v for k,v in os.environ.items() if k in ('OPENSSL_ia32cap','OPENSSL_armcap','OPENSSL_CONF','OPENSSL_MODULES')},'workspace_scope':'caller arena only; not a complete RAM measurement','performance_scope':'No formal acceptance or speedup conclusion is produced by this runner'}
 identity['expected_openssl_version']=a.expected_version
 records=[];summaries=[];start=time.monotonic();dump(out/'identity.xml',identity)
 def run(cmd,label):
  q=subprocess.run([str(x) for x in cmd],env=env,cwd=ROOT,capture_output=True,text=True,encoding='utf-8',errors='replace');log=out/(label+'.txt');log.write_text(json.capture_text(q.stdout+q.stderr),encoding='utf-8');records.append({'argv':[str(x) for x in cmd],'exit_code':q.returncode,'log':log.name,'log_sha256':sha(log)});dump(out/'commands.xml',records)
  if q.returncode:raise RuntimeError(label+' failed: '+str(q.returncode))
  return q.stdout
 try:
  identity['compiler']=run([cc,'--version'],'compiler_version').splitlines()[0];identity['compiler_target']=run([cc,'-dumpmachine'],'compiler_target').strip()
  exe=out/('driver.exe' if os.name=='nt' else 'driver');linkdir=prefix/'lib' if os.name=='nt' else crypto.parent
  command=[cc,'-O3','-std=c11','-Wall','-Wextra','-Werror','-I'+str(ROOT/'include'),'-I'+str(prefix/'include'),str(HERE/'driver.c'),'-L'+str(linkdir),'-lcrypto']
  if os.name!='nt':command+=['-ldl','-Wl,-rpath,'+str(crypto.parent)]
  command+=['-o',str(exe)];run(command,'build');identity['driver_sha256']=sha(exe);dump(out/'identity.xml',identity)
  paired={}
  for level in a.parameters:
   for op in a.operations:
    for pct in a.pct:
     for backend in (['compare'] if a.mode=='verify' else ['lattice','openssl']):
      label=f'{level}_{op}_{pct}_{backend}';raw=out/(label+'.csv')
      cmd=[exe,library,backend,level,op,a.count,a.seed,raw,a.workspace,a.message_bytes,a.context_bytes,pct,a.cpu,'verify' if a.mode=='verify' else 'measure',a.warmups,a.expected_version]
      summary=json.loads(run(cmd,label));loaded=Path(summary['openssl_library']).resolve()
      if not loaded.samefile(crypto) or sha(loaded)!=identity['crypto_library']['sha256']:raise ValueError('Unexpected actual loaded crypto library')
      if summary['status']!='PASS' or summary['provider']!='default' or summary['import_pct']!=pct or summary['cpu']!=a.cpu:raise ValueError('Unexpected implementation/mode identity')
      rows=validate_csv(raw,summary);identities=[tuple(row[k] for k in ('case_id','entropy_sha256','message_sha256','context_sha256')) for row in rows];pair=(level,op);value=(summary['input_sequence_sha256'],summary['output_sequence_sha256'],identities)
      if pair in paired and paired[pair]!=value:raise ValueError('Paired input or output sequence differs')
      paired[pair]=value;summary.update(raw_csv=raw.name,raw_csv_sha256=sha(raw));summaries.append(summary);dump(out/'progress.xml',{'completed_blocks':len(summaries),'latest':label});print(label,'PASS',flush=True)
  if sha(library)!=identity['library']['sha256'] or sha(crypto)!=identity['crypto_library']['sha256']:raise ValueError('Library changed during execution')
  result={'status':'PASS','identity':identity,'blocks':summaries,'raw_samples':sum(r['raw_rows'] for r in summaries),'distinct_operation_cells':len(paired),'all_input_output_sequences_match':True,'sample_trimming':False,'measurement_class':'correctness_only' if a.mode=='verify' else 'sanity_only_not_formal' if a.mode=='sanity' else 'raw_collection_no_acceptance_decision','elapsed_wall_seconds':time.monotonic()-start,'commands_sha256':sha(out/'commands.xml')};dump(out/'result.xml',result)
 except Exception as e:dump(out/'failure.xml',{'status':'FAILED','reason':str(e),'identity':identity,'completed':summaries,'commands':records});raise
if __name__=='__main__':main()
