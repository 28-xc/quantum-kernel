"""Replay a verified input matrix with separate, non-formal phase timers."""
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
import argparse, csv, hashlib, record_io as json, os, shutil, statistics, subprocess, time
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
PHASES=('import','setup','operation','export','free')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def dump(p,x):p.write_bytes((json.dumps(x,ensure_ascii=False,indent=2)+'\n').encode('utf-8'))
def validate_rows(rows,summary,verified):
 if len(rows)!=summary['samples'] or summary['raw_rows']!=len(rows):raise ValueError('Missing diagnostic rows')
 if summary['measurement_class']!='phase_diagnostic_only_not_formal':raise ValueError('Wrong measurement class')
 for i,(row,prior) in enumerate(zip(rows,verified,strict=True)):
  expected=f"{summary['seed']:016x}-{summary['parameter']}-{summary['operation']}-{i}"
  if row['case_id']!=expected or int(row['iteration'])!=i or int(row['openssl_first'])!=(i&1) or int(row['status']):raise ValueError('Case/order/status mismatch')
  if any(row[k]!=prior[k] for k in ('case_id','entropy_sha256','message_sha256','context_sha256')):raise ValueError('Verified input identity differs')
  values=[int(row['openssl_'+p+'_ticks']) for p in PHASES]
  if min(values+[int(row['lattice_total_ticks'])])<0 or int(row['frequency'])!=summary['frequency']:raise ValueError('Invalid timer')
  if sum(values)!=int(row['openssl_total_ticks']):raise ValueError('Phase sum differs')
  if summary['operation']==0 and int(row['openssl_import_ticks']):raise ValueError('Keygen cannot have serialized import')
  if summary['operation']!=0 and int(row['openssl_export_ticks']):raise ValueError('Output encoding must stay within operation')
 return {'median_ns':{k:statistics.median(int(r[k+'_ticks'])*1e9/summary['frequency'] for r in rows) for k in ('lattice_total','openssl_total',*('openssl_'+p for p in PHASES))},
         'scope':'Descriptive diagnostic only. Medians of phases need not add to median total. Instrumentation overhead is retained.'}
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--verify-evidence',type=Path,required=True);p.add_argument('--crypto-prefix',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--cc',default='gcc');a=p.parse_args()
 folder=a.verify_evidence.resolve();prior=json.loads((folder/'result.xml').read_text(encoding='utf-8'));identity=prior['identity'];out=a.output.resolve();prefix=a.crypto_prefix.resolve();cc=shutil.which(a.cc)
 if prior['status']!='PASS' or prior['measurement_class']!='correctness_only':raise ValueError('A successful untimed verification is required')
 if out.exists() or (os.name=='nt' and out.drive.upper()!='D:'):raise ValueError('Fresh D: output required on Windows')
 library=Path(identity['library']['path']);crypto=Path(identity['crypto_library']['path'])
 if not cc or sha(library)!=identity['library']['sha256'] or sha(crypto)!=identity['crypto_library']['sha256']:raise ValueError('Tool/library identity mismatch')
 if sha(HERE/'driver.c')!=identity['sources']['bench/openssl_serialized/driver.c']:raise ValueError('Primary driver source changed since verification')
 if any(b['warmups'] or b['mode']!='verify' for b in prior['blocks']):raise ValueError('Use a verification matrix without warmups')
 out.mkdir(parents=True);(out/'tmp').mkdir();env=os.environ.copy();env.update(TEMP=str(out/'tmp'),TMP=str(out/'tmp'),PYTHONDONTWRITEBYTECODE='1')
 key='PATH' if os.name=='nt' else 'LD_LIBRARY_PATH';env[key]=str(crypto.parent)+os.pathsep+env.get(key,'')
 sources=(HERE/'diagnostic.c',HERE/'diagnose.py',HERE/'driver.c',HERE/'method.md',ROOT/'include/latticecore.h')
 for source in sources:
  dest=out/'source_snapshot'/source.relative_to(ROOT);dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,dest)
 records=[];summaries=[];started=time.monotonic()
 provenance={'measurement_class':'phase_diagnostic_only_not_formal','verification_result':str(folder/'result.xml'),'verification_result_sha256':sha(folder/'result.xml'),'libraries':{'lattice':identity['library'],'openssl':identity['crypto_library']},'sources':{s.relative_to(ROOT).as_posix():sha(s) for s in sources},'no_primary_timer_modification':True,'no_preimported_hot_service_claim':True}
 dump(out/'identity.xml',provenance)
 def run(cmd,label):
  q=subprocess.run([str(s) for s in cmd],cwd=ROOT,env=env,capture_output=True,text=True,encoding='utf-8',errors='replace');log=out/(label+'.txt');log.write_bytes(json.capture_bytes((q.stdout+q.stderr).encode('utf-8')));records.append({'argv':[str(s) for s in cmd],'exit_code':q.returncode,'log':log.name,'sha256':sha(log)});dump(out/'commands.xml',records)
  if q.returncode:raise RuntimeError(label+' failed with '+str(q.returncode))
  return q.stdout
 try:
  run([cc,'--version'],'compiler');exe=out/('diagnostic.exe' if os.name=='nt' else 'diagnostic');linkdir=prefix/'lib' if os.name=='nt' else crypto.parent
  cmd=[cc,'-O3','-std=c11','-Wall','-Wextra','-Werror','-I'+str(ROOT/'include'),'-I'+str(prefix/'include'),str(HERE/'diagnostic.c'),'-L'+str(linkdir),'-lcrypto']
  if os.name!='nt':cmd+=['-ldl','-Wl,-rpath,'+str(crypto.parent)]
  run(cmd+['-o',exe],'build');provenance['driver_sha256']=sha(exe);dump(out/'identity.xml',provenance)
  for block in prior['blocks']:
   level=block['parameter'];op=block['operation'];pct=block['import_pct'];label=f'{level}_{op}_{pct}';raw=out/(label+'.csv')
   cmd=[exe,library,level,op,block['samples'],block['seed'],raw,block['workspace_reserved'],block['message_bytes'],block['context_bytes'],pct,block['cpu'],identity['expected_openssl_version'],'diagnostic_only']
   summary=json.loads(run(cmd,label));loaded=Path(summary['openssl_library']).resolve()
   if not loaded.samefile(crypto) or sha(loaded)!=identity['crypto_library']['sha256']:raise ValueError('Loaded OpenSSL identity differs')
   if summary['status']!='PASS' or summary['parameter']!=level or summary['operation']!=op or summary['import_pct']!=pct or summary['cpu']!=block['cpu'] or summary['seed']!=block['seed']:raise ValueError('Diagnostic cell identity differs')
   for field in ('input_sequence_sha256','output_sequence_sha256'):
    if summary[field]!=block[field]:raise ValueError('Diagnostic transcript differs from uninstrumented verification')
   with raw.open(newline='') as f:rows=list(csv.DictReader(f))
   original=folder/block['raw_csv']
   if sha(original)!=block['raw_csv_sha256']:raise ValueError('Verification CSV changed')
   with original.open(newline='') as f:verified=list(csv.DictReader(f))
   summary['descriptive']=validate_rows(rows,summary,verified);summary.update(raw_csv=raw.name,raw_csv_sha256=sha(raw));summaries.append(summary)
   dump(out/'progress.xml',{'completed_blocks':len(summaries),'latest':label});print(label,'PASS',flush=True)
  if sha(library)!=identity['library']['sha256'] or sha(crypto)!=identity['crypto_library']['sha256']:raise ValueError('Library changed during diagnostic')
  dump(out/'result.xml',{'status':'PASS','measurement_class':'phase_diagnostic_only_not_formal','identity':provenance,'blocks':summaries,'raw_samples':sum(s['raw_rows'] for s in summaries),'elapsed_wall_seconds':time.monotonic()-started,'sample_trimming':False,'commands_sha256':sha(out/'commands.xml')})
 except Exception as e:dump(out/'failure.xml',{'status':'FAILED','error':str(e),'identity':provenance,'completed':summaries,'commands':records});raise
if __name__=='__main__':main()
