"""Negative tests for phase integrity and actual diagnostic CLI guards."""
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
import argparse, copy, hashlib, importlib.util, record_io as json, os, shutil, subprocess
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
spec=importlib.util.spec_from_file_location('diagnose',HERE/'diagnose.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def main():
 p=argparse.ArgumentParser();p.add_argument('--library',type=Path,required=True);p.add_argument('--crypto-library',type=Path,required=True);p.add_argument('--crypto-prefix',type=Path,required=True);p.add_argument('--cc',default='gcc');p.add_argument('--output',type=Path,required=True);p.add_argument('--cpu',type=int,required=True);a=p.parse_args();out=a.output.resolve()
 if out.exists() or (os.name=='nt' and out.drive.upper()!='D:'):raise ValueError('Fresh D: output required')
 out.mkdir(parents=True);(out/'tmp').mkdir();records=[];commands=[]
 s={'samples':3,'raw_rows':3,'parameter':65,'operation':1,'seed':20260924,'frequency':10000000,'measurement_class':'phase_diagnostic_only_not_formal'}
 rows=[{'case_id':f'{s["seed"]:016x}-65-1-{i}','iteration':str(i),'openssl_first':str(i&1),'frequency':'10000000','lattice_total_ticks':'18','openssl_import_ticks':'2','openssl_setup_ticks':'3','openssl_operation_ticks':'5','openssl_export_ticks':'0','openssl_free_ticks':'7','openssl_total_ticks':'17','status':'0','entropy_sha256':'a'*64,'message_sha256':'b'*64,'context_sha256':'c'*64} for i in range(3)]
 def check(name,change=None,change_s=None):
  r=copy.deepcopy(rows);summary=copy.deepcopy(s)
  if change:change(r)
  if change_s:change_s(summary)
  rejected=False
  try:m.validate_rows(r,summary,rows)
  except (ValueError,KeyError):rejected=True
  wanted=change is not None or change_s is not None
  if rejected!=wanted:raise AssertionError(name)
  records.append({'case':name,'expected':'REJECT' if wanted else 'ACCEPT','observed':'REJECT' if rejected else 'ACCEPT','status':'PASS'})
 check('valid_phase_rows');check('missing_row',lambda r:r.pop());check('duplicate_case',lambda r:r[1].update(case_id=r[0]['case_id']));check('bad_status',lambda r:r[0].update(status='-1'));check('wrong_order',lambda r:r[0].update(openssl_first='1'));check('wrong_iteration',lambda r:r[0].update(iteration='9'));check('wrong_input',lambda r:r[0].update(entropy_sha256='d'*64));check('negative_phase',lambda r:r[0].update(openssl_import_ticks='-1'));check('invalid_frequency',lambda r:r[0].update(frequency='1'));check('phase_sum_mismatch',lambda r:r[0].update(openssl_total_ticks='18'));check('fictional_separate_export',lambda r:r[0].update(openssl_export_ticks='1',openssl_total_ticks='18'));check('wrong_class',change_s=lambda x:x.update(measurement_class='formal'))
 env=os.environ.copy();crypto=a.crypto_library.resolve();prefix=a.crypto_prefix.resolve();library=a.library.resolve();key='PATH' if os.name=='nt' else 'LD_LIBRARY_PATH';env[key]=str(crypto.parent)+os.pathsep+env.get(key,'');env.update(TEMP=str(out/'tmp'),TMP=str(out/'tmp'))
 def run(cmd,label):
  q=subprocess.run([str(c) for c in cmd],cwd=ROOT,env=env,capture_output=True,text=True,encoding='utf-8',errors='replace');log=out/(label+'.txt');log.write_bytes(json.capture_bytes((q.stdout+q.stderr).encode()));commands.append({'argv':[str(c) for c in cmd],'exit_code':q.returncode,'log':log.name,'sha256':m.sha(log)});m.dump(out/'commands.xml',commands);return q
 cc=shutil.which(a.cc)
 if not cc:raise ValueError('Compiler missing')
 exe=out/('diagnostic.exe' if os.name=='nt' else 'diagnostic');cmd=[cc,'-O3','-std=c11','-Wall','-Wextra','-Werror','-I'+str(ROOT/'include'),'-I'+str(prefix/'include'),str(HERE/'diagnostic.c'),'-L'+str(prefix/'lib' if os.name=='nt' else crypto.parent),'-lcrypto']
 if os.name!='nt':cmd+=['-ldl','-Wl,-rpath,'+str(crypto.parent)]
 if run(cmd+['-o',exe],'build').returncode:raise RuntimeError('compile failed')
 original=[str(exe),str(library),'512','0','1','20260924',str(out/'unused.csv'),'262144','1024','0','none',str(a.cpu),'3.6.4','diagnostic_only']
 for name,index,value,wanted in [('wrong_mode',13,'measure',3),('wrong_version',12,'3.6.0',4),('invalid_cpu',11,'99999',5),('invalid_pct',10,'fixed',3),('missing_library',1,str(out/'absent_library'),6),('invalid_parameter',2,'999',3),('invalid_capacity',7,'31',3)]:
  c=original.copy();c[index]=value;q=run(c,name)
  if q.returncode!=wanted:raise AssertionError((name,q.returncode,wanted))
  records.append({'case':name,'expected_exit':wanted,'exit_code':q.returncode,'status':'PASS'})
 raw=out/'preserved.csv';raw.write_bytes(b'preserved original diagnostic\n');digest=m.sha(raw);c=original.copy();c[6]=str(raw);q=run(c,'raw_overwrite')
 if q.returncode!=3 or m.sha(raw)!=digest:raise AssertionError('Raw overwrite protection')
 records.append({'case':'refuse_raw_overwrite','expected_exit':3,'exit_code':q.returncode,'unchanged':True,'status':'PASS'})
 m.dump(out/'result.xml',{'status':'PASS','tests':len(records),'records':records,'source_sha256':{p.name:m.sha(p) for p in (Path(__file__),HERE/'diagnostic.c',HERE/'diagnose.py',HERE/'driver.c')},'driver_sha256':m.sha(exe),'crypto_sha256':m.sha(crypto),'lattice_sha256':m.sha(library),'actual_measurements_collected':False});print(len(records),'diagnostic tests PASS')
if __name__=='__main__':main()
