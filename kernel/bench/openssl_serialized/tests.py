"""Negative checks for sample integrity and the actual compiled driver."""
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
import argparse, csv, copy, hashlib, importlib.util, record_io as json, os, subprocess
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('serialized_run',HERE/'run.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
def main():
 p=argparse.ArgumentParser();p.add_argument('--verify-evidence',type=Path,required=True);p.add_argument('--sanity-evidence',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();out=a.output.resolve()
 if out.exists():raise ValueError('Use a new directory')
 if os.name=='nt' and out.drive.upper()!='D:':raise ValueError('D: required')
 out.mkdir(parents=True);records=[]
 def sample_check(name,result,folder,mutation=None,summary_mutation=None):
  summary=copy.deepcopy(result['blocks'][0]);source=folder/summary['raw_csv']
  with source.open(newline='') as f:reader=csv.DictReader(f);fields=reader.fieldnames;rows=list(reader)
  if mutation:mutation(rows)
  if summary_mutation:summary_mutation(summary)
  dest=out/(name+'.csv')
  with dest.open('w',newline='') as f:w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(rows)
  rejected=False
  try:m.validate_csv(dest,summary)
  except (ValueError,KeyError):rejected=True
  wanted=mutation is not None or summary_mutation is not None
  if rejected!=wanted:raise AssertionError(name)
  records.append({'case':name,'expected':'REJECT' if wanted else 'ACCEPT','observed':'REJECT' if rejected else 'ACCEPT','status':'PASS'})
 vdir=a.verify_evidence.resolve();sdir=a.sanity_evidence.resolve();verify=json.loads((vdir/'result.xml').read_text());sanity=json.loads((sdir/'result.xml').read_text())
 sample_check('valid_verify',verify,vdir);sample_check('valid_sanity',sanity,sdir)
 sample_check('missing_row',verify,vdir,lambda r:r.pop())
 sample_check('duplicate_case',verify,vdir,lambda r:r[1].update(case_id=r[0]['case_id']))
 sample_check('error_status',verify,vdir,lambda r:r[0].update(status='-6'))
 sample_check('bad_entropy_id',verify,vdir,lambda r:r[0].update(entropy_sha256='bad'))
 sample_check('wrong_iteration',verify,vdir,lambda r:r[0].update(iteration='999'))
 sample_check('wrong_warmup_flag',sanity,sdir,lambda r:r[0].update(warmup='0' if r[0]['warmup']=='1' else '1'))
 sample_check('unexpected_verify_timing',verify,vdir,lambda r:r[0].update(elapsed_ns='1'))
 sample_check('wrong_metadata_count',verify,vdir,summary_mutation=lambda s:s.update(samples=s['samples']+1))
 sample_check('nan_time',sanity,sdir,lambda r:r[0].update(elapsed_ns='nan'))
 sample_check('negative_ticks',sanity,sdir,lambda r:r[0].update(elapsed_ticks='-1'))
 sample_check('wrong_frequency',sanity,sdir,lambda r:r[0].update(tick_frequency='1'))
 sample_check('wrong_tick_conversion',sanity,sdir,lambda r:r[0].update(elapsed_ns='999999999'))
 # Execute the exact driver already built for the verification evidence.
 exe=vdir/('driver.exe' if os.name=='nt' else 'driver');identity=verify['identity'];env=os.environ.copy();crypto=Path(identity['crypto_library']['path']);key='PATH' if os.name=='nt' else 'LD_LIBRARY_PATH';env[key]=str(crypto.parent)+os.pathsep+env.get(key,'')
 original=[str(exe),identity['library']['path'],'compare','512','0','1','20260924',str(out/'unused.csv'),'262144','1024','0','none',str(identity['cpu']),'verify','0',identity['expected_openssl_version']]
 cases=[('invalid_pct',11,'invalid',3),('invalid_cpu',12,'99999',5),('insufficient_workspace',8,'32',7),('missing_library',1,str(out/'absent_library'),6),('wrong_version',15,'3.6.4' if identity['expected_openssl_version']=='3.6.0' else '3.6.0',4)]
 for name,index,value,expected in cases:
  cmd=original.copy();cmd[index]=value;q=subprocess.run(cmd,env=env,capture_output=True,text=True);log=out/(name+'.txt');log.write_text(json.capture_text(q.stdout+q.stderr),encoding='utf-8')
  if q.returncode!=expected:raise AssertionError((name,q.returncode,q.stderr))
  records.append({'case':name,'argv':cmd,'expected_exit_code':expected,'exit_code':q.returncode,'status':'PASS'})
 prior=out/'preserved.csv';prior.write_bytes(b'original raw evidence\n');digest=m.sha(prior);cmd=original.copy();cmd[7]=str(prior);q=subprocess.run(cmd,env=env,capture_output=True,text=True)
 if q.returncode!=3 or m.sha(prior)!=digest:raise AssertionError('overwrite refusal')
 records.append({'case':'refuse_raw_overwrite','argv':cmd,'expected_exit_code':3,'exit_code':q.returncode,'file_unchanged':True,'status':'PASS'})
 result={'status':'PASS','tests':len(records),'records':records,'driver_sha256':m.sha(exe),'test_source_sha256':m.sha(Path(__file__)),'verification_result_sha256':m.sha(vdir/'result.xml'),'sanity_result_sha256':m.sha(sdir/'result.xml')};m.dump(out/'result.xml',result);print(len(records),'tests PASS')
if __name__=='__main__':main()
