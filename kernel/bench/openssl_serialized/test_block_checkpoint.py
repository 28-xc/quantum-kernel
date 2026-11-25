"""Ordinary fixed-input regression for bounded benchmark continuation.

This is a harness test: its elapsed values are not performance results.
Two valid local libraries and the previously verified comparison driver are
supplied through the normal configuration file.
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
import argparse, hashlib, record_io as json, shutil, subprocess, sys
HERE=Path(__file__).resolve().parent
def read(p):return json.loads(p.read_text(encoding='utf-8'))
def write(p,x):p.write_text(json.dumps(x,indent=2)+'\n',encoding='utf-8')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--configuration',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 out=a.output.resolve()
 if out.exists():raise ValueError('Fresh test output required')
 out.mkdir(parents=True)
 cfg=read(a.configuration);cfg.update(blocks=2,samples=10,warmups=2,seed=72812345,study_role='development')
 cfg['configurations']=[v for v in cfg['configurations'] if v['provider']=='lattice'][:2]
 if len(cfg['configurations'])!=2:raise ValueError('Two local libraries required')
 config=out/'fixture_configuration.xml';write(config,cfg);calls=[]
 def run(name,root,extra=(),passed=True,cfgpath=config):
  argv=[sys.executable,'-B',str(HERE/'blocked.py'),'--configuration',str(cfgpath),'--output',str(root),*extra]
  r=subprocess.run(argv,capture_output=True,text=True,encoding='utf-8',timeout=90)
  (out/(name+'.log')).write_text(json.capture_text(r.stdout+r.stderr),encoding='utf-8')
  calls.append(dict(name=name,exit_code=r.returncode,expected_success=passed,argv=argv))
  if (r.returncode==0)!=passed:raise AssertionError(name+' unexpected outcome: '+r.stderr[-1200:])
 full=out/'continuous';part=out/'segmented'
 run('continuous',full)
 run('first_block',part,['--blocks-per-invocation','1'])
 initial=read(part/'checkpoint.xml');assert initial['completed_blocks']==1 and not (part/'result.xml').exists()
 before={p.name:sha(p) for p in (part/'raw').iterdir()};manifest_before=sha(part/'manifest.xml')
 for case in ['changed_manifest','changed_raw','unrecorded_raw','changed_checkpoint','changed_journal','changed_configuration']:
  root=out/case;shutil.copytree(part,root);cp=config
  if case=='changed_manifest':
   d=read(root/'manifest.xml');d['configuration']['seed']+=1;write(root/'manifest.xml',d)
  elif case=='changed_raw':
   f=next((root/'raw').glob('*.csv'));f.write_bytes(f.read_bytes()+b'\n')
  elif case=='unrecorded_raw':(root/'raw'/'unexpected.txt').write_text('unrecorded',encoding='utf-8')
  elif case=='changed_checkpoint':
   d=read(root/'checkpoint.xml');d['completed']-=1;write(root/'checkpoint.xml',d)
  elif case=='changed_journal':
   f=root/'completed_calls.records.xml';f.write_text('',encoding='utf-8')
  else:
   cp=out/'changed_configuration.xml';d=dict(cfg);d['seed']+=1;write(cp,d)
  count=len(list((root/'raw').iterdir()));run(case,root,['--resume'],False,cp)
  assert len(list((root/'raw').iterdir()))==count
 run('second_block',part,['--resume','--blocks-per-invocation','1'])
 assert read(part/'result.xml')['status']=='PASS' and sha(part/'manifest.xml')==manifest_before
 assert all(sha(part/'raw'/name)==h for name,h in before.items())
 left=read(full/'commands.xml');right=read(part/'commands.xml')
 for x,y in zip(left,right,strict=True):
  for k in ['block','parameter','operation','variant','seed','label','input_sequence_sha256','output_sequence_sha256']:
   assert x[k]==y[k],k
 assert len(left)==len(right)==72
 run('completed_resume',part,['--resume'],False)
 run('implicit_overwrite',part,[],False)
 # Reuse the independent raw-matrix parser, without computing timing claims.
 sys.path.insert(0,str(HERE));import pooled_medians,blocked
 parsed=pooled_medians.load_dataset(part);assert parsed['raw_count']==864
 first=right[0];actual=read(part/first['log']);variant=cfg['configurations'][first['variant']]
 fields=['parameter','operation','seed','mode','message_bytes','context_bytes','workspace_reserved','fresh_serialized_key_every_call','entropy_mode','provider','message_encoding','mu','cpu','samples','warmups','backend','import_pct','status']
 for key in fields:
  altered=dict(actual);v=altered[key];altered[key]=not v if isinstance(v,bool) else v+1 if isinstance(v,int) else v+'-changed'
  try:blocked.validate_identity(altered,cfg,variant,first)
  except ValueError:pass
  else:raise AssertionError('Unverified scheduled identity: '+key)
 timeout_stdout=out/'timeout.stdout';timeout_stderr=out/'timeout.stderr'
 try:blocked.execute_driver([sys.executable,'-c',"import sys,time;print('begin',flush=True);print('diagnostic',file=sys.stderr,flush=True);time.sleep(5)"],None,timeout_stdout,timeout_stderr,timeout=1)
 except subprocess.TimeoutExpired:pass
 else:raise AssertionError('Timeout positive control did not terminate')
 assert b'begin' in timeout_stdout.read_bytes() and b'diagnostic' in timeout_stderr.read_bytes()
 result=dict(status='PASS',scope='fixed-input benchmark continuation regression; timing values are not performance evidence',driver_invocations=144,measured_operations=1440,warmup_operations=288,raw_rows_per_study=864,negative_cases=8,scheduled_identity_negative_cases=len(fields),timeout_stdout_stderr_preserved=True,unchanged_completed_raw_files=len(before),identical_schedules_and_input_output_transcripts=True,calls=calls,runner_sha256=sha(HERE/'blocked.py'))
 write(out/'result.xml',result);print(json.dumps({k:result[k] for k in ['status','driver_invocations','negative_cases','identical_schedules_and_input_output_transcripts']}))
if __name__=='__main__':main()
