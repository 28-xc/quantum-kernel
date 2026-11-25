"""Run complete application exchanges with fixed pools and protected stacks."""
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
import argparse, hashlib, importlib.util, record_io as json, os, platform, shutil, subprocess, time

ROOT=Path(__file__).resolve().parents[2]
import sys
sys.path.insert(0,str(ROOT))
from publicschemas.application_v1 import capture_stdout

RESOURCE=ROOT/'tests/resources'
spec=importlib.util.spec_from_file_location('image_inventory',RESOURCE/'image_inventory.py')
images=importlib.util.module_from_spec(spec);spec.loader.exec_module(images)
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def save(p,x):p.write_text(json.dumps(x,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
def core_reservation(path, image):
 path=Path(path);r=json.loads(path.read_text(encoding='utf-8'))
 assert r['status']=='PASS'
 if r.get('schema')=='lattice.normal_resource_measurement.v1':
  assert image['sha256']==r['library_sha256'] and r['H']==0
  assert {(x['parameter'],x['operation']) for x in r['cells']}=={(p,o) for p in (512,768,1024,44,65,87) for o in range(3)}
  assert r['G']==image['writable_image_plus_single_thread_tls_bytes'] and r['S']>=max(x['stack_reserved'] for x in r['cells'])
  observations=path.with_name('observations.xml');commands=path.with_name('commands.xml')
  assert sha(observations)==r['observations_sha256'] and sha(commands)==r['commands_sha256']
  records=json.loads(observations.read_text(encoding='utf-8'))
  assert len(records)==r['sequences'] and r['operations']==3*len(records) and r['seeds_per_parameter']>=24
  for row in records:
   v=row['result']
   assert v['outside_heap_peak_requested_bytes']==0 and v['heap_audit_errors']==0
   assert v['canaries_ok'] and v['recovery_full_sequence_ok'] and v['released_prefix_changed_nonzero_bytes']==0
  return r['S']
 assert image['sha256']==r['dll_sha256']
 assert len(r['parameters'])==6 and all(x['outside_heap_bytes']==0 for x in r['cells'].values())
 return max(x['stack_reserved_bytes'] for x in r['parameters'])
def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--configuration',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
 p.add_argument('--cc',default='gcc');p.add_argument('--objdump',default='objdump');p.add_argument('--seeds',type=int,default=24)
 a=p.parse_args();assert 24<=a.seeds<=100
 out=a.output.resolve();assert not out.exists()
 if os.name=='nt':assert out.drive.upper()=='D:'
 cfg=json.loads(a.configuration.read_text(encoding='utf-8'));libs=cfg['libraries'];assert len({x['id'] for x in libs})==len(libs)
 budgets=cfg.get('budgets_bytes',[32768,65536,131072,262144]);assert budgets==sorted(set(budgets)) and all(16384<=x<=1048576 for x in budgets)
 out.mkdir(parents=True);(out/'tmp').mkdir();(out/'source').mkdir()
 env=os.environ.copy();env.update(TEMP=str(out/'tmp'),TMP=str(out/'tmp'),TMPDIR=str(out/'tmp'),PYTHONDONTWRITEBYTECODE='1')
 machine=platform.machine().lower()
 assembly='stack_windows_x64.S' if os.name=='nt' else 'stack_aarch64.S' if machine in ('arm64','aarch64') else 'stack_linux_x64.S'
 sources=[ROOT/'tests/application_workload/resource_probe.c',Path(__file__),RESOURCE/'probe.c',RESOURCE/'image_inventory.py',RESOURCE/assembly,ROOT/'include/latticecore.h',RESOURCE/('windows_heap_audit.h' if os.name=='nt' else 'linux_heap_audit.c')]
 for f in sources:
  target=out/'source'/f.relative_to(ROOT);target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(f,target)
 commands=[]
 def command(argv,label):
  r=subprocess.run(list(map(str,argv)),env=env,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=180)
  log=out/(label+'.log');log.write_text(json.capture_text(r.stdout+r.stderr),encoding='utf-8');commands.append(dict(command=list(map(str,argv)),exit_code=r.returncode,log=log.name,log_sha256=sha(log)));save(out/'commands.xml',commands)
  if r.returncode:raise RuntimeError(label+' failed')
  return r.stdout
 cc=shutil.which(a.cc);objdump=shutil.which(a.objdump);assert cc and objdump
 exe=out/('application_resource.exe' if os.name=='nt' else 'application_resource')
 flags=['-O2','-std=c11','-Wall','-Wextra','-Werror','-fno-omit-frame-pointer']
 cmd=[cc,*flags,'-I'+str(out/'source/include'),out/'source/tests/application_workload/resource_probe.c',out/'source/tests/resources'/assembly,'-o',exe]
 if os.name!='nt':cmd+=['-ldl','-Wl,-z,noexecstack']
 command(cmd,'build');command([objdump,'-d',exe],'disassembly')
 if os.name!='nt':
  helper=out/'heap_audit.so';command([cc,*flags,'-shared','-fPIC',out/'source/tests/resources/linux_heap_audit.c','-o',helper],'heap_audit');env['LD_PRELOAD']=str(helper)
 bound=[]
 for lib in libs:
  im=images.inventory(lib['path']);assert im['sha256']==lib['sha256']
  stack=core_reservation(lib['resource'],im)
  bound.append(dict(**lib,core_stack=stack,application_stack=stack+768,globals=im['writable_image_plus_single_thread_tls_bytes'],resource_sha256=sha(lib['resource'])))
 protocol=dict(schema='lattice.application_resources.v1',libraries=bound,budgets_bytes=budgets,seeds=a.seeds,seed=20260927901,
  parameters=[[512,44],[768,65],[1024,87]],application_stack_extra_bytes=768,compiler=command([cc,'--version'],'compiler'),
  host=platform.platform(),machine=machine,source_sha256={f.relative_to(ROOT).as_posix():sha(f) for f in sources},executable_sha256=sha(exe),
  scope='Full six-step enrollment exchange, serialized objects, persistent application state and workspace in one fixed mutable-data pool; complete flow including cleanup runs on the protected stack.',
  budget_equation='pool + protected_stack + target_writable_image_and_one_TLS_copy + application_dispatch_pointer',
  infrastructure='Guard canaries, loaded-module controller, reference transcript, logging, OS mappings and heap-accounting instrumentation are recorded outside the application budget.',
  entropy='Deterministic paired test seed; private keys and shared secrets stay in process memory.',timing_collected=False)
 save(out/'protocol.xml',protocol);records=[];ledger=json.record_stream(out/'trials.records.xml')
 def trial(lib,kem,dsa,budget,stack,seed,control,purpose):
  argv=list(map(str,[exe,lib['path'],kem,dsa,budget,stack,lib['globals'],seed,control]));q=subprocess.run(argv,env=env,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=60)
  row=dict(id=len(records),library=lib['id'],kem=kem,dsa=dsa,budget=budget,stack=stack,seed=seed,control=control,purpose=purpose,command=argv,exit_code=q.returncode,stdout=capture_stdout(q.stdout),stderr=q.stderr)
  events=[json.loads(x) for x in q.stdout.splitlines() if x.startswith('{')];ends=[x for x in events if x.get('event')=='application_result']
  if not ends:
   faults=[x for x in events if x.get('event')=='stack_fault']
   if os.name=='nt' and q.returncode&0xffffffff in (0xc0000005,0xc00000fd):status='PROTECTED_STACK_EXIT'
   elif len(faults)==1 and faults[0]['protected_region_hit'] and q.returncode in (139,135,-11,-7):status='PROTECTED_STACK_FAULT'
   elif q.returncode==0 and len(events)==1 and events[0].get('status')=='POOL_TOO_SMALL':status='POOL_TOO_SMALL'
   else:status='INVALID'
   result=None
  else:
   result=ends[0];status=result['status']
   if len(ends)!=1 or q.returncode or any(result[k]!=v for k,v in dict(kem=kem,dsa=dsa,seed=seed,control=control,total_budget_bytes=budget,stack_reserved_bytes=stack,globals_and_tls_bytes=lib['globals']).items()):status='INVALID'
   if result['charged_bytes']>budget or result['stack_watermark_bytes']>stack or result['heap_errors'] or result['guard_error'] or not result['canaries_ok']:status='INVALID'
   if not control and status=='PASS' and (result['completed_operations']!=6 or not result['transcript_matches'] or result['external_heap_peak_bytes']):status='INVALID'
  row.update(classification=status,result=result);records.append(row);ledger.write(json.dumps(row)+'\n');ledger.flush()
  return status,result
 try:
  for lib in bound:
   for control,stack,wanted in [(1,4096,'PASS'),(2,4096,'FAULT'),(2,65536,'PASS'),(3,16384,'PASS')]:
    status,result=trial(lib,512,44,262144,stack,protocol['seed'],control,'instrument_control')
    assert status in ('PROTECTED_STACK_EXIT','PROTECTED_STACK_FAULT') if wanted=='FAULT' else status==wanted
    if control==3:assert result['external_heap_peak_bytes']==96
   for kem,dsa in protocol['parameters']:
    for budget in budgets:
     counts={}
     for n in range(a.seeds):
      seed=protocol['seed']+kem*65537+n*131071
      status,result=trial(lib,kem,dsa,budget,lib['application_stack'],seed,0,'fixed_application_budget')
      assert status in ('PASS','WORKSPACE_INSUFFICIENT','POOL_TOO_SMALL'),records[-1]
      counts[status]=counts.get(status,0)+1
     print(json.dumps(dict(library=lib['id'],kem=kem,dsa=dsa,budget=budget,counts=counts)),flush=True)
     save(out/'progress.xml',dict(trials=len(records),latest=records[-1]['id']))
  for lib in bound:assert sha(lib['path'])==lib['sha256'] and sha(lib['resource'])==lib['resource_sha256']
  assert sha(exe)==protocol['executable_sha256']
  ledger.close();save(out/'result.xml',dict(status='PASS',trials=len(records),protocol_sha256=sha(out/'protocol.xml'),raw_sha256=sha(out/'trials.records.xml'),all_rows_retained=True))
 except Exception as e:
  ledger.close();save(out/'failure.xml',dict(status='FAIL',error=repr(e),completed=len(records)));raise
if __name__=='__main__':main()
