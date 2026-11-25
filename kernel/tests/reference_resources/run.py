"""Measure immutable reference libraries with protected stack and heap accounting."""
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
import argparse, hashlib, record_io as json, os, platform, shutil, subprocess, sys, time
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
sys.path.insert(0,str(HERE));from image_inventory import inventory
LEVELS=[512,768,1024,44,65,87]
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def dump(p,x):p.write_text(json.dumps(x,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--config',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);ap.add_argument('--cc',default='gcc');a=ap.parse_args()
 cfg=json.loads(a.config.read_text(encoding='utf-8'));out=a.output.resolve();assert not out.exists();out.mkdir(parents=True);(out/'sources').mkdir();(out/'tmp').mkdir()
 env=os.environ.copy();env.update(TEMP=str(out/'tmp'),TMP=str(out/'tmp'),TMPDIR=str(out/'tmp'),PYTHONDONTWRITEBYTECODE='1')
 windows=os.name=='nt';assembly='stack_windows_x64.S' if windows else 'stack_aarch64.S' if platform.machine()=='aarch64' else 'stack_linux_x64.S'
 names=['probe.c',assembly,'windows_heap_audit.h' if windows else 'linux_heap_audit.c','image_inventory.py','run.py','probe_sources.xml']
 for name in names:shutil.copyfile(HERE/name,out/'sources'/name)
 shutil.copyfile(ROOT/'include/latticecore.h',out/'sources/latticecore.h')
 flags=['-O2','-std=c11','-Wall','-Wextra','-Werror','-fno-omit-frame-pointer'];exe=out/('probe.exe' if windows else 'probe')
 command=[a.cc,*flags,'-I'+str(out/'sources'),out/'sources/probe.c',out/'sources'/assembly,*([] if windows else ['-ldl','-Wl,-z,noexecstack']),'-o',exe]
 commands=[]
 def run_command(argv,name):
  q=subprocess.run(list(map(str,argv)),env=env,capture_output=True,text=True,encoding='utf-8',errors='replace');(out/name).write_text(json.capture_text(q.stdout+q.stderr),encoding='utf-8');commands.append(dict(argv=list(map(str,argv)),exit_code=q.returncode,log=name,sha256=sha(out/name)));dump(out/'commands.xml',commands);assert q.returncode==0,name
 run_command(command,'compile.log');run_command([a.cc,'--version'],'compiler.log')
 if not windows:
  helper=out/'heap_audit.so';run_command([a.cc,*flags,'-fPIC','-shared',out/'sources/linux_heap_audit.c','-o',helper],'compile_heap.log');env['LD_PRELOAD']=str(helper)
 protocol=dict(schema='lattice.reference_memory_protocol.v1',parameters=LEVELS,seed=20260927041,discovery_seeds=3,validation_seeds=24,stack_quantum_bytes=256,stack_margin_bytes=256,maximum_stack_bytes=262144,
    workspace_bytes=32,workspace_role='Minimum nonempty serialized-API adapter region; PQClean uses automatic arrays and its original heap.',
    allocation_accounting='Requested live algorithm heap bytes; all writable library sections and one thread TLS copy; OS mappings reported separately.',
    reserve_rule='Maximum discovery watermark per operation rounded up to 256 B plus 256 B; fixed for 24 independent validation seeds. Any validation failure is retained and stops this run.',
    measurement='Memory only; execution duration of the controller is not algorithm performance.',host=platform.platform(),machine=platform.machine(),probe_sha256=sha(exe),sources={p.name:sha(p) for p in (out/'sources').iterdir()},configuration=cfg)
 dump(out/'protocol.xml',protocol);ledger=json.record_stream(out/'trials.records.xml');count=0;results=[]
 def trial(lib,level,op,stack,seed,control,reason):
  nonlocal count
  argv=[str(exe),str(lib),str(level),str(op),'32',str(stack),str(seed),str(control)]
  q=subprocess.run(argv,env=env,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30)
  events=[json.loads(s) for s in q.stdout.splitlines() if s.startswith('{')];end=[x for x in events if x.get('event')=='trial_result'];fault=[x for x in events if x.get('event')=='stack_fault']
  status='PASS' if q.returncode==0 and len(end)==1 else 'STACK_LIMIT' if (windows and q.returncode&0xffffffff in (0xc0000005,0xc00000fd)) or (len(fault)==1 and fault[0]['protected_region_hit']) else 'ERROR'
  item=dict(trial=count,configuration=c['id'],parameter=level,operation=op,stack_bytes=stack,seed=seed,control=control,reason=reason,status=status,exit_code=q.returncode,stdout=q.stdout,stderr=q.stderr);ledger.write(json.dumps(item)+'\n');ledger.flush();count+=1
  r=end[0] if len(end)==1 else None
  if status=='PASS':
   assert r['rc']==0 and r['canaries_ok'] and r['recovery_full_sequence_ok'] and r['heap_audit_errors']==0
   assert r['outside_heap_live_requested_bytes']<=r['outside_heap_peak_requested_bytes']
   assert r['arena_high_water_bytes']==0 and r['released_prefix_changed_nonzero_bytes']==0
  return status,r,count-1
 for c in cfg['libraries']:
  lib=Path(c['path']).resolve();assert sha(lib)==c['sha256'];im=inventory(lib);dump(out/(c['id']+'-image.xml'),im)
  controls=[]
  for mode,stack,expected in [(1,4096,'PASS'),(2,4096,'STACK_LIMIT'),(2,65536,'PASS'),(3,16384,'PASS')]:
   status,r,i=trial(lib,512,3,stack,protocol['seed'],mode,'instrument_control');assert status==expected
   if mode==3:assert r['outside_heap_peak_requested_bytes']==96 and r['outside_heap_calls']>0
   controls.append(i)
  cells=[]
  for level in LEVELS:
   for op in range(3):
    seed=protocol['seed']+level*65537+op*101;discovery=[]
    for j in range(3):
     status,r,i=trial(lib,level,op,262144,seed+j*104729,0,'discovery');assert status=='PASS';discovery.append((r,i))
    s=((max(r['stack_watermark_observed_bytes'] for r,i in discovery)+255)//256+1)*256;assert s<=262144
    checks=[]
    for j in range(24):
     status,r,i=trial(lib,level,op,s,seed+1000000007+j*104729,0,'fixed_capacity_independent_seed');assert status=='PASS',(level,op,s,status);checks.append((r,i))
    allrows=discovery+checks;heap=max(r['outside_heap_peak_requested_bytes'] for r,i in allrows);globals_bytes=im['writable_image_plus_single_thread_tls_bytes'];core=32+s+64+globals_bytes+heap
    cell=dict(parameter=level,operation=op,workspace_reserved_bytes=32,workspace_observed_bytes=0,stack_reserved_bytes=s,stack_observed_max_bytes=max(r['stack_watermark_observed_bytes'] for r,i in allrows),context_bytes=64,globals_bytes=globals_bytes,heap_peak_requested_bytes=heap,algorithm_reserved_bytes=core,discovery_trials=[i for r,i in discovery],validation_trials=[i for r,i in checks]);cells.append(cell)
    print(json.dumps({'configuration':c['id'],'parameter':level,'operation':op,'stack_bytes':s,'heap_bytes':heap,'algorithm_bytes':core}),flush=True)
  total=32+max(x['stack_reserved_bytes'] for x in cells)+64+im['writable_image_plus_single_thread_tls_bytes']+max(x['heap_peak_requested_bytes'] for x in cells)
  results.append(dict(id=c['id'],image_sha256=sha(lib),controls=controls,cells=cells,six_parameter_componentwise_reserved_bytes=total,program_bytes=im['program_non_debug_image_bytes']))
  dump(out/'progress.xml',results)
 ledger.close();dump(out/'observations.xml',dict(schema='lattice.reference_memory_observations.v1',status='PASS',protocol_sha256=sha(out/'protocol.xml'),trials_sha256=sha(out/'trials.records.xml'),trials=count,libraries=results));print(json.dumps({'status':'PASS','trials':count,'libraries':len(results)}))
if __name__=='__main__':main()
