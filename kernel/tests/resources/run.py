"""Measure public-API resource envelopes without rebuilding the target library."""
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
import argparse, hashlib, record_io as json, os, platform, shutil, subprocess, time
from image_inventory import inventory
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
PARAMETERS=[512,768,1024,44,65,87];OPERATIONS=['keygen','encaps','decaps']
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def dump(p,x):
 q=p.with_name(p.name+'.tmp');q.write_bytes((json.dumps(x,ensure_ascii=False,indent=2)+'\n').encode());q.replace(p)
def io_bytes(parameter,operation):
 if parameter>100:
  k=parameter//256;pk=384*k+32;sk=768*k+96;ct={2:768,3:1088,4:1568}[k]
  return ((64,pk+sk),(pk+32,ct+32),(sk+ct,32))[operation]
 pk,sk,sig={44:(1312,2560,2420),65:(1952,4032,3309),87:(2592,4896,4627)}[parameter]
 return ((32,pk+sk),(sk+1024+32,sig),(pk+1024+sig,0))[operation]
def classify(returncode,events):
 final=[x for x in events if x.get('event')=='trial_result']
 if final:
  if len(final)!=1 or returncode:raise ValueError('Probe completed with an integrity error')
  r=final[0]
  if not r['canaries_ok'] or not r['recovery_full_sequence_ok'] or r['guard_error'] or r['init_rc'] or r['heap_audit_errors'] or r['arena_high_water_bytes']>r['arena_reserved_bytes'] or r['released_prefix_changed_nonzero_bytes']:raise ValueError('Resource/correctness guard failed')
  if r['rc']==0:return 'SUCCESS',r
  if r['rc']==-5 and r['allocation_failures']>0 and all(v in (None,1) for v in r['step_failure_outputs_zero']):return 'WORKSPACE_OOM',r
  raise ValueError('Unexpected API error')
 faults=[x for x in events if x.get('event')=='stack_fault']
 if faults:
  if len(faults)!=1 or not faults[0]['protected_region_hit'] or returncode not in (139,135,-11,-7):raise ValueError('Fault outside declared lower guard')
  return 'PROTECTED_STACK_FAULT',None
 if os.name=='nt' and returncode&0xffffffff in (0xc0000005,0xc00000fd):return 'WINDOWS_ACCESS_OR_STACK_EXIT',None
 raise ValueError('Unexpected process failure '+str(returncode))
def captured_timeout(value):
 if value is None:return None
 if isinstance(value,bytes):value=value.decode('utf-8',errors='surrogateescape')
 return json.capture_text(value)

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--build',type=Path,nargs='+',required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--cc',default='gcc');p.add_argument('--objdump',default='objdump');p.add_argument('--parameters',type=int,nargs='+',choices=PARAMETERS,default=PARAMETERS);p.add_argument('--stage',choices=['preflight','full'],default='full');p.add_argument('--stack-max',type=int,default=16384);p.add_argument('--validation-seeds',type=int,default=24);p.add_argument('--seed',type=int,default=719352019);a=p.parse_args()
 if len(set(a.parameters))!=len(a.parameters) or not a.parameters or a.stack_max%256 or not 4096<=a.stack_max<=65280 or a.validation_seeds<24 or not 0<a.seed<2**63:raise ValueError('Invalid fixed protocol')
 out=a.output.resolve();cc=shutil.which(a.cc);objdump=shutil.which(a.objdump)
 if out.exists() or (os.name=='nt' and out.drive.upper()!='D:') or not cc or not objdump:raise ValueError('Fresh output and explicit compiler/objdump required')
 candidates=[]
 for folder in a.build:
  folder=folder.resolve();manifest=folder/'build.xml';m=json.loads(manifest.read_text(encoding='utf-8'));lib=folder/('latticecore.dll' if os.name=='nt' else 'liblatticecore.so');image=inventory(lib)
  if m['binary']['sha256']!=image['sha256'] or m.get('sanitizer','none')!='none':raise ValueError('Unmatched or instrumented product build')
  candidates.append({'id':m['configuration'],'library':lib,'manifest':manifest,'build':m,'image':image})
 if len({c['id'] for c in candidates})!=len(candidates):raise ValueError('Repeated configuration identity; use a separate run for another compiler/backend')
 out.mkdir(parents=True);(out/'tmp').mkdir();(out/'sources').mkdir();env=os.environ.copy();env.update(TEMP=str(out/'tmp'),TMP=str(out/'tmp'),TMPDIR=str(out/'tmp'),PYTHONDONTWRITEBYTECODE='1')
 commands=[];all_results=[];trial_count=0;started=time.monotonic()
 selected=['probe.c','image_inventory.py','run.py','method.md']
 if os.name=='nt':assembly='stack_windows_x64.S';selected+=['windows_heap_audit.h']
 else:
  machine=platform.machine().lower()
  if machine not in ('aarch64','arm64','x86_64','amd64'):raise ValueError('Unsupported stack ABI')
  assembly='stack_aarch64.S' if machine in ('aarch64','arm64') else 'stack_linux_x64.S';selected+=['linux_heap_audit.c']
 selected.append(assembly)
 for name in selected:shutil.copyfile(HERE/name,out/'sources'/name)
 shutil.copyfile(ROOT/'include/latticecore.h',out/'sources/latticecore.h')
 protocol={'schema':'resources.protocol.r2.v1','stage':a.stage,'parameters':a.parameters,'stack_grid':list(range(256,a.stack_max+1,256)),'safety_margin_bytes':256,'validation_seeds':a.validation_seeds,'seed':a.seed,'arena_alignment_bytes':32,'arena_capacity_quantum_bytes':32,'parameter_fixed_arena_and_stack':True,'budgets_bytes':[16384,32768,65536,131072,262144],'host':platform.platform(),'machine':platform.machine(),'finite_inputs_not_static_bound':True,'physical_or_MCU_RAM_claim':False,'sources':{n:sha(out/'sources'/n) for n in selected+['latticecore.h']}}
 dump(out/'protocol.xml',protocol)
 def command(args,label):
  q=subprocess.run(list(map(str,args)),cwd=ROOT,env=env,capture_output=True,text=True,encoding='utf-8',errors='replace');log=out/(label+'.txt');log.write_bytes(json.capture_bytes((q.stdout+q.stderr).encode()));commands.append({'argv':list(map(str,args)),'exit_code':q.returncode,'log':log.name,'sha256':sha(log)});dump(out/'commands.xml',commands)
  if q.returncode:raise RuntimeError(label+' failed')
  return q.stdout
 try:
  command([cc,'--version'],'compiler');command([cc,'-dumpmachine'],'compiler_target')
  exe=out/('resource_probe.exe' if os.name=='nt' else 'resource_probe');flags=['-O2','-std=c11','-Wall','-Wextra','-Werror','-fno-omit-frame-pointer']
  cmd=[cc,*flags,'-I'+str(ROOT/'include'),HERE/'probe.c',HERE/assembly]
  if os.name!='nt':cmd+=['-ldl','-Wl,-z,noexecstack']
  command(cmd+['-o',exe],'build_probe');command([objdump,'-d',exe],'probe_disassembly');command([objdump,'-h',exe],'probe_sections')
  if os.name!='nt':
   helper=out/'heap_audit.so';command([cc,*flags,'-fPIC','-shared',HERE/'linux_heap_audit.c','-o',helper],'build_heap_audit');env['LD_PRELOAD']=str(helper)
   protocol['heap_interposer_sha256']=sha(helper)
  protocol['probe_sha256']=sha(exe);dump(out/'protocol.xml',protocol)
  ledger=json.record_stream(out/'trials.records.xml')
  def trial(c,parameter,op,arena,stack,seed,control,reason):
   nonlocal trial_count
   pause=out/'PAUSE.request'
   if pause.exists():
    dump(out/'pause_state.xml',{'state':'PAUSED_NO_CHILD','completed_trials':trial_count})
    while pause.exists():time.sleep(0.1)
    dump(out/'pause_state.xml',{'state':'RUNNING','completed_trials':trial_count})
   argv=[str(exe),str(c['library']),str(parameter),str(op),str(arena),str(stack),str(seed),str(control)];t=time.monotonic()
   try:q=subprocess.run(argv,cwd=ROOT,env=env,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=60)
   except subprocess.TimeoutExpired as e:
    ledger.write(json.dumps({'trial':trial_count,'configuration':c['id'],'reason':reason,'argv':argv,'classification':'TIMEOUT','stdout':captured_timeout(e.stdout),'stderr':captured_timeout(e.stderr)})+'\n');ledger.flush();raise
   events=[]
   for line in q.stdout.splitlines():
    if line.startswith('{'):events.append(json.loads(line))
   record={'trial':trial_count,'configuration':c['id'],'reason':reason,'argv':argv,'exit_code':q.returncode,'elapsed_wall_seconds':time.monotonic()-t,'stdout':json.capture_text(q.stdout),'stderr':json.capture_text(q.stderr)}
   trial_count+=1
   try:classification,r=classify(q.returncode,events);record.update(classification=classification,result=r)
   except Exception as e:record['classification']='UNEXPECTED_FAILURE';record['error']=str(e);ledger.write(json.dumps(record)+'\n');ledger.flush();raise
   if not any(e.get('event')=='trial_start' and e.get('parameter')==parameter and e.get('operation')==op and e.get('arena_bytes')==arena and e.get('stack_bytes')==stack and e.get('seed')==seed and e.get('control')==control for e in events):raise ValueError('Wrong trial identity')
   if r and (r['arena_reserved_bytes']!=arena or r['stack_enforced_bytes']!=stack or r['context_bytes']!=64):raise ValueError('Declared region or ABI size differs')
   ledger.write(json.dumps(record)+'\n');ledger.flush();return classification,r,record['trial']
  for c in candidates:
   dest=out/c['id'];dest.mkdir();shutil.copyfile(c['manifest'],dest/'build.xml');dump(dest/'image.xml',c['image']);cells={};parameter_results=[]
   controls=[]
   for control,stack,wanted in ((1,4096,'SUCCESS'),(2,4096,'FAULT'),(2,65536,'SUCCESS'),(3,16384,'SUCCESS')):
    status,r,index=trial(c,a.parameters[0],3,262144,stack,a.seed,control,'instrument_control')
    if wanted=='FAULT':
     if status not in ('PROTECTED_STACK_FAULT','WINDOWS_ACCESS_OR_STACK_EXIT'):raise ValueError('48 KiB positive control did not fault')
    elif status!=wanted:raise ValueError('Instrument control failed')
    if control==3 and (not r['outside_heap_calls'] or r['outside_heap_peak_requested_bytes']!=96 or r['outside_heap_live_requested_bytes']):raise ValueError('Heap positive control not observed')
    controls.append({'control':control,'stack_bytes':stack,'trial':index,'classification':status})
   for parameter in a.parameters:
    seed=a.seed+parameter*65537
    status,large,index=trial(c,parameter,3,262144,65536,seed,0,'workspace_discovery')
    if status!='SUCCESS' or large['step_rc']!=[0,0,0] or large['step_outputs_match']!=[1,1,1]:raise ValueError('Unrestricted full sequence failed')
    w=(max(large['step_arena_high_water'])+31)//32*32
    status,fixed,wtrial=trial(c,parameter,3,w,65536,seed,0,'parameter_fixed_workspace')
    if status!='SUCCESS':raise ValueError('Observed workspace is not sufficient when retained')
    status,oom,otrial=trial(c,parameter,3,max(32,w-32),65536,seed,0,'workspace_lower_failure')
    if status!='WORKSPACE_OOM':raise ValueError('Lower workspace capacity did not exhibit OOM; do not infer a minimum')
    pr={'parameter':parameter,'workspace_bytes':w,'arena_discovery_peak_by_operation':large['step_arena_high_water'],'workspace_success_trial':wtrial,'workspace_lower_oom_trial':otrial,'context_bytes':fixed['context_bytes']}
    print(c['id'],parameter,'fixed arena',w,flush=True)
    if a.stage=='preflight':parameter_results.append(pr);continue
    required=[];scans=[]
    for op in range(3):
     statuses=[]
     for stack in protocol['stack_grid']:
      status,r,idx=trial(c,parameter,op,w,stack,seed+op*101,0,'stack_grid')
      if status not in ('SUCCESS','PROTECTED_STACK_FAULT','WINDOWS_ACCESS_OR_STACK_EXIT'):raise ValueError('Arena/error failure during fixed-W stack scan')
      if status=='SUCCESS' and (r['step_rc'][op]!=0 or r['step_outputs_match'][op]!=1):raise ValueError('Incorrect output in a successful stack trial')
      statuses.append(status);scans.append({'operation':op,'stack_bytes':stack,'classification':status,'trial':idx})
     success=[s=='SUCCESS' for s in statuses];suffix=[i for i in range(len(success)) if all(success[i:])]
     if not suffix:raise ValueError('No successful contiguous stack suffix; extend the common preregistered grid')
     required.append(protocol['stack_grid'][suffix[0]])
    s=max(required)+256;confirm=[];zero_heap=True
    for n in range(a.validation_seeds):
     vseed=seed+0x19ab347+131071*n
     status,r,idx=trial(c,parameter,3,w,s,vseed,0,'fixed_workspace_stack_new_seed_sequence')
     if status!='SUCCESS' or r['step_rc']!=[0,0,0] or r['step_outputs_match']!=[1,1,1]:raise ValueError('Declared fixed resources failed independent seed sequence')
     if r['outside_heap_calls'] or r['outside_heap_peak_requested_bytes'] or r['outside_heap_live_requested_bytes']:zero_heap=False
     confirm.append({'seed':vseed,'trial':idx,'observed_watermark':r['stack_watermark_observed_bytes'],'os_reserved':r['os_stack_or_guard_mapping_reserved_bytes'],'os_committed_or_enabled_pages':r['os_enabled_or_committed_stack_pages_bytes']})
    heap=0 if zero_heap and not c['image']['unhandled_allocator_imports'] else None
    glob=c['image']['writable_image_plus_single_thread_tls_bytes'];ctx=pr['context_bytes'];full=None if heap is None else w+s+ctx+glob+heap
    budgets=[]
    for budget in protocol['budgets_bytes']:
     available=(budget-s-ctx-glob)//32*32
     if heap is None or available<32:budgets.append({'budget_bytes':budget,'status':'UNKNOWN_OR_NO_POSITIVE_ARENA','arena_bytes':None,'trial':None});continue
     status,r,idx=trial(c,parameter,3,available,s,seed+0xabc123,0,'explicit_total_budget')
     if status not in ('SUCCESS','WORKSPACE_OOM'):raise ValueError('Unexpected fixed-budget outcome')
     budgets.append({'budget_bytes':budget,'arena_bytes':available,'charged_ram_bytes':available+s+ctx+glob,'status':status,'trial':idx,'all_three_operations_completed':status=='SUCCESS' and r['step_rc']==[0,0,0]})
    pr.update(stack_minimum_contiguous_success_by_operation=required,stack_reserved_bytes=s,stack_scan=scans,confirmation_sequences=confirm,globals_conservative_bytes=glob,outside_heap_bytes=heap,full_core_budget_bytes=full,budget_trials=budgets)
    parameter_results.append(pr)
    family='ML-KEM' if parameter>100 else 'ML-DSA';ops=OPERATIONS if parameter>100 else ['keygen','sign','verify']
    for op,name in enumerate(ops):
     inp,output=io_bytes(parameter,op);cells[f'{family}/{parameter}/{name}']={'workspace_bytes':w,'stack_bytes':s,'external_context_bytes':ctx,'globals_bytes':glob,'outside_heap_bytes':heap,'full_ram_bytes':full,'logical_input_bytes':inp,'logical_output_bytes':output,'program_bytes':c['image']['program_non_debug_image_bytes'],'physical_ram_measured':False}
    dump(dest/'progress.xml',{'completed_parameters':parameter_results});print(c['id'],parameter,'fixed stack',s,'core budget',full,flush=True)
   if sha(c['library'])!=c['image']['sha256']:raise ValueError('Product library changed during resource trials')
   result={'status':'PASS','scope':'preflight_only' if a.stage=='preflight' else 'finite_input_fixed_resource_validation','configuration':c['id'],'library':str(c['library']),'dll_sha256':c['image']['sha256'],'build_manifest_sha256':sha(c['manifest']),'protocol_sha256':sha(out/'protocol.xml'),'controls':controls,'parameters':parameter_results,'cells':cells,'program_bytes':c['image']['program_non_debug_image_bytes'],'all_input_stack_bound_proved':False,'whole_process_or_MCU_ram_claim':False}
   dump(dest/'resource_evidence.xml',result);all_results.append({'configuration':c['id'],'path':str(dest/'resource_evidence.xml'),'sha256':sha(dest/'resource_evidence.xml')})
  ledger.close()
  if sha(exe)!=protocol['probe_sha256']:raise ValueError('Measurement executable changed')
  dump(out/'result.xml',{'status':'PASS','scope':a.stage,'trials':trial_count,'results':all_results,'protocol_sha256':sha(out/'protocol.xml'),'trials_sha256':sha(out/'trials.records.xml'),'commands_sha256':sha(out/'commands.xml'),'elapsed_wall_seconds':time.monotonic()-started})
 except Exception as e:dump(out/'failure.xml',{'status':'FAILED','reason':str(e),'trials_completed':trial_count,'partial_results':all_results});raise
if __name__=='__main__':main()
