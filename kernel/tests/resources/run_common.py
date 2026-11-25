"""Actual interleaved six-parameter, single-context fixed-budget witnesses."""
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
import argparse, copy, record_io as json, os, platform, shutil, subprocess, time
from controller import sha,read,dump,ref,require
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
ORDERS=((512,44,768,65,1024,87),(87,1024,65,768,44,512))

def classify(code,events,arena,stack,order,count,control):
    finals=[e for e in events if e.get('event')=='common_result']
    if not finals:
        faults=[e for e in events if e.get('event')=='stack_fault']
        if len(faults)==1 and faults[0]['protected_region_hit'] and code in (139,135,-11,-7):return 'PROTECTED_STACK_FAULT',None
        if os.name=='nt' and code&0xffffffff in (0xc0000005,0xc00000fd):return 'WINDOWS_ACCESS_OR_STACK_EXIT',None
        raise ValueError('Unexpected common probe failure')
    require(len(finals)==1 and code==0,'Common probe integrity exit');r=finals[0]
    require(r['arena_reserved_bytes']==arena and r['stack_enforced_bytes']==stack and r['order']==order and r['parameter_count']==count and r['control']==control,'Wrong common trial identity')
    require(r['context_bytes']==64 and r['context_in_measured_stack'] is False and r['context_init_calls']==1 and r['context_and_arena_identity_stable'] is True,'Context/arena replaced or reinitialized inside sequence')
    require(r['worker_rc']==r['guard_error']==r['init_rc']==r['heap_errors']==0 and r['canaries_ok'],'Common guard/heap failure')
    require(r['arena_high_water_observed_bytes']<=arena and r['stack_watermark_observed_bytes']<=stack,'Observed outside declared region')
    if control:
        require(r['rc']==0 and r['completed_operations']==0 and not r['recovery_executed'],'Invalid instrument control')
        return 'SUCCESS',r
    require(r['recovery_executed'] and r['same_context_reinitialized_recovery_ok'],'Whole sequence recovery failed')
    expected=[(p,o) for p in ORDERS[order][:count] for o in range(3)];rows=r['rows'];require(len(rows)==r['completed_operations'] and r['expected_operations']==3*count,'Wrong operation count')
    require([(x['parameter'],x['operation']) for x in rows]==expected[:len(rows)],'Wrong interleaving/order')
    for x in rows:
        require(x['arena_high_water_bytes']<=arena and x['stack_watermark_bytes']<=stack and x['changed_nonzero_released_bytes']==0,'Component bound or released-state failure')
        require((x['rc']==0 and x['output_matches']) or (x['rc']==-5 and x['failure_outputs_cleared'] is True),'Wrong output or uncleared failure')
    if r['rc']==0:
        require(len(rows)==len(expected) and all(x['rc']==0 for x in rows),'Incomplete successful sequence');return 'SUCCESS',r
    require(r['rc']==-5 and r['allocation_failures']>0 and rows and rows[-1]['rc']==-5 and all(x['rc']==0 for x in rows[:-1]),'Unexpected sequence error')
    return 'WORKSPACE_OOM',r

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--resource',type=Path,required=True);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--cc',default='gcc');p.add_argument('--objdump',default='objdump');p.add_argument('--seeds',type=int,default=24);p.add_argument('--seed',type=int,default=832650719);a=p.parse_args()
    require(a.seeds>=24 and 0<a.seed<2**63,'At least 24 confirmation seeds required');out=a.output.resolve();require(not out.exists() and (os.name!='nt' or out.drive.upper()=='D:'),'Fresh output required')
    resource=read(a.resource);lib=a.library.resolve();require(resource['status']=='PASS' and resource['dll_sha256']==sha(lib),'Different/unverified resource binary')
    cells=list(resource['cells'].values());require(len(cells)==18 and len(resource['parameters'])==6,'Full six-parameter resource evidence required')
    w=max(c['workspace_bytes'] for c in cells);s=max(c['stack_bytes'] for c in cells)
    for key in ('external_context_bytes','globals_bytes','outside_heap_bytes'):require(len({c[key] for c in cells})==1 and cells[0][key] is not None,'Unknown or inconsistent package metadata')
    overhead=sum(cells[0][k] for k in ('external_context_bytes','globals_bytes','outside_heap_bytes'));require(cells[0]['outside_heap_bytes']==0,'Nonzero heap requires a separate complete budget model')
    cc=shutil.which(a.cc);objdump=shutil.which(a.objdump);require(cc and objdump,'Compiler and objdump required')
    out.mkdir(parents=True);(out/'tmp').mkdir();(out/'sources').mkdir();env=os.environ.copy();env.update(TEMP=str(out/'tmp'),TMP=str(out/'tmp'),TMPDIR=str(out/'tmp'),PYTHONDONTWRITEBYTECODE='1')
    assembly='stack_windows_x64.S' if os.name=='nt' else 'stack_aarch64.S' if platform.machine().lower() in ('aarch64','arm64') else 'stack_linux_x64.S'
    names=['probe_common.c','probe.c','run_common.py',assembly,'windows_heap_audit.h' if os.name=='nt' else 'linux_heap_audit.c']
    for name in names:shutil.copyfile(HERE/name,out/'sources'/name)
    shutil.copyfile(ROOT/'include/latticecore.h',out/'sources/latticecore.h');source_hashes={n:sha(out/'sources'/n) for n in names+['latticecore.h']}
    commands=[];trials=[];start=time.monotonic()
    def command(argv,name):
        q=subprocess.run(list(map(str,argv)),cwd=ROOT,env=env,capture_output=True,text=True,encoding='utf-8',errors='replace');path=out/(name+'.log');path.write_text(json.capture_text(q.stdout+q.stderr),encoding='utf-8');commands.append({'argv':list(map(str,argv)),'exit_code':q.returncode,'log':ref(path)});dump(out/'commands.xml',commands);require(q.returncode==0,'Command failed: '+name);return q.stdout
    try:
        flags=['-O2','-std=c11','-Wall','-Wextra','-Werror','-fno-omit-frame-pointer'];exe=out/('common_probe.exe' if os.name=='nt' else 'common_probe')
        cmd=[cc,*flags,'-I'+str(out/'sources'),out/'sources/probe_common.c',out/'sources'/assembly]
        if os.name!='nt':cmd+=['-ldl','-Wl,-z,noexecstack']
        command(cmd+['-o',exe],'build');command([objdump,'-d',exe],'disassembly')
        if os.name!='nt':
            helper=out/'heap_audit.so';command([cc,*flags,'-fPIC','-shared',out/'sources/linux_heap_audit.c','-o',helper],'heap_audit');env['LD_PRELOAD']=str(helper)
        probe_hash=sha(exe)
        def trial(arena,stack,order,count,control,seed,purpose):
            mark=out/'PAUSE.request'
            if mark.exists():
                dump(out/'pause_state.xml',{'state':'PAUSED_NO_CHILD','completed':len(trials)})
                while mark.exists():time.sleep(.1)
                dump(out/'pause_state.xml',{'state':'RUNNING','completed':len(trials)})
            argv=list(map(str,[exe,lib,arena,stack,seed,order,count,control]));q=subprocess.run(argv,cwd=ROOT,env=env,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=120)
            events=[json.loads(x) for x in q.stdout.splitlines() if x.startswith('{')];entry={'id':len(trials),'purpose':purpose,'argv':argv,'exit_code':q.returncode,'stdout':json.capture_text(q.stdout),'stderr':json.capture_text(q.stderr)}
            try:
                status,r=classify(q.returncode,events,arena,stack,order,count,control);entry.update(classification=status,result=r)
            except Exception as exc:entry.update(classification='INVALID',error=str(exc));trials.append(entry);dump(out/'trials.xml',trials);raise
            trials.append(entry);dump(out/'trials.xml',trials);return status,r
        for control,stack,want in ((1,4096,'SUCCESS'),(2,4096,'FAULT'),(2,65536,'SUCCESS'),(3,16384,'SUCCESS')):
            status,r=trial(262144,stack,0,6,control,a.seed,'instrument_control');require(status in ('PROTECTED_STACK_FAULT','WINDOWS_ACCESS_OR_STACK_EXIT') if want=='FAULT' else status==want,'Instrument control did not behave as expected')
            if control==3:require(r['outside_heap_calls']>0 and r['outside_heap_peak_requested_bytes']==96,'Heap positive control failed')
        for count in (3,6):
            for order in (0,1):require(trial(w,s,order,count,0,a.seed+71,'interleaving_selfcheck')[0]=='SUCCESS','Normal interleaved sequence failed')
        for seed in range(a.seeds):
            for order in (0,1):require(trial(w,s,order,6,0,a.seed+1009+seed*65537,'common_fixed_reservation')[0]=='SUCCESS','Declared common budget failed')
        for order in (0,1):require(trial(w-32,s,order,6,0,a.seed+97,'lower_common_arena_oom')[0]=='WORKSPACE_OOM','Lower common workspace did not fail as expected')
        budget_results=[]
        for budget in (16384,32768,65536,131072,262144):
            cap=(budget-s-overhead)//32*32
            if cap<32:budget_results.append({'budget_bytes':budget,'status':'NO_POSITIVE_ARENA'});continue
            for order in (0,1):
                status,r=trial(cap,s,order,6,0,a.seed+113,'fixed_total_budget');require(status in ('SUCCESS','WORKSPACE_OOM'),'Unexpected total budget result');budget_results.append({'budget_bytes':budget,'arena_bytes':cap,'charged_core_bytes':cap+s+overhead,'order':order,'status':status,'trial':len(trials)-1})
        require(sha(lib)==resource['dll_sha256'],'Library changed during common-context measurement')
        require(sha(exe)==probe_hash,'Probe changed during common-context measurement')
        require(all(sha(out/'sources'/n)==h for n,h in source_hashes.items()),'Copied probe source changed')
        normal=next(t for t in trials if t['purpose']=='common_fixed_reservation');negative=[]
        for key,value in [('context_init_calls',2),('context_and_arena_identity_stable',False),('completed_operations',17),('canaries_ok',False),('same_context_reinitialized_recovery_ok',False),('heap_errors',1)]:
            r=copy.deepcopy(normal['result']);r[key]=value
            try:classify(0,[r],w,s,0,6,0)
            except ValueError:negative.append(key)
            else:raise ValueError('Damaged common evidence accepted: '+key)
        result={'status':'PASS','scope':'actual single context and same arena reused across interleaved six parameters','library':ref(lib),'source_resource':ref(a.resource),'workspace_common_bytes':w,'stack_common_bytes':s,'external_context_bytes':cells[0]['external_context_bytes'],'globals_bytes':cells[0]['globals_bytes'],'outside_heap_bytes':0,'full_reserved_core_budget_bytes':w+s+overhead,'source_sha256':source_hashes,'probe_sha256':sha(exe),'commands_sha256':sha(out/'commands.xml'),'trials_sha256':sha(out/'trials.xml'),'trial_count':len(trials),'budget_trials':budget_results,'negative_record_rejections':negative,'same_context_init_once_per_sequence':True,'orders':[list(x) for x in ORDERS],'seeds_per_order':a.seeds,'simultaneous_observed_peak_bytes':None,'physical_RAM_measured':False,'elapsed_seconds':time.monotonic()-start}
        dump(out/'result.xml',result);print(json.dumps({'status':'PASS','trials':len(trials),'workspace':w,'stack':s,'common_core_budget':w+s+overhead,'sha256':sha(out/'result.xml')}))
    except Exception as exc:dump(out/'failure.xml',{'status':'FAILED','reason':str(exc),'trial_count':len(trials),'source_resource':ref(a.resource)});raise
if __name__=='__main__':main()
