"""Prepare SHA-bound resource jobs, then run/pause independent guarded probes.

Preparation only reads artifacts and copies byte-identical measurement views;
it never builds or loads a target. Execution is an explicit separate action.
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
import argparse, hashlib, record_io as json, os, re, shutil, subprocess, sys, time
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
PUBLIC=sorted(['lc_context_init','lc_decaps','lc_encaps','lc_error_string','lc_get_sizes','lc_keypair','lc_sign','lc_verify'])
RESOURCE_PUBLIC=['lc_resource_query','lc_resource_make_plan','lc_resource_algorithm_bytes']
def require(ok,msg):
    if not ok:raise ValueError(msg)
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def read(p):return json.loads(Path(p).read_text(encoding='utf-8'))
def dump(p,d):
    q=Path(p).with_suffix('.writing');q.write_text(json.dumps(d,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    # Windows readers can briefly hold a non-delete-sharing file handle.
    # Retry only the atomic publication, never a completed resource trial.
    for attempt in range(50):
        try:q.replace(p);return
        except PermissionError:
            if os.name!='nt' or attempt==49:raise
            time.sleep(.02)
def ref(p):return {'path':str(Path(p).resolve()),'sha256':sha(p)}
def safe_id(x):return isinstance(x,str) and re.fullmatch('[A-Za-z0-9_-]+',x) is not None

def make_view(task,out):
    source=Path(task['build']).resolve();kind=task.get('kind','single');profile=task['profile'];dest=out/'views'/task['id'];dest.mkdir(parents=True)
    original=source/'build.xml';m=read(original);commands=source/'commands.xml'
    require(sha(commands)==m['commands_sha256'],'Original build command identity changed')
    records=read(commands);require(all(r['exit_code']==0 for r in records),'Original build has failed commands')
    if kind=='single':
        library=source/('latticecore.dll' if os.name=='nt' else 'liblatticecore.so')
        require(m['configuration']==profile and m.get('sanitizer','none')=='none','Wrong or instrumented configuration')
        normalized=dict(m);expected=m['binary']['sha256'];selected=records
    elif kind=='throughput':
        require(m['schema']=='latticecore.throughput-build.r2' and m['status']=='PASS','Incomplete throughput group')
        matches=[b for b in m['binaries'] if b['profile']==profile];require(len(matches)==1,'Missing/repeated throughput profile');b=matches[0]
        library=(source/b['library']).resolve();require(library.is_relative_to(source),'Build library escapes group');expected=b['sha256']
        recipe_path=Path(task['recipe']).resolve();require(sha(recipe_path)==m['recipe_sha256'],'Throughput recipe changed');recipe=read(recipe_path)['profiles'][profile]
        selected=[r for r in records if Path(r['log']).name.startswith(profile+'_')]
        require(selected,'No actual compile/link commands for throughput profile')
        compiler_kind=recipe['link'][0];version_path=source/('version_'+compiler_kind+'.log');version=version_path.read_text(encoding='utf-8');target=re.search(r'^Target:\s*(.+)$',version,re.M)
        normalized={'schema':'latticecore.build.v2','configuration':profile,'parameters':[512,768,1024,44,65,87],
          'schedule':{'throughput_profile':profile},'backend':'x86_64_native_recipe','optimization':'per_translation_unit_recipe','lto':any(str(a).startswith('-flto') for r in selected for a in r['argv']),
          'compiler':version.splitlines()[0],'target':target.group(1) if target else 'x86_64 Windows PE; explicit commands retained','sanitizer':'none','binary':b,
          'source_hashes':m['source_hashes'],'commands_sha256':m['commands_sha256'],'recipe_sha256':m['recipe_sha256'],'recipe':recipe}
        shutil.copyfile(recipe_path,dest/'original_recipe.xml');shutil.copyfile(version_path,dest/'original_compiler.log')
    else:raise ValueError('Unknown build kind')
    require(library.is_file() and sha(library)==expected,'Actual product binary does not match original build')
    if 'exports' not in normalized['binary'] and normalized['binary'].get('format')=='ELF':
        nm=shutil.which('nm');require(nm,'ELF public-export inspection requires nm')
        argv=[nm,'-D','--defined-only','--format=posix',str(library)];q=subprocess.run(argv,capture_output=True,text=True);require(q.returncode==0,'ELF public-export inspection failed')
        log=dest/'actual_elf_exports.log';log.write_text(json.capture_text(q.stdout),encoding='utf-8')
        normalized['binary']=dict(normalized['binary'],exports=[line.split()[0] for line in q.stdout.splitlines() if line.strip()])
        normalized['exports_derived_from']={'argv':argv,'stdout_sha256':sha(log),'library_sha256':expected}
    wanted=sorted(PUBLIC+(RESOURCE_PUBLIC if normalized.get('schedule',{}).get('runtime_cache') else []))
    require(normalized['parameters']==[512,768,1024,44,65,87] and sorted(normalized['binary']['exports'])==wanted,'Incomplete public deployment shape')
    for key,value in task.get('expected',{}).items():require(normalized[key]==value,'Unexpected build setting '+key)
    require(not any('-fsanitize=' in str(a) for r in selected for a in r['argv']),'Sanitizer build cannot be measured as product')
    copied=dest/library.name;shutil.copyfile(library,copied);require(sha(copied)==expected,'Copied measurement view changed bytes')
    shutil.copyfile(original,dest/'original_build.xml');shutil.copyfile(commands,dest/'original_commands.xml')
    normalized.update(measurement_view_only=True,new_build_performed=False,derived_from={'manifest':'original_build.xml','manifest_sha256':sha(original),'profile':profile,'original_library':str(library),'binary_sha256':expected,'commands':'original_commands.xml','commands_sha256':sha(commands)},actual_profile_commands=[r['argv'] for r in selected])
    dump(dest/'build.xml',normalized)
    return {'id':task['id'],'profile':profile,'priority':task.get('priority',100),'view':str(dest),'binary_sha256':expected,'view_manifest_sha256':sha(dest/'build.xml'),'original_build':ref(original),'original_library':ref(library),'kind':kind}

def prepare(spec_path,out):
    require(not out.exists(),'Fresh controller output required');spec=read(spec_path);tasks=spec['tasks']
    require(tasks and all(safe_id(t['id']) for t in tasks) and len({t['id'].casefold() for t in tasks})==len(tasks),'Invalid/repeated task identities')
    require(re.fullmatch('[0-9a-f]{40}',spec['source_commit']) is not None,'Explicit source commit required')
    out.mkdir(parents=True);(out/'tasks').mkdir();bindings=[make_view(t,out) for t in tasks]
    bindings.sort(key=lambda x:(x['priority'],x['id']))
    instrument={p.name:sha(p) for p in HERE.iterdir() if p.is_file() and p.suffix in ('.py','.c','.h','.S','.md')}
    snapshot=out/'instrument/tests/resources';snapshot.mkdir(parents=True);(out/'instrument/include').mkdir()
    for n in instrument:shutil.copyfile(HERE/n,snapshot/n)
    shutil.copyfile(ROOT/'include/latticecore.h',out/'instrument/include/latticecore.h')
    plan={'schema':'resources.controller.plan.v1','source_commit':spec['source_commit'],'spec':ref(spec_path),'bindings':bindings,'instrument_sha256':instrument,'public_header_sha256':sha(ROOT/'include/latticecore.h'),'previous_resource_results_inherited':False}
    dump(out/'plan.xml',plan);dump(out/'state.xml',{'state':'PREPARED','tasks':len(bindings),'plan_sha256':sha(out/'plan.xml')});return plan

def execute(out,jobs,cc,objdump):
    require(1<=jobs<=4,'Concurrency must be 1..4');plan=read(out/'plan.xml');state=read(out/'state.xml');require(state['state']=='PREPARED' and state['plan_sha256']==sha(out/'plan.xml'),'Execution requires intact prepared plan')
    instrument_root=out/'instrument';instrument_here=instrument_root/'tests/resources'
    for n,h in plan['instrument_sha256'].items():require(sha(instrument_here/n)==h,'Snapshot instrument changed after preparation')
    require(sha(instrument_root/'include/latticecore.h')==plan['public_header_sha256'],'Snapshot ABI header changed after preparation')
    pending=list(plan['bindings']);active={};finished=[];failure=False;start=time.monotonic();pause=out/'PAUSE.request'
    def save(st):dump(out/'state.xml',{'state':st,'controller_pid':os.getpid(),'plan_sha256':sha(out/'plan.xml'),'pending':[t['id'] for t in pending],'active':[{'id':k,'pid':v['process'].pid} for k,v in active.items()],'finished':finished,'elapsed_seconds':time.monotonic()-start})
    while pending or active:
        paused=pause.exists()
        for key,a in list(active.items()):
            run=a['folder']/'run';mark=run/'PAUSE.request'
            if run.is_dir():
                if paused and not mark.exists():mark.write_text('Controller requested pause',encoding='utf-8')
                if not paused and mark.exists():mark.unlink()
            rc=a['process'].poll()
            if rc is not None:
                a['log'].close();a['err'].close();task=a['task'];audit=a['folder']/'audit.xml'
                if rc==0:
                    with (a['folder']/'audit.log').open('w',encoding='utf-8') as f:
                        q=subprocess.run([sys.executable,'-B',str(instrument_here/'validate.py'),str(run),'--output',str(audit)],cwd=instrument_root,stdout=f,stderr=subprocess.STDOUT)
                    rc=q.returncode
                ok=rc==0
                if ok:
                    try:
                        result=read(run/'result.xml');entries=result['results'];require(len(entries)==1,'Unexpected per-job output scope');e=read(run/task['profile']/'resource_evidence.xml')
                        require(e['dll_sha256']==task['binary_sha256'] and sha(task['original_library']['path'])==task['binary_sha256'],'Product changed while measuring')
                    except (ValueError,OSError,KeyError) as exc:
                        ok=False;rc=2;dump(a['folder']/'identity_failure.xml',{'status':'FAILED','reason':str(exc)})
                finished.append({'id':key,'status':'PASS' if ok else 'FAILED','exit_code':rc,'binary_sha256':task['binary_sha256'],'result':ref(run/'result.xml') if (run/'result.xml').exists() else None,'audit':ref(audit) if audit.exists() else None})
                failure=failure or not ok;del active[key]
        if not paused and not failure:
            while pending and len(active)<jobs:
                t=pending[0]
                try:require(sha(Path(t['view'])/'build.xml')==t['view_manifest_sha256'] and sha(t['original_library']['path'])==t['binary_sha256'],'Frozen resource input changed')
                except (ValueError,OSError) as exc:
                    dump(out/'launch_failure.xml',{'status':'FAILED','id':t['id'],'reason':str(exc)});failure=True;break
                pending.pop(0)
                folder=out/'tasks'/t['id'];folder.mkdir();log=(folder/'stdout.log').open('w',encoding='utf-8');err=(folder/'stderr.log').open('w',encoding='utf-8')
                cmd=[sys.executable,'-B',str(instrument_here/'run.py'),'--build',t['view'],'--output',str(folder/'run'),'--cc',cc,'--objdump',objdump]
                dump(folder/'launch.xml',{'argv':cmd,'binary_sha256':t['binary_sha256']});process=subprocess.Popen(cmd,cwd=instrument_root,stdout=log,stderr=err)
                active[t['id']]={'process':process,'folder':folder,'log':log,'err':err,'task':t};print('START',t['id'],flush=True)
        all_stopped=paused
        if paused:
            for a in active.values():
                p=a['folder']/'run/pause_state.xml';mark=a['folder']/'run/PAUSE.request'
                if not p.exists() or not mark.exists() or read(p).get('state')!='PAUSED_NO_CHILD' or p.stat().st_mtime_ns<mark.stat().st_mtime_ns:all_stopped=False
        save('PAUSED_NO_CHILD' if all_stopped else 'PAUSING' if paused else 'RUNNING')
        if failure and not active:break
        if pending or active:time.sleep(.1)
    status='FAILED' if failure or pending else 'PASS';dump(out/'result.xml',{'status':status,'source_commit':plan['source_commit'],'plan_sha256':sha(out/'plan.xml'),'results':finished,'unstarted':[t['id'] for t in pending],'elapsed_seconds':time.monotonic()-start,'concurrency':jobs,'performance_samples_collected':False});save(status);print(status,len(finished),flush=True);return status

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=['prepare','run','pause','resume','status']);p.add_argument('--output',type=Path,required=True);p.add_argument('--spec',type=Path);p.add_argument('--jobs',type=int,default=3);p.add_argument('--cc',default='gcc');p.add_argument('--objdump',default='objdump');a=p.parse_args();out=a.output.resolve()
    require(os.name!='nt' or out.drive.upper()=='D:','Windows writes must stay on D:')
    if a.action=='prepare':require(a.spec is not None,'Specification required');plan=prepare(a.spec.resolve(),out);print('PREPARED',len(plan['bindings']))
    elif a.action=='run':
        if execute(out,a.jobs,a.cc,a.objdump)!='PASS':raise SystemExit(2)
    elif a.action=='pause':require((out/'state.xml').exists(),'Controller not prepared');(out/'PAUSE.request').write_text('Explicit timing coordination',encoding='utf-8');print('PAUSE_REQUESTED; wait for state PAUSED_NO_CHILD')
    elif a.action=='resume':
        require((out/'state.xml').exists(),'Controller not prepared');mark=out/'PAUSE.request'
        if mark.exists():mark.unlink()
        print('RESUME_REQUESTED')
    else:print((out/'state.xml').read_text(encoding='utf-8'))
if __name__=='__main__':main()
