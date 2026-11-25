"""Build and check the fixed-pool certificate and key-establishment application."""
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
import argparse, hashlib, importlib.util, record_io as json, os, platform, re, shutil, subprocess, sys

ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'examples/enrollment_owner'
EXPORTS=['app_object_bytes','app_pool_bytes','app_open','app_get_views','app_prepare','app_flow','app_finish','app_close','app_temporaries_clear']
PAIRS=((512,44),(768,65),(1024,87))
FILES=('application.c','application.h','latticecore.h','check.c','tests/cross_check.c','tests/resource_probe.c','tests/resources_pq/latticecore.h','tests/resources_pq/probe.c','tests/resources_pq/stack_windows_x64.S','tests/resources_pq/windows_heap_audit.h','deployment/entry.c','deployment/exports.def','deployment/exports.map','tests/resources_pq/stack_aarch64.S','tests/resources_pq/linux_heap_audit.c')

def require(ok,message):
    if not ok:raise ValueError(message)

def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def read(path):
    def unique(items):
        out={}
        for key,value in items:
            require(key not in out,'Duplicate JSON field');out[key]=value
        return out
    return json.loads(Path(path).read_text(encoding='utf-8'),object_pairs_hook=unique)

def write(path,value):
    Path(path).write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')

def reference(path):return dict(name=Path(path).name,sha256=sha(path))

def source_records(value=None):
    value=read(SOURCE/'source_identity.xml') if value is None else value
    require(set(value)=={'schema','files'} and value['schema']=='lattice.application_sources.v1','Invalid application source identity')
    rows=value['files'];require(isinstance(rows,list) and len(rows)==len(FILES),'Incomplete application sources')
    names=[]
    for row in rows:
        require(set(row)=={'path','sha256'} and isinstance(row['path'],str),'Invalid source record')
        name=row['path'];require(name in FILES and name not in names,'Unknown or duplicate application source')
        path=SOURCE/name;require(path.is_file() and not path.is_symlink() and sha(path)==row['sha256'],'Changed application source')
        names.append(name)
    require(set(names)==set(FILES),'Incomplete application source closure')
    return rows

def workspace(text):
    require(isinstance(text,str) and re.fullmatch(r'[0-9]+',text),'Workspace must be decimal bytes')
    value=int(text);require(32<=value<=1048576 and value%32==0,'Workspace must be a multiple of32 in32..1048576')
    return value

def fresh(path):
    path=path.resolve();require(not path.exists(),'Choose a fresh output directory')
    if os.name=='nt':require(path.drive.upper()=='D:','Windows output must be on D:')
    path.mkdir(parents=True);(path/'tmp').mkdir();return path

class Runner:
    def __init__(self,out):self.out=out;self.records=[]
    def run(self,label,argv,allowed=(0,),extra_env=None):
        index=len(self.records);stem=f'{index:03d}-{label}';env=dict(os.environ,TEMP=str(self.out/'tmp'),TMP=str(self.out/'tmp'),PYTHONDONTWRITEBYTECODE='1')
        env.update(extra_env or {})
        result=subprocess.run([str(x) for x in argv],capture_output=True,text=True,encoding='utf-8',errors='replace',env=env,timeout=120)
        so=self.out/(stem+'.stdout');se=self.out/(stem+'.stderr');so.write_text(json.capture_text(result.stdout),encoding='utf-8');se.write_text(result.stderr,encoding='utf-8')
        row=dict(label=label,command=[str(x) for x in argv],exit_code=result.returncode,stdout=dict(path=so.name,sha256=sha(so)),stderr=dict(path=se.name,sha256=sha(se)),events=[json.loads(x) for x in result.stdout.splitlines() if x.startswith('{')])
        self.records.append(row);write(self.out/'commands.xml',self.records)
        require(result.returncode in allowed or (result.returncode&0xffffffff) in allowed,'Process failed; see recorded diagnostic')
        require(not result.stderr,'Unexpected process diagnostic; see recorded stderr')
        return row

def build(args):
    require(os.name=='nt' or (platform.system()=='Linux' and platform.machine()=='aarch64'),'Supported deployment targets are Windows x86-64 and Linux AArch64')
    require(os.name!='nt' or args.sanitizer=='none','Use the existing Windows strict build workflow for sanitizers')
    sources=source_records();out=fresh(args.output);local=out/'source';local.mkdir()
    for row in sources:
        target=local/row['path'];target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(SOURCE/row['path'],target)
        require(sha(target)==row['sha256'],'Source copy changed')
    runner=Runner(out);cc=str(args.cc)
    version=runner.run('compiler',[cc,'--version'])
    common=[cc,'-std=c11','-Wall','-Wextra','-Werror']
    sanitize=['-fsanitize=address,undefined','-g','-fno-omit-frame-pointer'] if args.sanitizer=='address-undefined' else []
    if os.name=='nt':
        runner.run('application',[*common,'-Os','-fno-omit-frame-pointer','-shared',local/'application.c',local/'deployment/entry.c',local/'deployment/exports.def','-nostartfiles','-Wl,--entry,app_entry','-Wl,--undefined,app_entry','-Wl,--disable-auto-import','-Wl,--disable-runtime-pseudo-reloc','-Wl,--gc-sections','-Wl,--out-implib,'+str(out/'libapplication.dll.a'),'-Wl,-Map,'+str(out/'application.map'),'-o',out/'application.dll'])
        for name,source in [('deployment_check','check.c'),('cross_check','tests/cross_check.c')]:
            runner.run(name,[*common,'-O2','-I'+str(local),local/source,out/'libapplication.dll.a','-o',out/(name+'.exe')])
        runner.run('resource_probe',[*common,'-O2','-fno-omit-frame-pointer','-I'+str(local),local/'tests/resource_probe.c',local/'tests/resources_pq/stack_windows_x64.S',out/'libapplication.dll.a','-o',out/'resource_probe.exe'])
    else:
        target=runner.run('target',[cc,'-dumpmachine']);require((out/target['stdout']['path']).read_text().strip()=='aarch64-linux-gnu','Native AArch64 compiler required')
        runner.run('application',[*common,*sanitize,'-Os','-fno-omit-frame-pointer','-shared','-fPIC',local/'application.c','-Wl,--version-script='+str(local/'deployment/exports.map'),'-Wl,-z,relro,-z,now','-Wl,-Map,'+str(out/'application.map'),'-o',out/'libapplication.so'])
        linked=['-L'+str(out),'-l:libapplication.so','-Wl,-rpath,$ORIGIN','-ldl']
        for name,source in [('deployment_check','check.c'),('cross_check','tests/cross_check.c')]:
            runner.run(name,[*common,*sanitize,'-O2','-I'+str(local),local/source,*linked,'-o',out/name])
        runner.run('resource_probe',[*common,*sanitize,'-O2','-fno-omit-frame-pointer','-I'+str(local),local/'tests/resource_probe.c',local/'tests/resources_pq/stack_aarch64.S',*linked,'-o',out/'resource_probe'])
        runner.run('heap_audit',[*common,'-O2','-shared','-fPIC',local/'tests/resources_pq/linux_heap_audit.c','-o',out/'heap_audit.so'])
    artifacts={name:sha(out/name) for name in artifact_names()}
    write(out/'build.xml',dict(schema='lattice.application_build.v1',status='PASS',sources=sources,artifacts=artifacts,tool_sha256=sha(__file__),commands_sha256=sha(out/'commands.xml'),platform=platform.platform()))
    print(json.dumps(dict(status='PASS',build=reference(out/'build.xml'))))

def artifact_names():
    return ('application.dll','libapplication.dll.a','deployment_check.exe','cross_check.exe','resource_probe.exe') if os.name=='nt' else ('libapplication.so','deployment_check','cross_check','resource_probe','heap_audit.so')

def app_module(b):return b/('application.dll' if os.name=='nt' else 'libapplication.so')
def executable(b,name):return b/(name+('.exe' if os.name=='nt' else ''))

def loaded_build(path):
    path=path.resolve();value=read(path/'build.xml')
    require(set(value)=={'schema','status','sources','artifacts','tool_sha256','commands_sha256','platform'} and value['schema']=='lattice.application_build.v1' and value['status']=='PASS','Invalid application build')
    require(value['sources']==source_records() and value['tool_sha256']==sha(__file__),'Changed source/build tool identity')
    require(sha(path/'commands.xml')==value['commands_sha256'],'Changed build commands')
    for name,digest in value['artifacts'].items():
        require(name in artifact_names(),'Unknown build artifact')
        require(sha(path/name)==digest,'Changed application executable')
    require(len(value['artifacts'])==5,'Missing application executable')
    for row in value['sources']:require(sha(path/'source'/row['path'])==row['sha256'],'Changed copied source')
    return path,value

def check(args):
    b,manifest=loaded_build(args.build);core=args.library.resolve();baseline=args.baseline.resolve()
    identities=dict(candidate=reference(core),baseline=reference(baseline),application=reference(app_module(b)))
    out=fresh(args.output);runner=Runner(out)
    byte=runner.run('complete-outputs',[executable(b,'cross_check'),baseline,core,args.workspace])['events']
    life=runner.run('lifecycle',[executable(b,'deployment_check'),core,args.workspace])['events']
    require(len(byte)==1 and byte[0].get('complete_byte_comparisons')==1728 and byte[0].get('actual_flows')==2304 and byte[0].get('status')=='PASS','Incomplete full-output comparison')
    require(len(life)==2 and all(x.get('status')=='PASS' for x in life) and life[0]['lifecycle_assertions']==240 and life[1]['workspace_bytes']==args.workspace,'Incomplete lifecycle checks')
    require(reference(core)==identities['candidate'] and reference(baseline)==identities['baseline'],'Core identity changed')
    loaded_build(b)
    result=dict(schema='lattice.application_check.v1',status='PASS',artifacts=identities,build=reference(b/'build.xml'),workspace_bytes=args.workspace,complete_outputs=byte[0],lifecycle=life,commands_sha256=sha(out/'commands.xml'),timing_collected=False)
    write(out/'result.xml',result);print(json.dumps(result))

def project_image(value):
    out=dict(value);out['path']=Path(out['path']).name
    return out

def inventory(path,public):
    spec=importlib.util.spec_from_file_location('owner_image_inventory',ROOT/'tests/resources/image_inventory.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);module.PUBLIC=set(public)
    return project_image(module.inventory(path))

def resources(args):
    require(256<=args.stack_bytes<=262144 and args.stack_bytes%16==0,'Stack must be a multiple of16 in256..262144')
    require(0<=args.heap_bound<=1048576,'Heap reservation outside supported range')
    b,manifest=loaded_build(args.build);core=args.library.resolve();core_id=reference(core)
    core_image=inventory(core,['lc_get_sizes','lc_context_init','lc_keypair','lc_encaps','lc_decaps','lc_sign','lc_verify','lc_error_string']);app_image=inventory(app_module(b),EXPORTS)
    require(not app_image['unhandled_allocator_imports'] and not core_image['unhandled_allocator_imports'],'Unsupported application or core allocator import')
    module_globals=app_image['writable_image_plus_single_thread_tls_bytes']
    globals_=core_image['writable_image_plus_single_thread_tls_bytes'];out=fresh(args.output);runner=Runner(out)
    def trial(label,k,d,layout,fresh_,seed,work,stack,flows=4,control=0,allowed=(0,)):
        argv=[executable(b,'resource_probe'),core,k,d,layout,fresh_,work,stack,globals_,seed,flows,0,control,args.heap_bound,module_globals]
        extra={'LD_PRELOAD':str(b/'heap_audit.so')} if os.name!='nt' else None
        row=runner.run(label,argv,allowed,extra_env=extra);events=row['events'];result=next((x for x in events if 'status' in x),None);heap=next((x for x in events if x.get('event')=='heap_lifetime'),None)
        return row,result,heap
    # Both controls run with a legal roomy stack; no intentional overflow is executed.
    controls=((1,16384),(3,16384))
    for control,stack in controls:
        row,result,heap=trial('instrument-control',512,44,0,1,6179,args.workspace,stack,1,control)
        require(result is not None and result['status']=='PASS','Instrument control failed')
        if control==3:require(result['outside_heap_peak']==96,'Heap positive control failed')
    normal=[];recovery=[]
    for seed_index in range(4):
        for k,d in PAIRS:
            for fresh_ in (0,1):
                pair=[]
                for layout in (0,1):
                    row,result,heap=trial('normal',k,d,layout,fresh_,202610031612+seed_index*104729+k,args.workspace,args.stack_bytes)
                    require(result['status']=='PASS' and result['guards_ok'] and result['cleared'] and result['transcript_matches'] and result['completed_flows']==4,'Application resource check failed')
                    require(not result['timed'] and result['batch_ticks']==0 and result['stack_watermark_bytes']<=args.stack_bytes and result['workspace_high_water']<=args.workspace,'Invalid resource boundary')
                    require(result['heap_errors']==0 and heap['unsupported']==0 and heap['tls_slot_allocations']==0 and heap['peak_requested']<=args.heap_bound,'Invalid heap/resource accounting')
                    normal.append(result);pair.append(result)
                require(pair[0]['transcript']==pair[1]['transcript'],'Layout transcript mismatch')
    for k,d in PAIRS:
        for layout in (0,1):
            row,failed,heap=trial('insufficient',k,d,layout,1,202610041615+k,32,args.stack_bytes,1)
            require(failed['status']=='WORKSPACE_INSUFFICIENT' and failed['rc']==-5 and failed['cleared'] and failed['guards_ok'],'Capacity failure handling changed')
            row,restored,heap=trial('restored-capacity',k,d,layout,1,202610041615+k,args.workspace,args.stack_bytes,1)
            require(restored['status']=='PASS' and restored['cleared'] and restored['guards_ok'],'Restored capacity failed')
            recovery.append(dict(kem=k,dsa=d,layout=layout,failure=failed,restored=restored,same_process=False))
    cells=[]
    for k,d in PAIRS:
        for layout in (0,1):
            group=[x for x in normal if x['kem']==k and x['layout']==layout];require(len(group)==8,'Incomplete resource cell')
            keys=('pool_bytes','application_state_bytes','serialized_owner_bytes','workspace_bytes','stack_reserved_bytes','library_globals_tls_bytes','application_globals_bytes','application_module_globals_bytes','charged_bytes')
            for key in keys:require(len({x[key] for x in group})==1,'Inconsistent charged resources')
            cells.append(dict(kem=k,dsa=d,layout=layout,**{key:group[0][key] for key in keys},maximum_stack_watermark=max(x['stack_watermark_bytes'] for x in group),maximum_workspace_high_water=max(x['workspace_high_water'] for x in group),maximum_observed_heap=max(x['outside_heap_peak'] for x in group),heap_reserved_bytes=args.heap_bound,flows=32))
    require(reference(core)==core_id,'Core identity changed');loaded_build(b)
    result=dict(schema='lattice.application_resources.v1',status='PASS',core=core_id,application=reference(app_module(b)),build=reference(b/'build.xml'),core_image=core_image,application_image=app_image,program_bytes=core_image['program_non_debug_image_bytes']+app_image['program_non_debug_image_bytes'],cells=cells,normal_batches=48,normal_flows=192,capacity_recovery=recovery,positive_controls=len(controls),commands_sha256=sha(out/'commands.xml'),inventory_tool_sha256=sha(ROOT/'tests/resources/image_inventory.py'),timing_collected=False,scope='Fixed complete workflows with both serialized-owner layouts. Charged memory includes the state/object/workspace pool, protected full-application stack, library globals/TLS, application control globals and reserved external heap. Stack watermarks describe the executed inputs.')
    write(out/'result.xml',result);print(json.dumps(dict(status='PASS',result=reference(out/'result.xml'),program_bytes=result['program_bytes'],cells=[dict(kem=x['kem'],dsa=x['dsa'],layout=x['layout'],charged_bytes=x['charged_bytes']) for x in cells])))

def main():
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='action',required=True)
    b=sub.add_parser('build');b.add_argument('--output',type=Path,required=True);b.add_argument('--cc',default='gcc');b.add_argument('--sanitizer',choices=['none','address-undefined'],default='none')
    for name in ('check','resources'):
        a=sub.add_parser(name);a.add_argument('--build',type=Path,required=True);a.add_argument('--library',type=Path,required=True);a.add_argument('--workspace',type=workspace,required=True);a.add_argument('--output',type=Path,required=True)
        if name=='check':a.add_argument('--baseline',type=Path,required=True)
        else:a.add_argument('--stack-bytes',type=int,required=True);a.add_argument('--heap-bound',type=int,default=0)
    args=p.parse_args();{'build':build,'check':check,'resources':resources}[args.action](args)

if __name__=='__main__':main()
