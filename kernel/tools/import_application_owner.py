"""Project completed fixed-owner application runs into closed scientific data.

This command validates files and recomputes statistics. It never loads a target,
builds software, or starts a measurement. Remote archives may use explicit path
prefix maps; every mapped byte identity remains mandatory.
"""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import argparse
from datetime import datetime
import hashlib
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
import record_io as json
import math
import shutil
from publicschemas import application_owner_v1 as model
from publicschemas.application_v1 import read, sha, need, keys, integer, digest, loads


class Resolver:
    def __init__(self, mappings=()):
        self.mappings=[];self.checked_files={}
        for entry in mappings:
            old,new=entry.split('=',1);need(old and new,'Invalid path map')
            self.mappings.append((old.replace('\\','/').rstrip('/'),Path(new).resolve()))
        self.mappings.sort(key=lambda x:len(x[0]),reverse=True)

    def path(self,value):
        need(type(value) is str and value and '\x00' not in value,'Invalid source path')
        v=value.replace('\\','/')
        for old,new in self.mappings:
            if v==old or v.startswith(old+'/'):
                p=(new/v[len(old):].lstrip('/')).resolve()
                need(p.is_relative_to(new),'Path map escaped root');return p
        return Path(value).resolve()

    def check(self,ref):
        keys(ref,('path','sha256'));digest(ref['sha256']);p=self.path(ref['path'])
        need(p.is_file() and sha(p)==ref['sha256'],'Source identity mismatch: '+str(p))
        self.checked_files[str(p)]=ref['sha256'];return p


def image_program(image, expected_sha):
    need(image['sha256']==expected_sha,'Image inventory identity mismatch')
    sections=image['sections']
    total=sum(s['initialized_image_bytes'] for s in sections if s['allocated'] and not s['debug'])
    need(total==image['program_non_debug_image_bytes'],'Program size arithmetic mismatch')
    return total


def import_data(args):
    resolver=Resolver(args.path_map);root=args.input.resolve();result=read(root/'result.xml')
    keys(result,('schema','status','plan','records','processes','target_flows','oracle_flows','trimmed_processes','elapsed_controller_seconds','ended_utc'))
    need(result['schema']=='lattice.application_owner_timing.v2' and result['status']=='PASS' and type(result['processes']) is int and 432<=result['processes']<=2160 and result['trimmed_processes']==0,'Incomplete collection')
    plan_path=resolver.check(result['plan']);plan=read(plan_path)
    keys(plan,('schema','state','platform','cpu','clock','config','libraries','build','driver','bindings','jobs','blocks','seed','timeout_seconds','total_timeout_seconds','timed_scope','outside_scope','entropy','layouts','replication_unit','sample_scope','instrument','statistics'))
    need(plan['schema']==result['schema'] and plan['state']=='prepared' and plan['blocks']==9 and plan['timeout_seconds']==30 and plan['total_timeout_seconds']==300*len(plan['libraries']),'Changed frozen collection')
    need(plan['timed_scope']==model.TIME_SCOPE and plan['outside_scope']==model.OUTSIDE_SCOPE,'Changed timing boundary')
    need(plan['layouts']=={'0':'separate serialized objects','1':'public key view in the KEM secret key; signature storage first receives the generated public key and later holds ciphertext and shared secrets'},'Changed owner layouts')
    need(plan['replication_unit']==f"randomized complete block of {24*len(plan['libraries'])} independent application batches" and plan['sample_scope']==f"one complete initialized and cleared application batch per process; all {216*len(plan['libraries'])} batches retained",'Changed replication unit')
    need(plan['entropy']=='Deterministic common inputs paired within each block, parameter pair, identity mode and flow count' and plan['instrument']=='ordinary application timing driver without heap hooks or stack-resource instrumentation; reservations come from separately qualified identical application/core images','Changed instrument or inputs')
    need(type(result['elapsed_controller_seconds']) in (int,float) and math.isfinite(result['elapsed_controller_seconds']) and 0<=result['elapsed_controller_seconds']<=plan['total_timeout_seconds'],'Collection timeout')
    ended=datetime.fromisoformat(result['ended_utc']);need(ended.tzinfo is not None,'Missing completion timezone')
    need(resolver.check(result['records'])==root/'records.xml','Records outside collection')
    resolver.check(plan['config'])
    for ref in plan['bindings']:resolver.check(ref)
    driver_path=resolver.check(plan['driver']);driver=read(driver_path)
    keys(driver,('schema','status','platform','application_build','application','copied_application','sources','compiler','commands','executable','collector','timing_collected'))
    need(driver['schema']=='lattice.application_timing_driver.v1' and driver['status']=='PASS_BUILD_ONLY' and driver['platform']==plan['platform'] and driver['timing_collected'] is False,'Changed timing driver')
    for field in ('application_build','application','copied_application','commands','executable','collector'):resolver.check(driver[field])
    # A returned archive need not contain a runnable compiler, but its digest is retained.
    keys(driver['compiler'],('path','sha256'));digest(driver['compiler']['sha256'])
    need(driver['application']['sha256']==driver['copied_application']['sha256'],'Driver loaded another application')
    for s in driver['sources']:
        keys(s,('original','copied'));resolver.check(s['original']);resolver.check(s['copied'])
        need(s['original']['sha256']==s['copied']['sha256'],'Compiled driver source changed')
    build_path=resolver.check(driver['application_build']);build=read(build_path)
    keys(build,('schema','status','sources','artifacts','tool_sha256','commands_sha256','platform'))
    need(build['schema']=='lattice.application_build.v1' and build['status']=='PASS' and build['platform'].startswith('Windows' if plan['platform']=='windows_x86_64' else 'Linux'),'Application build is not qualified')
    need(resolver.path(plan['build'])==build_path.parent,'Changed application build location')
    sources={}
    for s in build['sources']:
        keys(s,('path','sha256'));model.relative(s['path']);digest(s['sha256'])
        p=build_path.parent/'source'/s['path'];need(p.is_file() and sha(p)==s['sha256'],'Application source changed')
        need(s['path'] not in sources,'Duplicate compiled source');sources[s['path']]=s['sha256']
    for name,value in build['artifacts'].items():
        model.relative(name);digest(value)
        p=build_path.parent/name;need(p.is_file() and sha(p)==value,'Application artifact changed')
    need(sha(build_path.parent/'commands.xml')==build['commands_sha256'],'Build command log changed')
    ids=[x['id'] for x in plan['libraries']]
    need(plan['jobs']==model.schedule(plan['seed'],ids),'Changed complete paired schedule')
    mapping={x:(args.current_id if x=='lattice-native' else x) for x in ids}
    need(len(set(mapping.values()))==len(ids),'Repeated public configuration identity')
    records=read(root/'records.xml');need(type(records) is list and len(records)==result['processes']==216*len(ids),'Incomplete process records')
    configs=[];resource_data=[];copy_jobs=[];source_raw=set();all_raw=[]
    out=args.output.resolve();need(not out.exists(),'Output directory already exists')
    # Validate all private paths before creating the public output.
    def raw_spec(parent,ref,newname):
        keys(ref,('path','sha256'));model.relative(ref['path']);digest(ref['sha256'])
        p=(parent/ref['path']).resolve();need(p.is_relative_to(parent.resolve()) and p.is_file() and sha(p)==ref['sha256'],'Raw file changed')
        spec=dict(path=newname,sha256=ref['sha256'],bytes=p.stat().st_size);copy_jobs.append((p,spec));return spec
    by_id={}
    for lib in plan['libraries']:
        keys(lib,('id','library','resources','resource_commands','reservation','program_bytes','cells'))
        resolver.check(lib['library']);rp=resolver.check(lib['resources']);cp=resolver.check(lib['resource_commands']);r=read(rp);commands=read(cp)
        need(r['schema']=='lattice.application_resources.v1' and r['status']=='PASS' and r['timing_collected'] is False and r['core']['sha256']==lib['library']['sha256'] and r['application']['sha256']==driver['application']['sha256'],'Resource image identity mismatch')
        need(r['build']['sha256']==driver['application_build']['sha256'] and r['commands_sha256']==lib['resource_commands']['sha256'] and r['cells']==lib['cells'],'Resource source or cell mismatch')
        cpbytes=image_program(r['core_image'],lib['library']['sha256']);apbytes=image_program(r['application_image'],r['application']['sha256'])
        need(cpbytes+apbytes==r['program_bytes']==lib['program_bytes'],'Changed program bytes')
        need(r['normal_batches']==48 and r['normal_flows']==192 and r['positive_controls']==2,'Incomplete resource qualification')
        for c in r['cells']:
            need(all(c[k]==v for k,v in lib['reservation'].items()),'Changed resource reservation')
            need(c['library_globals_tls_bytes']==r['core_image']['writable_image_plus_single_thread_tls_bytes'] and c['application_module_globals_bytes']==r['application_image']['writable_image_plus_single_thread_tls_bytes'],'Globals or TLS omitted')
        cfg=dict(id=mapping[lib['id']],binary_sha256=lib['library']['sha256'],application_sha256=r['application']['sha256'],workspace_bytes=lib['reservation']['workspace_bytes'],core_program_bytes=cpbytes,application_program_bytes=apbytes,source_sha256=sources)
        configs.append(cfg);by_id[lib['id']]=lib
        rr=[]
        for i,row in enumerate(commands):
            keys(row,('label','command','exit_code','stdout','stderr','events'))
            need(row['exit_code']==0 and len(row['command'])==15,'Failed or changed resource process')
            command=row['command'];need(resolver.path(command[1])==resolver.path(lib['library']['path']),'Resource loaded different core')
            probe=resolver.path(command[0]);need(probe.is_file() and sha(probe) in build['artifacts'].values(),'Unbound resource probe')
            raw=raw_spec(rp.parent,row['stdout'],f'raw/resources/{cfg["id"]}/{i:04d}.records.xml');err=raw_spec(rp.parent,row['stderr'],f'raw/resources/{cfg["id"]}/{i:04d}.stderr')
            decoded=[loads(s) for s in copy_jobs[-2][0].read_text(encoding='utf-8').splitlines() if s.strip()]
            need(decoded==row['events'] and copy_jobs[-1][0].stat().st_size==0,'Resource events differ from raw')
            x=decoded[0];need([str(x[k]) for k in ('kem','dsa','layout','fresh_identity','workspace_bytes','stack_reserved_bytes','library_globals_tls_bytes','seed','iterations')]==command[2:11] and command[11]=='0','Resource invocation differs from result')
            need(command[13]==str(decoded[1]['reserved_bound']) and command[14]==str(x['application_module_globals_bytes']),'Resource reservation command mismatch')
            label=row['label']
            if label=='instrument-control':
                need(command[12] in ('1','3'),'Changed legal control');label='heap-control' if command[12]=='3' else label
            elif label=='restored-capacity':
                need(command[12]=='0','Unexpected resource control');label='restored'
            else:need(command[12]=='0','Unexpected resource control')
            rr.append(dict(ordinal=i,label=label,exit_code=0,raw=raw,stderr=err))
        resource_data.append(dict(configuration=cfg['id'],result_sha256=lib['resources']['sha256'],commands_sha256=lib['resource_commands']['sha256'],cells=r['cells'],records=rr))
    jobs=[];last_start=None
    for i,(row,job) in enumerate(zip(records,plan['jobs'],strict=True)):
        keys(row,(*model.JOB_FIELDS,'command','exit_code','timed_out','execution_error','started_utc','elapsed_controller_seconds','stdout','stderr','result'))
        need({k:row[k] for k in model.JOB_FIELDS}==job and row['exit_code']==0 and row['timed_out'] is False and row['execution_error'] is None,'Failed or reordered timing run')
        elapsed=row['elapsed_controller_seconds'];need(type(elapsed) in (float,int) and math.isfinite(elapsed) and 0<=elapsed<=30,'Process timeout')
        started=datetime.fromisoformat(row['started_utc']);need(started.tzinfo is not None and started<=ended and (last_start is None or started>=last_start),'Changed timestamp order');last_start=started
        lib=by_id[job['configuration']]
        expected=[driver['executable']['path'],lib['library']['path'],*[str(job[k]) for k in ('kem','dsa','layout','fresh_identity')],str(lib['reservation']['workspace_bytes']),str(job['seed']),str(job['flows']),str(plan['cpu']),'1']
        need(row['command']==expected,'Changed measured invocation')
        raw=raw_spec(root,row['stdout'],f'raw/timing/{i:04d}.records.xml');err=raw_spec(root,row['stderr'],f'raw/timing/{i:04d}.stderr')
        source_raw.update((copy_jobs[-2][0],copy_jobs[-1][0]))
        decoded=[loads(x) for x in copy_jobs[-2][0].read_text(encoding='utf-8').splitlines() if x.strip()]
        need(decoded==[row['result']] and copy_jobs[-1][0].stat().st_size==0,'Timing raw differs from stored result')
        jobs.append(dict(job,configuration=mapping[job['configuration']],exit_code=0,raw=raw,stderr=err))
    need(source_raw==set((root/'raw').iterdir()),'Unrecorded or missing timing raw files')
    need(result['target_flows']==result['oracle_flows']==sum(j['flows'] for j in jobs)==21708*len(ids),'Changed flow counts')
    for j in jobs:all_raw.extend([j['raw'],j['stderr']])
    for r in resource_data:
        for row in r['records']:all_raw.extend([row['raw'],row['stderr']])
    obs=dict(schema=model.SCHEMA,dataset_id=plan['platform']+'_fixed_owner_application',platform=plan['platform'],
             method=dict(blocks=9,seed=plan['seed'],cpu=plan['cpu'],clock=plan['clock'],timed_scope=model.TIME_SCOPE,outside_scope=model.OUTSIDE_SCOPE,statistics=plan['statistics'],unit='complete initialized and closed application batch',transcript_scope='paired 64-bit full-output transcripts; complete-byte equivalence qualified separately'),
             configurations=configs,provenance=dict(plan_sha256=result['plan']['sha256'],result_sha256=sha(root/'result.xml'),records_sha256=result['records']['sha256'],application_build_sha256=driver['application_build']['sha256'],driver_sha256=plan['driver']['sha256'],collector_sha256=driver['collector']['sha256'],driver_binary_sha256=driver['executable']['sha256'],compiler_sha256=driver['compiler']['sha256'],driver_source_sha256={s['copied']['path'].replace('\\','/').rsplit('/',1)[-1]:s['copied']['sha256'] for s in driver['sources']},all_records_retained=True),resources=resource_data,jobs=jobs,raw_files=all_raw)
    model.validate_observations(obs)
    out.mkdir(parents=True)
    for p,s in copy_jobs:
        q=out/s['path'];q.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,q)
    model.save(out/'observations.xml',obs);summary=model.recompute(out/'observations.xml');model.save(out/'summary.xml',summary)
    (out/'summary.csv').write_text(model.samples_csv(summary),encoding='utf-8',newline='')
    if args.audit:
        model.save(args.audit,dict(status='PASS',source_result=str(root/'result.xml'),source_files=resolver.checked_files,public_observations=dict(path=str(out/'observations.xml'),sha256=sha(out/'observations.xml')),summary=dict(path=str(out/'summary.xml'),sha256=sha(out/'summary.xml')),configuration_mapping=mapping,counts=summary['counts'],raw_files=len(all_raw)))
    print(json.dumps(dict(status='PASS',dataset_id=obs['dataset_id'],counts=summary['counts'],output=str(out))))


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--input',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--path-map',action='append',default=[]);p.add_argument('--current-id',default='lattice-native');p.add_argument('--audit',type=Path);a=p.parse_args();import_data(a)


if __name__=='__main__':main()
