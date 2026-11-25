"""Measure six-parameter library memory with fixed inputs and legal stack reserves."""
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
import argparse, hashlib, record_io as json, os, platform, shutil, subprocess, sys
ROOT=Path(__file__).resolve().parents[1];HERE=ROOT/'tests/resources'
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--cc',default='gcc');p.add_argument('--seeds',type=int,default=24);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--workspace',type=int,help='Explicit aligned workspace for a runtime resource policy; no inferred minimum claim.')
    a=p.parse_args()
    if a.workspace is not None and (a.workspace<32 or a.workspace>262144 or a.workspace%32):raise ValueError('Workspace must be an aligned capacity from 32 to 262144')
    assert 24<=a.seeds<=48 and not a.output.exists();lib=a.library.resolve();out=a.output.resolve();out.mkdir(parents=True);(out/'tmp').mkdir()
    sys.path.insert(0,str(HERE));from image_inventory import inventory
    image=inventory(lib);assert not image['unhandled_allocator_imports'];cc=shutil.which(a.cc);assert cc
    arch=platform.machine().lower();assembly='stack_windows_x64.S'if os.name=='nt'else'stack_aarch64.S'if arch in('aarch64','arm64')else'stack_linux_x64.S'
    assert arch in('amd64','x86_64','aarch64','arm64')
    env=dict(os.environ,TEMP=str(out/'tmp'),TMP=str(out/'tmp'),TMPDIR=str(out/'tmp'));commands=[];rows=[]
    env['PATH']=str(Path(cc).parent)+os.pathsep+env.get('PATH','')
    def save(name,x):(out/name).write_text(json.dumps(x,indent=2,allow_nan=False)+'\n',encoding='utf-8')
    def call(label,argv,probe=False):
        e=dict(env)
        if probe and os.name!='nt':e['LD_PRELOAD']=str(out/'heap_audit.so')
        q=subprocess.run(list(map(str,argv)),capture_output=True,text=True,env=e,timeout=60)
        log=out/(label+'.log');log.write_text(json.capture_text(q.stdout+q.stderr),encoding='utf-8');commands.append(dict(label=label,command=list(map(str,argv)),exit_code=q.returncode,log_sha256=sha(log)));save('commands.xml',commands)
        assert q.returncode==0,(label,q.stderr[-1000:]);return q.stdout
    sources=[HERE/'probe.c',HERE/assembly,HERE/'image_inventory.py',ROOT/'include/latticecore.h',Path(__file__)]
    sources+=[HERE/('windows_heap_audit.h'if os.name=='nt'else'linux_heap_audit.c')]
    binding={f.relative_to(ROOT).as_posix():sha(f)for f in sources};save('image.xml',image)
    compiler=call('compiler',[cc,'--version']).splitlines()[0];exe=out/('probe.exe'if os.name=='nt'else'probe')
    flags=['-O2','-std=c11','-Wall','-Wextra','-Werror','-fno-omit-frame-pointer']
    call('compile',[cc,*flags,'-I'+str(ROOT/'include'),HERE/'probe.c',HERE/assembly,*([]if os.name=='nt'else['-ldl','-Wl,-z,noexecstack']),'-o',exe])
    if os.name!='nt':call('heap-audit-build',[cc,*flags,'-fPIC','-shared',HERE/'linux_heap_audit.c','-o',out/'heap_audit.so'])
    def trial(stage,level,i,W,S):
        seed=610052317+i;text=call(f'{stage}-{level}-{i}',[exe,lib,level,3,W,S,seed,0],probe=True)
        events=[json.loads(x)for x in text.splitlines()if x.strip()];values=[x for x in events if x.get('event')=='trial_result'];assert len(values)==1;r=values[0]
        assert all(r[k]==0 for k in('rc','worker_rc','guard_error','init_rc','heap_audit_errors','allocation_failures'))
        assert r['canaries_ok']and r['recovery_full_sequence_ok']and r['step_outputs_match']==[1,1,1]and r['step_rc']==[0,0,0]
        assert r['released_prefix_changed_nonzero_bytes']==0 and r['step_changed_nonzero_bytes']==[0,0,0]
        assert r['outside_heap_live_requested_bytes']==0 and r['stack_watermark_observed_bytes']<=S and r['arena_high_water_bytes']<=W and r.get('heap_unhandled_imports',0)==0
        rows.append(dict(stage=stage,result=r));return r
    for level in (512,768,1024,44,65,87):
        for i in range(a.seeds):trial('roomy',level,i,a.workspace or 262144,65536)
    W=a.workspace or max(x['result']['arena_high_water_bytes']for x in rows);observed=max(x['result']['stack_watermark_observed_bytes']for x in rows);S=((observed+511)//256)*256
    assert W%32==0 and observed+256<=S<=65536
    for level in (512,768,1024,44,65,87):
        for i in range(a.seeds):trial('reserved',level,i,W,S)
    normal=[x['result']for x in rows if x['stage']=='reserved'];C=max(x['context_bytes']for x in normal);G=image['writable_image_plus_single_thread_tls_bytes'];H=max(x['outside_heap_peak_requested_bytes']for x in normal)
    cells=[]
    for level in (512,768,1024,44,65,87):
        group=[x for x in normal if x['parameter']==level]
        for op in range(3):
            w=max(x['step_arena_high_water'][op]for x in group);s=max(x['step_stack_watermark'][op]for x in group)
            cells.append(dict(parameter=level,operation=op,workspace_highwater=w,stack_watermark=s,stack_reserved=((s+511)//256)*256))
    assert sha(lib)==image['sha256']and all(sha(ROOT/n)==h for n,h in binding.items())
    save('observations.xml',rows);result=dict(schema='lattice.normal_resource_measurement.v1',status='PASS',library_sha256=sha(lib),compiler=compiler,source_hashes=binding,probe_sha256=sha(exe),W=W,S=S,C=C,G=G,H=H,R=W+S+C+G+H,P=image['program_non_debug_image_bytes'],sequences=len(rows),operations=len(rows)*3,cells=cells,seed_start=610052317,seeds_per_parameter=a.seeds,stack_reserve_rule='round up to 256 bytes after adding 256 bytes to the observed maximum',scope='Core workspace, reserved stack, external context, writable image/TLS and observed outside heap; serialized caller input/output objects are accounted by the complete application experiment.',observations_sha256=sha(out/'observations.xml'),commands_sha256=sha(out/'commands.xml'),formal_timing_collected=False)
    result['explicit_workspace_policy_bytes']=a.workspace
    save('result.xml',result);print(json.dumps({k:result[k]for k in('status','W','S','C','G','H','R','P','operations')}))
if __name__=='__main__':main()
