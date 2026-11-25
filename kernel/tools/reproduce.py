"""Build, qualify and recompute a complete local release in one invocation."""
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
import argparse, datetime, hashlib, record_io as json, os, platform, shutil, subprocess, sys, time
ROOT=Path(__file__).resolve().parents[1]
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
MEMBERS=['09_keccak_f1600_x4_avx2_asm.o','25_mlkem_polyvec_basemul_acc_montgomery_cached_k3_avx2_asm.o','26_mlkem_polyvec_basemul_acc_montgomery_cached_k4_avx2_asm.o','28_mlkem_rej_uniform_avx2_asm.o','40_mldsa_poly_decompose_32_avx2_asm.o','41_mldsa_poly_decompose_88_avx2_asm.o','46_mldsa_rej_uniform_avx2_asm.o']
CONFIGURATIONS=('compact-rate','native-x86','native-arm',
    'native-x86-cache40-gamma','native-x86-cache48-gamma','native-x86-cache56-gamma','native-x86-speed32',
    'native-arm-cache40-yall','native-arm-cache48-yall','native-arm-cache56-yall','native-arm-speed32',
    'native-x86-sign-pipeline','native-arm-sign-pipeline')
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--mode',choices=['quick','full'],default='quick');p.add_argument('--configuration',choices=CONFIGURATIONS,default='compact-rate')
    p.add_argument('--toolchain-directory',type=Path);p.add_argument('--bundle',type=Path,default=ROOT.parent)
    p.add_argument('--reference-source',type=Path,help='Bundled mature reference tree; defaults to BUNDLE/reference-source/current')
    p.add_argument('--output',type=Path,required=True);p.add_argument('--source-only',action='store_true',help='Build and test source without the separately packaged experimental datasets')
    a=p.parse_args();out=a.output.resolve();bundle=a.bundle.resolve()
    if out.exists() or out.is_relative_to(ROOT):raise ValueError('Use a fresh output outside the source tree')
    out.mkdir(parents=True);(out/'tmp').mkdir();(out/'logs').mkdir()
    env=dict(os.environ,TEMP=str(out/'tmp'),TMP=str(out/'tmp'),TMPDIR=str(out/'tmp'),PYTHONDONTWRITEBYTECODE='1',PYTHONUTF8='1')
    if a.toolchain_directory:env['PATH']=str(a.toolchain_directory.resolve())+os.pathsep+env.get('PATH','')
    tools={n:shutil.which(n,path=env.get('PATH')) for n in ('gcc','gcc-ar','nm','objdump','size')}
    if not all(tools.values()):raise ValueError('GCC and its matching archive/binary tools are required')
    result=dict(schema='lattice.reproduction.v1',status='RUNNING',mode=a.mode,configuration=a.configuration,utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),platform=platform.platform(),python=sys.version,entry_sha256=sha(__file__),tools=tools,records=[])
    def save():(out/'result.xml').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    def run(label,cmd,timeout=900):
        start=time.monotonic();proc=subprocess.run(list(map(str,cmd)),cwd=ROOT,env=env,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=timeout)
        log=out/'logs'/(label+'.log');log.write_text(json.capture_text(proc.stdout+proc.stderr),encoding='utf-8')
        result['records'].append(dict(name=label,command=list(map(str,cmd)),exit_code=proc.returncode,seconds=time.monotonic()-start,log=log.relative_to(out).as_posix(),log_sha256=sha(log)));save()
        if proc.returncode:raise RuntimeError(label+' failed; inspect '+str(log))
        print(label,'PASS',flush=True);return proc.stdout
    save()
    try:
        result['compiler']=run('compiler',[tools['gcc'],'--version']).splitlines()[0]
        recipes=json.loads((ROOT/'configs/recipes.xml').read_text(encoding='utf-8'))['recipes']
        backend=recipes[a.configuration]['defaults']['backend']
        if backend not in recipes[a.configuration]['backends']:raise ValueError('Recipe default backend is not supported')
        result['backend']=backend
        optimization=recipes[a.configuration]['defaults']['optimization']
        result['optimization']=optimization
        tool_args=sum((['--'+k,tools[v]] for k,v in [('cc','gcc'),('ar','gcc-ar'),('nm','nm'),('objdump','objdump'),('size','size')]),[])
        py=[sys.executable,'-B'];libraries={}
        reference_source=(a.reference_source or bundle/'reference-source/current').resolve()
        if not (reference_source/'tools/build.py').is_file():raise ValueError('Bundled reference-source/current is missing; provide --bundle or --reference-source')
        for role,recipe in [('selected',a.configuration),('reference','reference-lowram')]:
            plan=out/(role+'-plan.xml');build=out/(role+'-build')
            if role=='reference':
                run(role+'-build',py+[ROOT/'tools/build_reference.py','--reference-source',reference_source,'--configuration','lowram','--backend',backend,'--optimization',optimization,'--compiler',tools['gcc'],'--ar',tools['gcc-ar'],'--nm',tools['nm'],'--objdump',tools['objdump'],'--size',tools['size'],'--output',build])
                artifacts=build/'build/artifacts'
            else:
                run(role+'-plan',py+[ROOT/'tools/build.py','plan','--configuration',recipe,'--backend',backend,'--opt',optimization,'--lto','--probe-count','20' if a.mode=='quick' else '100',*tool_args,'--output',plan])
                run(role+'-build',py+[ROOT/'tools/build.py','build','--plan',plan,'--output',build])
                artifacts=build/'artifacts'
            if role=='selected' and backend=='x86_64' and os.name=='nt':
                deployment=out/'selected-deployment'
                omitted=[n for n in MEMBERS if not (a.configuration=='native-x86-sign-pipeline' and n=='09_keccak_f1600_x4_avx2_asm.o')]
                run('linked-entities',py+[ROOT/'tools/relink_pe.py','--parent',artifacts,'--control',out/'link-control','--output',deployment,'--cc',tools['gcc'],'--ar',tools['gcc-ar'],'--nm',tools['nm'],'--objdump',tools['objdump'],*sum((['--omit-member',n] for n in omitted),[])])
                artifacts=deployment
            libraries[role]=artifacts/('latticecore.dll' if os.name=='nt' else 'liblatticecore.so')
            assert libraries[role].is_file()
        result['images']={k:dict(path=v.relative_to(out).as_posix(),sha256=sha(v))for k,v in libraries.items()};save()
        # This common capacity is an execution allowance. Per-operation and
        # deployment memory figures come from resource measurements separately.
        run('functional-'+a.mode,py+[ROOT/'tools/validate_release.py','--library',libraries['selected'],'--reference',libraries['reference'],'--workspace','262144','--mode',a.mode,'--output',out/'functional'])
        run('published-key-boundaries',py+[ROOT/'tests/normal_capacity/key_encoding.py','--library',libraries['selected'],'--workspace','262144','--output',out/'key-encoding.xml'])
        run('selected-resources',py+[ROOT/'tools/measure_resources.py','--library',libraries['selected'],'--cc',tools['gcc'],'--output',out/'resources'])
        if a.mode=='full':
            run('published-vectors',py+[ROOT/'tests/interop/wycheproof.py','--library',libraries['selected'],'--workspace','262144','--output',out/'wycheproof'])
        if not a.source_only:
            manifest=bundle/'reproduction.xml'
            if not manifest.is_file():raise ValueError('Packaged scientific data manifest is missing; --source-only selects a source-only check explicitly')
            data=json.loads(manifest.read_text(encoding='utf-8'));assert data['schema']=='lattice.reproduction_pipeline.v1'
            for task in data['tasks']:
                if a.mode not in task['modes']:continue
                script=(bundle/task['script']).resolve();assert script.is_relative_to(bundle) and script.suffix=='.py' and sha(script)==task['script_sha256']
                args=[x.replace('@BUNDLE@',str(bundle)).replace('@OUTPUT@',str(out/'science')) for x in task['arguments']]
                (out/'science').mkdir(exist_ok=True)
                run('science-'+task['name'],py+[script,*args],timeout=1800)
            result['scientific_manifest_sha256']=sha(manifest)
        result.update(status='PASS',scientific_data='EXPLICIT_SOURCE_ONLY' if a.source_only else 'RECOMPUTED',formal_timing_collected=False)
    except BaseException as error:
        result.update(status='FAILED_OR_INCOMPLETE',error=repr(error));raise
    finally:save()
    print('Reproduction complete: '+str(out/'result.xml'))
if __name__=='__main__':main()
