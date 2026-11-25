"""Independent source-root-bound shared prototype with direct call-graph review.

This is a supplementary tool version: the original build.py and any failed
original result remain unchanged. Scientific arithmetic/front ends are unpatched.

The control image, complete source fingerprints and compiler flags are explicit.
No arithmetic or SHAKE front-end source is patched.
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
import argparse, hashlib, record_io as json, os, re, shutil, subprocess, sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"shared_keccak"))
ROOT=None
from reachability import analyze

def main():
    p=argparse.ArgumentParser();p.add_argument('--source-root',type=Path,required=True);p.add_argument('--control',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--nm',default='nm');p.add_argument('--objdump',default='objdump');p.add_argument('--provider',choices=['direct','single'],default='direct');a=p.parse_args()
    global ROOT,sha,read,write,binary_info,pe_exports,PUBLIC
    ROOT=a.source_root.resolve();sys.path.insert(0,str(ROOT/'tools'))
    from size_variants import sha,read,write,binary_info,pe_exports,PUBLIC
    control=a.control.resolve();out=a.output.resolve();result=read(control/'result.xml')
    if result['backend']!='portable' or result['parameters']!=[512,768,1024,44,65,87]:raise ValueError('Initial prototype requires an explicit full portable control')
    for path,digest in result['source_hashes'].items():
        if sha(path)!=digest:raise ValueError('Control source changed: '+path)
    windows=result['inspections']['shared_library']['format']=='PE';libname='latticecore.dll' if windows else 'liblatticecore.so';base=control/libname
    if sha(base)!=result['inspections']['shared_library']['sha256']:raise ValueError('Control binary changed')
    out.mkdir(parents=True,exist_ok=False)
    for name in ('obj','generated','tmp'):(out/name).mkdir()
    for path in (control/'generated').iterdir():shutil.copyfile(path,out/'generated'/path.name)
    export='exports.def' if windows else 'exports.map';shutil.copyfile(control/export,out/export)
    environment=os.environ.copy();environment.update(TEMP=str(out/'tmp'),TMP=str(out/'tmp'),TMPDIR=str(out/'tmp'),PYTHONDONTWRITEBYTECODE='1')
    log=[];backends=ROOT/'configs/shared_keccak_compact';here=ROOT/'tests/pruning/shared_keccak'
    def run(argv,label):
        proc=subprocess.run(list(map(str,argv)),cwd=ROOT,env=environment,capture_output=True,text=True,encoding='utf-8',errors='replace')
        path=out/(label+'.log');path.write_text(json.capture_text(proc.stdout+proc.stderr),encoding='utf-8');log.append(dict(argv=list(map(str,argv)),exit_code=proc.returncode,log=path.name,sha256=sha(path)));write(out/'commands.xml',log)
        if proc.returncode:raise RuntimeError(label+' failed; original result retained')
        return proc.stdout
    def relocated(argv):return [x.replace(str(control),str(out)) for x in argv]
    try:
        original=read(control/'commands.xml');compiled=[];preprocessed=[]
        for row in original:
            argv=row['argv']
            if not row['log'].startswith('compile_') or '-c' not in argv:continue
            argv=relocated(argv);source=Path(argv[argv.index('-c')+1]);obj=Path(argv[argv.index('-o')+1])
            extra=['-I'+str(backends)]
            if source.name=='mlkem_selected.c':extra+=['-DMLK_CONFIG_USE_NATIVE_BACKEND_FIPS202','-DMLK_CONFIG_FIPS202_BACKEND_FILE="lc_shared_mlk.h"']
            elif any(v.startswith('-DMLD_CONFIG_FILE=') for v in argv):extra+=['-DMLD_CONFIG_USE_NATIVE_BACKEND_FIPS202','-DMLD_CONFIG_FIPS202_BACKEND_FILE="lc_shared_mld.h"']
            at=argv.index('-c');argv[at:at]=extra
            run(argv,row['log'].removesuffix('.log'));compiled.append(obj)
            preprocessed.append({'path':str(obj.with_suffix('.i')),'sha256':sha(obj.with_suffix('.i')),'object_sha256':sha(obj)})
        first=next(r['argv'] for r in original if r['log']=='compile_00.log');cc=first[0]
        owner=out/'obj/shared_owner.o';owner_command=relocated(first)
        owner_command=[v for v in owner_command if not v.startswith('-D')]
        owner_source=backends/('owner.c' if a.provider=='direct' else 'owner_single.c')
        owner_command[owner_command.index('-c')+1]=str(owner_source);owner_command[owner_command.index('-o')+1]=str(owner);owner_command[owner_command.index('-MF')+1]=str(owner.with_suffix('.d'))
        at=owner_command.index('-c');owner_command[at:at]=['-I'+str(backends),'-DMLK_CONFIG_FILE="owner_config.h"']
        run(owner_command,'compile_owner');preprocessed.append({'path':str(owner.with_suffix('.i')),'sha256':sha(owner.with_suffix('.i')),'object_sha256':sha(owner)})
        for name in ('link_shared','archive'):
            command=relocated(next(r['argv'] for r in original if r['log']==name+'.log'))
            command.append(str(owner));run(command,name)
        for linkage in ('shared','static'):
            for phase in ('compile','run'):
                name=linkage+'_probe_'+phase;run(relocated(next(r['argv'] for r in original if r['log']==name+'.log')),name)
        # Actual mldsa-native original permutation versus shared object; two
        # independently namespaced implementations inside a test-only image.
        oracle=out/('oracle.exe' if windows else 'oracle')
        common=['-'+result['optimization'],'-g','-std=c11','-ffunction-sections','-fdata-sections','-fno-omit-frame-pointer']
        if result['lto']:common+=['-flto']
        run([cc,*common,'-I'+str(backends),'-I'+str(here),'-DMLD_CONFIG_FILE="oracle_config.h"',here/'oracle.c',owner,'-Wl,--gc-sections','-o',oracle],'oracle_compile')
        observed=run([oracle],'oracle_run');rows=[json.loads(x) for x in observed.splitlines() if x.startswith('{')]
        assert rows[0]['random_state_pairs']==10000 and rows[0]['original_mldsa_C_oracle_equal']
        kat=[]
        for row in rows[1:]:
            data=bytes((i*17+11)%256 for i in range(row['input_bytes']));n=len(row['output_hex'])//2
            expected=(hashlib.shake_128 if row['shake_bits']==128 else hashlib.shake_256)(data).hexdigest(n)
            assert expected==row['output_hex'],row
            kat.append({'shake_bits':row['shake_bits'],'input_bytes':row['input_bytes'],'output_bytes':n,'output_sha256':hashlib.sha256(bytes.fromhex(expected)).hexdigest(),'status':'PASS'})
        write(out/'primitive_oracle.xml',{'status':'PASS','random_state_pairs':10000,'random_oracle':'unmodified mldsa-native portable permutation; 25-lane canaries','fixed_xof_answers':kat,'answer_provider':'Python hashlib SHAKE cross implementation; test-only byte-oriented composition, actual production front ends are covered by public ACVP','oracle_executable_sha256':sha(oracle)})
        binary=out/libname
        run([sys.executable,'-B',ROOT/'tests/pruning/acvp.py','--library',binary,'--parameters',*map(str,result['parameters']),'--output',out/'acvp.xml'],'acvp')
        run([sys.executable,'-B',ROOT/'tests/platform/compare_public.py','--left',base,'--right',binary,'--count','100','--resource-mode','equal','--output',out/'differential.xml'],'differential')
        run([sys.executable,'-B',ROOT/'tests/pruning/inspect_existing.py','--library',binary,'--map',out/'shared.map','--output',out/'inspection','--nm',a.nm,'--objdump',a.objdump],'inspect')
        entities=read(out/'inspection/entities.xml')['entities'];shared=[r for r in entities if r['symbol']=='lc_shared_keccakf1600']
        cores=[r for r in entities if re.search(r'(?:mlk|mld)_keccakf1600_permute_c',r['symbol'])]
        if len(shared)!=1 or len(cores)>1 or any('mld_' in r['symbol'] for r in cores):raise ValueError('Final image did not retain exactly one shared permutation provider')
        disasm=(out/'inspection/disassembly.log').read_text(encoding='utf-8')
        reachability=analyze(entities,disasm)
        reachability.update(library_sha256=sha(binary),entities_sha256=sha(out/'inspection/entities.xml'),disassembly_sha256=sha(out/'inspection/disassembly.log'),review_source_sha256=sha(ROOT/'tests/pruning/shared_keccak/reachability.py'))
        write(out/'reachability.xml',reachability)
        image=binary_info(binary)
        if windows:assert sorted(pe_exports(binary))==sorted(PUBLIC)
        source_files=[*backends.glob('*'),*here.glob('*'),Path(__file__),ROOT/'tests/pruning/shared_keccak/reachability.py']
        for source,digest in result['source_hashes'].items():
            if sha(source)!=digest:raise ValueError('Source changed during prototype build')
        write(out/'result.xml',{'status':'SHARED_PROVIDER_VALIDATED','provider':a.provider,'control':{'result':str(control/'result.xml'),'result_sha256':sha(control/'result.xml'),'library_sha256':sha(base)},'candidate':{'library':str(binary),'sha256':sha(binary)},'unchanged_polynomial_arithmetic_and_shake_frontends':True,'permutation_round_schedule':24 if a.provider=='single' else 'upstream 12 iterations of 2 rounds',
            'compiler':result['compiler'],'optimization':result['optimization'],'lto':result['lto'],'source_files':{str(f):sha(f) for f in source_files if f.is_file()},'control_source_hashes':result['source_hashes'],'preprocessed_units':preprocessed,
            'shared_entity':shared[0],'retained_original_core_entities':cores,'actual_cross_family_reachability':reachability,'reachability_sha256':sha(out/'reachability.xml'),
            'control_image':result['inspections']['shared_library'],'candidate_image':image,'readonly_delta_bytes':image['readonly_allocated_bytes']-result['inspections']['shared_library']['readonly_allocated_bytes'],
            'primitive_oracle_sha256':sha(out/'primitive_oracle.xml'),'acvp_sha256':sha(out/'acvp.xml'),'differential_sha256':sha(out/'differential.xml'),'commands_sha256':sha(out/'commands.xml'),'call_cost_measured':False,'native_backends_verified':False,
            'limits':['Portable provider through upstream native-backend extension hooks; no claim of hardware-native implementation.','Primitive implementation inherited from mlkem-native, not newly invented.','SHAKE rate/domain/context remain in their original algorithm-family front ends.','Timing requires separately coordinated measurement.']})
        print('One actual shared portable permutation, both-family machine references, 10000 states, fixed XOF answers, full applicable ACVP and 6x100 differential PASS')
    except Exception as error:
        write(out/'failure.xml',{'status':'FAILED','error':str(error),'commands_sha256':sha(out/'commands.xml') if (out/'commands.xml').exists() else None});raise
if __name__=='__main__':main()
