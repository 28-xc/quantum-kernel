"""Build and optionally execute the real compact core on M4/RV32 QEMU targets.

This tool never measures time. Each fresh output directory binds source bytes,
tool versions, ELF/map, exact commands, ACVP subset, console and RAM accounting.
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
import argparse, datetime, hashlib, importlib.util, record_io as json, os, re, shlex, shutil, subprocess, sys
ROOT=Path(__file__).resolve().parents[1]
SPECS={
 'm4':dict(cc='arm-none-eabi-gcc',prefix='arm-none-eabi-',triple='arm-none-eabi',
   flags=['-mcpu=cortex-m4','-mthumb','-mfloat-abi=soft'],code='0x00000000',ram='0x20000000',
   qemu='qemu-system-arm',qargs=['-M','mps2-an386','-cpu','cortex-m4','-display','none','-monitor','none','-serial','stdio',
        '-semihosting-config','enable=on,target=native','-kernel']),
 'rv32':dict(cc='riscv64-unknown-elf-gcc',prefix='riscv64-unknown-elf-',triple='riscv64-unknown-elf',
   flags=['-march=rv32im','-mabi=ilp32','-mno-relax'],code='0x80000000',ram='0x80400000',
   qemu='qemu-system-riscv32',qargs=['-M','virt','-cpu','rv32','-smp','1','-m','128M','-bios','none',
        '-display','none','-monitor','none','-serial','stdio','-kernel'])
}

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def write(p,x):p.write_text(json.dumps(x,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
def module(path,name):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def sources():
    # Current source identity, never a historical-lock exception list.
    roots=('include','src/common','src/dsa_packed','src/kem','configs/hosted',
      'baselines/mlkem','build/adapted_mlkem','configs/pruned',
      'src/dsa_compact/build/sign_bitmap_stream_alias/adapted','targets','tests/targets')
    found={}
    for base in roots:
        for p in (ROOT/base).rglob('*'):
            if p.is_file() and p.suffix in ('.c','.h','.S','.s','.inc','.in','.py'):
                if p.is_symlink() or not p.resolve().is_relative_to(ROOT):raise ValueError('Indirect source')
                found[p.relative_to(ROOT).as_posix()]=sha(p)
    for rel in ['tools/build_targets.py','tools/pruning_sources.py','tools/operation_selection.py',
                'tools/size_variants.py','tools/build_variants.py','tools/binary_build_utils.py','tools/public_recipes.py','configs/recipes.xml']:found[rel]=sha(ROOT/rel)
    return found


def symbols(text):
    result={}
    for line in text.splitlines():
        row=line.split()
        if len(row)>=3:
            try:result[row[2]]=int(row[0],16)
            except ValueError:pass
    return result
def ledger(s):
    pairs={'code_and_rodata_load_bytes':('code_start','code_end'),
      'data_bytes':('data_start','data_end'),'bss_excluding_arena_io_stacks_bytes':('bss_start','bss_end'),
      'arena_reservation_with_guards_bytes':('arena_start','arena_end'),
      'caller_io_reservation_with_guards_bytes':('io_start','io_end'),
      'test_stack_reservation_bytes':('test_stack_bottom','test_stack_top'),
      'control_stack_reservation_bytes':('control_stack_bottom','control_stack_top'),
      'writable_image_span_bytes':('ram_start','ram_end')}
    result={k:s['__'+b]-s['__'+a] for k,(a,b) in pairs.items()}
    components=sum(result[k] for k in ('data_bytes','bss_excluding_arena_io_stacks_bytes',
      'arena_reservation_with_guards_bytes','caller_io_reservation_with_guards_bytes',
      'test_stack_reservation_bytes','control_stack_reservation_bytes'))
    result['alignment_gap_bytes']=result['writable_image_span_bytes']-components
    if result['alignment_gap_bytes']<0:raise ValueError('Overlapping RAM accounting')
    result['emulator_image_occupied_ram_bytes']=result['writable_image_span_bytes']+result['code_and_rodata_load_bytes']
    result['accounting_note']='Both chosen QEMU boards map code/RO in RAM. Writable reservation is not total physical image RAM or an MCU Flash claim. Initial data load copy is counted in the code region and its live copy in writable RAM.'
    return result

def validate_elf_layout(elf, values, syms_text):
    """Finite allocated-section ownership and alignment check on the real ELF."""
    from size_variants import binary_info
    image=binary_info(elf);regions=[]
    if image['format']!='ELF' or image['bits']!=32:raise ValueError('Actual ELF32 image required')
    for name in ('code','data','bss','arena','io','test_stack','control_stack'):
        begin=values['__'+name+('_bottom' if name.endswith('stack') else '_start')]
        end=values['__'+name+('_top' if name.endswith('stack') else '_end')]
        if end<begin:raise ValueError('Invalid image interval')
        if name!='code' and begin%32:raise ValueError('Misaligned image owner '+name)
        regions.append(dict(owner=name,start=begin,end=end,bytes=end-begin))
    for index,a in enumerate(regions):
        for b in regions[index+1:]:
            if a['bytes'] and b['bytes'] and not (a['end']<=b['start'] or b['end']<=a['start']):raise ValueError('Image owners overlap')
    sections=[s for s in image['sections'] if s['allocated'] and s['memory_bytes']]
    for section in sections:
        start=section['address'];end=start+section['memory_bytes']
        owners=[r['owner'] for r in regions if r['start']<=start and end<=r['end']]
        if len(owners)!=1:raise ValueError('Allocated section lacks one image owner: '+section['name'])
    names=set(symbols(syms_text))
    forbidden=names&{'malloc','calloc','realloc','free','sbrk','_sbrk','_malloc_r','_calloc_r'}
    if forbidden:raise ValueError('Unexpected target heap allocator')
    return dict(status='PASS',pointer_bits=32,regions=regions,allocated_sections=sections,
                heap_bytes=0,heap_allocator_symbols=[],pool_io_and_stacks_already_counted_in_writable_span=True,
                initial_data_load_and_live_copy_are_distinct=True)
def parse_run(text,expected_ledger,vector_manifest=None):
    records=[]
    for line in text.splitlines():
        if line.startswith('{'):records.append(json.loads(line))
    begin=[r for r in records if r.get('event')=='begin'];layout=[r for r in records if r.get('event')=='layout']
    summaries=[r for r in records if r.get('event')=='summary'];controls=[r for r in records if r.get('event')=='watermark_positive_control']
    cases=[r for r in records if r.get('event')=='case']
    if len(begin)!=1 or len(layout)!=1 or len(summaries)!=1 or len(controls)!=1:raise ValueError('Incomplete or repeated target run')
    if begin[0].get('rng')!='test_callback_only' or layout[0].get('pointer_bits')!=32:raise ValueError('Wrong target contract')
    if not controls[0].get('ok'):raise ValueError('Watermark positive control failed')
    if any(r.get('event')=='fatal' for r in records):raise ValueError('Target trapped')
    for k,v in expected_ledger.items():
        if k in layout[0] and layout[0][k]!=v:raise ValueError('ELF/target ledger mismatch '+k)
    requested=vector_manifest['cases'] if vector_manifest else [dict(parameter=p,operation=o,accepted=True) for p in (512,768,1024,44,65,87) for o in range(3)]+[dict(parameter=p,operation=2,accepted=False) for p in (44,65,87)]
    if vector_manifest and 'operation_mask' in vector_manifest:
        excluded=[r for r in records if r.get('event')=='excluded_operations']
        if len(excluded)!=1 or excluded[0].get('ok') is not True or excluded[0].get('cases')!=18-vector_manifest['operation_mask'].bit_count() or excluded[0].get('cross_algorithm_argument_cases')!=12:
            raise ValueError('Excluded operation interface check differs')
    expected_count=sum(5+2*(r['operation'] in (0,1)) if r['accepted'] else 1 for r in requested)
    if len(cases)!=expected_count or summaries[0].get('cases')!=expected_count or summaries[0].get('failures')!=0:raise ValueError('Coverage/failure count differs')
    seen=set()
    for r in cases:
        identity=(r['index'],r['kind'])
        if identity in seen or r.get('ok') is not True:raise ValueError('Duplicate/failed test case')
        seen.add(identity)
        if r['stack_watermark_bytes']>layout[0]['test_stack_reservation_bytes']-32:raise ValueError('Stack guard crossed')
    expected_cells={(r['parameter'],r['operation']) for r in requested if r['accepted']}
    for kind in ('acvp_positive','short_length','alias','workspace_exhaustion','recovery_after_errors'):
        if {(r['parameter'],r['operation']) for r in cases if r['kind']==kind}!=expected_cells:raise ValueError('Missing operation cells '+kind)
    for kind in ('rng_failure','missing_rng'):
        if {(r['parameter'],r['operation']) for r in cases if r['kind']==kind}!={(p,o) for p,o in expected_cells if o in (0,1)}:raise ValueError('Missing RNG cells')
    if {(r['parameter'],r['operation']) for r in cases if r['kind']=='acvp_negative'}!={(r['parameter'],r['operation']) for r in requested if not r['accepted']}:raise ValueError('Missing negative signatures')
    return {'status':'SUBSET_AND_BOUNDARY_CHECKS_PASSED','records':records,
      'watermark_interpretation':'Observed lower bound for these executions, including the call adapter. A5 collision and unvisited stack paths remain possible; the full reserved stack is counted in whole-image RAM.',
      'coverage':dict(positive_cells=len(expected_cells),negative_cases=sum(not r['accepted'] for r in requested),normal_boundary_and_recovery_cases=expected_count)}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--target',choices=list(SPECS),required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--cc');p.add_argument('--run',action='store_true')
    p.add_argument('--codec',type=int,choices=(0,1,2),default=1)
    p.add_argument('--parameters',default='all');p.add_argument('--operations')
    p.add_argument('--code-bytes',type=int,default=4194304);p.add_argument('--total-image-ram-bytes',type=int,default=8388608)
    p.add_argument('--profile',choices=('compact','rate','recompute'),default='compact')
    p.add_argument('--workspace-bytes',type=int,default=24576);p.add_argument('--stack-bytes',type=int,default=16384)
    p.add_argument('--control-stack-bytes',type=int,default=2048);p.add_argument('--ram-bytes',type=int,default=65536)
    p.add_argument('--timeout-seconds',type=int,default=900);a=p.parse_args();spec=SPECS[a.target]
    from pruning_sources import selected_parameters,public_source,kem_source,adapter_source
    from operation_selection import normalize,cells
    levels=selected_parameters(a.parameters);operations=normalize(a.operations,levels)
    selected=operations is not None or len(levels)!=6
    if not 1<=a.code_bytes<=4194304 or not 1<=a.total_image_ram_bytes<=134217728:raise ValueError('Invalid code or total image budget')
    out=a.output.resolve()
    if out.exists() or out==ROOT or out in ROOT.parents:raise ValueError('Use a new dedicated output directory')
    if os.name=='nt' and out.drive.upper()!='D:':raise ValueError('Windows output must stay on D:')
    for v in (a.workspace_bytes,a.stack_bytes,a.control_stack_bytes):
        if not 1024<=v<=1048576 or v%32:raise ValueError('RAM component must be a 32-byte multiple in 1024..1048576')
    if not 1024<=a.ram_bytes<=1048576:raise ValueError('Writable RAM budget outside supported region')
    cc=shutil.which(a.cc or spec['cc']);nm=shutil.which(spec['prefix']+'nm');size=shutil.which(spec['prefix']+'size')
    if not all((cc,nm,size)):raise ValueError('Compiler, nm and size are required')
    initial=sources();out.mkdir(parents=True);(out/'obj').mkdir();(out/'tmp').mkdir()
    env=os.environ.copy();env.update(TEMP=str(out/'tmp'),TMP=str(out/'tmp'),TMPDIR=str(out/'tmp'),PYTHONDONTWRITEBYTECODE='1')
    commands=[]
    def run(cmd,label,timeout=300):
        try:
            r=subprocess.run([str(x) for x in cmd],cwd=ROOT,env=env,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=timeout)
            text=r.stdout+r.stderr;rc=r.returncode
        except subprocess.TimeoutExpired as e:
            text=((e.stdout or b'').decode('utf-8',errors='replace') if isinstance(e.stdout,bytes) else e.stdout or '')+'\nTIMEOUT\n';rc=-999
        log=out/(label+'.txt');log.write_text(text,encoding='utf-8');commands.append({'argv':[str(x) for x in cmd],'exit_code':rc,'log':log.name,'log_sha256':sha(log)})
        write(out/'commands.xml',commands)
        if rc:raise RuntimeError(label+' failed with '+str(rc)+'; '+str(log))
        return text
    try:
        version=run([cc,'--version'],'compiler_version').splitlines()[0];triple=run([cc,'-dumpmachine'],'compiler_target').strip()
        if triple!=spec['triple']:raise ValueError('Unexpected target triple '+triple)
        if a.target=='rv32':
            target_options=run([cc,'--help=target'],'compiler_target_options')
            # Some cross-toolchain builds have no -misa-spec option.
            # If supported, select 2.2 explicitly, retaining the same IM ABI.
            if '-misa-spec' in target_options:spec['flags'].append('-misa-spec=2.2')
        multilib=run([cc,*spec['flags'],'-print-multi-directory'],'multilib').strip()
        if a.target=='rv32' and ('rv32' not in multilib or 'ilp32' not in multilib):raise ValueError('Not using a real RV32/ILP32 multilib')
        vectors=module(ROOT/'tests/targets/generate_vectors.py','target_vectors').generate(ROOT,out,cells(operations,levels))
        operation_mask=sum(1<<(3*(512,768,1024,44,65,87).index(level)+op) for level,op in cells(operations,levels))
        vectors['operation_mask']=operation_mask;write(out/'vectors.xml',vectors)
        linker=(ROOT/'targets/common/image.ld.in').read_text(encoding='utf-8')
        for k,v in {'CODE_BYTES':a.code_bytes,'TOTAL_IMAGE_RAM_BYTES':a.total_image_ram_bytes,'CODE_BASE':spec['code'],'RAM_BASE':spec['ram'],'RAM_BYTES':a.ram_bytes,'STACK_BYTES':a.stack_bytes,'CONTROL_STACK_BYTES':a.control_stack_bytes}.items():linker=linker.replace('@'+k+'@',str(v))
        (out/'image.ld').write_text(linker,encoding='ascii')
        common=[*spec['flags'],'-ffreestanding','-fno-builtin','-fno-unwind-tables','-fno-asynchronous-unwind-tables',
          '-I'+str(ROOT/'targets/include'),'-I'+str(ROOT/'include'),'-DLC_RNG_CALLBACK_ONLY=1','-DLC_DSA_W0_CODEC='+str(a.codec)]
        kemroot=ROOT/'build/adapted_mlkem'
        dsaroot=ROOT/'src/dsa_compact/build/sign_bitmap_stream_alias/adapted'
        dsaconfig=ROOT/'src/dsa_packed'
        common_opts=['-Os','-std=c11','-flto','-ffunction-sections','-fdata-sections',
          '-fstack-usage','-fno-omit-frame-pointer','-Wall','-Wextra']
        kflags=['-I'+str(ROOT/'configs/hosted'),'-I'+str(kemroot),'-I'+str(ROOT/'src/kem'),
          '-DMLK_CONFIG_FILE="mlkem_config.h"','-DLC_KEM_ROWS=1','-DLC_KEM_BATCH=1','-DLC_KEM_NOISE_CACHE=0']
        dflags=['-I'+str(dsaconfig),'-I'+str(dsaroot),'-DMLD_CONFIG_FILE="lc_dsa_config.h"',
          '-DMLD_CONFIG_REDUCE_RAM','-DLC_DSA_ALIAS_SIGN_CP=1','-DLC_DSA_ALIAS_VERIFY_TMP=1',
          '-DLC_DSA_STREAM_KEYGEN=1','-DLC_DSA_PACK_W0=1','-DLC_DSA_A_CACHE_POLYS=0',
          '-DLC_DSA_A_CACHE_SIGN_ONLY=0','-DLC_DSA_A_CACHE_BATCH4=0','-DLC_DSA_A_STREAM_BATCH4=0',
          '-DLC_DSA_S1_CACHE_POLYS=0','-DLC_DSA_RETAIN_FULL_HIGH=0']
        schedule=dict(inplace_sample=2 if a.profile!='compact' else 0,
          packed_accum=int(a.profile=='recompute'),fused_matrix=int(a.profile=='recompute'),
          stream_recompute=int(a.profile=='recompute'))
        dflags += ['-DLC_DSA_INPLACE_SAMPLE='+str(schedule['inplace_sample']),
          '-DLC_DSA_PACKED_ACCUM='+str(schedule['packed_accum']),
          '-DLC_DSA_FUSED_PACKED_MATRIX='+str(schedule['fused_matrix']),
          '-DLC_DSA_STREAM_RECOMPUTE='+str(schedule['stream_recompute'])]
        kem_entry=ROOT/'baselines/mlkem/all.c';dsa_entry=dsaconfig/'adapter.c';public_entry=ROOT/'src/common/public_api.c'
        generated_hashes={}
        if selected:
            common+=['-I'+str(ROOT/'configs/pruned'),'-I'+str(ROOT/'src/common')]
            generated=out/'generated';generated.mkdir()
            for name,body in {'kem.c':kem_source(ROOT,levels,operations),'adapter.c':adapter_source(dsa_entry,levels,operations),'public.c':public_source(ROOT,levels,operations)}.items():
                path=generated/name;path.write_text(body,encoding='utf-8');generated_hashes[path.relative_to(out).as_posix()]=sha(path)
            kem_entry=generated/'kem.c';dsa_entry=generated/'adapter.c';public_entry=generated/'public.c'
        units=[(kem_entry,kflags),(ROOT/'src/common/arena.c',[])]
        for i,level in enumerate(p for p in levels if p<100):
            units.append((dsaroot/'mldsa_native.c',dflags+['-DMLD_CONFIG_PARAMETER_SET='+str(level),
              '-DMLD_CONFIG_MULTILEVEL_'+('WITH_SHARED' if i==0 else 'NO_SHARED')]))
        units.extend([(dsa_entry,dflags),(public_entry,['-I'+str(dsaconfig)])])
        objs=[];used={}
        def dependencies(dep):
            raw=dep.read_text(encoding='utf-8').replace('\\\n',' ');tail=raw.split(': ',1)[1]
            names=re.split(r'(?<!\\)\s+',tail.strip()) if os.name=='nt' else shlex.split(tail)
            for name in names:
                q=Path(name.replace('\\ ',' '));q=q.resolve() if q.is_absolute() else (ROOT/q).resolve()
                if q.is_relative_to(ROOT):
                    rel=q.relative_to(ROOT).as_posix()
                    if initial.get(rel)!=sha(q):raise ValueError('Dependency outside current target source whitelist: '+rel)
                    used[rel]=sha(q)
                elif not q.is_relative_to(out):raise ValueError('Project dependency outside target/source roots')
        for i,(src,opts) in enumerate(units):
            obj=out/'obj'/f'{i:02}_{src.stem}.o';dep=obj.with_suffix('.d')
            run([cc,*common_opts,*opts,*common,'-MMD','-MF',dep,'-c',src,'-o',obj],f'compile_{i:02}')
            dependencies(dep);objs.append(obj)
        extra=[ROOT/'targets/common/runtime.c',ROOT/'targets/common/harness.c',ROOT/f'targets/{a.target}/platform.c',ROOT/f'targets/{a.target}/start.S']
        for i,src in enumerate(extra,len(units)):
            obj=out/'obj'/f'{i:02}_{src.stem}.o';opts=['-Os','-std=c11','-Wall','-Wextra','-ffunction-sections','-fdata-sections','-fstack-usage','-fomit-frame-pointer']
            # Keep the trampoline/runtime separate from LTO so their ABI and
            # stack switch cannot be silently inlined into the control stack.
            run([cc,*opts,*common,'-I'+str(ROOT/'targets/common'),'-I'+str(out),
                 '-DLC_TARGET_NAME="'+a.target+'"','-DLC_TARGET_WORKSPACE='+str(a.workspace_bytes),'-DLC_TARGET_OPERATION_MASK='+str(operation_mask),'-MMD','-MF',obj.with_suffix('.d'),'-c',src,'-o',obj],f'compile_{i:02}');dependencies(obj.with_suffix('.d'));objs.append(obj)
        elf=out/'latticecore.elf'
        run([cc,*spec['flags'],'-Os','-flto','-nostdlib','-nostartfiles','-Wl,--gc-sections',
             '-Wl,--build-id=none','-Wl,-Map,'+str(out/'latticecore.map'),'-T',out/'image.ld',*objs,'-lgcc','-o',elf],'link')
        syms=run([nm,'-n',elf],'symbols');run([size,'-A',elf],'sections');account=ledger(symbols(syms));write(out/'memory_ledger.xml',account)
        retained=set(symbols(syms));omitted=[]
        from operation_selection import names as operation_names
        for level in (512,768,1024,44,65,87):
            marker='lc_base_mlk'+str(level)+'_' if level>100 else 'lcbase'+str(level)+'_'
            if level not in levels:omitted += [name for name in retained if marker in name]
            elif operations is not None:
                for operation in operation_names(level):
                    if operation in operations[str(level)]:continue
                    stems=({'keypair':['keypair_derand'],'encaps':['enc_derand'],'decaps':['dec']} if level>100 else
                           {'keypair':['keypair_internal','keypair'],'sign':['signature_internal','signature'],'verify':['verify_internal','verify','verify_segments']})[operation]
                    omitted += [name for name in retained if any(re.match(re.escape(marker+stem)+r'(?:\.|$)',name) for stem in stems)]
        if omitted:raise ValueError('Excluded internal entities retained: '+str(omitted))
        layout=validate_elf_layout(elf,symbols(syms),syms);write(out/'layout_checks.xml',layout)
        if account['writable_image_span_bytes']>a.ram_bytes:raise ValueError('Linked image exceeds configured RAM')
        qcommand=[spec['qemu'],*spec['qargs'],str(elf)];checks=None;qversion=None
        if a.run:
            qemu=shutil.which(spec['qemu'])
            if not qemu:raise ValueError('QEMU not found')
            qversion=run([qemu,'--version'],'qemu_version').splitlines()[0]
            output=run([qemu,*qcommand[1:]],'qemu_console',a.timeout_seconds)
            checks=parse_run(output,account,vectors);write(out/'checks.xml',checks)
        if sources()!=initial:raise ValueError('Source changed during build/run')
        manifest={'schema':1,'status':'BUILD_AND_SUBSET_CHECKS_PASSED' if checks else 'BUILD_ONLY',
          'created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'target':a.target,'codec':a.codec,'parameters':levels,'operations':operations,'generated_source_hashes':generated_hashes,
          'compiler':version,'compiler_target':triple,'architecture_flags':spec['flags'],'multilib':multilib,'qemu':qversion,
          'source_recipe':'portable_'+a.profile,'source_sha256':initial,'actual_compiler_dependencies':used,
          'configuration':dict(kem_rows=1,kem_batch=1,w0_codec=a.codec,matrix_cache_polys=0,secret_prefix_polys=0,retain_full_high=0,stream_keygen=1,alias_verify_tmp=1,**schedule),
          'previous_results_inherited':False,'excluded_internal_entities':omitted,
          'elf_sha256':sha(elf),'map_sha256':sha(out/'latticecore.map'),'linker_sha256':sha(out/'image.ld'),
          'commands_sha256':sha(out/'commands.xml'),'vectors':vectors,'memory':account,'layout_checks_sha256':sha(out/'layout_checks.xml'),
          'qemu_command':qcommand,'qemu_timeout_seconds':a.timeout_seconds,'configured_writable_ram_bytes':a.ram_bytes,'configured_code_bytes':a.code_bytes,'configured_total_image_ram_bytes':a.total_image_ram_bytes,
          'checks_sha256':sha(out/'checks.xml') if checks else None,
          'scope':'Real core/public API. Functional subset, error recovery and observed stack watermark on emulated ISA. No host timing, physical cycles, board energy, WCET or exhaustive safety claims.',
          'formal_performance_collected':False}
        write(out/'build.xml',manifest);print(manifest['status'],a.target,'writable bytes',account['writable_image_span_bytes'],flush=True)
    except Exception as e:
        write(out/'failure.xml',{'status':'FAILED','error':str(e),'commands':commands});raise
if __name__=='__main__':main()
