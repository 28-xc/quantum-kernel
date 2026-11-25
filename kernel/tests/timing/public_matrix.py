"""Post-screen attribution; preserve all original INVESTIGATE results."""
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
import argparse, hashlib, importlib.util, record_io as json, math, shutil, struct
import numpy as np
HERE=Path(__file__).resolve().parent
r=None;ORIGINAL=None;OUT=None

def configure(original,out):
    global r,ORIGINAL,OUT
    ORIGINAL=Path(original).resolve();OUT=Path(out).resolve()
    spec=importlib.util.spec_from_file_location('archived_screen_runner',ORIGINAL/'run.py')
    r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)


def sample(rho,row,col):
    xof=hashlib.shake_128(rho+bytes([row,col]));length=504
    while True:
        b=xof.digest(length);values=[];proposals=0;pairs=0
        for pos in range(0,len(b),3):
            pairs+=1
            for v in [(b[pos]|b[pos+1]<<8)&4095,(b[pos+1]>>4)|(b[pos+2]<<4)]:
                proposals+=1
                if v<3329:values.append(v)
                if len(values)==256:break
            if len(values)==256:break
        if len(values)==256:return values,dict(proposals=proposals,pairs=pairs,squeeze_blocks=max(3,math.ceil(3*pairs/168)))
        length+=168
def matrix_schedule(k,batch,rows):
    result=[]
    for first in range(0,k,rows or k):
        count=min(rows or k,k-first)*k
        for i in range(0,count,batch):
            for lane in range(batch):
                idx=min(i+lane,count-1);result.append((first+idx//k,idx%k))
    return result

def prepare(args):
    OUT.mkdir(exist_ok=False,parents=True);p=r.checked(ORIGINAL)
    syms=json.loads((ORIGINAL/'nm.xml').read_text())['stdout'];name='lc_base_mlk_poly_rej_uniform'+('_x4' if args.sampler=='x4' else '')
    lines=[x for x in syms.splitlines() if x.split() and x.split()[-1]==name]
    if len(lines)!=1:raise ValueError('Need one exact actual sampler symbol')
    fields=lines[0].split();va=int(fields[0],16)
    linux=hasattr(r,'elf')
    if linux:
        size=int(fields[1],16);sections=r.elf(Path(p['dll']));rva=va
        if size<=0 or fields[2].lower()!='t' or not any(s['vaddr']<=va and va+size<=s['vaddr']+s['bytes'] and s['flags']&1 for s in sections):raise ValueError('Sampler not executable ELF code')
    else:
        base,sections=r.pe(Path(p['dll']));rva=va-base
        if not any(s['rva']<=rva<s['rva']+s['bytes'] and s['flags']&0x20000000 for s in sections):raise ValueError('Sampler not executable PE code')
    shutil.copyfile(HERE/'public_matrix.c',OUT/'public_matrix.c');shutil.copyfile(__file__,OUT/'public_matrix.py')
    shutil.copyfile(ORIGINAL/'screen.c',OUT/'archived_screen.c')
    header=ORIGINAL/'latticecore.h'
    if not header.exists():
        if not args.source_root:raise ValueError('Original has no archived header; explicit frozen --source-root is required')
        header=Path(args.source_root)/'include/latticecore.h'
    if p.get('public_header_sha256') and r.sha(header)!=p['public_header_sha256']:raise ValueError('Original public header identity differs')
    shutil.copyfile(header,OUT/'latticecore.h')
    exe=OUT/('public_matrix' if linux else 'public_matrix.exe')
    cc=args.cc or str(r.GCC)
    batch=4 if args.sampler=='x4' else 1
    if args.matrix_rows not in [0,1,2,3,4]:raise ValueError('Invalid explicit matrix row grouping')
    r.command([cc,'-O3','-std=c11','-Wall','-Wextra','-Wno-cast-function-type',*(['-mavx2'] if not linux else []),'-DLC_ATTRIBUTION_BATCH='+str(batch),'-DLC_ATTRIBUTION_ROWS='+str(args.matrix_rows),'-I'+str(OUT),OUT/'public_matrix.c',*(['-ldl'] if linux else []),'-o',exe],OUT/'build.xml')
    original_results=json.loads((ORIGINAL/'measurements/results.xml').read_text())
    originals=[x for x in original_results['records'] if x['mode']=='decaps_key' and not x['positive']]
    originals.sort(key=lambda x:(x['parameter'],x['seed']))
    expected={(param,seed) for param in [512,768,1024] for seed in p['seeds']}
    if len(originals)!=9 or {(x['parameter'],x['seed']) for x in originals}!=expected:raise ValueError('Complete original 3x3 key-pool records required')
    jobs=[];validation=[]
    for job in originals:
        level=job['parameter'];seed=job['seed'];label=f'{level}_{seed:x}';prefix=OUT/f'oracle_{label}'
        z=r.command([exe,p['dll'],hex(rva),level,0,hex(seed),prefix,p.get('cpu',-1)],OUT/f'oracle_{label}.xml')
        rhos=Path(str(prefix)+'.rhos.bin').read_bytes();polys=np.fromfile(str(prefix)+'.polys.bin',dtype='<i2');k={512:2,768:3,1024:4}[level]
        schedule=matrix_schedule(k,batch,args.matrix_rows)
        if len(rhos)!=257*32 or len(polys)!=257*len(schedule)*256:raise ValueError('oracle dimensions')
        counts=[]
        for index in range(257):
            total=dict(proposals=0,pairs=0,squeeze_blocks=0)
            for slot,(row,col) in enumerate(schedule):
                expected,c=sample(rhos[32*index:32*index+32],row,col);offset=(index*len(schedule)+slot)*256
                if not np.array_equal(polys[offset:offset+256],expected):raise ValueError('SHAKE128 SampleNTT oracle mismatch, including repeated lane')
                for key in total:total[key]+=c[key]
            counts.append(total)
        r.write(OUT/f'counts_{label}.xml',dict(public_rhos_sha256=r.sha(str(prefix)+'.rhos.bin'),counts=counts,
            fixed=counts[0],random_pool_mean={key:float(np.mean([v[key] for v in counts[1:]])) for key in counts[0]}))
        validation.append(dict(parameter=level,seed=seed,polynomials=257*len(schedule),distinct_matrix_entries=k*k,scheduled_lanes=len(schedule),lane_indices=schedule,oracle='PASS',rhos_sha256=r.sha(str(prefix)+'.rhos.bin'),polynomials_sha256=r.sha(str(prefix)+'.polys.bin')))
        jobs.append(dict(parameter=level,seed=seed,expected_original_input_fnv64=job['metadata']['input_fnv64'],original_record_id=job['id'],original_detected=job['detected']))
    # This registration is AFTER observation of original flags and BEFORE the new
    # diagnostic timing; it is explicitly an attribution experiment.
    protocol=dict(schema='r2-public-attribution-v1',created_utc=r.now(),dll=p['dll'],dll_sha256=p['dll_sha256'],
       exe=str(exe),exe_sha256=r.sha(exe),source_sha256=r.sha(HERE/'public_matrix.c'),base_driver_sha256=r.sha(ORIGINAL/'screen.c'),
       original_protocol_sha256=r.sha(ORIGINAL/'protocol.xml'),original_result_sha256=r.sha(ORIGINAL/'measurements/results.xml'),
       grouping_source={'sha256':r.sha(args.grouping_source),'filename':Path(args.grouping_source).name} if args.grouping_source else None,
       original_directory=str(ORIGINAL),sampler=args.sampler,matrix_rows=args.matrix_rows,grouping=args.grouping_scope,sampler_symbol=name,sampler_rva=rva,abi='aapcs64' if linux else 'win64',cpu=p.get('cpu',-1),timer_unit='ns' if linux else 'TSC ticks',samples_per_job=100000,warmup=1000,
       runner_sha256=r.sha(__file__),archived_header_sha256=r.sha(OUT/'latticecore.h'),header_binding='original protocol hash' if p.get('public_header_sha256') else 'explicit diagnostic frozen source, functional ABI revalidated',
       checkpoints=r.CHECKPOINTS,threshold_abs_t=4.5,statistics=['raw_mean','centered_second_moment'],
       complete_original_seed_set=True,original_key_class_schedule_replayed=True,secret_input_to_timed_region=False,
       no_outlier_trim=True,no_early_stop=True,no_retry=True,
       hypothesis='The same original key-pool classes also change the PUBLIC matrix sampling path; evaluate this exact release-DLL path alone, retaining every original result.',
       interpretation='Does not replace original findings; public-only detection and sampler branch review can explain public-input timing, not prove absence of all key leakage.',
       jobs=jobs)
    r.write(OUT/'protocol.xml',protocol);r.write(OUT/'prepared.xml',dict(protocol_sha256=r.sha(OUT/'protocol.xml'),state='ORACLE_VALIDATED_NOT_TIMED',validation=validation))
    # Archive the actual sampler machine code; no guessed static helper name.
    objdump=args.objdump or (str(Path(cc).with_name('objdump.exe')) if not linux else 'objdump')
    result=r.command([objdump,'-d',*(['-M','intel'] if not linux else []),'--disassemble='+name,p['dll']],OUT/'sampler-disassembly-command.xml')
    (OUT/'sampler.asm').write_text(json.capture_text(result.stdout),encoding='utf-8')
    print('PUBLIC_ATTRIBUTION_READY',len(jobs),'jobs; oracle polynomials',sum(x['polynomials'] for x in validation))

def collect(token):
    p=json.loads((OUT/'protocol.xml').read_text());prep=json.loads((OUT/'prepared.xml').read_text())
    if r.sha(OUT/'protocol.xml')!=prep['protocol_sha256']:raise ValueError('protocol changed')
    if r.sha(p['dll'])!=p['dll_sha256'] or r.sha(p['exe'])!=p['exe_sha256']:raise ValueError('artifact changed')
    if r.sha(__file__)!=p['runner_sha256'] or r.sha(OUT/'public_matrix.c')!=p['source_sha256'] or r.sha(OUT/'archived_screen.c')!=p['base_driver_sha256'] or r.sha(OUT/'latticecore.h')!=p['archived_header_sha256']:raise ValueError('Attribution source/header changed')
    if r.sha(ORIGINAL/'protocol.xml')!=p['original_protocol_sha256'] or r.sha(ORIGINAL/'measurements/results.xml')!=p['original_result_sha256']:raise ValueError('Original investigation changed')
    dest=OUT/'measurements';dest.mkdir(exist_ok=False);r.write(dest/'session.xml',dict(token=token,start_utc=r.now(),protocol_sha256=r.sha(OUT/'protocol.xml')))
    records=[]
    orig_records=json.loads((ORIGINAL/'measurements/results.xml').read_text())['records']
    for job in p['jobs']:
        label=f'{job["parameter"]}_{job["seed"]:x}';prefix=dest/label
        proc=r.command([p['exe'],p['dll'],hex(p['sampler_rva']),job['parameter'],100000,hex(job['seed']),prefix,p['cpu']],dest/(label+'.xml'))
        meta=json.loads(proc.stdout)
        if meta.get('loaded_module_path_checked') is not True:raise ValueError('Actual loaded module unchecked')
        if meta['input_fnv64']!=job['expected_original_input_fnv64']:raise ValueError('original key-input replay mismatch')
        orig=next(x for x in orig_records if x['id']==job['original_record_id'])
        matches=list((ORIGINAL/'measurements').glob(job['original_record_id']+'_*.csv'))
        if len(matches)!=1:raise ValueError('Original raw identity ambiguous')
        orig_raw=matches[0]
        if r.sha(orig_raw)!=orig['raw_sha256']:raise ValueError('Original raw observations changed')
        a=np.loadtxt(str(prefix)+'.csv',delimiter=',',skiprows=1);b=np.loadtxt(orig_raw,delimiter=',',skiprows=1)
        if a.shape!=(100000,3) or b.shape!=(100000,3):raise ValueError('Incomplete raw pair')
        if not np.array_equal(a[:,0],b[:,0]):raise ValueError('class order differs')
        rhos=Path(str(prefix)+'.rhos.bin');expected=next(v for v in prep['validation'] if v['parameter']==job['parameter'] and v['seed']==job['seed'])
        if r.sha(rhos)!=expected['rhos_sha256']:raise ValueError('public rho pool changed')
        counts=json.loads((OUT/f'counts_{label}.xml').read_text())['counts'];indices=np.fromfile(str(prefix)+'.keyidx.bin',dtype='<u2')
        if len(indices)!=100000 or not np.array_equal(indices==0,a[:,0]==0):raise ValueError('key-index mapping mismatch')
        counter_comparison={key:[float(np.mean([counts[int(i)][key] for i in indices[a[:,0]==c]])) for c in [0,1]] for key in counts[0]}
        stats=r.statistics(Path(str(prefix)+'.csv'),p)
        result=dict(**job,**stats,metadata=meta,original_history=orig['history'],public_operation_counts_by_class=counter_comparison,
                    identical_original_classes=True,identical_original_key_inputs=True)
        records.append(result);r.write(dest/'progress.xml',records);print(label,stats['detected'],flush=True)
        if r.sha(p['dll'])!=p['dll_sha256']:raise ValueError('DLL changed')
    r.write(dest/'results.xml',dict(state='PUBLIC_PATH_ATTRIBUTION_COMPLETED_REVIEW_REQUIRED',records=records,original_investigation_preserved=True,end_utc=r.now()))
if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('action',choices=['prepare','collect']);ap.add_argument('--original',required=True);ap.add_argument('--output',required=True);ap.add_argument('--source-root');ap.add_argument('--cc');ap.add_argument('--objdump');ap.add_argument('--token');ap.add_argument('--sampler',choices=['x1','x4'],default='x1');ap.add_argument('--matrix-rows',type=int,default=0);ap.add_argument('--grouping-source');ap.add_argument('--grouping-scope',default='public sampler subpath; not a claim of complete production matrix cost');args=ap.parse_args()
    configure(args.original,args.output)
    if args.action=='prepare':prepare(args)
    else:
        if not args.token:raise ValueError('coordination token required')
        collect(args.token)
