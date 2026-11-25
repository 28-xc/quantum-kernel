"""R2 adaptation of the project's finite release-DLL timing screens.

prepare never samples timings. collect requires a preregistered manifest, a
completed oracle-only validation, and an explicit coordination token. It never
retries/deletes a failed or significant job. Existing files are preserved.
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
import argparse, hashlib, record_io as json, os, re, struct, subprocess, sys, datetime, shutil
import numpy as np

ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
GCC=Path('C:/msys64/mingw64/bin/gcc.exe')
NM=GCC.with_name('nm.exe')
SEEDS=[0xa127202609240101,0xa127202609240102,0xa127202609240103]
CHECKPOINTS=[10000,25000,50000,75000,100000]
N=100000
REGISTRY={
 'ntt':'lcbase_poly_ntt','intt':'lcbase_poly_invntt_tomont',
 'pw':'lcbase_poly_pointwise_montgomery',
 'k1':'lc_base_mlk_keccakf1600_permute',
 'k4':'lc_base_mlk_keccakf1600x4_permute',
 'update':'lc_sntt_update','crt':'lc_crt_product',
 'n3329':'lc_base_mlk_ntt_avx2_asm','r3329':'lc_base_mlk_reduce_avx2_asm',
 'c3329':'lc_base_mlk_poly_mulcache_compute_avx2_asm','q3329':'lc_base_mlk_qdata',
 'n769':'lc769_ntt_avx2_asm','r769':'lc769_reduce_avx2_asm',
 'c769':'lc769_poly_mulcache_compute_avx2_asm','q769':'lc769_qdata'}

def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def write(p,obj):Path(p).write_text(json.dumps(obj,indent=2,ensure_ascii=False,allow_nan=False)+'\n',encoding='utf-8')
def env():
    e=os.environ.copy();tmp=ROOT.parent/'tmp';tmp.mkdir(exist_ok=True);e['TEMP']=e['TMP']=str(tmp);return e
def command(cmd,dst):
    start=now();r=subprocess.run(list(map(str,cmd)),capture_output=True,text=True,env=env())
    record=dict(command=list(map(str,cmd)),start_utc=start,end_utc=now(),exit_code=r.returncode,stdout=r.stdout,stderr=r.stderr)
    write(dst,record)
    if r.returncode:raise RuntimeError(f'command failed; original log retained: {dst}')
    return r
def pe(p):
    b=p.read_bytes();o=struct.unpack_from('<I',b,60)[0]
    if b[o:o+4]!=b'PE\0\0':raise ValueError('not PE')
    ns=struct.unpack_from('<H',b,o+6)[0];osz=struct.unpack_from('<H',b,o+20)[0];opt=o+24
    if struct.unpack_from('<H',b,opt)[0]!=0x20b:raise ValueError('requires PE32+')
    base=struct.unpack_from('<Q',b,opt+24)[0];sections=[]
    for i in range(ns):
        s=opt+osz+i*40;size,va,rawsize,raw,flags=(*struct.unpack_from('<IIII',b,s+8),struct.unpack_from('<I',b,s+36)[0])
        sections.append(dict(name=b[s:s+8].split(b'\0')[0].decode(),rva=va,bytes=max(size,rawsize),flags=flags))
    return base,sections
def bind(dll,out):
    base,secs=pe(dll);r=command([NM,'--defined-only',dll],out/'nm.xml');syms={}
    for line in r.stdout.splitlines():
        m=re.match(r'^([0-9a-fA-F]+)\s+([a-zA-Z])\s+(\S+)$',line)
        if m:syms[m[3]]=(int(m[1],16),m[2])
    bindings={}
    for key,name in REGISTRY.items():
        if name not in syms:continue
        va,kind=syms[name];rva=va-base;sec=next((s for s in secs if s['rva']<=rva<s['rva']+s['bytes']),None)
        if not sec or (not key.startswith('q') and not sec['flags']&0x20000000):raise ValueError(f'invalid symbol {name}')
        abi='not_applicable_data' if key.startswith('q') else 'sysv_abi' if key[0] in 'nrc' and key not in ['ntt','crt'] else 'win64'
        bindings[key]=dict(symbol=name,rva=rva,kind=kind,section=sec['name'],abi=abi)
    (out/'bindings.txt').write_text(''.join(f'{key} {v["rva"]:x}\n' for key,v in bindings.items()),encoding='ascii')
    write(out/'bindings.xml',dict(dll_sha256=sha(dll),image_base=hex(base),symbols=bindings,sections=secs))
    return bindings
def prepare(args):
    # Compact configurations use q8380417 arithmetic; the separately built
    # throughput configuration also retains the reviewed small-prime helpers.
    global REGISTRY
    if args.speed_helpers and (args.only_keccak or args.keccak_family!='kem'):
        raise ValueError('Speed helper screen uses the full main protocol')
    if not args.speed_helpers:
        REGISTRY={k:v for k,v in REGISTRY.items() if k in ('ntt','intt','pw','k1','k4')}
    if args.keccak_family=='dsa':
        REGISTRY['k1']='lcbase_keccakf1600_permute'
        REGISTRY['k4']='lcbase_keccakf1600x4_permute'
    out=Path(args.output).resolve()
    if out.drive.upper()!='D:':raise ValueError('Windows evidence must remain on D:')
    out.mkdir(parents=True,exist_ok=False)
    dll=Path(args.dll).resolve();bindings=bind(dll,out)
    needed=('k1','k4') if args.only_keccak else ('ntt','intt','pw','k1','k4')
    if any(k not in bindings for k in needed):raise ValueError('Missing reviewed R2 private symbol; do not infer an address')
    shutil.copyfile(HERE/'screen.c',out/'screen.c');shutil.copyfile(__file__,out/'run.py')
    exe=out/'screen.exe';cmd=[GCC,'-O3','-std=c11','-Wall','-Wextra','-Wno-cast-function-type','-mavx2','-I'+str(ROOT/'include'),HERE/'screen.c','-o',exe]
    command(cmd,out/'build.xml')
    jobs=[]
    for mode in ([] if args.only_keccak else ['decaps_key','decaps_z','decaps_ct','decaps_pke_diagnostic']):
        for parameter in [512,768,1024]:
            for seed in SEEDS:jobs.append(dict(mode=mode,parameter=parameter,seed=seed,positive=False))
    for mode in ([] if args.only_keccak else ['ntt_eta','ntt_y','pointwise']):
        for parameter in [44,65,87]:
            for seed in SEEDS:jobs.append(dict(mode=mode,parameter=parameter,seed=seed,positive=False))
    for mode in ['keccak1','keccak4']:
        for seed in SEEDS:jobs.append(dict(mode=mode,parameter=44,seed=seed,positive=False))
    if args.speed_helpers:
        if not all(k in bindings for k in ['update','crt','n3329','r3329','c3329','q3329','n769','r769','c769','q769']):
            raise ValueError('Missing actual throughput helper binding')
        for mode in ['small_update','small_subtract','crt_product']:
            for parameter in [44,65,87]:
                for seed in SEEDS:jobs.append(dict(mode=mode,parameter=parameter,seed=seed,positive=False))
    controls=[('keccak1',44)] if args.only_keccak else [('decaps_z',768),('ntt_eta',65),('keccak1',44)]
    if args.speed_helpers:controls += [('small_update',65),('small_subtract',65),('crt_product',65)]
    for mode,parameter in controls:
        for seed in SEEDS:jobs.append(dict(mode=mode,parameter=parameter,seed=seed,positive=True))
    # Lock a reproducible shuffled JOB order; class order is independently
    # balanced and shuffled in each 1000-observation block by the C driver.
    order=np.random.Generator(np.random.PCG64(202609241723)).permutation(len(jobs))
    jobs=[dict(id=f'{i:03}',**jobs[int(k)]) for i,k in enumerate(order)]
    protocol=dict(schema='r2-release-timing-v1',created_utc=now(),dll=str(dll),dll_sha256=sha(dll),
       keccak_family=args.keccak_family,only_keccak=args.only_keccak,speed_helpers=args.speed_helpers,
       exe=str(exe),exe_sha256=sha(exe),source_sha256=sha(HERE/'screen.c'),runner_sha256=sha(__file__),bindings_sha256=sha(out/'bindings.txt'),
       samples_per_job=N,warmup=1000,class_assignment='500 per class per block; Fisher-Yates xorshift64 independent class stream',
       seeds=SEEDS,checkpoints=CHECKPOINTS,threshold_abs_t=4.5,statistics=['raw_mean','centered_second_moment'],
       no_outlier_trim=True,no_significance_early_stop=True,no_automatic_retry=True,
       input_families={
        'decaps_key':'one valid fixed serialized secret key vs 256 other valid generated serialized keys; same fixed random ciphertext; finite pool',
        'decaps_z':'same valid dk_PKE, ek and H(ek); fixed-even-first-byte z vs uniform 32-byte secret z; same fixed random ciphertext',
        'decaps_ct':'fixed valid ciphertext vs random ciphertext; fixed valid secret key; PUBLIC-INPUT diagnostic, not key secrecy test',
        'decaps_pke_diagnostic':'public ek/H(ek)/z fixed; class0 original dk_PKE, class1 independently sampled eta coefficients through FIPS203 NTT and canonical12bit packing; ARITHMETIC-DOMAIN-VALID but NOT claimed matching generated key pairs; attribution supplement only',
        'ntt_eta':'zero polynomial vs random secret coefficients uniformly in [-eta,eta]',
        'ntt_y':'zero polynomial vs random ephemeral coefficients in [-(gamma1-1),gamma1]',
        'pointwise':'zero operand vs uniform q-domain operand; same independent fixed second operand; in-place Montgomery product',
        'keccak1':'zero state vs uniform 200-byte secret state',
        'keccak4':'four zero states vs four uniform secret states, canonical sequential-state API',
        'small_update':'zero secret vs uniform eta secret; actual NTT/cache preparation precedes timer; fixed tau-sparse challenge, base=0, subtract=0, bound=gamma1-beta; retain norm result',
        'small_subtract':'zero secret vs uniform eta secret; fixed subtract=1 with actual out==base alias; fixed legal w0 base with first coefficient bound-1; bound=gamma2-beta; retain both norm outcomes',
        'crt_product':'zero t0 secret vs uniform t0 in [-4095,4096]; actual dual-prime caches and fixed tau-sparse challenge'},
       positive_control='inside measured wrapper: if SECRET-derived low bit is one, execute 4096 volatile LCG rounds; independent of class labels; original DLL unmodified',
       interpretation='Any |t|>=4.5 at any preregistered checkpoint/statistic flags investigation. Absence is finite screen only, not constant-time proof. No global familywise security probability claimed.',
       limits=['time observations may be autocorrelated','fixed/random key pool changes embedded public key too; detection needs attribution','no physical power/EM/fault test','no comprehensive microarchitectural attack proof','full signature retries are outside these kernel screens and must be assessed separately','This Windows PE/RDTSC implementation does not produce ARM timing evidence.','Fixed zero versus uniform eta/gamma1 is an arithmetic-domain input family, not a collection of valid encoded signing keys.'],jobs=jobs)
    protocol['input_families']={k:v for k,v in protocol['input_families'].items() if any(j['mode']==k for j in jobs)}
    write(out/'protocol.xml',protocol)
    write(out/'prepared.xml',dict(protocol_sha256=sha(out/'protocol.xml'),state='PREPARED_NOT_MEASURED',created_utc=now()))
    print(out/'protocol.xml')
def checked(out):
    p=json.loads((out/'protocol.xml').read_text(encoding='utf-8'))
    if sha(out/'protocol.xml')!=json.loads((out/'prepared.xml').read_text())['protocol_sha256']:raise ValueError('protocol changed')
    for k,h in [('dll','dll_sha256'),('exe','exe_sha256')]:
        if sha(p[k])!=p[h]:raise ValueError(f'{k} changed')
    if sha(out/'bindings.txt')!=p['bindings_sha256']:raise ValueError('bindings changed')
    if sha(out/'screen.c')!=p['source_sha256'] or sha(out/'run.py')!=p['runner_sha256']:raise ValueError('archived source changed')
    if sha(__file__)!=p['runner_sha256']:raise ValueError('Executing runner differs from frozen plan; prepare a new directory')
    return p
def validate(args):
    out=Path(args.output).resolve();p=checked(out);dst=out/'validation';dst.mkdir(exist_ok=False)
    seen=set();records=[]
    for job in p['jobs']:
        pair=job['mode'],job['parameter']
        if pair in seen:continue
        seen.add(pair);log=dst/f'{pair[0]}_{pair[1]}.xml'
        r=command([p['exe'],p['dll'],out/'bindings.txt',pair[0],pair[1],0,hex(SEEDS[0]),0,'UNUSED'],log)
        meta=json.loads(r.stdout)
        if meta.get('oracle')!='PASS' or meta.get('loaded_module_path_checked') is not True:raise ValueError('Loaded module/oracle not confirmed')
        records.append(dict(mode=pair[0],parameter=pair[1],metadata=meta,log_sha256=sha(log)))
    write(out/'validation.xml',dict(state='FUNCTIONAL_ORACLES_PASS_NOT_TIMED',protocol_sha256=sha(out/'protocol.xml'),records=records))
def statistics(path,p):
    a=np.loadtxt(path,delimiter=',',skiprows=1,dtype=np.float64)
    if a.shape!=(p['samples_per_job'],3) or not np.isfinite(a).all() or not np.isin(a[:,0],[0,1]).all() or not np.isin(a[:,2],[0,1]).all() or not (a[:,1]>=0).all():raise ValueError('invalid raw data')
    history=[]
    for n in p['checkpoints']:
        x=a[:n];center=x[:,1].mean()
        for name,z in [('raw_mean',x[:,1]),('centered_second_moment',(x[:,1]-center)**2)]:
            u=z[x[:,0]==0];v=z[x[:,0]==1];den=np.sqrt(u.var(ddof=1)/len(u)+v.var(ddof=1)/len(v))
            if len(u)!=n//2 or len(v)!=n//2:raise ValueError('unbalanced preregistered classes')
            if not den>0:raise ValueError('degenerate variance')
            t=float((u.mean()-v.mean())/den)
            history.append(dict(samples=n,statistic=name,welch_t=t,n0=len(u),n1=len(v),mean0=float(u.mean()),mean1=float(v.mean())))
    return dict(history=history,detected=any(abs(x['welch_t'])>=p['threshold_abs_t'] for x in history),raw_sha256=sha(path),retained_samples=len(a),norm_one_counts_by_class=[int(a[a[:,0]==c,2].sum()) for c in [0,1]])
def collect(args):
    out=Path(args.output).resolve();p=checked(out)
    if not args.token or not args.final_build_reviewed:raise ValueError('explicit exclusive coordination token and final source/ABI review acknowledgment required')
    if not (out/'validation.xml').exists():raise ValueError('functional validation required')
    val=json.loads((out/'validation.xml').read_text())
    if val['protocol_sha256']!=sha(out/'protocol.xml'):raise ValueError('validation mismatch')
    dest=out/'measurements';dest.mkdir(exist_ok=False)
    write(dest/'session.xml',dict(token=args.token,start_utc=now(),protocol_sha256=sha(out/'protocol.xml'),no_automatic_resume=True))
    records=[]
    for job in p['jobs']:
        checked(out);name=f'{job["id"]}_{job["mode"]}_{job["parameter"]}_{job["seed"]:x}_{int(job["positive"])}'
        raw=dest/(name+'.csv');log=dest/(name+'.xml')
        r=command([p['exe'],p['dll'],out/'bindings.txt',job['mode'],job['parameter'],p['samples_per_job'],hex(job['seed']),int(job['positive']),raw],log)
        checked(out);meta=json.loads(r.stdout)
        if meta.get('loaded_module_path_checked') is not True or meta.get('samples')!=p['samples_per_job'] or meta.get('mode')!=job['mode'] or meta.get('parameter')!=job['parameter']:raise ValueError('Driver observation identity differs from plan')
        record=dict(**job,metadata=meta,**statistics(raw,p),log_sha256=sha(log));records.append(record)
        write(dest/'progress.xml',records)
        print(name,'DETECTED' if record['detected'] else 'not_detected',flush=True)
    controls=[r for r in records if r['positive']];targets=[r for r in records if not r['positive']]
    state='INVESTIGATE' if any(r['detected'] for r in targets) else 'NO_DIFFERENCE_DETECTED_IN_REGISTERED_SCOPE'
    if not all(r['detected'] for r in controls):state='INVALID_POSITIVE_CONTROL'
    write(dest/'results.xml',dict(state=state,end_utc=now(),protocol_sha256=sha(out/'protocol.xml'),dll_sha256=p['dll_sha256'],records=records,not_constant_time_proof=True))
def main():
    ap=argparse.ArgumentParser();sub=ap.add_subparsers(dest='cmd',required=True)
    p=sub.add_parser('prepare');p.add_argument('--dll',required=True);p.add_argument('--output',required=True)
    p.add_argument('--keccak-family',choices=['kem','dsa'],default='kem');p.add_argument('--only-keccak',action='store_true')
    p.add_argument('--speed-helpers',action='store_true',help='Include actual small-prime/CRT entry points retained in the throughput package.')
    for name in ['validate','collect']:
        p=sub.add_parser(name);p.add_argument('--output',required=True)
        if name=='collect':p.add_argument('--token',required=True);p.add_argument('--final-build-reviewed',action='store_true')
    a=ap.parse_args();globals()[a.cmd](a)
if __name__=='__main__':main()
