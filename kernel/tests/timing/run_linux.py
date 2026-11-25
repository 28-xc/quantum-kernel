"""Linux/AArch64 port of the finite actual-library timing screens.

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
GCC=Path(shutil.which('gcc') or 'gcc')
NM=Path(shutil.which('nm') or 'nm')
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
    e=os.environ.copy();tmp=HERE/'tmp';tmp.mkdir(exist_ok=True);e['TEMP']=e['TMP']=e['TMPDIR']=str(tmp);e['PYTHONDONTWRITEBYTECODE']='1';return e
def command(cmd,dst):
    start=now();r=subprocess.run(list(map(str,cmd)),capture_output=True,text=True,env=env())
    record=dict(command=list(map(str,cmd)),start_utc=start,end_utc=now(),exit_code=r.returncode,stdout=r.stdout,stderr=r.stderr)
    write(dst,record)
    if r.returncode:raise RuntimeError(f'command failed; original log retained: {dst}')
    return r
def elf(p):
    b=p.read_bytes()
    if b[:6]!=b'\x7fELF\x02\x01' or struct.unpack_from('<H',b,16)[0]!=3 or struct.unpack_from('<H',b,18)[0]!=183:
        raise ValueError('Requires little-endian ELF64 ET_DYN AArch64')
    phoff=struct.unpack_from('<Q',b,32)[0];ents,count=struct.unpack_from('<HH',b,54);segments=[]
    if ents!=56 or phoff+ents*count>len(b):raise ValueError('Invalid program header table')
    for i in range(count):
        kind,flags,offset,vaddr,paddr,filesz,memsz,align=struct.unpack_from('<IIQQQQQQ',b,phoff+i*ents)
        if kind==1:
            if filesz>memsz or offset+filesz>len(b):raise ValueError('Invalid load extent')
            segments.append(dict(vaddr=vaddr,bytes=memsz,file_bytes=filesz,flags=flags))
    return segments

def bind(dll,out):
    segments=elf(dll);r=command([NM,'-S','--defined-only',dll],out/'nm.xml');syms={}
    for line in r.stdout.splitlines():
        m=re.match(r'^([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([a-zA-Z])\s+(\S+)$',line)
        if m:
            if m[4] in syms and m[4] in REGISTRY.values():raise ValueError('Duplicate requested symbol')
            syms[m[4]]=(int(m[1],16),int(m[2],16),m[3])
    bindings={}
    for key,name in REGISTRY.items():
        if name not in syms:continue
        value,size,kind=syms[name]
        segment=next((s for s in segments if s['vaddr']<=value and value+size<=s['vaddr']+s['bytes'] and s['flags']&1),None)
        if not size or kind.lower()!='t' or not segment:raise ValueError('Symbol is not within executable PT_LOAD: '+name)
        bindings[key]=dict(symbol=name,elf_value=value,bytes=size,kind=kind,abi='AAPCS64',load_segment=segment)
    (out/'bindings.txt').write_text(''.join(f'{key} {v["elf_value"]:x}\n' for key,v in bindings.items()),encoding='ascii')
    write(out/'bindings.xml',dict(elf_sha256=sha(dll),symbols=bindings,load_segments=segments,address_rule='Runtime dlinfo load bias plus verified st_value; dladdr/realpath actual object check for every private address'))
    return bindings

def prepare(args):
    # R2 uses the ordinary q8380417 secret arithmetic, not the old v1
    # small-prime/CRT candidate. Keep only reviewed R2 symbol interfaces.
    global REGISTRY,ROOT
    ROOT=Path(args.source_root).resolve()
    if not (ROOT/'include/latticecore.h').is_file():raise ValueError('Missing explicit project include source')
    REGISTRY={k:v for k,v in REGISTRY.items() if k in ('ntt','intt','pw','k1','k4')}
    if args.keccak_family=='dsa':
        REGISTRY['k1']='lcbase_keccakf1600_permute'
        REGISTRY['k4']='lcbase_keccakf1600x4_permute'
    out=Path(args.output).resolve()
    if sys.platform!='linux' or os.uname().machine!='aarch64':raise ValueError('Only execute on Linux AArch64')
    out.mkdir(parents=True,exist_ok=False)
    if args.cpu<0:raise ValueError('Invalid CPU')
    dll=Path(args.dll).resolve();bindings=bind(dll,out)
    needed=('k1','k4') if args.only_keccak else ('ntt','intt','pw','k1','k4')
    if any(k not in bindings for k in needed):raise ValueError('Missing reviewed R2 private symbol; do not infer an address')
    shutil.copyfile(HERE/'screen_linux.c',out/'screen.c');shutil.copyfile(__file__,out/'run.py')
    shutil.copyfile(ROOT/'include/latticecore.h',out/'latticecore.h')
    exe=out/'screen';cmd=[GCC,'-O3','-std=c11','-Wall','-Wextra','-Wno-cast-function-type','-I'+str(ROOT/'include'),HERE/'screen_linux.c','-ldl','-o',exe]
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
    for mode,parameter in ([('keccak1',44)] if args.only_keccak else [('decaps_z',768),('ntt_eta',65),('keccak1',44)]):
        for seed in SEEDS:jobs.append(dict(mode=mode,parameter=parameter,seed=seed,positive=True))
    # Lock a reproducible shuffled JOB order; class order is independently
    # balanced and shuffled in each 1000-observation block by the C driver.
    order=np.random.Generator(np.random.PCG64(202609241723)).permutation(len(jobs))
    jobs=[dict(id=f'{i:03}',**jobs[int(k)]) for i,k in enumerate(order)]
    protocol=dict(schema='r2-linux-elf-timing-v1',created_utc=now(),dll=str(dll),dll_sha256=sha(dll),
       cpu=args.cpu,timer='CLOCK_MONOTONIC_RAW',timer_unit='ns',ordering='dsb ish + isb before and after each clock read',
       public_header_sha256=sha(ROOT/'include/latticecore.h'),
       keccak_family=args.keccak_family,only_keccak=args.only_keccak,
       exe=str(exe),exe_sha256=sha(exe),source_sha256=sha(HERE/'screen_linux.c'),runner_sha256=sha(__file__),bindings_sha256=sha(out/'bindings.txt'),
       samples_per_job=N,warmup=1000,class_assignment='500 per class per block; Fisher-Yates xorshift64 independent class stream',
       seeds=SEEDS,checkpoints=CHECKPOINTS,threshold_abs_t=4.5,statistics=['raw_mean','centered_second_moment'],
       no_outlier_trim=True,no_significance_early_stop=True,no_automatic_retry=True,
       raw_persistence='Header before warmup; completed 1000-sample blocks flushed; operation failure saves current measured prefix and error log, then stops without retry',
       input_families={
        'decaps_key':'one valid fixed serialized secret key vs 256 other valid generated serialized keys; same fixed random ciphertext; finite pool',
        'decaps_z':'same valid dk_PKE, ek and H(ek); fixed-even-first-byte z vs uniform 32-byte secret z; same fixed random ciphertext',
        'decaps_ct':'fixed valid ciphertext vs random ciphertext; fixed valid secret key; PUBLIC-INPUT diagnostic, not key secrecy test',
        'decaps_pke_diagnostic':'public ek/H(ek)/z fixed; class0 original dk_PKE, class1 independently sampled eta coefficients through FIPS203 NTT and canonical12bit packing; ARITHMETIC-DOMAIN-VALID but NOT claimed matching generated key pairs; attribution supplement only',
        'ntt_eta':'zero polynomial vs random secret coefficients uniformly in [-eta,eta]',
        'ntt_y':'zero polynomial vs random ephemeral coefficients in [-(gamma1-1),gamma1]',
        'pointwise':'zero operand vs uniform q-domain operand; same independent fixed second operand; in-place Montgomery product',
        'keccak1':'zero state vs uniform 200-byte secret state',
        'keccak4':'four zero states vs four uniform secret states, canonical sequential-state API'},
       positive_control='inside measured wrapper: if SECRET-derived low bit is one, execute 4096 volatile LCG rounds; independent of class labels; original DLL unmodified',
       interpretation='Any |t|>=4.5 at any preregistered checkpoint/statistic flags investigation. Absence is finite screen only, not constant-time proof. No global familywise security probability claimed.',
       limits=['time observations may be autocorrelated','fixed/random key pool changes embedded public key too; detection needs attribution','no physical power/EM/fault test','no comprehensive microarchitectural attack proof','full signature retries are outside these kernel screens and must be assessed separately','Linux/AArch64 ELF-only; clock nanoseconds are not CPU cycles and the timer wrapper adds overhead.','Fixed zero versus uniform eta/gamma1 is an arithmetic-domain input family, not a collection of valid encoded signing keys.'],jobs=jobs)
    protocol['input_families']={k:v for k,v in protocol['input_families'].items() if any(j['mode']==k for j in jobs)}
    write(out/'protocol.xml',protocol)
    write(out/'prepared.xml',dict(protocol_sha256=sha(out/'protocol.xml'),state='PREPARED_NOT_MEASURED',created_utc=now()))
    print(out/'protocol.xml')
def checked(out):
    p=json.loads((out/'protocol.xml').read_text(encoding='utf-8'))
    if sha(out/'protocol.xml')!=json.loads((out/'prepared.xml').read_text())['protocol_sha256']:raise ValueError('protocol changed')
    if sha(out/'latticecore.h')!=p['public_header_sha256']:raise ValueError('Archived public header changed')
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
        r=command([p['exe'],p['dll'],out/'bindings.txt',pair[0],pair[1],0,hex(SEEDS[0]),0,'UNUSED',p['cpu']],log)
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
        r=command([p['exe'],p['dll'],out/'bindings.txt',job['mode'],job['parameter'],p['samples_per_job'],hex(job['seed']),int(job['positive']),raw,p['cpu']],log)
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
    p.add_argument('--source-root',required=True);p.add_argument('--cpu',type=int,default=2)
    for name in ['validate','collect']:
        p=sub.add_parser(name);p.add_argument('--output',required=True)
        if name=='collect':p.add_argument('--token',required=True);p.add_argument('--final-build-reviewed',action='store_true')
    a=ap.parse_args();globals()[a.cmd](a)
if __name__=='__main__':main()
