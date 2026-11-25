"""Replay the pinned applicable ML-KEM and ML-DSA published vector files.

Each file runs in a separate bounded process. External-mu and malformed seed
import cases are enumerated separately because these entry points are absent
from the eight-function public API. No generated mutation campaign is used.
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
import argparse, collections, ctypes as C, hashlib, importlib.util, record_io as json, os, subprocess, sys
ROOT=Path(__file__).resolve().parents[2]
sp=importlib.util.spec_from_file_location('public_abi',ROOT/'tests/platform/compare_public.py')
abi=importlib.util.module_from_spec(sp);sp.loader.exec_module(abi)
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def read(p):return json.loads(Path(p).read_text(encoding='utf-8'))
def write(p,x):Path(p).write_text(json.dumps(x,indent=2)+'\n',encoding='utf-8')
class Buffer:
    def __init__(self,x):
        self.n=x if isinstance(x,int) else len(x);self.raw=(abi.U*(self.n+64))();C.memset(self.raw,0xa5,len(self.raw))
        self.p=C.cast(C.byref(self.raw,32),abi.P)
        if not isinstance(x,int):C.memmove(self.p,x,self.n)
    def value(self):return C.string_at(self.p,self.n)
    def guards(self):return bytes(self.raw[:32])==b'\xa5'*32 and bytes(self.raw[32+self.n:])==b'\xa5'*32
def run_file(a):
    corpus=read(a.vector);lib=abi.library(a.library.resolve());level=int(a.vector.name.split('_')[1]);size=abi.Sizes()
    assert lib.lc_get_sizes(level,C.byref(size))==0
    arena=(abi.U*(a.workspace+128))();address=(C.addressof(arena)+63)&~31;ctx=abi.Context();entropy=[b'',0];rows=[]
    @abi.RANDOM
    def rng(user,out,n):
        seed,pos=entropy
        if n>len(seed)-pos:return -1
        C.memmove(out,seed[pos:pos+n],n);entropy[1]+=n;return 0
    for gi,g in enumerate(corpus['testGroups']):
        for t in g['tests']:
            row=dict(file=a.vector.name,group=gi,tcId=t['tcId'],expected=t['result'],flags=t.get('flags',[]))
            write(a.output.with_suffix('.progress.xml'),row)
            objects=[]
            def buffer(b):
                x=Buffer(b);objects.append(x);return x
            def hb(b):return buffer(bytes.fromhex(b))
            C.memset(arena,0xa5,len(arena));C.memset(address,0,a.workspace)
            assert lib.lc_context_init(C.byref(ctx),address,a.workspace,rng,None)==0
            valid=t['result']=='valid';rc=None;ok=False;pk=None;sk=None
            if 'Internal' in t.get('flags',[]) or ('mldsa' in a.vector.name and 'msg' not in t):
                row.update(status='OUTSIDE_PUBLIC_API',reason='external_mu_entry');rows.append(row);continue
            seedhex=g.get('privateSeed',t.get('seed'))
            if seedhex is not None:
                seed=bytes.fromhex(seedhex);needed=64 if level>100 else 32
                if len(seed)!=needed:
                    row.update(status='OUTSIDE_PUBLIC_API',reason='seed_import_length_entry');rows.append(row);continue
                pk=buffer(size.public_key);sk=buffer(size.secret_key);entropy[:]=[seed,0]
                assert lib.lc_keypair(C.byref(ctx),level,pk.p,pk.n,sk.p,sk.n)==0
                if g.get('publicKey'):assert pk.value()==bytes.fromhex(g['publicKey'])
                if t.get('ek'):assert pk.value()==bytes.fromhex(t['ek'])
                if t.get('dk'):assert sk.value()==bytes.fromhex(t['dk'])
            if level>100:
                if 'keygen_seed' in a.vector.name:rc=0;ok=valid
                elif 'encaps' in a.vector.name:
                    pk=hb(t['ek']);ct=buffer(size.ciphertext);ss=buffer(32);entropy[:]=[bytes.fromhex(t['m']),0]
                    rc=lib.lc_encaps(C.byref(ctx),level,ct.p,ct.n,ss.p,32,pk.p,pk.n)
                    ok=(rc==0 and ct.value()==bytes.fromhex(t['c']) and ss.value()==bytes.fromhex(t['K'])) if valid else rc in (-1,-2,-6)
                else:
                    if sk is None:sk=hb(t['dk'])
                    ct=hb(t['c']);ss=buffer(32)
                    rc=lib.lc_decaps(C.byref(ctx),level,ss.p,32,ct.p,ct.n,sk.p,sk.n)
                    ok=(rc==0 and ss.value()==bytes.fromhex(t['K'])) if valid else rc in (-1,-2,-6)
            else:
                msg=hb(t['msg']);domain=hb(t.get('ctx',''));pub=hb(g['publicKey']) if g.get('publicKey') is not None else None
                if 'verify' in a.vector.name:
                    sig=hb(t['sig']);rc=lib.lc_verify(C.byref(ctx),level,sig.p,sig.n,msg.p,msg.n,domain.p,domain.n,pub.p,pub.n)
                    ok=(rc==0) if valid else rc in (-1,-2,-6)
                else:
                    if sk is None:sk=hb(g['privateKey'])
                    sig=buffer(size.signature);entropy[:]=[bytes.fromhex(t.get('rnd','00'*32)),0]
                    rc=lib.lc_sign(C.byref(ctx),level,sig.p,sig.n,msg.p,msg.n,domain.p,domain.n,sk.p,sk.n)
                    ok=(rc==0 and sig.value()==bytes.fromhex(t['sig'])) if valid else rc in (-1,-2,-6)
                    if valid and ok:ok=lib.lc_verify(C.byref(ctx),level,sig.p,sig.n,msg.p,msg.n,domain.p,domain.n,pub.p,pub.n)==0
            guards=all(x.guards()for x in objects) and C.string_at(address-32,32)==b'\xa5'*32 and C.string_at(address+a.workspace,32)==b'\xa5'*32
            erased=ctx.arena_high_water<=a.workspace and C.string_at(address,ctx.arena_high_water)==bytes(ctx.arena_high_water)
            row.update(status='PASS' if ok and guards and erased else 'FAIL',actual_status=rc,guards_preserved=guards,used_workspace_erased=erased,workspace_highwater=ctx.arena_high_water)
            rows.append(row)
    assert len(rows)==corpus['numberOfTests']
    counts=dict(collections.Counter(x['status']for x in rows))
    result=dict(status='FAIL' if counts.get('FAIL') else 'PASS',vector_sha256=sha(a.vector),library_sha256=sha(a.library),test_sha256=sha(__file__),published_cases=corpus['numberOfTests'],counts=counts,records=rows)
    write(a.output,result);return 1 if counts.get('FAIL') else 0
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True)
    p.add_argument('--vectors',type=Path,default=ROOT/'tests/vectors/wycheproof');p.add_argument('--workspace',type=int,required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--vector',type=Path);a=p.parse_args()
    assert 32<=a.workspace<=262144 and not a.output.exists()
    if a.vector:return run_file(a)
    a.output.mkdir(parents=True);lock=read(a.vectors/'vectors.lock.xml')
    for x in lock['files']:assert sha(a.vectors/x['path'])==x['sha256']
    rows=[];totals=collections.Counter()
    for f in sorted((a.vectors/'testvectors_v1').glob('*.xml')):
        dest=a.output/f.name;cmd=[sys.executable,'-B',__file__,'--library',str(a.library.resolve()),'--workspace',str(a.workspace),'--vector',str(f.resolve()),'--output',str(dest.resolve())]
        try:
            proc=subprocess.run(cmd,capture_output=True,text=True,encoding='utf-8',timeout=120);code=proc.returncode;log=proc.stdout+proc.stderr
        except subprocess.TimeoutExpired as e:code=None;log='Fixed-vector file exceeded 120 seconds.'
        (a.output/(f.stem+'.log')).write_text(log,encoding='utf-8')
        row=dict(file=f.name,exit_code=code)
        if dest.exists():
            data=read(dest);row.update(status=data['status'],counts=data['counts'],result_sha256=sha(dest));totals.update(data['counts'])
        else:row['status']='INCOMPLETE'
        rows.append(row);write(a.output/'progress.xml',dict(files=rows,counts=dict(totals)));print(f.name,row['status'],flush=True)
    result=dict(schema='lattice.published_vectors.v1',status='PASS' if all(x['status']=='PASS' and x['exit_code']==0 for x in rows) else 'FAIL_OR_INCOMPLETE',upstream=lock['repository'],commit=lock['commit'],library_sha256=sha(a.library),test_sha256=sha(__file__),vectors_lock_sha256=sha(a.vectors/'vectors.lock.xml'),counts=dict(totals),files=rows,workspace=a.workspace)
    write(a.output/'result.xml',result);print(json.dumps(result['counts']));return 0 if result['status']=='PASS' else 1
if __name__=='__main__':sys.exit(main())
