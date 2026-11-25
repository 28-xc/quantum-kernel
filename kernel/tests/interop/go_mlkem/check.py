"""Bidirectional ML-KEM interoperability with Go's independent standard library."""
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
import argparse, ctypes as C, hashlib, importlib.util, record_io as json, subprocess
ROOT=Path(__file__).resolve().parents[3]
sp=importlib.util.spec_from_file_location('public_abi',ROOT/'tests/platform/compare_public.py')
abi=importlib.util.module_from_spec(sp);sp.loader.exec_module(abi)
def buf(b):return (abi.U*b)() if isinstance(b,int) else (abi.U*len(b)).from_buffer_copy(b)
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--library',type=Path,required=True);p.add_argument('--peer',type=Path,required=True)
    p.add_argument('--workspace',type=int,required=True);p.add_argument('--count',type=int,default=100)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    assert 1<=a.count<=1000 and 32<=a.workspace<=262144 and not a.output.exists()
    a.output.parent.mkdir(parents=True,exist_ok=True)
    lib=abi.library(a.library.resolve());arena=buf(a.workspace+128);address=(C.addressof(arena)+63)&~31
    state=abi.Context();entropy=[b'',0]
    @abi.RANDOM
    def rng(user,out,n):
        b,pos=entropy
        if pos+n>len(b):return -1
        C.memmove(out,b[pos:pos+n],n);entropy[1]+=n;return 0
    assert lib.lc_context_init(C.byref(state),address,a.workspace,rng,None)==0
    proc=subprocess.Popen([str(a.peer.resolve())],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    version=None;rows=[]
    def peer(level,op,**fields):
        nonlocal version
        proc.stdin.write(json.dumps(dict(Parameter=level,Operation=op,**fields))+'\n');proc.stdin.flush()
        line=proc.stdout.readline()
        if not line:raise RuntimeError('Interop peer exited')
        r=json.loads(line);version=r['Version']
        return r
    try:
        for level in (768,1024):
            size=abi.Sizes();assert lib.lc_get_sizes(level,C.byref(size))==0
            for i in range(a.count):
                seed=hashlib.shake_256(b'go-standard-interop-v1'+level.to_bytes(2,'little')+i.to_bytes(4,'little')).digest(64)
                entropy[:]=[seed,0];pk=buf(size.public_key);sk=buf(size.secret_key);ct=buf(size.ciphertext);ss=buf(32);ss2=buf(32)
                assert lib.lc_keypair(C.byref(state),level,pk,len(pk),sk,len(sk))==0 and entropy[1]==64
                r=peer(level,'keypair',Seed=seed.hex());assert not r['Error'] and r['Public']==bytes(pk).hex()
                entropy[:]=[hashlib.shake_256(seed+b'encaps').digest(32),0]
                assert lib.lc_encaps(C.byref(state),level,ct,len(ct),ss,32,pk,len(pk))==0
                r=peer(level,'decaps',Seed=seed.hex(),Ciphertext=bytes(ct).hex());assert not r['Error'] and r['Shared']==bytes(ss).hex()
                ct[i%len(ct)]^=1
                assert lib.lc_decaps(C.byref(state),level,ss2,32,ct,len(ct),sk,len(sk))==0
                r=peer(level,'decaps',Seed=seed.hex(),Ciphertext=bytes(ct).hex());assert not r['Error'] and r['Shared']==bytes(ss2).hex() and bytes(ss)!=bytes(ss2)
                r=peer(level,'encaps',Public=bytes(pk).hex());assert not r['Error'];other=buf(bytes.fromhex(r['Ciphertext']))
                assert lib.lc_decaps(C.byref(state),level,ss2,32,other,len(other),sk,len(sk))==0 and bytes(ss2).hex()==r['Shared']
                assert C.string_at(address,state.arena_high_water)==bytes(state.arena_high_water)
                rows.append(dict(parameter=level,case=i,public_key_equal=True,project_encaps_go_decaps=True,go_encaps_project_decaps=True,implicit_rejection_equal=True,workspace_erased=True))
        proc.stdin.close();assert proc.wait(timeout=10)==0
        assert not proc.stderr.read()
    finally:
        if proc.poll() is None:proc.kill();proc.wait()
    result=dict(status='PASS',library=dict(sha256=sha(a.library),filename=a.library.name),peer=dict(sha256=sha(a.peer),version=version),workspace=a.workspace,records=rows,counts=dict(cases=len(rows),key_derivation_comparisons=len(rows),bidirectional_valid_exchanges=2*len(rows),implicit_rejection_comparisons=len(rows)),test_sha256=sha(__file__),peer_source_sha256=sha(Path(__file__).with_name('main.go')),test_seed_domain='go-standard-interop-v1',raw_private_material_persisted=False)
    a.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8');print(json.dumps(result['counts']))
if __name__=='__main__':main()
