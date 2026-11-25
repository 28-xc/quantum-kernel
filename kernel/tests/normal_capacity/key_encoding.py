"""Published out-of-range secret encodings: rejection, clearing and recovery."""
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
import argparse, ctypes as C, hashlib, importlib.util, record_io as json
ROOT=Path(__file__).resolve().parents[2]
sp=importlib.util.spec_from_file_location('abi',ROOT/'tests/platform/compare_public.py');abi=importlib.util.module_from_spec(sp);sp.loader.exec_module(abi)
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--workspace',type=int,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists()
    lib=abi.library(a.library);rows=[];vectors=[]
    def b(x):return (abi.U*x)() if isinstance(x,int) else (abi.U*len(x)).from_buffer_copy(x)
    arena=b(a.workspace+128);address=(C.addressof(arena)+63)&~31;context=abi.Context();tape=[b'',0,0]
    @abi.RANDOM
    def random(user,out,n):
        tape[2]+=1
        if n>len(tape[0])-tape[1]:return -1
        C.memmove(out,tape[0][tape[1]:tape[1]+n],n);tape[1]+=n;return 0
    for level in (44,65,87):
        f=ROOT/f'tests/vectors/wycheproof/testvectors_v1/mldsa_{level}_sign_noseed_test.xml';d=json.loads(f.read_text());vectors.append(dict(path=f.relative_to(ROOT).as_posix(),sha256=sha(f)))
        sizes=abi.Sizes();assert lib.lc_get_sizes(level,C.byref(sizes))==0
        good=d['testGroups'][0];valid=next(t for t in good['tests'] if t['result']=='valid');signature=b(sizes.signature+32)
        for g in d['testGroups']:
            for t in g['tests']:
                if 'InvalidPrivateKey' not in t.get('flags',[]):continue
                C.memset(arena,0xa5,len(arena));assert lib.lc_context_init(C.byref(context),address,a.workspace,random,None)==0
                sk=b(bytes.fromhex(g['privateKey']));msg=b(bytes.fromhex(t['msg']));domain=b(bytes.fromhex(t.get('ctx','')))
                C.memset(signature,0xa5,len(signature));tape[:]=[b'\x00'*32,0,0]
                rc=lib.lc_sign(C.byref(context),level,signature,len(signature),msg,len(msg),domain,len(domain),sk,len(sk))
                assert rc==-6 and context.last_error==-6 and tape[2]==0
                assert bytes(signature[:sizes.signature])==bytes(sizes.signature) and bytes(signature[sizes.signature:])==b'\xa5'*32
                assert context.arena_high_water==0 and C.string_at(address,a.workspace)==b'\xa5'*a.workspace
                sk=b(bytes.fromhex(good['privateKey']));msg=b(bytes.fromhex(valid['msg']));domain=b(bytes.fromhex(valid.get('ctx','')));tape[:]=[bytes.fromhex(valid.get('rnd','00'*32)),0,0]
                rc=lib.lc_sign(C.byref(context),level,signature,len(signature),msg,len(msg),domain,len(domain),sk,len(sk))
                assert rc==0 and bytes(signature[:sizes.signature])==bytes.fromhex(valid['sig'])
                used=C.string_at(address,context.arena_high_water)
                # Allocated objects are cleared; alignment gaps retain their
                # caller-provided marker. The dedicated clearing test checks
                # the actual allocation intervals separately.
                assert all(x in (0,0xa5) for x in used) and used.count(0)>0
                rows.append(dict(parameter=level,tcId=t['tcId'],status='PASS',invalid_key_rng_calls=0,signature_erased=True,unused_workspace_preserved=True,same_context_recovery=True,preserved_padding_bytes=used.count(0xa5)))
    out=dict(status='PASS',library_sha256=sha(a.library),test_sha256=sha(__file__),vectors=vectors,records=rows)
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(dict(status='PASS',cases=len(rows))))
if __name__=='__main__':main()
