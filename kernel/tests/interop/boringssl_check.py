"""Interoperate with BoringSSL using public serialized objects and seed APIs."""
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
sp=importlib.util.spec_from_file_location('public_abi',ROOT/'tests/platform/compare_public.py')
abi=importlib.util.module_from_spec(sp);sp.loader.exec_module(abi)
def buf(b):return (abi.U*b)() if isinstance(b,int) else (abi.U*len(b)).from_buffer_copy(b)
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--peer',type=Path,required=True)
    p.add_argument('--workspace',type=int,required=True);p.add_argument('--count',type=int,default=100);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    assert 1<=a.count<=1000 and not a.output.exists();a.output.parent.mkdir(parents=True,exist_ok=True)
    lib=abi.library(a.library.resolve());peer=C.CDLL(str(a.peer.resolve()));tape=[b'',0]
    @abi.RANDOM
    def rng(user,out,n):
        seed,pos=tape
        if pos+n>len(seed):return -1
        C.memmove(out,seed[pos:pos+n],n);tape[1]+=n;return 0
    arena=buf(a.workspace+128);address=(C.addressof(arena)+63)&~31;state=abi.Context()
    assert lib.lc_context_init(C.byref(state),address,a.workspace,rng,None)==0
    def fn(name,args):
        f=getattr(peer,name);f.argtypes=args;f.restype=C.c_int;return f
    records=[]
    for level in (768,1024,44,65,87):
        z=abi.Sizes();assert lib.lc_get_sizes(level,C.byref(z))==0;kem=level>100
        key=fn('b_key_'+str(level),[abi.P,abi.P])
        if kem:
            enc=fn('b_enc_'+str(level),[abi.P,abi.P,abi.P]);dec=fn('b_dec_'+str(level),[abi.P,abi.P,abi.P])
        else:
            sign=fn('b_sign_'+str(level),[abi.P,abi.P,C.c_size_t,abi.P,C.c_size_t,abi.P]);verify=fn('b_verify_'+str(level),[abi.P,abi.P,C.c_size_t,abi.P,C.c_size_t,abi.P])
        for i in range(a.count):
            seed=hashlib.shake_256(b'boringssl-interop-v1'+level.to_bytes(2,'little')+i.to_bytes(4,'little')).digest(64 if kem else 32)
            seedbuf=buf(seed);tape[:]=[seed,0];pk=buf(z.public_key);sk=buf(z.secret_key);bpk=buf(z.public_key)
            assert lib.lc_keypair(C.byref(state),level,pk,len(pk),sk,len(sk))==0 and key(seedbuf,bpk)==1
            assert bytes(pk)==bytes(bpk)
            row=dict(parameter=level,case=i,public_key_equal=True)
            if kem:
                ct=buf(z.ciphertext);ss=buf(32);bss=buf(32);check=buf(32)
                tape[:]=[hashlib.shake_256(seed+b'e').digest(32),0]
                assert lib.lc_encaps(C.byref(state),level,ct,len(ct),ss,32,bpk,len(bpk))==0
                assert dec(seedbuf,ct,bss)==1 and bytes(ss)==bytes(bss)
                ct[i%len(ct)]^=1
                assert lib.lc_decaps(C.byref(state),level,check,32,ct,len(ct),sk,len(sk))==0 and dec(seedbuf,ct,bss)==1
                assert bytes(check)==bytes(bss) and bytes(check)!=bytes(ss)
                assert enc(pk,ct,bss)==1 and lib.lc_decaps(C.byref(state),level,check,32,ct,len(ct),sk,len(sk))==0 and bytes(check)==bytes(bss)
                row.update(project_encapsulation=True,peer_encapsulation=True,implicit_rejection_equal=True)
            else:
                n=(0,1,32,1024,4096)[i%5];cn=(0,1,32,255)[(i//5)%4]
                msg=buf(hashlib.shake_256(seed+b'm').digest(n));ctx=buf(hashlib.shake_256(seed+b'c').digest(cn));sig=buf(z.signature)
                tape[:]=[hashlib.shake_256(seed+b's').digest(32),0]
                assert lib.lc_sign(C.byref(state),level,sig,len(sig),msg,n,ctx,cn,sk,len(sk))==0 and verify(pk,msg,n,ctx,cn,sig)==1
                sig[i%len(sig)]^=1;assert verify(pk,msg,n,ctx,cn,sig)==0
                assert sign(seedbuf,msg,n,ctx,cn,sig)==1 and lib.lc_verify(C.byref(state),level,sig,len(sig),msg,n,ctx,cn,pk,len(pk))==0
                sig[i%len(sig)]^=1;assert lib.lc_verify(C.byref(state),level,sig,len(sig),msg,n,ctx,cn,pk,len(pk))==-6
                row.update(project_sign_peer_verify=True,peer_sign_project_verify=True,modified_signature_rejected=True,message_bytes=n,context_bytes=cn)
            assert C.string_at(address,state.arena_high_water)==bytes(state.arena_high_water);records.append(row)
        print(level,'PASS',flush=True)
    result=dict(status='PASS',library=dict(sha256=sha(a.library),filename=a.library.name),peer=dict(sha256=sha(a.peer),filename=a.peer.name),workspace=a.workspace,records=records,counts=dict(key_derivations=5*a.count,bidirectional_kem_exchanges=4*a.count,implicit_rejection_comparisons=2*a.count,bidirectional_signature_checks=6*a.count,modified_signature_rejections=6*a.count),test_sha256=sha(__file__),wrapper_sha256=sha(Path(__file__).with_name('boringssl_peer.c')),raw_private_material_persisted=False)
    a.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8');print(json.dumps(result['counts']))
if __name__=='__main__':main()
