"""Complete-output and bidirectional checks against a separately built liboqs."""
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
import argparse, ctypes as C, hashlib, importlib.util, record_io as json, os
ROOT=Path(__file__).resolve().parents[2]
sp=importlib.util.spec_from_file_location('public_abi',ROOT/'tests/platform/compare_public.py')
abi=importlib.util.module_from_spec(sp);sp.loader.exec_module(abi)
def buf(b):return (abi.U*b)() if isinstance(b,int) else (abi.U*len(b)).from_buffer_copy(b)
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True)
    p.add_argument('--liboqs',type=Path,required=True);p.add_argument('--workspace',type=int,required=True)
    p.add_argument('--count',type=int,default=100);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    assert 1<=a.count<=1000 and 32<=a.workspace<=262144 and not a.output.exists()
    a.output.parent.mkdir(parents=True,exist_ok=True)
    dll_dir=os.add_dll_directory(str(a.liboqs.resolve().parent)) if os.name=='nt' else None
    lib=abi.library(a.library.resolve());oqs=C.CDLL(str(a.liboqs.resolve()));oqs.OQS_version.restype=C.c_char_p
    arena=buf(a.workspace+128);address=(C.addressof(arena)+63)&~31;state=abi.Context();tape=[b'',0];oqstape=[b'',0];errors=[]
    def supply(store,out,n):
        data,pos=store
        if pos+n>len(data):errors.append('insufficient test entropy');C.memset(out,0,n);return -1
        C.memmove(out,data[pos:pos+n],n);store[1]+=n;return 0
    @abi.RANDOM
    def rng(user,out,n):return supply(tape,out,n)
    CALLBACK=C.CFUNCTYPE(None,abi.P,C.c_size_t)
    @CALLBACK
    def oqsrng(out,n):supply(oqstape,out,n)
    oqs.OQS_randombytes_custom_algorithm.argtypes=[CALLBACK];oqs.OQS_randombytes_custom_algorithm(oqsrng)
    assert lib.lc_context_init(C.byref(state),address,a.workspace,rng,None)==0
    rows=[];counts=dict(keypairs=0,complete_ciphertexts=0,complete_signatures=0,cross_decaps=0,cross_verify=0,implicit_rejection=0,modified_signature_rejections=0)
    def bind(name,args):
        fn=getattr(oqs,name);fn.argtypes=args;fn.restype=C.c_int;return fn
    for level in (512,768,1024,44,65,87):
        z=abi.Sizes();assert lib.lc_get_sizes(level,C.byref(z))==0;kem=level>100
        prefix=f'OQS_KEM_ml_kem_{level}_' if kem else f'OQS_SIG_ml_dsa_{level}_'
        kp=bind(prefix+'keypair',[abi.P,abi.P])
        if kem:
            en=bind(prefix+'encaps',[abi.P,abi.P,abi.P]);de=bind(prefix+'decaps',[abi.P,abi.P,abi.P])
        else:
            si=bind(prefix+'sign_with_ctx_str',[abi.P,C.POINTER(C.c_size_t),abi.P,C.c_size_t,abi.P,C.c_size_t,abi.P])
            ve=bind(prefix+'verify_with_ctx_str',[abi.P,C.c_size_t,abi.P,C.c_size_t,abi.P,C.c_size_t,abi.P])
        for i in range(a.count):
            seed=hashlib.shake_256(b'liboqs-release-interop-v1'+level.to_bytes(2,'little')+i.to_bytes(4,'little')).digest(256)
            tape[:]=[seed,0];oqstape[:]=[seed,0];pk=buf(z.public_key);sk=buf(z.secret_key);opk=buf(z.public_key);osk=buf(z.secret_key)
            assert lib.lc_keypair(C.byref(state),level,pk,len(pk),sk,len(sk))==0 and kp(opk,osk)==0
            assert not errors and bytes(pk)==bytes(opk) and bytes(sk)==bytes(osk);counts['keypairs']+=1
            entropy_keygen=(tape[1],oqstape[1]);tape[:]=[seed[96:],0];oqstape[:]=[seed[96:],0]
            row=dict(parameter=level,case=i,key_bytes_equal=True,keygen_entropy_bytes=entropy_keygen)
            if kem:
                ct=buf(z.ciphertext);oct=buf(z.ciphertext);ss=buf(32);oss=buf(32);check=buf(32)
                assert lib.lc_encaps(C.byref(state),level,ct,len(ct),ss,32,pk,len(pk))==0 and en(oct,oss,pk)==0
                assert bytes(ct)==bytes(oct) and bytes(ss)==bytes(oss);counts['complete_ciphertexts']+=1
                assert de(check,ct,osk)==0 and bytes(check)==bytes(ss)
                assert lib.lc_decaps(C.byref(state),level,check,32,oct,len(oct),sk,len(sk))==0 and bytes(check)==bytes(oss);counts['cross_decaps']+=2
                ct[i%len(ct)]^=1
                assert de(oss,ct,osk)==0 and lib.lc_decaps(C.byref(state),level,check,32,ct,len(ct),sk,len(sk))==0
                assert bytes(check)==bytes(oss) and bytes(check)!=bytes(ss);counts['implicit_rejection']+=1
                row.update(ciphertext_bytes_equal=True,bidirectional_decapsulation=True,rejection_secret_equal=True)
            else:
                n=(0,1,32,1024,4096)[i%5];cn=(0,1,32,255)[(i//5)%4]
                msg=buf(hashlib.shake_256(seed+b'm').digest(n));ctx=buf(hashlib.shake_256(seed+b'c').digest(cn))
                sig=buf(z.signature);osig=buf(z.signature);sn=C.c_size_t()
                assert lib.lc_sign(C.byref(state),level,sig,len(sig),msg,n,ctx,cn,sk,len(sk))==0
                assert si(osig,C.byref(sn),msg,n,ctx,cn,osk)==0 and sn.value==z.signature
                assert bytes(sig)==bytes(osig);counts['complete_signatures']+=1
                assert ve(msg,n,sig,len(sig),ctx,cn,opk)==0
                assert lib.lc_verify(C.byref(state),level,osig,len(osig),msg,n,ctx,cn,pk,len(pk))==0;counts['cross_verify']+=2
                sig[i%len(sig)]^=1
                assert ve(msg,n,sig,len(sig),ctx,cn,opk)!=0
                assert lib.lc_verify(C.byref(state),level,sig,len(sig),msg,n,ctx,cn,pk,len(pk))==-6;counts['modified_signature_rejections']+=2
                row.update(signature_bytes_equal=True,bidirectional_verification=True,modified_signature_rejected=True,message_bytes=n,context_bytes=cn)
            assert not errors and C.string_at(address,state.arena_high_water)==bytes(state.arena_high_water)
            row.update(operation_entropy_bytes=(tape[1],oqstape[1]),workspace_erased=True);rows.append(row)
        print(level,'PASS',flush=True)
    result=dict(status='PASS',library=dict(filename=a.library.name,sha256=sha(a.library)),peer=dict(version=oqs.OQS_version().decode(),filename=a.liboqs.name,sha256=sha(a.liboqs)),workspace=a.workspace,counts=counts,records=rows,test_source_sha256=sha(__file__),scope='Separately released and built liboqs integration; liboqs ML-KEM/ML-DSA share native upstream lineage with project sources.',raw_private_material_persisted=False)
    a.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8');print(json.dumps(counts))
    oqs.OQS_randombytes_switch_algorithm.argtypes=[C.c_char_p];assert oqs.OQS_randombytes_switch_algorithm(b'system')==0
    if dll_dir:dll_dir.close()
if __name__=='__main__':main()
