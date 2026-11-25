"""Bounded PQClean adapter checks; preserves the original heap contract."""
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
import argparse, ctypes as C, hashlib, record_io as json, sys
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tests/platform'))
from compare_public import library,Context,Sizes,RANDOM,U,sha
def buf(value):return (U*value)() if isinstance(value,int) else (U*len(value)).from_buffer_copy(value)
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 out=a.output.resolve()
 if out.exists():raise ValueError('Fresh output required')
 out.parent.mkdir(parents=True,exist_ok=True);path=a.library.resolve();d=library(path);records=[];rng_calls=[];rng_fail=[False]
 @RANDOM
 def random(user,target,n):
  rng_calls.append(int(n))
  if rng_fail[0]:return -1
  b=hashlib.shake_256(b'PQClean-adapter-boundary-v1'+len(rng_calls).to_bytes(8,'little')).digest(n);C.memmove(target,b,n);return 0
 def check(name,passed,level):
  records.append(dict(test=name,parameter=level,status='PASS' if passed else 'FAIL'))
  if not passed:raise AssertionError(records[-1])
 def store(status,error=None):
  value=dict(schema='pqclean.adapter.validation.v1',status=status,library={'path':str(path),'sha256':sha(path)},source_sha256=sha(Path(__file__)),records=records,error=error,scope='Object/RNG/FIPS203 checks and pure-context ML-DSA boundaries; original heap allocation and failure exit retained; no timing or total-memory claim',secrets_written=False)
  out.write_bytes((json.dumps(value,indent=2)+'\n').encode())
 try:
  for level in (512,768,1024,44,65,87):
   z=Sizes();assert d.lc_get_sizes(level,C.byref(z))==0
   area=buf(b'\xa5'*96);ctx=Context();assert d.lc_context_init(C.byref(ctx),C.byref(area,32),32,random,None)==0
   pk=buf(z.public_key);sk=buf(z.secret_key);ct=buf(z.ciphertext);sig=buf(z.signature);ss=buf(32);recovered=buf(32)
   check('valid_keypair',d.lc_keypair(C.byref(ctx),level,pk,len(pk),sk,len(sk))==0,level)
   check('keypair_entropy_request',rng_calls[-1]==(64 if level>100 else 32),level)
   check('short_output',d.lc_keypair(C.byref(ctx),level,pk,len(pk)-1,sk,len(sk))==-2,level)
   check('aliased_output',d.lc_keypair(C.byref(ctx),level,sk,len(pk),sk,len(sk))==-3,level)
   if level>100:
    reference=bytes(pk);body=len(pk)-32
    def coefficient(data,index,value):
     offset=(index//2)*3
     if index%2==0:data[offset]=value&255;data[offset+1]=(data[offset+1]&240)|(value>>8)
     else:data[offset+1]=(data[offset+1]&15)|((value&15)<<4);data[offset+2]=value>>4
    # Both packed half-coefficients and both edges of every polynomial.
    positions=sorted({256*j+i for j in range(body//384) for i in (0,1,2,127,128,253,254,255)})
    for position in positions:
     for value in (3328,3329,3330,4095):
      altered=bytearray(reference);coefficient(altered,position,value);key=buf(altered)
      C.memset(ct,0xa5,len(ct));C.memset(ss,0xa5,32);rc=d.lc_encaps(C.byref(ctx),level,ct,len(ct),ss,32,key,len(key))
      check(f'coefficient_{position}_{value}',rc==(0 if value==3328 else -6),level)
      if value!=3328:check(f'rejected_output_erasure_{position}_{value}',not any(ct) and not any(ss),level)
    key=buf(reference[:-32]+b'\xff'*32)
    check('rho_excluded_from_modulus_check',d.lc_encaps(C.byref(ctx),level,ct,len(ct),ss,32,key,len(key))==0,level)
    check('normal_encapsulation',d.lc_encaps(C.byref(ctx),level,ct,len(ct),ss,32,pk,len(pk))==0,level)
    check('normal_decapsulation',d.lc_decaps(C.byref(ctx),level,recovered,32,ct,len(ct),sk,len(sk))==0 and bytes(ss)==bytes(recovered),level)
    for index in range(32):
     changed=buf(bytes(sk));changed[len(sk)-64+index]^=1;C.memset(recovered,0xa5,32)
     check(f'decapsulation_hash_byte_{index}',d.lc_decaps(C.byref(ctx),level,recovered,32,ct,len(ct),changed,len(changed))==-6 and not any(recovered),level)
    for index in (0,len(ct)//2,len(ct)-1):
     altered=buf(bytes(ct));altered[index]^=1
     check(f'implicit_rejection_{index}',d.lc_decaps(C.byref(ctx),level,recovered,32,altered,len(altered),sk,len(sk))==0 and bytes(ss)!=bytes(recovered),level)
    rng_fail[0]=True;C.memset(ct,0xa5,len(ct));C.memset(ss,0xa5,32)
    check('encapsulation_rng_failure',d.lc_encaps(C.byref(ctx),level,ct,len(ct),ss,32,pk,len(pk))==-4 and not any(ct) and not any(ss),level);rng_fail[0]=False
   else:
    for mn in (0,32,1024,16384):
     for dn in (0,1,255):
      message=buf(hashlib.shake_256(b'message'+mn.to_bytes(4,'little')).digest(mn));domain=buf(bytes([dn])*dn)
      rc=d.lc_sign(C.byref(ctx),level,sig,len(sig),message,mn,domain,dn,sk,len(sk))
      check(f'sign_{mn}_{dn}',rc==0 and rng_calls[-1]==32,level)
      check(f'verify_{mn}_{dn}',d.lc_verify(C.byref(ctx),level,sig,len(sig),message,mn,domain,dn,pk,len(pk))==0,level)
      sig[0]^=1;check(f'changed_signature_{mn}_{dn}',d.lc_verify(C.byref(ctx),level,sig,len(sig),message,mn,domain,dn,pk,len(pk))==-6,level);sig[0]^=1
    domain=buf(256);check('context_256_rejected',d.lc_sign(C.byref(ctx),level,sig,len(sig),None,0,domain,256,sk,len(sk))==-2,level)
    rng_fail[0]=True;C.memset(sig,0xa5,len(sig))
    check('sign_rng_failure',d.lc_sign(C.byref(ctx),level,sig,len(sig),None,0,None,0,sk,len(sk))==-4 and not any(sig),level);rng_fail[0]=False
   rng_fail[0]=True;C.memset(pk,0xa5,len(pk));C.memset(sk,0xa5,len(sk))
   check('keygen_rng_failure',d.lc_keypair(C.byref(ctx),level,pk,len(pk),sk,len(sk))==-4 and not any(pk) and not any(sk),level);rng_fail[0]=False
   check('rng_recovery',d.lc_keypair(C.byref(ctx),level,pk,len(pk),sk,len(sk))==0,level)
   check('workspace_untouched_and_not_total_RAM',bytes(area)==b'\xa5'*96 and ctx.arena_high_water==0 and ctx.allocations==0 and ctx.allocation_failures==0,level)
   print(level,'PASS',flush=True)
  store('PASS');print(json.dumps({'status':'PASS','checks':len(records)}))
 except Exception as e:store('FAIL',str(e));raise
if __name__=='__main__':main()
