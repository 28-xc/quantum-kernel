"""Fixed local FIPS203 hash and implicit-rejection regressions.

Synthetic test inputs only. Every expected rejection secret is independently
computed with hashlib SHAKE256; all bad embedded hash bytes are checked.
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
import argparse, ctypes as C, hashlib, record_io as json, sys
ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'tests/platform'))
from compare_public import Context,Sizes,RANDOM,U,library,sha
def buf(b):return (U*b)() if isinstance(b,int) else (U*len(b)).from_buffer_copy(b)
def main():
 p=argparse.ArgumentParser();p.add_argument('--library',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 out=a.output.resolve();assert not out.exists();path=a.library.resolve();before=sha(path);d=library(path);rows=[]
 for parameter in [512,768,1024]:
  z=Sizes();assert d.lc_get_sizes(parameter,C.byref(z))==0
  area=buf(262144+64);offset=(-C.addressof(area))%32;ctx=Context();seed=b'';requests=[]
  @RANDOM
  def rng(user,target,n):
   block=hashlib.shake_256(seed+len(requests).to_bytes(4,'little')).digest(n);requests.append(n);C.memmove(target,block,n);return 0
  def init():
   C.memset(area,0xa5,len(area));assert d.lc_context_init(C.byref(ctx),C.byref(area,offset),262144,rng,None)==0
  pk=buf(z.public_key);sk=buf(z.secret_key);ct=buf(z.ciphertext);ss=buf(32);got=buf(32)
  def dec(cipher,key=sk):
   init();C.memset(got,0xa5,32);rc=d.lc_decaps(C.byref(ctx),parameter,got,32,cipher,len(cipher),key,len(key))
   assert bytes(area[:offset])==b'\xa5'*offset and bytes(area[offset+262144:])==b'\xa5'*(64-offset)
   return rc
  for case in range(32):
   seed=b'R3-shared-fixed-semantics-v1'+parameter.to_bytes(4,'little')+case.to_bytes(4,'little');requests.clear();init()
   assert d.lc_keypair(C.byref(ctx),parameter,pk,len(pk),sk,len(sk))==0 and requests==[64]
   assert hashlib.sha3_256(bytes(pk)).digest()==bytes(sk[-64:-32])
   init();assert d.lc_encaps(C.byref(ctx),parameter,ct,len(ct),ss,32,pk,len(pk))==0
   assert dec(ct)==0 and bytes(got)==bytes(ss)
   invalid=buf(hashlib.shake_256(seed+b'ciphertext').digest(len(ct)))
   expected=hashlib.shake_256(bytes(sk[-32:])+bytes(invalid)).digest(32)
   assert dec(invalid)==0 and bytes(got)==expected
   altered=buf(bytes(ct));altered[case%len(ct)]^=1
   expected2=hashlib.shake_256(bytes(sk[-32:])+bytes(altered)).digest(32)
   assert dec(altered)==0 and bytes(got)==expected2
   rows.append(dict(parameter=parameter,case=case,normal_roundtrip=True,independent_J_equal_for_two_ciphertexts=True))
  for byte in range(32):
   bad=buf(bytes(sk));bad[len(bad)-64+byte]^=1
   assert dec(ct,bad)==-6 and bytes(got)==bytes(32)
   rows.append(dict(parameter=parameter,invalid_embedded_hash_byte=byte,status=-6,output_erased=True))
  badpk=buf(bytes(pk));badpk[0]=255;badpk[1]=(badpk[1]&240)|15
  init();C.memset(ct,0xa5,len(ct));C.memset(ss,0xa5,32)
  assert d.lc_encaps(C.byref(ctx),parameter,ct,len(ct),ss,32,badpk,len(badpk))==-6
  assert not any(ct) and not any(ss)
  rows.append(dict(parameter=parameter,noncanonical_public_coefficient_rejected=True,output_erased=True))
 assert sha(path)==before
 result=dict(status='PASS',library=dict(path=str(path),sha256=before),test_source_sha256=sha(Path(__file__)),
  public_loader_sha256=sha(ROOT/'tests/platform/compare_public.py'),fixed_standard_key_cases=96,
  independently_checked_rejection_secrets=192,invalid_embedded_hash_byte_checks=96,noncanonical_public_key_checks=3,
  records=rows,scope='Fixed synthetic test corpus, independent hashlib SHA3/SHAKE oracle, final unmodified library; no timings and no adaptive input search',secrets_written=False)
 out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items() if k in ['status','fixed_standard_key_cases','independently_checked_rejection_secrets','invalid_embedded_hash_byte_checks']}))
if __name__=='__main__':main()
