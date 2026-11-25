"""Sweep every aligned arena capacity for fixed valid staged signatures.

Checks partial allocation/prefill/attempt failure cleanup and same-context
recovery. This is neither a universal minimal-RAM proof nor a timing test.
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
import argparse, ctypes as C, hashlib, importlib.util, record_io as json
ROOT=Path(__file__).resolve().parents[2]
sp=importlib.util.spec_from_file_location('api_types',ROOT/'tests/platform/compare_public.py');m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def data(b):return(m.U*len(b)).from_buffer_copy(b)
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--library',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
 out=a.output.resolve();dll=a.library.resolve();before=sha(dll)
 if out.exists() or out.drive.upper()!='D:':raise ValueError('Fresh D: output required')
 out.parent.mkdir(parents=True,exist_ok=True);d=m.library(dll);rows=[]
 for level in (44,65,87):
  sizes=m.Sizes();assert d.lc_get_sizes(level,C.byref(sizes))==0
  raw=(m.U*(65536+96))();offset=32+(-C.addressof(raw)-32)%32;work=C.addressof(raw)+offset;c=m.Context();coins=b'';requests=[]
  @m.RANDOM
  def random(user,p,n):
   requests.append(n)
   if n!=32:return -1
   C.memmove(p,coins,32);return 0
  def init(cap):
   C.memset(raw,0xa5,len(raw));C.memset(work,0,cap)
   assert d.lc_context_init(C.byref(c),work,cap,random,None)==0
  init(65536);coins=hashlib.shake_256(b'R2-staged-capacity-key'+bytes([level])).digest(32)
  pk=(m.U*sizes.public_key)();sk=(m.U*sizes.secret_key)();assert d.lc_keypair(C.byref(c),level,pk,len(pk),sk,len(sk))==0
  msg=data(hashlib.shake_256(b'R2-staged-capacity-message').digest(1024));domain=data(bytes(range(255)))
  coins=hashlib.shake_256(b'R2-staged-capacity-rnd'+bytes([level])).digest(32);sig=(m.U*(sizes.signature+32))()
  def sign(cap):
   init(cap);C.memset(sig,0xa5,len(sig));requests.clear()
   rc=d.lc_sign(C.byref(c),level,sig,sizes.signature,msg,len(msg),domain,len(domain),sk,len(sk))
   assert requests==[32] and c.arena_high_water<=cap
   assert bytes(raw[:offset])==b'\xa5'*offset and bytes(raw[offset+cap:])==b'\xa5'*(len(raw)-offset-cap)
   assert bytes(sig[sizes.signature:])==b'\xa5'*32
   assert bytes(raw[offset:offset+c.arena_high_water])==bytes(c.arena_high_water)
   return rc,bytes(sig[:sizes.signature]),c.arena_high_water,c.allocations,c.allocation_failures
  rc,expected,peak,_,_=sign(65536);assert rc==0 and peak%32==0
  checked=[]
  for cap in range(32,peak+33,32):
   rc,observed,high,allocs,fails=sign(cap)
   assert rc==(-5 if cap<peak else 0),(level,cap,peak,rc)
   if rc:assert observed==bytes(len(observed)) and fails>0
   else:assert observed==expected and fails==0
   checked.append({'capacity':cap,'status':rc,'high_water':high,'allocations':allocs,'allocation_failures':fails})
   if rc:
    recovery=sign(65536);assert recovery[0]==0 and recovery[1]==expected
  rows.append({'parameter':level,'fixed_aligned_input_peak':peak,'capacities_tested':len(checked),'minimum_tested_success_capacity':peak,'below_peak_failures_recovered':len(checked)-2,'signature_sha256':hashlib.sha256(expected).hexdigest(),'trials':checked})
 assert sha(dll)==before
 result={'status':'PASS','library':{'path':str(dll),'sha256':before},'test_source_sha256':sha(Path(__file__)),'loader_source_sha256':sha(ROOT/'tests/platform/compare_public.py'),'records':rows,'formal_timing':False,'scope':'Every 32-byte-aligned capacity from 32 through fixed-input observed peak+32; three valid ML-DSA inputs with domain255/message1024. Exact outputs, failure zeroing, guards, zero-initialized used arena and same-context recovery. Not every input, stack/whole-RAM capacity, or arbitrary unaligned arena.'}
 out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8');print(json.dumps({'status':'PASS','capacities':sum(x['capacities_tested'] for x in rows),'output':str(out)}))
if __name__=='__main__':main()
