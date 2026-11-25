"""Compare complete public outputs under identical deterministic test entropy.

The deterministic callback is only a test fixture and must not be used by an
application. Raw secret outputs are compared in memory and never written.
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
import argparse, ctypes as C, hashlib, record_io as json, os, platform
ROOT=Path(__file__).resolve().parents[2]
U=C.c_uint8; P=C.POINTER(U); Z=C.c_size_t
RANDOM=C.CFUNCTYPE(C.c_int,C.c_void_p,P,Z)
class Context(C.Structure):
 _fields_=[('workspace',C.c_void_p),('workspace_bytes',Z),('random',RANDOM),('random_user',C.c_void_p),('arena_high_water',Z),('allocations',Z),('allocation_failures',Z),('last_error',C.c_int)]
class Sizes(C.Structure):
 _fields_=[(x,Z) for x in ('public_key','secret_key','ciphertext','shared_secret','signature')]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def library(path):
 d=C.CDLL(str(path));ctx=C.POINTER(Context)
 signatures={'lc_get_sizes':[C.c_int,C.POINTER(Sizes)],'lc_context_init':[ctx,C.c_void_p,Z,RANDOM,C.c_void_p],
 'lc_keypair':[ctx,C.c_int,P,Z,P,Z], 'lc_encaps':[ctx,C.c_int,P,Z,P,Z,P,Z],
 'lc_decaps':[ctx,C.c_int,P,Z,P,Z,P,Z], 'lc_sign':[ctx,C.c_int,P,Z,P,Z,P,Z,P,Z],
 'lc_verify':[ctx,C.c_int,P,Z,P,Z,P,Z,P,Z]}
 for name,args in signatures.items():getattr(d,name).argtypes=args;getattr(d,name).restype=C.c_int
 return d
def checked(rc):
 if rc!=0:raise AssertionError('Unexpected status '+str(rc))
def allzero(a,n):return not any(a[:n])
def run(d,parameter,seed,system=False,expect_reject=False):
 sizes=Sizes();checked(d.lc_get_sizes(parameter,C.byref(sizes)));requests=[]
 @RANDOM
 def random(user,out,n):
  data=hashlib.shake_256(seed+len(requests).to_bytes(4,'little')).digest(n)
  requests.append(n);C.memmove(out,data,n);return 0
 arena=(U*(262144+64))();C.memset(arena,0xa5,len(arena));offset=(-C.addressof(arena))%32
 ctx=Context();rng=RANDOM() if system else random
 checked(d.lc_context_init(C.byref(ctx),C.byref(arena,offset),262144,rng,None))
 def buffer(n):
  a=(U*(n+32))();C.memset(a,0xa5,len(a));return a
 pk=buffer(sizes.public_key);sk=buffer(sizes.secret_key);ct=buffer(sizes.ciphertext);ss=buffer(32);ss2=buffer(32);sig=buffer(sizes.signature)
 rc=d.lc_keypair(C.byref(ctx),parameter,pk,sizes.public_key,sk,sizes.secret_key)
 if expect_reject:
  assert rc==-4 and allzero(pk,sizes.public_key) and allzero(sk,sizes.secret_key)
  assert bytes(pk[sizes.public_key:])==b'\xa5'*32 and bytes(sk[sizes.secret_key:])==b'\xa5'*32
  # Create an input key with a supplied callback, then remove the callback.
  # Check the other entropy-requiring operation through the same public ABI.
  ctx.random=random
  checked(d.lc_keypair(C.byref(ctx),parameter,pk,sizes.public_key,sk,sizes.secret_key))
  ctx.random=RANDOM()
  if sizes.ciphertext:
   rc=d.lc_encaps(C.byref(ctx),parameter,ct,sizes.ciphertext,ss,32,pk,sizes.public_key)
   assert rc==-4 and allzero(ct,sizes.ciphertext) and allzero(ss,32)
  else:
   rc=d.lc_sign(C.byref(ctx),parameter,sig,sizes.signature,None,0,None,0,sk,sizes.secret_key)
   assert rc==-4 and allzero(sig,sizes.signature)
  for a,n in [(pk,sizes.public_key),(sk,sizes.secret_key),(ct,sizes.ciphertext),(ss,32),(sig,sizes.signature)]:assert bytes(a[n:])==b'\xa5'*32
  return {'default_entropy_rejected':True,'outputs_erased':True,'guards_preserved':True}
 checked(rc);high=[ctx.arena_high_water];out=[bytes(pk[:sizes.public_key]),bytes(sk[:sizes.secret_key])]
 message=hashlib.shake_256(seed+b'message').digest(1024);domain=b'platform-adapter-test'
 msg=(U*len(message)).from_buffer_copy(message);dom=(U*len(domain)).from_buffer_copy(domain)
 if sizes.ciphertext:
  checked(d.lc_encaps(C.byref(ctx),parameter,ct,sizes.ciphertext,ss,32,pk,sizes.public_key));high.append(ctx.arena_high_water)
  checked(d.lc_decaps(C.byref(ctx),parameter,ss2,32,ct,sizes.ciphertext,sk,sizes.secret_key));high.append(ctx.arena_high_water)
  assert bytes(ss[:32])==bytes(ss2[:32]);out.extend([bytes(ct[:sizes.ciphertext]),bytes(ss[:32])])
  ct[0]^=1;checked(d.lc_decaps(C.byref(ctx),parameter,ss2,32,ct,sizes.ciphertext,sk,sizes.secret_key));out.append(bytes(ss2[:32]));ct[0]^=1
 else:
  checked(d.lc_sign(C.byref(ctx),parameter,sig,sizes.signature,msg,len(msg),dom,len(dom),sk,sizes.secret_key));high.append(ctx.arena_high_water)
  checked(d.lc_verify(C.byref(ctx),parameter,sig,sizes.signature,msg,len(msg),dom,len(dom),pk,sizes.public_key));high.append(ctx.arena_high_water)
  out.append(bytes(sig[:sizes.signature]));sig[0]^=1
  assert d.lc_verify(C.byref(ctx),parameter,sig,sizes.signature,msg,len(msg),dom,len(dom),pk,sizes.public_key)==-6
  sig[0]^=1
 for a,n in [(pk,sizes.public_key),(sk,sizes.secret_key),(ct,sizes.ciphertext),(ss,32),(ss2,32),(sig,sizes.signature)]:assert bytes(a[n:])==b'\xa5'*32
 assert bytes(arena[:offset])==b'\xa5'*offset and bytes(arena[offset+262144:])==b'\xa5'*(len(arena)-offset-262144)
 return out,requests,high
def main():
 p=argparse.ArgumentParser();p.add_argument('--left',type=Path,required=True);p.add_argument('--right',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--count',type=int,default=100);p.add_argument('--expect-no-system',action='store_true');p.add_argument('--resource-mode',choices=['equal','record'],default='equal',help='record permits different measured layouts while still requiring byte and entropy-request equality');a=p.parse_args()
 if not 1<=a.count<=10000:raise ValueError('count must be 1..10000')
 output=a.output.resolve()
 if output.exists():raise ValueError('Use a new output JSON')
 if os.name=='nt' and output.drive.upper()!='D:':raise ValueError('D: output required')
 left=a.left.resolve();right=a.right.resolve();dll=[library(left),library(right)];rows=[]
 for param in (512,768,1024,44,65,87):
  digest=hashlib.sha256();high=None;resource_pairs=[]
  for i in range(a.count):
   seed=b'R2-public-platform-v1'+param.to_bytes(4,'little')+i.to_bytes(4,'little')
   x=run(dll[0],param,seed);y=run(dll[1],param,seed)
   assert x[:2]==y[:2],('Byte/RNG-request mismatch',param,i)
   resource_pairs.append({'case':i,'left':x[2],'right':y[2]})
   if a.resource_mode=='equal':assert x[2]==y[2],('Arena mismatch',param,i)
   for part in y[0]:digest.update(part)
   high=y[2]
  hosted=run(dll[1],param,b'hosted-smoke',system=True,expect_reject=a.expect_no_system)
  rows.append({'parameter':param,'complete_sequences':a.count,'outputs_byte_equal':True,'entropy_requests_equal':True,'arena_highwater_equal':all(r['left']==r['right'] for r in resource_pairs),'arena_observations':resource_pairs,'last_arena_highwater':high,'aggregate_output_sha256':digest.hexdigest(),'system_rng_smoke':'REJECTED_AND_CLEARED' if a.expect_no_system else 'ROUNDTRIP_PASS','mutated_input_checked':True,'guards_preserved':True})
  print(param,'PASS',flush=True)
 result={'status':'PASS','resource_mode':a.resource_mode,'host':platform.platform(),'libraries':{'left':{'path':str(left),'sha256':sha(left)},'right':{'path':str(right),'sha256':sha(right)}},'cells':rows,'test_source_sha256':sha(Path(__file__)),'secrets_written':False,'formal_performance_collected':False}
 output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
if __name__=='__main__':main()
