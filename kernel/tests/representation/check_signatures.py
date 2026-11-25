"""Compare complete signatures across new libraries without persistent key state.

Reuses each public context across alternating serialized keys, messages and
domains. Entropy is explicit test data; no signing secrets are written.
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
import argparse, ctypes as C, hashlib, importlib.util, record_io as json, os
ROOT=Path(__file__).resolve().parents[2]
sp=importlib.util.spec_from_file_location('public_platform',ROOT/'tests/platform/compare_public.py')
m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def octets(data):return (m.U*len(data)).from_buffer_copy(data)
class Session:
    def __init__(self,path,capacity):
        self.capacity=capacity
        self.lib=m.library(path);self.workspace=(m.U*(capacity+96))();C.memset(self.workspace,0xa5,len(self.workspace))
        self.offset=32+(-C.addressof(self.workspace)-32)%32;self.context=m.Context();self.coins=b'';self.pos=0
        @m.RANDOM
        def entropy(user,out,n):
            if n>len(self.coins)-self.pos:return -1
            C.memmove(out,self.coins[self.pos:self.pos+n],n);self.pos+=n;return 0
        self.rng=entropy
        assert self.lib.lc_context_init(C.byref(self.context),C.byref(self.workspace,self.offset),capacity,self.rng,None)==0
    def reset_coins(self,x):self.coins=x;self.pos=0
    def guards(self):
        assert bytes(self.workspace[:self.offset])==b'\xa5'*self.offset
        assert bytes(self.workspace[self.offset+self.capacity:])==b'\xa5'*(len(self.workspace)-self.offset-self.capacity)
def main():
    p=argparse.ArgumentParser();p.add_argument('--left',type=Path,required=True);p.add_argument('--right',type=Path,required=True)
    p.add_argument('--count',type=int,default=100);p.add_argument('--workspace',type=int,default=65536,help='Equal workspace capacity for both compared libraries');p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if not 1<=a.count<=1000:raise ValueError('Count outside 1..1000')
    if not 32<=a.workspace<=262144 or a.workspace%32:raise ValueError('Workspace must be a multiple of32 in32..262144')
    out=a.output.resolve()
    if out.exists() or (os.name=='nt' and out.drive.upper()!='D:'):raise ValueError('Fresh D: output required on Windows')
    paths=[a.left.resolve(),a.right.resolve()];sessions=[Session(x,a.workspace) for x in paths];rows=[]
    for level in (44,65,87):
        keys=[];sizes=m.Sizes();assert sessions[0].lib.lc_get_sizes(level,C.byref(sizes))==0
        for key_id in (0,1):
            outputs=[];seed=hashlib.shake_256(b'representation-key-v1'+bytes([level,key_id])).digest(32)
            for s in sessions:
                pk=(m.U*sizes.public_key)();sk=(m.U*sizes.secret_key)();s.reset_coins(seed)
                assert s.lib.lc_keypair(C.byref(s.context),level,pk,len(pk),sk,len(sk))==0
                assert s.pos==32;s.guards();outputs.append((bytes(pk),bytes(sk)))
            assert outputs[0]==outputs[1];keys.append(outputs[0])
        digest=hashlib.sha256();observations=[]
        for i in range(a.count):
            key_id=i%2;pk,sk=map(octets,keys[key_id]);n=(0,32,1024,4096)[(i//2)%4];dn=(0,1,32,255)[(i//8)%4]
            seed=b'representation-sign-v1'+bytes([level])+i.to_bytes(4,'little')
            msg=octets(hashlib.shake_256(seed+b'm').digest(n));domain=octets(hashlib.shake_256(seed+b'd').digest(dn))
            coins=hashlib.shake_256(seed+b'r').digest(32);signatures=[];peaks=[]
            for s in sessions:
                sig=(m.U*(sizes.signature+32))();C.memset(sig,0xa5,len(sig));s.reset_coins(coins)
                assert s.lib.lc_sign(C.byref(s.context),level,sig,sizes.signature,msg,n,domain,dn,sk,len(sk))==0
                assert s.pos==32 and bytes(sig[sizes.signature:])==b'\xa5'*32
                peaks.append(s.context.arena_high_water)
                assert s.lib.lc_verify(C.byref(s.context),level,sig,sizes.signature,msg,n,domain,dn,pk,len(pk))==0
                sig[i%sizes.signature]^=1
                assert s.lib.lc_verify(C.byref(s.context),level,sig,sizes.signature,msg,n,domain,dn,pk,len(pk))==-6
                sig[i%sizes.signature]^=1;s.guards();signatures.append(bytes(sig[:sizes.signature]))
            assert signatures[0]==signatures[1],(level,i);digest.update(signatures[0])
            observations.append({'case':i,'key_id':key_id,'message_bytes':n,'domain_bytes':dn,'arena_peak_pair':peaks})
        rows.append({'parameter':level,'count':a.count,'complete_signatures_byte_equal':True,'same_context_alternating_keys':True,
          'mutated_signatures_rejected':True,'entropy_bytes_per_signature':32,'signature_aggregate_sha256':digest.hexdigest(),'cases':observations})
    result={'status':'PASS','libraries':[{'path':str(x),'sha256':sha(x)} for x in paths],'records':rows,'workspace_capacity_bytes':a.workspace,
      'test_sha256':sha(Path(__file__)),'library_loader_source_sha256':sha(ROOT/'tests/platform/compare_public.py'),
      'formal_performance_collected':False,'secrets_written':False,
      'limits':'Complete byte equality for deterministic test inputs and natural signing retries; not exhaustive retries, full malformed-domain campaign, timing or a proof of constant time.'}
    out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8');print('PASS',3*a.count,'complete signatures')
if __name__=='__main__':main()
