"""Normal bounded ARM demonstrations of the actual public API and fixed-pool application."""
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
import argparse, ctypes as C, datetime, hashlib, record_io as json, os, platform, subprocess, sys
P=C.c_void_p;N=C.c_size_t;I=C.c_int
class Context(C.Structure):
 _fields_=[('workspace',P),('workspace_bytes',N),('random',P),('random_user',P),('arena_high_water',N),('allocations',N),('allocation_failures',N),('last_error',I)]
class Sizes(C.Structure):_fields_=[(n,N) for n in ('public_key','secret_key','ciphertext','shared_secret','signature')]
class Flow(C.Structure):_fields_=[(n,N) for n in ('pool','workspace','peak')]+[(n,C.c_uint) for n in ('observed','completed','temporary_clear','pool_clear','canaries')]+[('rc',I)]
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def require(ok,message):
 if not ok:raise ValueError(message)
def write(p,d):p.write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
class Arena:
 def __init__(self,n):
  self.raw=C.create_string_buffer(n+128);self.n=n;self.p=(C.addressof(self.raw)+63)&~31;C.memset(self.p-32,0xa5,n+64);C.memset(self.p,0,n)
 def intact(self):return C.string_at(self.p-32,32)==b'\xa5'*32 and C.string_at(self.p+self.n,32)==b'\xa5'*32
 def close(self):C.memset(C.addressof(self.raw),0,len(self.raw))
def buffer(n):return C.create_string_buffer(n)
class Demo:
 def __init__(self,base):
  self.base=base;self.config=json.loads((base/'configuration.xml').read_text(encoding='utf-8'));self.w=self.config['workspace_bytes']
  for x in self.config['artifacts'].values():require(sha(base/x['path'])==x['sha256'],'Artifact identity differs')
  self.bridge=C.CDLL(str(base/self.config['artifacts']['bridge']['path']));self.bridge.td_open.argtypes=[C.c_char_p];self.bridge.td_open.restype=I
  self.library=(base/self.config['artifacts']['library']['path']).resolve();require(self.bridge.td_open(os.fsencode(self.library))==0,'Native loader failed')
  self.bridge.td_loaded_path.restype=C.c_char_p;require(Path(os.fsdecode(self.bridge.td_loaded_path())).resolve()==self.library,'Loaded image differs')
  self.bridge.td_symbol.argtypes=[C.c_char_p];self.bridge.td_symbol.restype=P
  signatures={'lc_get_sizes':[I,C.POINTER(Sizes)],'lc_context_init':[C.POINTER(Context),P,N,P,P],
   'lc_keypair':[C.POINTER(Context),I,P,N,P,N],'lc_encaps':[C.POINTER(Context),I,P,N,P,N,P,N],
   'lc_decaps':[C.POINTER(Context),I,P,N,P,N,P,N],'lc_sign':[C.POINTER(Context),I,P,N,P,N,P,N,P,N],
   'lc_verify':[C.POINTER(Context),I,P,N,P,N,P,N,P,N]}
  self.f={k:C.CFUNCTYPE(I,*v)(self.bridge.td_symbol(k.encode())) for k,v in signatures.items()}
  self.arena=Arena(self.w);self.ctx=Context();require(self.init(self.w)==0,'Context init failed')
 def init(self,w):return self.f['lc_context_init'](C.byref(self.ctx),self.arena.p,w,None,None)
 def call(self,name,*args):
  rc=self.f[name](C.byref(self.ctx),*args);require(self.arena.intact(),'Workspace guard changed')
  return dict(operation=name.removeprefix('lc_'),return_code=rc,peak_bytes=self.ctx.arena_high_water,guards_ok=True)
 def one(self,p):
  size=Sizes();require(self.f['lc_get_sizes'](p,C.byref(size))==0,'Size query failed');pk=buffer(size.public_key);sk=buffer(size.secret_key);objects=[pk,sk]
  rows=[];negative=[]
  try:
   rows.append(self.call('lc_keypair',p,pk,size.public_key,sk,size.secret_key));require(rows[-1]['return_code']==0,'Key generation failed')
   if p>100:
    ct=buffer(size.ciphertext);ss=buffer(32);peer=buffer(32);objects += [ct,ss,peer]
    rows.append(self.call('lc_encaps',p,ct,size.ciphertext,ss,32,pk,size.public_key));require(rows[-1]['return_code']==0,'Encapsulation failed')
    rows.append(self.call('lc_decaps',p,peer,32,ct,size.ciphertext,sk,size.secret_key));require(rows[-1]['return_code']==0 and ss.raw==peer.raw,'Shared secret differs')
    ct[0]=bytes([ct.raw[0]^1]);expected=hashlib.shake_256(sk.raw[-32:]+ct.raw).digest(32)
    r=self.call('lc_decaps',p,peer,32,ct,size.ciphertext,sk,size.secret_key);r.update(check='FIPS203 implicit rejection',expected_output_matches=peer.raw==expected);require(r['return_code']==0 and r['expected_output_matches'],'Implicit rejection oracle differs');negative.append(r)
    r=self.call('lc_decaps',p,peer,32,ct,size.ciphertext-1,sk,size.secret_key);require(r['return_code']==-2,'Wrong ciphertext length accepted');r['check']='ciphertext length';negative.append(r)
   else:
    msg=buffer(32);C.memmove(msg,b'device public key demonstration!!',32);domain=buffer(0);sig=buffer(size.signature);objects += [msg,sig]
    rows.append(self.call('lc_sign',p,sig,size.signature,msg,32,domain,0,sk,size.secret_key));require(rows[-1]['return_code']==0,'Signing failed')
    rows.append(self.call('lc_verify',p,sig,size.signature,msg,32,domain,0,pk,size.public_key));require(rows[-1]['return_code']==0,'Verification failed')
    sig[0]=bytes([sig.raw[0]^1]);r=self.call('lc_verify',p,sig,size.signature,msg,32,domain,0,pk,size.public_key);require(r['return_code']==-6,'Modified signature accepted');r['check']='modified signature';negative.append(r)
    r=self.call('lc_verify',p,sig,size.signature-1,msg,32,domain,0,pk,size.public_key);require(r['return_code']==-2,'Wrong signature length accepted');r['check']='signature length';negative.append(r)
   return dict(parameter=p,sizes={n:getattr(size,n) for n,_ in Sizes._fields_},normal=rows,negative=negative,normal_pass=3,negative_pass=len(negative),peak_bytes=max(x['peak_bytes'] for x in rows+negative),guards_ok=self.arena.intact())
  finally:
   for x in objects:C.memset(C.addressof(x),0,C.sizeof(x))
 def selftest(self):
  rows=[self.one(p) for p in (512,768,1024,44,65,87)]
  print('参数         正常  负例  工作区峰值 / 容量')
  for r in rows:print('%-12s 3/3   2/2   %5d / %d B'%('ML-KEM-'+str(r['parameter']) if r['parameter']>100 else 'ML-DSA-'+str(r['parameter']),r['peak_bytes'],self.w))
  print('PASS 18 正常操作，12 负例；无效密文输出匹配，修改签名 rc=-6')
  return dict(normal_operations=18,negative_cases=12,failures=0,rows=rows,random_source='OS CSPRNG',workspace_bytes=self.w,same_workspace=True)
 def flow(self):
  f=self.bridge.td_flow;f.argtypes=[C.c_char_p,I,I,N,C.POINTER(Flow)];f.restype=I;rows=[]
  for k,d in ((512,44),(768,65),(1024,87)):
   r=Flow();rc=f(os.fsencode(self.base/self.config['artifacts']['application']['path']),k,d,self.w,C.byref(r));v={n:getattr(r,n) for n,_ in Flow._fields_}
   require(rc==0 and r.observed==63 and r.temporary_clear and r.pool_clear and r.canaries,'Complete fixed-pool flow failed')
   rows.append(dict(kem=k,dsa=d,**v))
   if k==768:
    print('ML-KEM-768 / ML-DSA-65')
    print('PASS 密钥生成 → 公钥签署 → 验签 → 封装 → 解封装')
    print('应用池 %d B（含工作区 %d B）；清理、边界检查 PASS'%(r.pool,r.workspace))
  print('PASS 3 组参数流程')
  return dict(pairs=rows,random_source='OS CSPRNG',layout='signature reuse',identity='reused authority',state_cleanup=True)
 def workspace(self):
  rows=[self.one(p) for p in (512,44,768,65,1024,87)];size=Sizes();self.f['lc_get_sizes'](768,C.byref(size));pk=buffer(size.public_key);sk=buffer(size.secret_key)
  try:
   require(self.init(32)==0,'Insufficient-capacity context init failed');C.memset(pk,0xcc,len(pk));C.memset(sk,0xcc,len(sk))
   short=self.call('lc_keypair',768,pk,len(pk),sk,len(sk));require(short['return_code']==-5 and pk.raw==bytes(len(pk)) and sk.raw==bytes(len(sk)),'Capacity error or output cleanup differs')
   require(self.init(self.w)==0,'Recovery initialization failed');recovery=self.one(768)
   print('同一 %d B 工作区：6 组参数、18 项操作 PASS'%self.w)
   print('容量 32 B：ML-KEM-768 密钥生成 rc=-5；失败输出清零 PASS')
   print('恢复 %d B：密钥生成 / 封装 / 解封装 PASS'%self.w)
   print('边界检查 PASS')
   return dict(workspace_bytes=self.w,alignment=32,same_workspace=True,rows=rows,insufficient=dict(capacity=32,output_zero=True,**short),recovery=recovery,guards_ok=self.arena.intact())
  finally:C.memset(pk,0,len(pk));C.memset(sk,0,len(sk))
 def close(self):self.arena.close();self.bridge.td_close()
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('command',choices=['info','selftest','flow','workspace']);p.add_argument('--bundle',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
 status=0;d=None;record=dict(schema='lattice.terminal_demo.v1',command=a.command,utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
 try:
  d=Demo(a.bundle.resolve());record['library_sha256']=sha(d.library);record['build_sha256']=sha(d.base/'build.xml')
  if a.command=='info':
   build=json.loads((d.base/'build.xml').read_text(encoding='utf-8'));record['environment']=build['environment'];record['artifacts']=d.config['artifacts'];record['resources']=d.config.get('resources')
   print(platform.machine()+' | '+build['compiler'].splitlines()[0])
   print(d.config['backend']+' | ML-KEM 512/768/1024 | ML-DSA 44/65/87')
   if d.config.get('resources'):
    r=d.config['resources'];print('密码核心：RAM %d B；程序 %d B；工作区 %d B'%(r['R'],r['P'],r['W']))
  else:record['results']=getattr(d,a.command)()
  record['status']='PASS'
 except Exception as e:record.update(status='FAIL',error=str(e));print('检查失败：'+str(e));status=1
 finally:
  if d:d.close()
  write(a.output/'result.xml',record)
 return status
if __name__=='__main__':sys.exit(main())
