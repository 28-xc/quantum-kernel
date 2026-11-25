# Scoped adaptation of tests/platform/check_public_acvp.py; arithmetic and vectors unchanged.
"""Published vectors via the eight public APIs; no internal entry substitution.

Adapted from the earlier public-vector harness. Internal ML-DSA/HashML-DSA
vectors are counted explicitly outside this public API's scope, never as passes.
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
import argparse, ctypes as C, hashlib, record_io as json, os, sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"platform"))
from compare_public import library,Context,Sizes,RANDOM,U,sha
ROOT=Path(__file__).resolve().parents[2]
def buf(x):return (U*x)() if isinstance(x,int) else (U*len(x)).from_buffer_copy(x)
def main():
 p=argparse.ArgumentParser();p.add_argument('--library',type=Path,nargs='+',required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--parameters',type=int,nargs='+',required=True);a=p.parse_args()
 if not a.parameters or len(set(a.parameters))!=len(a.parameters) or not set(a.parameters)<={512,768,1024,44,65,87}:raise ValueError('Explicit standard parameter subset required')
 output=a.output.resolve()
 if output.exists():raise ValueError('Use a fresh output JSON')
 if os.name=='nt' and output.drive.upper()!='D:':raise ValueError('D: output required')
 folder=ROOT/'tests/vectors/acvp';rows=[];binaries=[]
 for path in a.library:
  path=path.resolve();d=library(path);digest=sha(path);binaries.append({'path':str(path),'sha256':digest});entropy=[b'',0];state=Context()
  @RANDOM
  def supplied(user,out,n):
   data,pos=entropy
   if n>len(data)-pos:return -1
   C.memmove(out,data[pos:pos+n],n);entropy[1]+=n;return 0
  for category in sorted(x for x in folder.iterdir() if x.is_dir()):
   prompt=json.loads((category/'prompt.xml').read_text());want=json.loads((category/'expectedResults.xml').read_text());expected={t['tcId']:t for g in want['testGroups'] for t in g['tests']}
   for group in prompt['testGroups']:
    level=int(group['parameterSet'].split('-')[-1]);z=Sizes();size_status=d.lc_get_sizes(level,C.byref(z))
    if level not in a.parameters:
     assert size_status==-8,('Expected unsupported parameter',level,size_status)
     rows.extend({'library_sha256':digest,'category':category.name,'tgId':group['tgId'],'tcId':tc['tcId'],'parameter':level,'status':'UNSUPPORTED_AS_CONFIGURED'} for tc in group['tests'])
     continue
    assert size_status==0
    W=262144;raw=buf(W+128);address=(C.addressof(raw)+63)&~31
    for tc in group['tests']:
     row={'library_sha256':digest,'category':category.name,'tgId':group['tgId'],'tcId':tc['tcId'],'parameter':level}
     if group.get('preHash')=='preHash' or group.get('signatureInterface')=='internal':
      row.update(status='OUTSIDE_PUBLIC_SCOPE',reason='Internal-mu and HashML-DSA entry points are not exposed');rows.append(row);continue
     C.memset(raw,0xa5,len(raw));assert d.lc_context_init(C.byref(state),address,W,supplied,None)==0
     entropy[:]=[b'\0'*64,0];target=expected[tc['tcId']];pk=buf(z.public_key);sk=buf(z.secret_key);ct=buf(z.ciphertext);sig=buf(z.signature);ss=buf(32);call=prompt['mode']
     if call=='keyGen':
      iskem=level>100;entropy[:]=[bytes.fromhex(tc['d']+tc['z'] if iskem else tc['seed']),0]
      rc=d.lc_keypair(C.byref(state),level,pk,len(pk),sk,len(sk));ok=rc==0 and bytes(pk)==bytes.fromhex(target['ek' if iskem else 'pk']) and bytes(sk)==bytes.fromhex(target['dk' if iskem else 'sk'])
     elif call=='encapDecap':
      function=group['function']
      if function in ('encapsulation','encapsulationKeyCheck'):
       key=buf(bytes.fromhex(tc['ek']));entropy[:]=[bytes.fromhex(tc.get('m','00'*32)),0]
       rc=d.lc_encaps(C.byref(state),level,ct,len(ct),ss,32,key,len(key));ok=((rc==0)==target['testPassed']) if function.endswith('KeyCheck') else (rc==0 and bytes(ct)==bytes.fromhex(target['c']) and bytes(ss)==bytes.fromhex(target['k']))
      else:
       if 'dk' in tc:key=buf(bytes.fromhex(tc['dk']))
       else:
        entropy[:]=[bytes.fromhex(tc['d']+tc['z']),0];assert d.lc_keypair(C.byref(state),level,pk,len(pk),sk,len(sk))==0;key=sk
       ciphertext=buf(bytes.fromhex(tc.get('c','00'*z.ciphertext)))
       rc=d.lc_decaps(C.byref(state),level,ss,32,ciphertext,len(ciphertext),key,len(key));ok=((rc==0)==target['testPassed']) if function.endswith('KeyCheck') else (rc==0 and bytes(ss)==bytes.fromhex(target['k']))
     else:
      message=buf(bytes.fromhex(tc['message']));domain=buf(bytes.fromhex(tc.get('context','')))
      if call=='sigGen':
       key=buf(bytes.fromhex(tc['sk']));entropy[:]=[bytes.fromhex(tc.get('rnd','00'*32)),0]
       rc=d.lc_sign(C.byref(state),level,sig,len(sig),message,len(message),domain,len(domain),key,len(key));ok=rc==0 and bytes(sig)==bytes.fromhex(target['signature'])
      else:
       key=buf(bytes.fromhex(tc['pk']));signature=buf(bytes.fromhex(tc['signature']))
       rc=d.lc_verify(C.byref(state),level,signature,len(signature),message,len(message),domain,len(domain),key,len(key));ok=(rc==0)==target['testPassed']
     guards=C.string_at(address-32,32)==b'\xa5'*32 and C.string_at(address+W,32)==b'\xa5'*32
     row.update(status='PASS' if ok and guards else 'FAIL',status_code=rc,workspace_bytes=W,arena_highwater=state.arena_high_water,canaries=guards);rows.append(row)
     if row['status']!='PASS':raise AssertionError(row)
   print(path.parent.name,category.name,'selected-scope traversal complete',flush=True)
 result={'status':'PASS','scope':'Retained parameters only; omitted parameters explicitly unsupported, internal/prehash vectors separately outside public interface','binaries':binaries,'selected_parameters':a.parameters,'counts':{s:sum(r['status']==s for r in rows) for s in ('PASS','FAIL','OUTSIDE_PUBLIC_SCOPE','UNSUPPORTED_AS_CONFIGURED')},'source_commit':(folder/'commit.txt').read_text().strip(),'vector_files':{p.relative_to(folder).as_posix():sha(p) for p in sorted(folder.rglob('*.xml'))},'test_source_sha256':sha(Path(__file__)),'records':rows,'formal_performance_collected':False}
 output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
if __name__=='__main__':main()
