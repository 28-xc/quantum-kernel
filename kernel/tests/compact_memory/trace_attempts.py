"""Finite signature diagnostic; the two production cores are unchanged before observation calls are inserted."""
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
import argparse, ctypes as C, difflib, hashlib, importlib.util, record_io as json, re, shutil, subprocess, sys
parser=argparse.ArgumentParser(description='Record complete signature attempt and entropy sequences in two isolated diagnostic builds.')
parser.add_argument('--source',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
args=parser.parse_args();ORIGINAL=args.source.resolve();OUT=args.output.resolve()
if OUT.exists() or OUT.is_relative_to(ORIGINAL) or ORIGINAL.is_relative_to(OUT):raise ValueError('Use a fresh diagnostic directory outside the source tree')
if sys.platform!='linux':raise ValueError('This exact diagnostic recipe uses the Linux shared-library fixture')
OUT.mkdir(parents=True,exist_ok=False)
ROOT=OUT/'source';shutil.copytree(ORIGINAL,ROOT,ignore=shutil.ignore_patterns('.git','__pycache__'))
changes={};patches=[]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
source_files={p.relative_to(ROOT).as_posix():sha(p) for p in sorted(ROOT.rglob('*'))
              if p.is_file() and p.suffix in ('.c','.h','.S','.inc','.py')}
source_identity=hashlib.sha256(json.dumps(source_files,sort_keys=True,separators=(',',':')).encode()).hexdigest()
(OUT/'source_manifest.xml').write_text(json.dumps(dict(schema='lattice.diagnostic_source.v1',files=source_files,identity_sha256=source_identity),indent=2)+'\n')
def change(rel,new):
 p=ROOT/rel;old=p.read_text();before=sha(p);p.write_text(new)
 changes[rel]=dict(before_sha256=before,after_sha256=sha(p));patches.extend(difflib.unified_diff(old.splitlines(True),new.splitlines(True),fromfile=rel,tofile=rel))
rel='src/dsa_compact/build/sign_bitmap_stream_alias/adapted/src/sign.c';text=(ROOT/rel).read_text()
pattern=r'ret = mld_attempt_signature_generation\([\s\S]*?context\);'
matches=list(re.finditer(pattern,text));assert len(matches)==1
m=matches[0];text=text[:m.start()]+'lc_diag_event(attempt,0x80000000u);\n    '+m.group(0)+'\n    lc_diag_event(attempt,(unsigned)ret);'+text[m.end():]
change(rel,'void lc_diag_event(unsigned,unsigned);\n'+text)
rel='src/common/arena.c';text=(ROOT/rel).read_text()
text+='\n/* Finite serial observation only; excluded from performance and resource products. */\nstatic uint64_t lc_trace[4096];static unsigned lc_trace_count;\nvoid lc_diag_event(unsigned attempt,unsigned result) {if(lc_trace_count<4096)lc_trace[lc_trace_count]=((uint64_t)attempt<<32)|result;lc_trace_count++;}\nvoid lc_diag_reset(void) {lc_trace_count=0;}\nunsigned lc_diag_count(void) {return lc_trace_count;}\nuint64_t lc_diag_read(unsigned index) {return index<lc_trace_count&&index<4096?lc_trace[index]:UINT64_MAX;}\n';change(rel,text)
rel='tools/build_variants.py';text=(ROOT/rel).read_text();assert text.count("'lc_error_string']")==1
change(rel,text.replace("'lc_error_string']","'lc_error_string','lc_diag_reset','lc_diag_count','lc_diag_read']"))
(OUT/'instrumentation.patch').write_text(''.join(patches));(OUT/'instrumentation.xml').write_text(json.dumps(dict(source_identity_sha256=source_identity,source_manifest_sha256=sha(OUT/'source_manifest.xml'),changed_files=changes,events='attempt begin marker and unchanged mld_attempt_signature_generation return code',signature_cases=300,timing_collected=False),indent=2)+'\n')
for cfg in ['compact-fixed','compact-recompute']:
 argv=[sys.executable,'-B',str(ROOT/'tools/build_variants.py'),'--output',str(OUT/cfg),'--config',cfg,'--backend','portable','--opt','Os','--lto','--probe-count','2']
 p=subprocess.run(argv,capture_output=True,text=True,timeout=180);(OUT/(cfg+'_build.log')).write_text(json.capture_text(p.stdout+p.stderr));assert p.returncode==0,p.stderr
spec=importlib.util.spec_from_file_location('sig_fixture',ROOT/'tests/representation/check_signatures.py');fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
sessions=[fixture.Session(OUT/cfg/'liblatticecore.so') for cfg in ['compact-fixed','compact-recompute']]
for s in sessions:
 s.requests=[]
 @fixture.m.RANDOM
 def entropy(user,out,n,s=s):
  if n>len(s.coins)-s.pos:return -1
  s.requests.append(n);C.memmove(out,s.coins[s.pos:s.pos+n],n);s.pos+=n;return 0
 s.rng=entropy
 assert s.lib.lc_context_init(C.byref(s.context),C.byref(s.workspace,s.offset),65536,s.rng,None)==0
 s.lib.lc_diag_reset.argtypes=[];s.lib.lc_diag_reset.restype=None;s.lib.lc_diag_count.argtypes=[];s.lib.lc_diag_count.restype=C.c_uint
 s.lib.lc_diag_read.argtypes=[C.c_uint];s.lib.lc_diag_read.restype=C.c_uint64
records=[]
for parameter in [44,65,87]:
 sizes=fixture.m.Sizes();assert sessions[0].lib.lc_get_sizes(parameter,C.byref(sizes))==0
 for index in range(100):
  seed=b'row-attempt-trace-v1'+bytes([parameter])+index.to_bytes(4,'little')
  n=[0,32,1024,4096][index%4];dn=[0,1,32,255][(index//4)%4]
  message=fixture.octets(hashlib.shake_256(seed+b'm').digest(n));domain=fixture.octets(hashlib.shake_256(seed+b'd').digest(dn))
  outputs=[]
  for s in sessions:
   pk=(fixture.m.U*sizes.public_key)();sk=(fixture.m.U*sizes.secret_key)();sig=(fixture.m.U*sizes.signature)()
   s.reset_coins(hashlib.shake_256(seed+b'k').digest(32));s.requests=[]
   assert s.lib.lc_keypair(C.byref(s.context),parameter,pk,len(pk),sk,len(sk))==0 and s.requests==[32]
   s.reset_coins(hashlib.shake_256(seed+b'r').digest(32));s.requests=[];s.lib.lc_diag_reset()
   assert s.lib.lc_sign(C.byref(s.context),parameter,sig,len(sig),message,n,domain,dn,sk,len(sk))==0
   count=s.lib.lc_diag_count();assert 2<=count<=4096 and count%2==0
   trace=[int(s.lib.lc_diag_read(i)) for i in range(count)]
   assert trace[-1]&0xffffffff==0 and s.requests==[32] and s.pos==32
   assert s.lib.lc_verify(C.byref(s.context),parameter,sig,len(sig),message,n,domain,dn,pk,len(pk))==0
   outputs.append((bytes(pk),bytes(sk),bytes(sig),trace,s.requests[:]))
  assert outputs[0]==outputs[1],(parameter,index)
  records.append(dict(parameter=parameter,index=index,message_bytes=n,domain_bytes=dn,input_seed_hex=seed.hex(),attempt_events=outputs[0][3],attempts=len(outputs[0][3])//2,random_requests=outputs[0][4],signature_sha256=hashlib.sha256(outputs[0][2]).hexdigest(),public_key_sha256=hashlib.sha256(outputs[0][0]).hexdigest(),complete_bytes_and_trace_equal=True))
(OUT/'observations.xml').write_text(json.dumps(dict(status='PASS',cases=len(records),libraries={cfg:sha(OUT/cfg/'liblatticecore.so') for cfg in ['compact-fixed','compact-recompute']},instrumentation_sha256=sha(OUT/'instrumentation.xml'),records=records),indent=2)+'\n')
print('PASS',len(records),'complete signatures, entropy requests and exact attempt/return sequences')
