"""Target actual SIGN_ONLY/cache-prefill helpers, without editing the core."""
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
import argparse, hashlib, record_io as json, os, shutil, subprocess
ROOT=Path(__file__).resolve().parents[2];HERE=Path(__file__).resolve().parent
SRC=ROOT/'src/dsa_compact/build/sign_bitmap_stream_alias/adapted'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',type=Path,required=True);ap.add_argument('--cc',default='gcc');ap.add_argument('--native-x86',action='store_true');ap.add_argument('--initial-blocks',type=int,choices=[1,5],default=5);ap.add_argument('--counts',nargs='+',type=int,default=[0,3,40,56]);ap.add_argument('--bits',nargs='+',type=int,choices=[24,32],default=[24,32]);a=ap.parse_args()
 out=a.output.resolve();cc=shutil.which(a.cc)
 if not cc or out.exists() or out.drive.upper()!='D:' or any(n not in (0,3,16,30,40,56) for n in a.counts):raise ValueError('Compiler, fresh D: output, and bounded counts required')
 out.mkdir(parents=True);(out/'tmp').mkdir();env=os.environ.copy();env.update(TMP=str(out/'tmp'),TEMP=str(out/'tmp'),TMPDIR=str(out/'tmp'),PYTHONDONTWRITEBYTECODE='1');env['PATH']=str(Path(cc).parent)+os.pathsep+env.get('PATH','')
 source=out/'actual_staged.c';text=(SRC/'mldsa_native.c').read_text(encoding='utf-8');source.write_text(text[:text.index("/* Macro #undef's")]+ '\n#include "staged_probe_impl.h"\n',encoding='utf-8')
 bound={p.relative_to(ROOT).as_posix():sha(p) for p in SRC.rglob('*') if p.is_file() and p.suffix.lower() in ('.c','.h','.s','.inc')}
 for p in (HERE/'run_staged.py',HERE/'staged_probe_impl.h'):bound[p.relative_to(ROOT).as_posix()]=sha(p)
 commands=[];rows=[]
 def run(cmd,label):
  p=subprocess.run(list(map(str,cmd)),cwd=ROOT,env=env,capture_output=True,text=True,encoding='utf-8',errors='replace');log=out/(label+'.log');log.write_text(json.capture_text(p.stdout+p.stderr),encoding='utf-8')
  commands.append({'argv':list(map(str,cmd)),'exit_code':p.returncode,'log':log.name,'sha256':sha(log)});(out/'commands.xml').write_text(json.dumps(commands,indent=2)+'\n',encoding='utf-8')
  if p.returncode:raise RuntimeError(label+' failed; original log retained')
  return p.stdout
 try:
  compiler=run([cc,'--version'],'compiler').splitlines()[0]
  for count in a.counts:
   for level in (44,65,87):
    for bits in a.bits:
     label=f'c{count}-p{level}-b{bits}';exe=out/(label+'.exe')
     flags=['-O2','-std=c11','-ffunction-sections','-fdata-sections','-Wl,--gc-sections','-I'+str(ROOT/'include'),'-I'+str(ROOT/'src/dsa_packed'),'-I'+str(SRC),'-I'+str(HERE),'-DMLD_CONFIG_FILE="lc_dsa_config.h"','-DMLD_CONFIG_PARAMETER_SET='+str(level),'-DMLD_CONFIG_MULTILEVEL_WITH_SHARED','-DMLD_CONFIG_REDUCE_RAM','-DLC_DSA_ALIAS_SIGN_CP=1','-DLC_DSA_ALIAS_VERIFY_TMP=1','-DLC_DSA_STREAM_KEYGEN=1','-DLC_DSA_PACK_W0=1','-DLC_DSA_W0_CODEC=1','-DLC_DSA_A_CACHE_POLYS='+str(count),'-DLC_DSA_A_CACHE_BITS='+str(bits),'-DLC_DSA_A_CACHE_SIGN_ONLY=1','-DLC_DSA_A_CACHE_BATCH4=1','-DTEST_INITIAL_BLOCKS='+str(a.initial_blocks)]
     if a.initial_blocks==1:flags+=['-DMLD_POLY_UNIFORM_NBLOCKS=1']
     extra=[]
     if a.native_x86:flags+=['-march=native','-DMLD_CONFIG_USE_NATIVE_BACKEND_ARITH','-DMLD_CONFIG_USE_NATIVE_BACKEND_FIPS202'];extra=[SRC/'mldsa_native_asm.S']
     run([cc,*flags,source,*extra,'-o',exe],label+'-build');r=json.loads(run([exe],label+'-run'))
     assert r['status']=='PASS' and r['parameter']==level and r['requested_count']==count and r['retained_count']==min(count,{44:16,65:30,87:56}[level]) and r['cache_bits']==bits and r['initial_blocks_test_override']==a.initial_blocks
     r['executable_sha256']=sha(exe);rows.append(r);print(label+' PASS',flush=True)
  for name,h in bound.items():
   if sha(ROOT/name)!=h:raise ValueError('Source changed during targeted probe: '+name)
  result={'status':'PASS','compiler':compiler,'native_x86':a.native_x86,'source_hashes':bound,'extracted_prefix_sha256':sha(source),'records':rows,'formal_timing':False,'scope':'Separate extracted actual helper TU; unused full API paths abort. Scalar unbound/fill/hit, exact prefix bytes after four-lane prefill, stale-state reset, legal domain, native permutation and guards. Not full API, not resource evidence. Initial-blocks=1 is a forced continuation test, never the release build.'}
  (out/'result.xml').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
 except Exception as e:(out/'failure.xml').write_text(json.dumps({'status':'FAIL_OR_INCOMPLETE','error':str(e),'completed':rows},indent=2)+'\n',encoding='utf-8');raise
if __name__=='__main__':main()
