"""Compile actual sampler/cache/codec code and run bounded representation checks.

No engine C is changed. The real SCU prefix is copied verbatim to an isolated
translation unit; only the trailing macro-cleanup block is omitted so this
test can call internal functions. This is not the released library binary.
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
import argparse, hashlib, record_io as json, os, shutil, subprocess
ROOT=Path(__file__).resolve().parents[2]
SRC=ROOT/'src/dsa_compact/build/sign_bitmap_stream_alias/adapted'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True)
    p.add_argument('--cc',default='gcc');p.add_argument('--native-x86',action='store_true')
    p.add_argument('--sanitize',choices=('none','undefined'),default='none')
    p.add_argument('--cache-count',type=int,choices=(1,4,8,16),default=16)
    p.add_argument('--codec',type=int,choices=(0,1,2),default=1);a=p.parse_args()
    out=a.output.resolve()
    if out.exists():raise ValueError('Use a fresh output directory')
    if os.name=='nt' and out.drive.upper()!='D:':raise ValueError('D: required')
    out.mkdir(parents=True);(out/'tmp').mkdir();cc=shutil.which(a.cc)
    if not cc:raise ValueError('Compiler not found')
    env=os.environ.copy();env.update(TMP=str(out/'tmp'),TEMP=str(out/'tmp'),TMPDIR=str(out/'tmp'))
    env['PATH']=str(Path(cc).parent)+os.pathsep+env.get('PATH','')
    text=(SRC/'mldsa_native.c').read_text(encoding='utf-8');marker='/* Macro #undef\'s'
    source=out/'actual_probe.c';source.write_text(text[:text.index(marker)]+'\n#include "probe_impl.h"\n',encoding='utf-8')
    bound={x.relative_to(ROOT).as_posix():sha(x) for x in SRC.rglob('*') if x.is_file() and x.suffix in ('.h','.c','.S','.inc')}
    for x in Path(__file__).parent.glob('*'):
        if x.is_file():bound[x.relative_to(ROOT).as_posix()]=sha(x)
    commands=[];rows=[]
    def run(cmd,label):
        r=subprocess.run(list(map(str,cmd)),cwd=ROOT,env=env,capture_output=True,text=True,encoding='utf-8',errors='replace')
        log=out/(label+'.log');log.write_text(json.capture_text(r.stdout+r.stderr),encoding='utf-8')
        commands.append({'argv':list(map(str,cmd)),'exit_code':r.returncode,'log':log.name,'sha256':sha(log)})
        (out/'commands.xml').write_text(json.dumps(commands,indent=2)+'\n',encoding='utf-8')
        if r.returncode:raise RuntimeError(label+' failed; see '+str(log))
        return r.stdout
    version=run([cc,'--version'],'compiler').splitlines()[0]
    for level in (44,65,87):
        for bits in (24,32):
            name=f'p{level}-b{bits}';exe=out/(name+('.exe' if os.name=='nt' else ''))
            flags=['-O2','-std=c11','-ffunction-sections','-fdata-sections','-Wl,--gc-sections',
             '-I'+str(ROOT/'include'),'-I'+str(ROOT/'src/dsa_packed'),'-I'+str(SRC),'-I'+str(Path(__file__).parent),
             '-DMLD_CONFIG_FILE="lc_dsa_config.h"','-DMLD_CONFIG_PARAMETER_SET='+str(level),'-DMLD_CONFIG_MULTILEVEL_WITH_SHARED',
             '-DMLD_CONFIG_REDUCE_RAM','-DLC_DSA_ALIAS_SIGN_CP=1','-DLC_DSA_ALIAS_VERIFY_TMP=1','-DLC_DSA_STREAM_KEYGEN=1',
             '-DLC_DSA_PACK_W0=1','-DLC_DSA_W0_CODEC='+str(a.codec),'-DLC_DSA_A_CACHE_POLYS='+str(a.cache_count),'-DLC_DSA_A_CACHE_BITS='+str(bits)]
            extra=[]
            if a.native_x86:
                flags+=['-march=native','-DMLD_CONFIG_USE_NATIVE_BACKEND_ARITH','-DMLD_CONFIG_USE_NATIVE_BACKEND_FIPS202']
                extra=[SRC/'mldsa_native_asm.S']
            if a.sanitize!='none':flags+=['-fsanitize=undefined','-fno-sanitize-recover=all']
            run([cc,*flags,source,*extra,'-o',exe],name+'-build')
            result=json.loads(run([exe],name+'-run'));result['executable_sha256']=sha(exe);rows.append(result)
    for rel,h in bound.items():
        if sha(ROOT/rel)!=h:raise ValueError('Source changed during experiment')
    result={'status':'PASS','compiler':version,'native_x86':a.native_x86,'sanitizer':a.sanitize,'codec':a.codec,
      'source_sha256':bound,'extracted_prefix_sha256':sha(source),'records':rows,'formal_performance_collected':False,
      'scope':'Actual cache helper plus real sampler/backend permutation; full q-domain cache-reader and lowpart signed boundary/differential probes. Instrumentation is a separate TU, not a released binary or a complete-signature test.'}
    (out/'result.xml').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8');print(json.dumps(rows,indent=2))
if __name__=='__main__':main()
