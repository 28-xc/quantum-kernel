"""Ordinary finite endpoint/seeded checks of actual bitmap/high/low helpers.

Copies only the SCU pre-cleanup prefix to make static functions callable.
No released binary or engine C is changed. No timing or coverage feedback.
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
HERE=Path(__file__).resolve().parent
SRC=ROOT/'src/dsa_compact/build/sign_bitmap_stream_alias/adapted'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def write(p,x):p.write_text(json.dumps(x,indent=2)+'\n',encoding='utf-8')
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--cc',default='gcc');ap.add_argument('--native-x86',action='store_true')
    ap.add_argument('--sanitize',choices=['none','undefined'],default='none');a=ap.parse_args()
    out=a.output.resolve()
    if out.exists() or (os.name=='nt' and out.drive.upper()!='D:'):raise ValueError('Fresh D: output required on Windows')
    out.mkdir(parents=True);(out/'tmp').mkdir();cc=shutil.which(a.cc)
    if not cc:raise ValueError('Compiler not found')
    env=os.environ.copy();env.update(TMP=str(out/'tmp'),TEMP=str(out/'tmp'),TMPDIR=str(out/'tmp'))
    env['PATH']=str(Path(cc).parent)+os.pathsep+env.get('PATH','')
    text=(SRC/'mldsa_native.c').read_text(encoding='utf-8');source=out/'actual_bitmap_probe.c'
    source.write_text(text[:text.index("/* Macro #undef's")]+ '\n#include "bitmap_probe_impl.h"\n',encoding='utf-8')
    bound={p.relative_to(ROOT).as_posix():sha(p) for p in SRC.rglob('*') if p.is_file() and p.suffix in ('.h','.c','.S','.inc')}
    for p in [HERE/'bitmap_probe_impl.h',Path(__file__),ROOT/'src/dsa_packed/lc_dsa_config.h',ROOT/'src/dsa_packed/lc_dsa_arena.h']:bound[p.relative_to(ROOT).as_posix()]=sha(p)
    result={'status':'RUNNING','source_hashes':bound,'extracted_prefix_sha256':sha(source),'native_x86':a.native_x86,'sanitizer':a.sanitize,'formal_timing':False,'coverage_guided':False,'records':[],'commands':[]}
    def run(cmd,label):
        p=subprocess.run(list(map(str,cmd)),cwd=ROOT,env=env,capture_output=True,text=True,encoding='utf-8',errors='replace')
        log=out/(label+'.log');log.write_text(json.capture_text(p.stdout+p.stderr),encoding='utf-8')
        result['commands'].append({'argv':list(map(str,cmd)),'exit_code':p.returncode,'log':log.name,'log_sha256':sha(log)})
        write(out/'result.xml',result)
        if p.returncode:raise RuntimeError(label+' failed; evidence preserved')
        return p.stdout
    try:
        result['compiler']=run([cc,'--version'],'compiler').splitlines()[0]
        for level in [44,65,87]:
            for codec in [0,1]:
                for full in [0,1]:
                    name=f'p{level}-c{codec}-h{full}';exe=out/(name+('.exe' if os.name=='nt' else ''))
                    flags=['-O2','-std=c11','-ffunction-sections','-fdata-sections','-Wl,--gc-sections',
                       '-I'+str(ROOT/'include'),'-I'+str(ROOT/'src/dsa_packed'),'-I'+str(SRC),'-I'+str(HERE),
                       '-DMLD_CONFIG_FILE="lc_dsa_config.h"','-DMLD_CONFIG_PARAMETER_SET='+str(level),'-DMLD_CONFIG_MULTILEVEL_WITH_SHARED',
                       '-DMLD_CONFIG_REDUCE_RAM','-DLC_DSA_ALIAS_SIGN_CP=1','-DLC_DSA_ALIAS_VERIFY_TMP=1','-DLC_DSA_STREAM_KEYGEN=1',
                       '-DLC_DSA_PACK_W0=1','-DLC_DSA_W0_CODEC='+str(codec),'-DLC_DSA_A_CACHE_POLYS=0','-DLC_DSA_RETAIN_FULL_HIGH='+str(full)]
                    extra=[]
                    if a.native_x86:
                        flags+=['-march=native','-flto','-fwhole-program','-DMLD_CONFIG_USE_NATIVE_BACKEND_ARITH','-DMLD_CONFIG_USE_NATIVE_BACKEND_FIPS202']
                        # Bind only entities reached by this helper probe. The
                        # release build also assembles entities separately;
                        # concatenating both polyz files repeats local labels.
                        suffix='88' if level==44 else '32'
                        extra=[SRC/f'src/native/x86_64/src/mldsa_poly_decompose_{suffix}_avx2_asm.S',SRC/'src/fips202/native/x86_64/src/keccak_f1600_x4_avx2_asm.S']
                    if a.sanitize!='none':flags+=['-fsanitize=undefined','-fno-sanitize-recover=all']
                    run([cc,*flags,source,*extra,'-o',exe],name+'-build')
                    row=json.loads(run([exe],name+'-run'));assert row['status']=='PASS';row['exe_sha256']=sha(exe);result['records'].append(row)
        for rel,h in bound.items():
            if sha(ROOT/rel)!=h:raise ValueError('Source changed during check: '+rel)
        result['status']='PASS'
        result['scope']='Actual helper SCU, fixed endpoints and fixed seed; full HighBits before challenge hashing, predicate after all signing norm checks, exact signed 19/20 bit bounds and Hint encoding. Not an exhaustive proof or actual released binary.'
    except Exception as e:
        result.update(status='FAIL_OR_INCOMPLETE',error=str(e));raise
    finally:write(out/'result.xml',result)
    print(json.dumps({'status':result['status'],'records':len(result['records'])}))
if __name__=='__main__':main()
