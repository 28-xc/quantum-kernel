"""Prepare or execute actual-header preprocessor guard fixtures; no linking.

Preparation is the default. Pass --execute --cc <compiler> to run each fixed
fixture through that compiler's preprocessor. Expected rejection is checked by
its exact diagnostic substring as well as exit status.
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
import argparse, hashlib, record_io as json, subprocess

ROOT=Path(__file__).resolve().parents[2]
SIGN='src/dsa_compact/build/sign_bitmap_stream_alias/adapted/src/sign.c'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--execute',action='store_true');ap.add_argument('--cc',default='gcc');a=ap.parse_args()
    out=a.output.resolve()
    if out.exists()or out.is_relative_to(ROOT):raise ValueError('Fresh output outside source required')
    out.mkdir(parents=True);(out/'mldsa_native_config.h').write_text('/* Guard fixture: backend configuration intentionally empty. */\n',encoding='utf-8')
    text=(ROOT/SIGN).read_text(encoding='utf-8');start=text.index('#ifndef LC_DSA_PARTIAL_DENSE_ROWS');end=text.index('#include "rounding.h"',start);guard=text[start:end]
    common=dict(__ASSEMBLER__=1,MLD_CONFIG_REDUCE_RAM=1,MLDSA_K=8,MLDSA_L=7,LC_DSA_PARTIAL_DENSE_ROWS=5,
                LC_DSA_A_CACHE_COUNT=35,LC_DSA_INPLACE_AY=1,LC_DSA_A_PLANES24=1,LC_DSA_DENSE_SIGN_ROWS=1,
                LC_DSA_CACHED_DOT_TILE=1,LC_DSA_STREAM_CACHE24=1,LC_DSA_A_CACHE_BITS=24,
                LC_DSA_A_CACHE_POLYS=56,LC_DSA_A_CACHE_SIGN_ONLY=1)
    x86=dict(common,__AVX2__=1,LC_DSA_MATRIX_INTERLEAVED=1)
    arm=dict(common,__aarch64__=1,LC_BUILD_ARM_PROFILE=1,LC_DSA_STREAM_NEON=1,LC_DSA_STREAM_DIRECT_STATE=1,MLD_SYS_LITTLE_ENDIAN=1,LC_DSA_ARM_SPEED32=1)
    cases=[]
    def add(name,defs,error=None,native=False):cases.append(dict(name=name,defines=defs,error=error,native=native))
    add('x86-valid',x86);add('arm-valid',arm)
    add('separate-valid',dict(x86,LC_DSA_PARTIAL_DENSE_ROWS=4,LC_DSA_A_CACHE_COUNT=28,LC_DSA_PARTIAL_DENSE_SEPARATE_Y=1))
    add('bad-separate',dict(x86,LC_DSA_PARTIAL_DENSE_SEPARATE_Y=2),'partial dense separate Y')
    add('missing-rows',dict(x86,LC_DSA_PARTIAL_DENSE_ROWS=0,LC_DSA_PARTIAL_DENSE_SEPARATE_Y=1),'separate Y requires')
    add('too-many-rows',dict(x86,LC_DSA_PARTIAL_DENSE_ROWS=7),'partial dense rows must')
    add('x86-no-interleaved',dict(x86,LC_DSA_MATRIX_INTERLEAVED=0),'partial dense x86 sampling')
    add('arm-no-neon',dict(arm,LC_DSA_STREAM_NEON=0),'partial dense AArch64 sampling')
    add('arm-no-direct-state',dict(arm,LC_DSA_STREAM_DIRECT_STATE=0),'partial dense AArch64 sampling')
    d=dict(arm);d.pop('MLD_SYS_LITTLE_ENDIAN');add('arm-no-little-endian',d,'canonical little-endian')
    add('arm-custom-order',dict(arm,MLD_USE_NATIVE_NTT_CUSTOM_ORDER=1),'canonical little-endian')
    add('cache-shape',dict(x86,LC_DSA_A_CACHE_COUNT=34),'exact whole cached rows')
    add('no-inplace',dict(x86,LC_DSA_INPLACE_AY=0),'exact whole cached rows')
    add('no-planes',dict(x86,LC_DSA_A_PLANES24=0),'exact whole cached rows')
    add('session-partial',dict(x86,LC_DSA_PUBLIC_A_SESSION=1),'mutually exclusive')
    add('session-prefill',dict(x86,LC_DSA_PUBLIC_A_SESSION=1,LC_DSA_PARTIAL_DENSE_ROWS=0,LC_DSA_A_CACHE_COUNT=56,LC_DSA_A_CACHE_BATCH4=1),'public session forbids call-owned batch prefill')
    n=dict(__ASSEMBLER__=1,MLD_CONFIG_REDUCE_RAM=1,LC_DSA_PUBLIC_A_SESSION=1,LC_NATIVE_A_SESSION_POLYS=34)
    add('native-session-valid',n,native=True)
    add('native-session-zero',dict(n,LC_NATIVE_A_SESSION_POLYS=0),'prefix must be in 1..56',True)
    add('native-session-large',dict(n,LC_NATIVE_A_SESSION_POLYS=57),'prefix must be in 1..56',True)
    add('native-session-duplicate',dict(n,LC_NATIVE_MATRIX_CACHE=1),'must not both allocate',True)
    add('native-session-no-api',dict(n,LC_DSA_PUBLIC_A_SESSION=0),'requires the public session API',True)
    add('native-session-pct',dict(n,MLD_CONFIG_KEYGEN_PCT=1),'nested key-generation PCT',True)
    add('native-s1-range',dict(n,LC_NATIVE_S1_CACHE=8),'outside the supported',True)
    add('native-s2-range',dict(n,LC_NATIVE_S2_CACHE=9),'outside the supported',True)
    add('native-t0-range',dict(n,LC_NATIVE_T0_CACHE=9),'outside the supported',True)
    records=[]
    for c in cases:
        header='baselines/mldsa/lc_dsa_config.h'if c['native']else'src/dsa_packed/lc_dsa_config.h'
        code=''.join(f'#define {k} {v}\n'for k,v in c['defines'].items())+f'#include "{(ROOT/header).as_posix()}"\n'+(''if c['native']else guard)
        p=out/(c['name']+'.c');p.write_text(code,encoding='utf-8')
        argv=[a.cc,'-E','-P','-x','c','-U__aarch64__','-U__AVX2__','-I'+str(out),str(p)]
        record=dict(**c,fixture_sha256=sha(p),argv=argv)
        if a.execute:
            r=subprocess.run(argv,capture_output=True,text=True);(out/(c['name']+'.stdout')).write_text(json.capture_text(r.stdout),encoding='utf-8');(out/(c['name']+'.stderr')).write_text(r.stderr,encoding='utf-8')
            ok=r.returncode==0 if c['error']is None else r.returncode!=0 and c['error']in r.stderr
            record.update(exit_code=r.returncode,matched=ok)
        records.append(record)
    result=dict(status=('PASS'if all(r['matched']for r in records)else'FAIL')if a.execute else'PREPARED_NOT_EXECUTED',
                records=records,source_sha256={p:sha(ROOT/p)for p in [SIGN,'src/dsa_packed/lc_dsa_config.h','baselines/mldsa/lc_dsa_config.h']},
                scope='Preprocessor feature contract only; no cryptographic execution or linking')
    (out/'result.xml').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8');print(json.dumps({'status':result['status'],'fixtures':len(records)}))
    if result['status']=='FAIL':raise SystemExit(1)
if __name__=='__main__':main()
