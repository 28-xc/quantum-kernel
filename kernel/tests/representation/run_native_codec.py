"""Finite complete value-domain and endpoint checks of selected AVX2 codecs."""
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
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);p.add_argument('--cc',default='gcc');a=p.parse_args()
    assert not a.output.exists();a.output.mkdir(parents=True);(a.output/'tmp').mkdir()
    cc=shutil.which(a.cc);assert cc
    env=dict(os.environ,PATH=str(Path(cc).parent)+os.pathsep+os.environ.get('PATH',''),TMP=str(a.output/'tmp'),TEMP=str(a.output/'tmp'))
    text=(SRC/'mldsa_native.c').read_text();source=a.output/'actual_selected_codec.c'
    source.write_text(text[:text.index("/* Macro #undef's")]+ '\n#include "native_codec_impl.h"\n')
    result=dict(status='RUNNING',formal_timing=False,compiler=None,records=[],commands=[],source_hashes={})
    def run(label,cmd):
        proc=subprocess.run(list(map(str,cmd)),capture_output=True,text=True,env=env,timeout=120)
        log=a.output/(label+'.log');log.write_text(json.capture_text(proc.stdout+proc.stderr))
        result['commands'].append(dict(command=list(map(str,cmd)),exit_code=proc.returncode,log_sha256=sha(log)))
        (a.output/'result.xml').write_text(json.dumps(result,indent=2)+'\n');assert proc.returncode==0,label
        return proc.stdout
    result['compiler']=run('compiler',[cc,'--version']).splitlines()[0]
    for level,polyz in [(44,1),(65,0),(65,1),(87,1)]:
        name=f'p{level}-polyz{polyz}';exe=a.output/(name+('.exe' if os.name=='nt' else ''))
        flags=['-Os','-std=c11','-march=native','-ffunction-sections','-fdata-sections','-Wl,--gc-sections','-I'+str(ROOT/'include'),'-I'+str(ROOT/'src/dsa_packed'),'-I'+str(SRC),'-I'+str(HERE),'-DMLD_CONFIG_FILE="lc_dsa_config.h"','-DMLD_CONFIG_PARAMETER_SET='+str(level),'-DMLD_CONFIG_MULTILEVEL_WITH_SHARED','-DMLD_CONFIG_REDUCE_RAM','-DLC_DSA_ALIAS_SIGN_CP=1','-DLC_DSA_ALIAS_VERIFY_TMP=1','-DLC_DSA_STREAM_KEYGEN=1','-DLC_DSA_PACK_W0=1','-DLC_DSA_W0_CODEC=1','-DLC_DSA_A_CACHE_POLYS=0','-DLC_DSA_EARLY_HINT_FLAGS=1','-DLC_DSA_W0_VECTOR=1','-DLC_DSA_W0_POLYZ20='+str(polyz),'-DMLD_CONFIG_USE_NATIVE_BACKEND_ARITH','-DMLD_CONFIG_USE_NATIVE_BACKEND_FIPS202']
        assembly=[SRC/'src/native/x86_64/src/mldsa_polyz_unpack_19_avx2_asm.S'] if polyz and level!=44 else []
        run(name+'-build',[cc,*flags,'-flto','-fwhole-program',source,*assembly,'-o',exe])
        row=json.loads(run(name+'-run',[exe]));row['image_sha256']=sha(exe);result['records'].append(row)
    for f in [Path(__file__),HERE/'native_codec_impl.h',source,*[x for x in SRC.rglob('*') if x.is_file() and x.suffix in ('.h','.c','.S','.inc')]]:
        result['source_hashes'][f.relative_to(ROOT).as_posix() if f.is_relative_to(ROOT) else f.name]=sha(f)
    result['status']='PASS';result['scope']='Each representable value tested once across full rows, six endpoints at each coefficient position; actual selected helper and native polyz decoder. The 19-bit vector path is also tested as an available representation.'
    (a.output/'result.xml').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result['records']))
if __name__=='__main__':main()
