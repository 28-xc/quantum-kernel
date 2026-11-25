"""Build and check the actual platform signed-24 helpers against scalar math."""
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
import argparse, hashlib, record_io as json, os, platform, shutil, subprocess
ROOT=Path(__file__).resolve().parents[2];HERE=Path(__file__).resolve().parent
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--cc',default='gcc');p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);(a.output/'tmp').mkdir()
    cc=shutil.which(a.cc);assert cc
    env=dict(os.environ,PATH=str(Path(cc).parent)+os.pathsep+os.environ.get('PATH',''),TMP=str(a.output/'tmp'),TEMP=str(a.output/'tmp'),TMPDIR=str(a.output/'tmp'))
    exe=a.output/('vector24.exe' if os.name=='nt' else 'vector24');arch=platform.machine().lower();flag='-mcpu=native' if arch in ('aarch64','arm64') else '-march=native'
    result=dict(status='RUNNING',architecture=arch,commands=[],source_hashes={})
    def run(label,argv):
        q=subprocess.run(list(map(str,argv)),capture_output=True,text=True,env=env,timeout=120)
        log=a.output/(label+'.log');log.write_text(json.capture_text(q.stdout+q.stderr))
        result['commands'].append(dict(argv=list(map(str,argv)),exit_code=q.returncode,log_sha256=sha(log)))
        (a.output/'result.xml').write_text(json.dumps(result,indent=2)+'\n');assert q.returncode==0,label
        return q.stdout
    result['compiler']=run('compiler',[cc,'--version']).splitlines()[0]
    run('compile',[cc,'-Os',flag,'-std=c11','-I'+str(ROOT/'src/dsa_packed'),HERE/'vector24.c','-o',exe])
    result['test']=json.loads(run('run',[exe]));result['image_sha256']=sha(exe)
    for f in [Path(__file__),HERE/'vector24.c',*[ROOT/'src/dsa_packed'/n for n in ('lc_codec24_neon.h','lc_stream_neon.h','lc_stream4_vector.h')]]:result['source_hashes'][f.relative_to(ROOT).as_posix()]=sha(f)
    result['status']='PASS';(a.output/'result.xml').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result['test']))
if __name__=='__main__':main()
