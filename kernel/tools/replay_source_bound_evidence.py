"""Replay recorded component experiments using their exact bound source snapshot."""
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
import argparse, hashlib, record_io as json, os, shutil, subprocess, sys
from pathlib import Path,PurePosixPath
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def load(p):return json.loads(Path(p).read_text(encoding='utf-8'))
def main():
    p=argparse.ArgumentParser();p.add_argument('--bundle',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--kind',choices=['arithmetic','compilation'],required=True);a=p.parse_args()
    bundle=a.bundle.resolve();out=a.output.resolve();snapshot=bundle/'data/historical-source-bindings';doc=load(snapshot/'manifest.xml')
    if out.exists()or out.is_relative_to(bundle):raise ValueError('Use fresh output outside the delivered bundle')
    if doc['schema']!='lattice.experiment_source_snapshot.v1':raise ValueError('Unexpected source snapshot')
    seen=set()
    for r in doc['source_files']:
        rel=PurePosixPath(r['path'])
        if rel.is_absolute()or'..'in rel.parts or':'in r['path']or'\\'in r['path']or r['path']in seen:raise ValueError('Invalid snapshot path')
        seen.add(r['path']);q=snapshot/'source'/r['path']
        if q.stat().st_size!=r['bytes']or sha(q)!=r['sha256']:raise ValueError('Experiment source identity differs: '+r['path'])
    out.mkdir(parents=True);data=bundle/'data';env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',PYTHONUTF8='1')
    if a.kind=='arithmetic':
        original=data/'verification-speed32-arithmetic/reproduce.py'
        argv=[sys.executable,'-X','utf8','-B',str(original),'--input',str(original.parent),'--source',str(snapshot/'source'),'--output',str(out/'arithmetic')]
    else:
        # The original verifier locates source and observations relative to its
        # own file. Recreate that layout with exact evidence bytes and exact
        # experiment source; execute the original unchanged verifier.
        stage=out/'layout';shutil.copytree(snapshot/'source',stage/'source')
        shutil.copytree(data/'source-equivalence',stage/'data/source-equivalence')
        for platform in ['windows','arm']:
            name='new-signing-speed32-'+platform;target=stage/'data'/name;target.mkdir(parents=True)
            shutil.copyfile(data/name/'observations.xml',target/'observations.xml')
        original=data/'source-equivalence/verify.py';script=stage/'data/source-equivalence/verify.py'
        if sha(original)!=sha(script):raise ValueError('Original verification script differs')
        argv=[sys.executable,'-X','utf8','-B',str(script)]
    completed=subprocess.run(argv,capture_output=True,text=True,encoding='utf-8',env=env,timeout=300)
    (out/'stdout.log').write_text(json.capture_text(completed.stdout),encoding='utf-8');(out/'stderr.log').write_text(completed.stderr,encoding='utf-8')
    result=dict(schema='lattice.source_bound_replay.v1',status='PASS'if completed.returncode==0 else'FAIL',kind=a.kind,
        source_snapshot_manifest_sha256=sha(snapshot/'manifest.xml'),source_files_verified=len(seen),original_verifier_sha256=sha(original),
        exit_code=completed.returncode,stdout_sha256=sha(out/'stdout.log'),stderr_sha256=sha(out/'stderr.log'),
        scope='Exact experiment source identities and unchanged recorded evidence; current deployment validation has independent image bindings.')
    (out/'result.xml').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8');print(json.dumps(result))
    if completed.returncode:raise SystemExit(completed.returncode)
if __name__=='__main__':main()
