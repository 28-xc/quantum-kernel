"""Run quick or full functional qualification directly on explicit images."""
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
import argparse, datetime, hashlib, record_io as json, os, subprocess, sys, time
ROOT=Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--library',type=Path,required=True);p.add_argument('--reference',type=Path,required=True)
    p.add_argument('--workspace',type=int,required=True);p.add_argument('--mode',choices=['quick','full'],default='quick')
    p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    out=a.output.resolve();lib=a.library.resolve();ref=a.reference.resolve()
    if out.exists() or not lib.is_file() or not ref.is_file() or not 32<=a.workspace<=262144:raise ValueError('Fresh output and valid library/capacity required')
    out.mkdir(parents=True);(out/'tmp').mkdir()
    env=dict(os.environ,TEMP=str(out/'tmp'),TMP=str(out/'tmp'),TMPDIR=str(out/'tmp'),PYTHONDONTWRITEBYTECODE='1',PYTHONUTF8='1')
    images=[dict(role=r,filename=x.name,sha256=sha(x))for r,x in [('selected',lib),('reference',ref)]]
    count=200 if a.mode=='full' else 2;sigcount=300 if a.mode=='full' else 2
    tasks=[('acvp','tests/platform/check_public_acvp.py',['--library',lib,'--workspace',a.workspace,'--output',out/'acvp.xml']),
           ('complete-outputs','tests/platform/compare_public.py',['--left',lib,'--right',ref,'--resource-mode','record','--count',count,'--output',out/'complete-outputs.xml']),
           ('signatures','tests/representation/check_signatures.py',['--left',lib,'--right',ref,'--count',sigcount,'--workspace',a.workspace,'--output',out/'signatures.xml']),
           ('normal-capacity','tests/normal_capacity/run.py',['--library',lib,'--capacity',a.workspace,'--output',out/'normal-capacity.xml'])]
    result=dict(schema='lattice.release_validation.v1',status='RUNNING',mode=a.mode,utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),images=images,runner_sha256=sha(__file__),workspace=a.workspace,records=[])
    def save():(out/'result.xml').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    save()
    try:
        for label,source,args in tasks:
            cmd=[sys.executable,'-B',str(ROOT/source),*map(str,args)];start=time.monotonic()
            proc=subprocess.run(cmd,cwd=ROOT,env=env,capture_output=True,text=True,encoding='utf-8',timeout=600)
            log=out/(label+'.log');log.write_text(json.capture_text(proc.stdout+proc.stderr),encoding='utf-8')
            record=dict(test=label,source=source,source_sha256=sha(ROOT/source),exit_code=proc.returncode,seconds=time.monotonic()-start,log=log.name,log_sha256=sha(log))
            result['records'].append(record);save()
            if proc.returncode:raise RuntimeError(label+' failed')
            data=json.loads((out/(label+'.xml')).read_text(encoding='utf-8'));assert data['status']=='PASS'
            record['result_sha256']=sha(out/(label+'.xml'));print(label,'PASS',flush=True)
        assert [sha(lib),sha(ref)]==[x['sha256']for x in images]
        result.update(status='PASS',counts=dict(acvp=json.loads((out/'acvp.xml').read_text())['counts'],complete_sequences=6*count,complete_signature_pairs=3*sigcount,normal_capacity_records=json.loads((out/'normal-capacity.xml').read_text())['total_records']))
    except BaseException as e:
        result.update(status='FAILED_OR_INCOMPLETE',error=str(e));raise
    finally:save()
    print(json.dumps(result['counts']))
if __name__=='__main__':main()
