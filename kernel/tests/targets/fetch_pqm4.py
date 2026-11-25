"""Fetch the exact upstream revisions used by the Cortex-M4 resource comparison."""
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
import argparse, record_io as json, subprocess

PQM4='5e5cc76d0b072ee7077e58afcbc619a1a67a53b4'
MUPQ='ddcccedb2db9d0250856bd58ee5c46c61e506c5d'

def fetch(url,revision,path,records):
 path.mkdir(parents=True,exist_ok=False)
 for command in (['git','init'],['git','remote','add','origin',url],
                 ['git','fetch','--depth','1','origin',revision],
                 ['git','-c','core.symlinks=true','checkout','--detach','FETCH_HEAD']):
  result=subprocess.run(command,cwd=path,capture_output=True,text=True,timeout=300)
  records.append(dict(repository=url,revision=revision,command=command,exit_code=result.returncode,stdout=result.stdout,stderr=result.stderr))
  if result.returncode:raise RuntimeError('Pinned upstream fetch failed; log retained')
 actual=subprocess.check_output(['git','rev-parse','HEAD'],cwd=path,text=True).strip()
 if actual!=revision:raise ValueError('Upstream revision mismatch')
 (path/'SOURCE_COMMIT').write_text(revision+'\n')

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',required=True,type=Path);a=p.parse_args();output=a.output.resolve()
 if output.exists():raise ValueError('Fresh upstream output directory required')
 records=[]
 try:
  fetch('https://github.com/mupq/pqm4.git',PQM4,output,records)
  sub=output/'mupq'
  if sub.is_dir() and not any(sub.iterdir()):sub.rmdir()
  fetch('https://github.com/mupq/mupq.git',MUPQ,sub,records)
 finally:
  if output.exists():(output/'fetch_records.xml').write_text(json.dumps(records,indent=2)+'\n')
 print(json.dumps(dict(status='PASS',pqm4=PQM4,mupq=MUPQ)))
if __name__=='__main__':main()
