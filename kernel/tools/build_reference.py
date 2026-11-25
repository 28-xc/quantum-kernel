"""Rebuild the bundled mature full-memory or low-memory reference offline."""
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
import argparse, hashlib, record_io as json, subprocess, sys

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--reference-source',type=Path,default=Path(__file__).resolve().parents[2]/'reference-source/current')
 p.add_argument('--configuration',choices=['full','lowram'],required=True)
 p.add_argument('--backend',choices=['portable','x86_64','aarch64'],required=True)
 p.add_argument('--optimization',choices=['O3','Os'],default='O3')
 p.add_argument('--compiler',default='gcc');p.add_argument('--ar',default='gcc-ar');p.add_argument('--nm',default='nm');p.add_argument('--objdump',default='objdump');p.add_argument('--size',default='size')
 p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 source=a.reference_source.resolve();out=a.output.resolve()
 if not (source/'tools/build.py').is_file() or not (source/'configs/source_files.xml').is_file():raise ValueError('Bundled reference source is incomplete')
 if out.exists() or out.is_relative_to(source) or source.is_relative_to(out):raise ValueError('Use a fresh output outside the source tree')
 out.mkdir(parents=True);plan=out/'plan.xml';build=out/'build';records=[]
 cmds=[['plan','--mode','hosted','--configuration','reference-'+a.configuration,'--backend',a.backend,'--opt',a.optimization,'--lto','--probe-count','100','--cc',a.compiler,'--ar',a.ar,'--nm',a.nm,'--objdump',a.objdump,'--size',a.size,'--output',str(plan)],['build','--plan',str(plan),'--output',str(build)]]
 for i,args in enumerate(cmds):
  cmd=[sys.executable,'-X','utf8','-B',str(source/'tools/build.py'),*args]
  q=subprocess.run(cmd,capture_output=True,text=True,encoding='utf8',errors='replace')
  log=out/('plan.log'if i==0 else 'build.log');log.write_text(json.capture_text(q.stdout+q.stderr),encoding='utf8')
  records.append(dict(command=cmd,exit_code=q.returncode,log=log.name,log_sha256=hashlib.sha256(log.read_bytes()).hexdigest()))
  (out/'commands.xml').write_text(json.dumps(records,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
  if q.returncode:raise RuntimeError('Reference build failed; inspect '+str(log))
 print(json.dumps(dict(status='PASS',configuration='reference-'+a.configuration,backend=a.backend,optimization=a.optimization,lto=True,plan_sha256=hashlib.sha256(plan.read_bytes()).hexdigest(),artifacts=str(build/'artifacts')),ensure_ascii=False))

if __name__=='__main__':main()
