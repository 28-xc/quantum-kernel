"""Rebuild a selected firmware or a named control without accessing hardware."""
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
import argparse, record_io as json, hashlib, os, subprocess, sys
from build_support import read,write,sha,require,relative,argument,parse_dependencies,memory_ledger

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--profile',default='cached');ap.add_argument('--output',type=Path,required=True);ap.add_argument('--cc',type=Path,required=True)
 a=ap.parse_args();target=Path(__file__).resolve().parent;out=a.output.resolve();cc=a.cc.resolve(strict=True)
 require(not out.exists() and not out.is_relative_to(target.parents[1]),'Use a fresh output directory outside the source tree')
 registry=read(target/'profiles.xml')['profiles'];require(a.profile in registry,'Unknown profile');entry=registry[a.profile];rp=target/relative(entry['path']);require(sha(rp)==entry['sha256'],'Recipe identity changed');r=read(rp)
 require(sha(cc)==r['compiler']['sha256'],'Compiler differs from the measured toolchain')
 for x in r['toolchain_files']:require(sha(cc.parent/x['relative_to_compiler_directory'])==x['sha256'],'Toolchain differs')
 tools={k:cc.with_name(k)for k in r['tools']}
 for k,p in tools.items():require(sha(p)==r['tools'][k],'Binary tool differs')
 out.mkdir(parents=True);(out/'obj').mkdir();(out/'tmp').mkdir();view=out/'input';view.mkdir();allowed={}
 for logical,x in r['inputs'].items():
  origin=target.parents[1] if x.get('scope')=='project' else target
  p=origin/relative(x['path']);require(sha(p)==x['sha256'],'Source identity changed: '+x['path']);q=view/relative(logical);q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(p.read_bytes());allowed[str(q.resolve()).casefold()]=sha(q)
 for name,x in r['generated'].items():
  p=target/relative(x['path']);require(sha(p)==x['sha256'],'Generated input changed');q=out/relative(name);q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(p.read_bytes());allowed[str(q.resolve()).casefold()]=sha(q)
 roots=dict(INPUT=view,BUILD=out);env=os.environ.copy();env.update(TEMP=str(out/'tmp'),TMP=str(out/'tmp'),PYTHONDONTWRITEBYTECODE='1');commands=[]
 for step in r['steps']:
  argv=[str(tools[step['tool']]),*[argument(v,roots)for v in step['args']]];run=subprocess.run(argv,cwd=out,env=env,capture_output=True,timeout=300)
  log=out/relative(step['log']);log.write_bytes(json.capture_bytes(run.stdout+run.stderr));commands.append(dict(argv=argv,exit_code=run.returncode,log=log.name,log_sha256=sha(log)));write(out/'commands.xml',commands);require(run.returncode==0,'Build failed: '+log.name)
 dependencies={}
 for p in (out/'obj').glob('*.d'):
  for q in parse_dependencies(p):
   require(str(q).casefold()in allowed and sha(q)==allowed[str(q).casefold()],'Unexpected or changed dependency: '+str(q));dependencies[str(q)]=sha(q)
 write(out/'dependencies.xml',dependencies)
 got={k:sha(out/f'latticecore-live.{k}')for k in ('bin','hex')};require(got==r['expected'],'Rebuilt BIN/HEX differ from the measured image')
 ledger,sections=memory_ledger(out/'latticecore-live.elf',(out/'symbols.log').read_text());write(out/'memory-ledger.xml',ledger)
 result=dict(status='EXACT_MEASURED_FIRMWARE_REBUILD_PASS',profile=a.profile,build_id=r['build_id'],recipe_sha256=sha(rp),artifacts=got,resources=ledger,dependencies_sha256=sha(out/'dependencies.xml'),allocated_sections=sections,hardware_access=False,new_measurements=False)
 write(out/'result.xml',result);print(json.dumps(result))
if __name__=='__main__':main()
