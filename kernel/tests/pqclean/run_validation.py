"""Run the public-vector, full-transcript and fixed-boundary PQClean checks."""
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
import argparse, hashlib, record_io as json, os, subprocess, sys
ROOT=Path(__file__).resolve().parents[2]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def desc(p):return {'path':str(p.resolve()),'sha256':sha(p)}
def write(p,x):p.write_bytes((json.dumps(x,indent=2)+'\n').encode())
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,nargs='+',required=True);p.add_argument('--reference',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--count',type=int,default=100);a=p.parse_args()
 out=a.output.resolve();libs=[x.resolve() for x in a.library];reference=a.reference.resolve()
 if out.exists() or not 1<=a.count<=1000 or (os.name=='nt' and out.drive.upper()!='D:'):raise ValueError('Fresh output, bounded count and Windows D: required')
 if len(libs)!=len(set(libs)) or not all(x.is_file() for x in [*libs,reference]):raise ValueError('Explicit distinct library inputs required')
 out.mkdir(parents=True);(out/'tmp').mkdir();env=os.environ.copy();env.update(TEMP=str(out/'tmp'),TMP=str(out/'tmp'),TMPDIR=str(out/'tmp'),PYTHONDONTWRITEBYTECODE='1')
 identities=[desc(x) for x in libs];refdesc=desc(reference);calls=[];artifacts=[]
 tools=[ROOT/'tests/platform/check_public_acvp.py',ROOT/'tests/platform/compare_public.py',ROOT/'tests/pqclean/check_adapter.py',Path(__file__)]
 sources=[desc(x) for x in tools]
 def run(argv,label):
  result=subprocess.run(list(map(str,argv)),cwd=ROOT,env=env,capture_output=True,text=True,encoding='utf-8',errors='replace')
  log=out/(label+'.log');log.write_bytes(json.capture_bytes((result.stdout+result.stderr).encode()));calls.append(dict(argv=list(map(str,argv)),exit_code=result.returncode,log=desc(log)));write(out/'commands.xml',calls)
  if result.returncode:raise RuntimeError(label+' failed; complete logs retained')
  print(label,'PASS',flush=True)
 try:
  acvp=out/'public_acvp.xml';run([sys.executable,'-B',tools[0],'--library',*libs,'--output',acvp],'public_acvp');data=json.loads(acvp.read_text())
  if data['counts']!={'PASS':645*len(libs),'FAIL':0,'OUTSIDE_PUBLIC_SCOPE':405*len(libs)}:raise ValueError('Unexpected vector scope/count')
  artifacts.append(desc(acvp))
  for index,lib in enumerate(libs):
   difference=out/f'differential_{index}.xml';boundary=out/f'boundaries_{index}.xml'
   run([sys.executable,'-B',tools[1],'--left',reference,'--right',lib,'--resource-mode','record','--count',a.count,'--output',difference],f'differential_{index}')
   run([sys.executable,'-B',tools[2],'--library',lib,'--output',boundary],f'boundaries_{index}')
   artifacts.extend([desc(difference),desc(boundary)])
  if identities!=[desc(x) for x in libs] or refdesc!=desc(reference) or sources!=[desc(x) for x in tools]:raise ValueError('Inputs changed during checks')
  write(out/'result.xml',dict(schema='pqclean.clean.validation.v1',status='PASS',libraries=identities,reference=refdesc,test_sources=sources,artifacts=artifacts,commands=desc(out/'commands.xml'),public_acvp_cases_per_library=645,outside_public_scope_cases_per_library=405,full_byte_and_rng_sequences_per_parameter=a.count,parameters=[512,768,1024,44,65,87],timing_collected=False,heap_failure_recovery_claimed=False))
 except Exception as e:write(out/'failure.xml',dict(status='FAIL',error=str(e),libraries=identities,reference=refdesc,test_sources=sources,commands=desc(out/'commands.xml') if (out/'commands.xml').exists() else None));raise
if __name__=='__main__':main()
