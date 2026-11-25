"""Compile the production RNG service and exercise its failure contract."""
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
ROOT=Path(__file__).resolve().parents[2]
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser(); p.add_argument('--output',type=Path,required=True);p.add_argument('--cc',default='gcc');a=p.parse_args()
 out=a.output.resolve()
 if out.exists(): raise ValueError('Use a fresh output directory')
 if os.name=='nt' and out.drive.upper()!='D:': raise ValueError('D: output required')
 out.mkdir(parents=True);(out/'tmp').mkdir();cc=shutil.which(a.cc)
 if not cc: raise ValueError('Compiler unavailable')
 env=os.environ.copy();env.update(TEMP=str(out/'tmp'),TMP=str(out/'tmp'));records=[]
 for name,src,extra in [('hosted','random_hosted.c',[]),('callback','random_hosted.c',['-DLC_RNG_CALLBACK_ONLY=1']),('linux_faults','random_faults.c',['-I'+str(ROOT/'tests/platform/fake')])]:
  exe=out/(name+('.exe' if os.name=='nt' else ''));cmd=[cc,'-O2','-std=c11','-Wall','-Wextra','-Werror','-I'+str(ROOT/'include'),*extra,str(ROOT/'tests/platform'/src)]
  if name!='linux_faults':cmd += [str(ROOT/'src/platform/random.c')]
  if name=='hosted' and os.name=='nt':cmd+=['-lbcrypt']
  cmd+=['-o',str(exe)]
  for stage,args in [('build',cmd),('run',[str(exe)])]:
   q=subprocess.run(args,env=env,capture_output=True,text=True);log=out/(name+'_'+stage+'.txt');log.write_text(json.capture_text(q.stdout+q.stderr),encoding='utf-8')
   records.append({'name':name,'stage':stage,'argv':args,'exit_code':q.returncode,'log':log.name,'log_sha256':sha(log)})
   (out/'commands.xml').write_text(json.dumps(records,indent=2)+'\n',encoding='utf-8')
   if q.returncode:raise RuntimeError(str(log))
 # Prove the callback-only platform object itself has no undefined OS/libc
 # references. This is not a complete bare-metal firmware/linker validation.
 obj=out/'callback_freestanding.o';nm=shutil.which('nm')
 if not nm:raise ValueError('nm required for dependency inspection')
 for stage,args in [('build',[cc,'-Os','-std=c11','-ffreestanding','-fno-builtin','-DLC_RNG_CALLBACK_ONLY=1','-I'+str(ROOT/'include'),'-c',str(ROOT/'src/platform/random.c'),'-o',str(obj)]),('undefined',[nm,'-u',str(obj)])]:
  q=subprocess.run(args,env=env,capture_output=True,text=True);log=out/('freestanding_'+stage+'.txt');log.write_text(json.capture_text(q.stdout+q.stderr),encoding='utf-8')
  records.append({'name':'callback_freestanding','stage':stage,'argv':args,'exit_code':q.returncode,'log':log.name,'log_sha256':sha(log)})
  (out/'commands.xml').write_text(json.dumps(records,indent=2)+'\n',encoding='utf-8')
  if q.returncode or (stage=='undefined' and q.stdout.strip()):raise RuntimeError(str(log))
 result={'status':'PASS','host':platform.platform(),'callback_platform_undefined_symbols':[],'linux_fault_test':'scripted production branch; not native Linux syscall execution' if os.name=='nt' else 'scripted production Linux syscall boundary','source_hashes':{p.relative_to(ROOT).as_posix():sha(p) for p in [Path(__file__),ROOT/'src/platform/random.c',ROOT/'include/lc_platform.h',*sorted((ROOT/'tests/platform').rglob('*.c')),*sorted((ROOT/'tests/platform').rglob('*.h'))]},'commands':records,'formal_performance_collected':False}
 (out/'result.xml').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8');print('RNG contracts PASS')
if __name__=='__main__':main()
