"""Bounded native sampling of complete operations; separate from latency runs."""
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
import argparse, hashlib, record_io as json, os, subprocess, time
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def dump(p,x):p.write_text(json.dumps(x,indent=2)+'\n',encoding='utf-8')
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--library',type=Path,required=True);p.add_argument('--crypto-prefix',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--cpu',type=int,required=True);p.add_argument('--parameters',type=int,nargs='+',default=[512,768,1024,44,65,87]);p.add_argument('--operations',type=int,nargs='+',default=[0,1,2]);p.add_argument('--frequency',type=int,default=199);a=p.parse_args()
 if os.name=='nt' or a.output.exists() or not 49<=a.frequency<=499 or set(a.parameters)-{512,768,1024,44,65,87} or set(a.operations)-{0,1,2}:raise ValueError('Invalid sampling configuration')
 out=a.output.resolve();out.mkdir(parents=True);lib=a.library.resolve();prefix=a.crypto_prefix.resolve();crypto=prefix/'lib/libcrypto.so.3';records=[]
 env=os.environ.copy();env['LD_LIBRARY_PATH']=str(crypto.parent);started=time.monotonic()
 identity=dict(library_sha256=sha(lib),crypto_sha256=sha(crypto),source_hashes={x.name:sha(x) for x in [HERE/'profile_driver.c',HERE/'driver.c',Path(__file__),ROOT/'include/latticecore.h']},cpu=a.cpu,frequency=a.frequency,scope='User-space PMU cycle sampling; fixed key/message per run, fresh operation entropy; analyze target core DSO samples. Not elapsed-time benchmark data.')
 dump(out/'identity.xml',identity)
 def run(cmd,label,timeout=300):
  with (out/(label+'.stdout')).open('wb') as stdout,(out/(label+'.stderr')).open('wb') as stderr:r=subprocess.run(list(map(str,cmd)),cwd=ROOT,env=env,stdout=stdout,stderr=stderr,timeout=timeout)
  records.append(dict(argv=list(map(str,cmd)),exit_code=r.returncode,stdout=label+'.stdout',stderr=label+'.stderr',stdout_sha256=sha(out/(label+'.stdout')),stderr_sha256=sha(out/(label+'.stderr'))));dump(out/'commands.xml',records)
  if r.returncode:raise RuntimeError(label+' failed')
 try:
  exe=out/'profile_driver';run(['gcc','-O3','-g','-fno-omit-frame-pointer','-std=c11','-I'+str(ROOT/'include'),'-I'+str(prefix/'include'),HERE/'profile_driver.c','-L'+str(crypto.parent),'-lcrypto','-ldl','-Wl,-rpath,'+str(crypto.parent),'-o',exe],'build')
  identity['driver_sha256']=sha(exe);dump(out/'identity.xml',identity);run(['perf','--version'],'perf_version')
  cells=[]
  for parameter in a.parameters:
   for operation in a.operations:
    name=f'{parameter}_{operation}';count=150000 if parameter>100 else 15000 if operation==1 else 50000;data=out/(name+'.data')
    run(['sudo','-n','env','LD_LIBRARY_PATH='+str(crypto.parent),'perf','record','-e','cycles:u','-F',str(a.frequency),'--call-graph','dwarf,4096','-o',data,'--',exe,lib,parameter,operation,count,20260924,a.cpu],name+'_record')
    run(['sudo','-n','chown',str(os.getuid())+':'+str(os.getgid()),data],name+'_data_owner')
    result=json.loads((out/(name+'_record.stdout')).read_text())
    if result['status']!='PASS' or result['parameter']!=parameter or result['operation']!=operation:raise ValueError('Invalid workload status')
    run(['perf','report','-i',data,'--stdio','--no-children','--call-graph','none','--percent-limit','0','--sort','dso,symbol','--field-separator',';'],name+'_report')
    run(['perf','report','-i',data,'--header-only','--stdio'],name+'_header')
    cells.append(dict(parameter=parameter,operation=operation,iterations=count,data=data.name,sha256=sha(data),workload=result));dump(out/'progress.xml',dict(completed=len(cells),latest=name))
  if sha(lib)!=identity['library_sha256'] or sha(crypto)!=identity['crypto_sha256']:raise ValueError('Library changed')
  dump(out/'result.xml',dict(status='PASS',identity=identity,cells=cells,commands_sha256=sha(out/'commands.xml'),elapsed_seconds=time.monotonic()-started))
 except Exception as e:dump(out/'failure.xml',dict(error=str(e),commands=records));raise
if __name__=='__main__':main()
