"""Separate ASan/UBSan builds of the changed permutation and fixed oracle.

This finite component test is bound to the candidate's exact owner source.
The original release DLL is unchanged and is checked by its own API probes.
"""
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
ROOT=Path(__file__).resolve().parents[3]
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def put(p,x):p.write_text(json.dumps(x,indent=2)+'\n')
def main():
 p=argparse.ArgumentParser();p.add_argument('--candidate',type=Path,required=True);p.add_argument('--compiler',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 out=a.output.resolve();assert not out.exists();out.mkdir(parents=True);(out/'tmp').mkdir()
 candidate=a.candidate.resolve();bound=json.loads((candidate/'result.xml').read_text());owner=ROOT/'configs/shared_keccak_compact/owner_single.c'
 assert sha(owner)==bound['source_files'][str(owner)]
 cc=a.compiler.resolve();env=os.environ.copy();env.update(PATH=str(cc.parent)+os.pathsep+env.get('PATH',''),TEMP=str(out/'tmp'),TMP=str(out/'tmp'),TMPDIR=str(out/'tmp'),ASAN_OPTIONS='halt_on_error=1:detect_leaks=0',UBSAN_OPTIONS='halt_on_error=1')
 oracle=ROOT/'tests/pruning/shared_keccak/oracle.c';commands=[];records=[]
 def run(cmd,name,require_zero=True):
  started=time.monotonic();proc=subprocess.run(list(map(str,cmd)),cwd=out,env=env,capture_output=True,text=True,timeout=120)
  log=out/(name+'.log');log.write_text(json.capture_text(proc.stdout+proc.stderr))
  commands.append(dict(command=list(map(str,cmd)),exit_code=proc.returncode,log=log.name,sha256=sha(log),elapsed_seconds=time.monotonic()-started));put(out/'commands.xml',commands)
  if require_zero:assert proc.returncode==0,name
  return proc
 try:
  version=run([cc,'--version'],'compiler').stdout.splitlines()[0]
  for sanitizer in ['undefined','address']:
   flags=['-O2','-g','-std=c11','-fsanitize='+sanitizer,'-fno-sanitize-recover=all']
   exe=out/(sanitizer+'.exe');run([cc,*flags,'-I'+str(owner.parent),'-I'+str(oracle.parent),'-DMLD_CONFIG_FILE="oracle_config.h"',oracle,owner,'-o',exe],sanitizer+'_build')
   tested=run([exe],sanitizer+'_fixed_oracle');rows=[json.loads(line) for line in tested.stdout.splitlines() if line.startswith('{')]
   assert rows[0]['random_state_pairs']==10000 and rows[0]['original_mldsa_C_oracle_equal']
   for r in rows[1:]:
    data=bytes((i*17+11)%256 for i in range(r['input_bytes']));f=hashlib.shake_128 if r['shake_bits']==128 else hashlib.shake_256
    assert f(data).hexdigest(len(r['output_hex'])//2)==r['output_hex']
   source=out/(sanitizer+'_instrument_control.c')
   if sanitizer=='undefined':source.write_text('#include <limits.h>\nint main(void){volatile int a=INT_MAX,b=1;volatile int c=a+b;return c==0;}\n')
   else:source.write_text('#include <stdlib.h>\nint main(int argc,char**argv){volatile unsigned char*p=(unsigned char*)malloc(8);(void)argv;p[argc+15]=7;free((void*)p);return 0;}\n')
   positive=out/(sanitizer+'_instrument_control.exe');run([cc,*flags,source,'-o',positive],sanitizer+'_control_build')
   check=run([positive],sanitizer+'_control',False);text=check.stdout+check.stderr
   detected=check.returncode!=0 and (('signed integer overflow' in text and 'runtime error' in text) if sanitizer=='undefined' else ('AddressSanitizer' in text and 'heap-buffer-overflow' in text));assert detected
   records.append(dict(sanitizer=sanitizer,oracle_pairs=10000,fixed_shake_vectors=20,oracle_sha256=sha(exe),instrument_control_detected=detected,flags=flags))
  assert sha(owner)==bound['source_files'][str(owner)] and sha(candidate/'latticecore.dll')==bound['candidate']['sha256']
  result=dict(status='PASS',records=records,compiler=version,release_library_sha256=bound['candidate']['sha256'],owner_source_sha256=sha(owner),oracle_source_sha256=sha(oracle),runner_sha256=sha(Path(__file__)),commands_sha256=sha(out/'commands.xml'),scope='Separate instrumented changed-provider component; fixed synthetic state/XOF oracle, not an instrumented release DLL or coverage-guided search')
  put(out/'result.xml',result);print(json.dumps(dict(status='PASS',sanitizers=[r['sanitizer'] for r in records])))
 except Exception as e:
  put(out/'result.xml',dict(status='INCOMPLETE',error=str(e),records=records,commands_sha256=sha(out/'commands.xml')));raise
if __name__=='__main__':main()
