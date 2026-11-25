"""Own-worker Windows instruction attribution, never a performance timer.

prepare freezes explicit DLL identities and a complete 18-operation plan;
selftest checks sampling controls and every API cell without profiling it;
collect requires the successful controls and runs the frozen sampling plan.
Only the child program's own worker can be observed. No PID/TID is accepted.
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
import argparse, collections, csv, hashlib, record_io as json, os, re, shutil, struct, subprocess, sys

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
LEVELS=(512,768,1024,44,65,87)
CLASS='perturbing_instruction_sampling_only'

def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def read(p):return json.loads(Path(p).read_text(encoding='utf-8'))
def write(p,x):Path(p).write_text(json.dumps(x,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
def desc(p):return {'path':str(Path(p).resolve()),'sha256':sha(p)}
def bound(d):
 p=Path(d['path'])
 if not p.is_file() or sha(p)!=d['sha256']:raise ValueError('Bound file changed: '+str(p))
 return p

def new_output(p):
 p=p.resolve()
 if os.name!='nt' or p.drive.upper()!='D:' or p.exists():raise ValueError('A fresh Windows D: output is required')
 p.mkdir(parents=True);(p/'tmp').mkdir();return p

def environment(out,crypto):
 env=os.environ.copy();env.update(TEMP=str(out/'tmp'),TMP=str(out/'tmp'),PYTHONDONTWRITEBYTECODE='1',PYTHONUTF8='1')
 env['PATH']=str(crypto.parent)+os.pathsep+env.get('PATH','')
 return env

class Runner:
 def __init__(self,out,env):self.out=out;self.env=env;self.records=[]
 def run(self,cmd,label,expected=0,timeout=120):
  cmd=list(map(str,cmd));timed_out=False
  try:
   p=subprocess.run(cmd,cwd=ROOT,env=self.env,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=timeout)
   stdout,stderr,code=p.stdout,p.stderr,p.returncode
  except subprocess.TimeoutExpired as e:
   # subprocess terminates only its own newly created child. No external PID.
   stdout=e.stdout or '';stderr=e.stderr or '';code=None;timed_out=True
   if isinstance(stdout,bytes):stdout=stdout.decode('utf-8','replace')
   if isinstance(stderr,bytes):stderr=stderr.decode('utf-8','replace')
  log=self.out/(label+'.stdout.txt');err=self.out/(label+'.stderr.txt')
  log.write_text(json.capture_text(stdout),encoding='utf-8');err.write_text(stderr,encoding='utf-8')
  self.records.append({'argv':cmd,'exit_code':code,'expected_exit_code':expected,'timed_out':timed_out,'stdout':desc(log),'stderr':desc(err)})
  write(self.out/'commands.xml',self.records)
  if timed_out or code!=expected:raise RuntimeError(f'{label}: exit {code}, expected {expected}; all logs retained')
  return stdout

def pe_info(path):
 b=path.read_bytes()
 if b[:2]!=b'MZ':raise ValueError('Expected actual Windows PE')
 at=struct.unpack_from('<I',b,60)[0];opt=at+24
 if b[at:at+4]!=b'PE\0\0' or struct.unpack_from('<H',b,at+4)[0]!=0x8664 or struct.unpack_from('<H',b,opt)[0]!=0x20b:raise ValueError('Expected x64 PE32+')
 base=struct.unpack_from('<Q',b,opt+24)[0];span=struct.unpack_from('<I',b,opt+56)[0]
 n=struct.unpack_from('<H',b,at+6)[0];sz=struct.unpack_from('<H',b,at+20)[0];sections=[]
 for i in range(n):
  o=opt+sz+40*i;name=b[o:o+8].split(b'\0')[0].decode('ascii','replace');vs,rva,fs,fo=struct.unpack_from('<IIII',b,o+8);flags=struct.unpack_from('<I',b,o+36)[0]
  sections.append({'name':name,'rva':rva,'virtual_bytes':vs,'raw_bytes':fs,'executable':bool(flags&0x20000000),'sha256':hashlib.sha256(b[fo:fo+fs]).hexdigest()})
 return {'image_base':base,'image_bytes':span,'sections':sections}

def instruction_map(path,nm_text,disassembly):
 pe=pe_info(path);base=pe['image_base'];aliases=collections.defaultdict(list)
 for line in nm_text.splitlines():
  m=re.match(r'^([0-9a-fA-F]+)\s+(?:[0-9a-fA-F]+\s+)?[tT]\s+(\S+)$',line)
  if m:aliases[int(m[1],16)].append(m[2])
 instructions={};symbol=None;start=None
 for line in disassembly.splitlines():
  label=re.match(r'^([0-9a-fA-F]+)\s+<(.+)>:$',line.strip())
  if label:start=int(label[1],16);symbol=label[2];continue
  m=re.match(r'^\s*([0-9a-fA-F]+):\s+(.+)$',line)
  if not m:continue
  address=int(m[1],16);rva=address-base
  if not 0<rva<pe['image_bytes']:continue
  if not any(s['executable'] and s['rva']<=rva<s['rva']+s['virtual_bytes'] for s in pe['sections']):continue
  if rva in instructions:raise ValueError('Duplicate disassembled instruction address')
  instructions[rva]={'rva':rva,'instruction':m[2].strip(),'disassembly_label':symbol,'label_rva':start-base if start else None,'same_address_nm_aliases':aliases.get(start,[])}
 if not instructions:raise ValueError('No executable instructions mapped')
 return {'binary':desc(path),'pe':pe,'instructions':list(instructions.values()),'scope':'Exact disassembled instruction starts. COFF labels/aliases are not asserted source-function size boundaries. Inlined/source-line attribution is not inferred.'}

def validate_samples(path,summary,image_bytes,mapping):
 with path.open(newline='',encoding='utf-8') as f:
  reader=csv.DictReader(f)
  if reader.fieldnames!=['sample_id','observer_qpc','core_instruction_rva']:raise ValueError('Unexpected raw fields')
  rows=list(reader)
 expected=summary['samples'];core=0;previous=-1;by_rva=collections.Counter()
 if len(rows)!=expected:raise ValueError('Raw count mismatch')
 for i,r in enumerate(rows):
  if int(r['sample_id'])!=i:raise ValueError('Sample omission/reorder')
  qpc=int(r['observer_qpc']);rva=int(r['core_instruction_rva'])
  if qpc<previous or not 0<=rva<image_bytes:raise ValueError('Invalid timestamp or module offset')
  previous=qpc
  if rva:core+=1;by_rva[rva]+=1
 if core!=summary['core_samples'] or len(rows)-core!=summary['outside_core_samples']:raise ValueError('Raw attribution count mismatch')
 lookup={i['rva']:i for i in mapping['instructions']};by_symbol=collections.Counter();details=[];unknown=0
 for rva,count in sorted(by_rva.items()):
  entry=lookup.get(rva)
  if entry:by_symbol[(entry['disassembly_label'],entry['label_rva'])]+=count
  else:unknown+=count
  details.append({'rva':rva,'count':count,'exact_instruction':entry})
 return {'raw':desc(path),'retained_samples':len(rows),'core_samples':core,'outside_core_samples':len(rows)-core,'unknown_core_instruction_samples':unknown,
         'instructions':details,'labels':[{'label':k[0],'label_rva':k[1],'samples':v,'fraction_of_core_samples':v/core if core else None} for k,v in by_symbol.most_common()],
         'denominator_scope':'Samples while explicitly loaded core is executing; outside core retained as zero. These proportions are perturbed observations, not elapsed time, cycles, unbiased probabilities, or whole-call costs.'}

def verify_identity(summary,library,crypto,version):
 if not Path(summary['library']).samefile(bound(library)) or not Path(summary['openssl_library']).samefile(bound(crypto)):raise ValueError('Actually loaded module path differs')
 if not summary['openssl_version'].startswith('OpenSSL '+version+' '):raise ValueError('Actually loaded version differs')
 if summary['status']!='PASS' or summary['exit_code'] or summary['context_failures'] or summary['resume_failures'] or summary['dropped']:raise ValueError('Failed operation or observer')

def check_bound_plan(prepared):
 p=read(prepared)
 if p['schema']!='own_worker_profile.prepared.v1':raise ValueError('Wrong prepared schema')
 for d in [p['driver'],p['crypto_library'],*p['sources'],*p['tools'].values()]:bound(d)
 for lib in p['libraries']:
  bound(lib['binary']);bound(lib['mapping'])
  if read(lib['mapping']['path'])['binary']!=lib['binary']:raise ValueError('Mapping binary mismatch')
  if lib.get('build_provenance'):
   bound(lib['build_provenance']['record']);bound(lib['build_provenance']['link_map'])
 bound(p['self_control']['binary']);bound(p['self_control']['mapping'])
 expected=[(lib['label'],level,op) for lib in p['libraries'] for level in LEVELS for op in range(3)]
 if [(c['label'],c['parameter'],c['operation']) for c in p['plan']]!=expected:raise ValueError('Incomplete/reordered operation plan')
 return p

def prepare(a):
 libraries=read(a.libraries)
 if not isinstance(libraries,list) or not libraries:raise ValueError('Explicit nonempty list of library descriptors required')
 labels=set()
 for lib in libraries:
  if set(lib) not in ({'label','path','sha256'},{'label','path','sha256','build_record','link_map'}) or not re.fullmatch('[a-z][a-z0-9_]{0,40}',lib['label']) or lib['label'] in labels:raise ValueError('Invalid/duplicate explicit library')
  labels.add(lib['label']);bound(lib)
 if not 100<=a.iterations<=1000000 or not 0<a.seed<2**64 or not 0<=a.cpu<64 or not 0<=a.observer_cpu<64 or a.cpu==a.observer_cpu:raise ValueError('Invalid bounded sampling plan')
 crypto=a.crypto_library.resolve();prefix=a.crypto_prefix.resolve();out=new_output(a.output);run=Runner(out,environment(out,crypto));tools={k:shutil.which(getattr(a,k)) for k in ('cc','nm','objdump')}
 if not all(tools.values()) or not crypto.is_file() or not (prefix/'include/openssl/evp.h').is_file():raise ValueError('Missing explicit tool/library/header')
 try:
  version=run.run([tools['cc'],'--version'],'compiler_version').splitlines()[0]
  exe=out/'profile_windows.exe'
  sources=[HERE/'profile_windows.c',HERE/'profile_windows.py',HERE/'test_profile_windows.py',HERE/'driver.c',HERE/'profile_windows.md',ROOT/'include/latticecore.h']
  for p in sources:
   dest=out/'source_snapshot'/p.relative_to(ROOT);dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,dest)
  run.run([tools['cc'],'-O3','-g','-std=c11','-Wall','-Wextra','-Werror','-I'+str(ROOT/'include'),'-I'+str(prefix/'include'),HERE/'profile_windows.c','-L'+str(prefix/'lib'),'-lcrypto','-o',exe],'build')
  mapped=[]
  for lib in [*libraries,{'label':'self_control','path':str(exe),'sha256':sha(exe)}]:
   path=Path(lib['path']).resolve();label=lib['label'];nm=run.run([tools['nm'],'-n',path],label+'_nm');dis=run.run([tools['objdump'],'-d','-w','--no-show-raw-insn',path],label+'_disassembly')
   dest=out/(label+'_mapping.xml');write(dest,instruction_map(path,nm,dis));entry={'label':label,'binary':desc(path),'mapping':desc(dest),'nm':desc(out/(label+'_nm.stdout.txt')),'disassembly':desc(out/(label+'_disassembly.stdout.txt'))}
   if 'build_record' in lib:
    record=read(bound(lib['build_record']));link_map=bound(lib['link_map']);hashes=record.get('source_hashes',{})
    binary_hashes=[record.get('binary',{}).get('sha256'),*[x.get('sha256') for x in record.get('binaries',[])]]
    if lib['sha256'] not in binary_hashes or not hashes or any(not re.fullmatch('[0-9a-f]{64}',v) for v in hashes.values()):raise ValueError('Build provenance lacks bound binary/source hashes')
    if 'map_sha256' in record and record['map_sha256']!=sha(link_map):raise ValueError('Actual link map differs from build record')
    entry['build_provenance']={'record':lib['build_record'],'link_map':lib['link_map'],'source_file_hashes_as_recorded_at_build':hashes,'scope':'Build-time source identity; current working-tree files may have changed. Not an assertion of source-line attribution or independent rebuild.'}
   else:entry['build_provenance']=None
   mapped.append(entry)
  plan=[{'label':l['label'],'parameter':p,'operation':o,'iterations':a.iterations,'seed':a.seed} for l in libraries for p in LEVELS for o in range(3)]
  identity={'schema':'own_worker_profile.prepared.v1','measurement_class':CLASS,'driver':desc(exe),'sources':[desc(p) for p in sources],'compiler':version,'tools':{k:desc(p) for k,p in tools.items()},'crypto_library':desc(crypto),'expected_version':a.expected_version,'worker_cpu':a.cpu,'observer_cpu':a.observer_cpu,'libraries':mapped[:-1],'self_control':mapped[-1],'plan':plan,'plan_complete_18_cells_per_library':True,'source_symbols_are_not_machine_entity_counts':True}
  write(out/'prepared.xml',identity);print(str(out/'prepared.xml'))
 except Exception as e:write(out/'failure.xml',{'status':'FAIL','reason':str(e),'commands':run.records});raise

def execute(a):
 p=check_bound_plan(a.prepared);out=new_output(a.output);exe=bound(p['driver']);crypto=bound(p['crypto_library']);run=Runner(out,environment(out,crypto));cases=[];cpu=p['worker_cpu'];obs=p['observer_cpu']
 try:
  if a.command=='selftest':
   for mode in ('positive','outside','observer_timeout'):
    raw=out/(mode+'.csv');expected=72 if mode=='observer_timeout' else 0
    text=run.run([exe,'--self-test',mode,cpu,obs,raw],mode,expected,15)
    if expected:cases.append({'mode':mode,'expected_exit_code':expected,'actual_exit_code':run.records[-1]['exit_code'],'status':'PASS_EXPECTED_PROCESS_EXIT'});continue
    result=json.loads(text);mapping=read(bound(p['self_control']['mapping']));attribution=validate_samples(raw,result,mapping['pe']['image_bytes'],mapping)
    if mode=='positive' and sum(x['samples'] for x in attribution['labels'] if x['label']=='lc_profile_positive_control')<20:raise ValueError('Positive control did not map to known actual function')
    if mode=='outside' and attribution['core_samples']:raise ValueError('Outside control leaked a non-core address')
    cases.append({'mode':mode,'result':result,'attribution':attribution})
   first=p['libraries'][0]['binary'];raw=out/'invalid.csv';base=[exe,bound(first),512,0,0,1,cpu,obs,raw,p['expected_version']]
   invalid=list(base);invalid[7]=cpu;run.run(invalid,'same_cpu_rejected',3)
   invalid=list(base);invalid[3]=3;run.run(invalid,'operation_rejected',3)
   invalid=list(base);invalid[9]='3.6.0' if p['expected_version']=='3.6.4' else '3.6.4';run.run(invalid,'wrong_version_rejected',17)
   raw.write_text('existing output must survive\n',encoding='utf-8');before=sha(raw);run.run(base,'existing_output_rejected',4)
   if sha(raw)!=before:raise ValueError('Existing output was overwritten')
   cases.append({'mode':'argument_identity_output_negatives','checks':4,'status':'PASS'})
  else:
   check=read(a.selftest)
   if check['status']!='PASS' or check['schema']!='own_worker_profile.selftest.v1' or check['prepared']!=desc(a.prepared) or check['api_cells']!=len(p['plan']):raise ValueError('Matching completed selftest is required')
   bound(check['prepared'])
  cells=[];by_label={x['label']:x for x in p['libraries']}
  for cell in p['plan']:
   lib=by_label[cell['label']];label=f"{cell['label']}_{cell['parameter']}_{cell['operation']}";raw=out/(label+'.csv');count=0 if a.command=='selftest' else cell['iterations']
   text=run.run([exe,bound(lib['binary']),cell['parameter'],cell['operation'],count,cell['seed'],cpu,obs,raw,p['expected_version']],label,timeout=180)
   result=json.loads(text);verify_identity(result,lib['binary'],p['crypto_library'],p['expected_version'])
   if (result['parameter'],result['operation'],result['iterations'],result['completed'],result['seed'],result['worker_cpu'],result['observer_cpu'])!=(cell['parameter'],cell['operation'],count,count or 1,cell['seed'],cpu,obs):raise ValueError('Executed cell differs from frozen plan')
   mapping=read(bound(lib['mapping']));attribution=validate_samples(raw,result,mapping['pe']['image_bytes'],mapping)
   if result['image_bytes']!=mapping['pe']['image_bytes']:raise ValueError('Loaded image span differs from inspected PE')
   cells.append({'plan':cell,'result':result,'attribution':attribution});write(out/'progress.xml',{'completed_cells':len(cells),'latest':label});print(label,'PASS',flush=True)
  check_bound_plan(a.prepared)
  write(out/'result.xml',{'schema':'own_worker_profile.'+a.command+'.v1','status':'PASS','prepared':desc(a.prepared),'measurement_class':'sampler_controls_and_api_verification' if a.command=='selftest' else CLASS,'controls':cases,'api_cells':len(cells),'cells':cells,'raw_sample_count':sum(x['attribution']['retained_samples'] for x in cells),'sample_trimming':False,'commands':desc(out/'commands.xml')})
 except Exception as e:write(out/'failure.xml',{'status':'FAIL','reason':str(e),'prepared':desc(a.prepared),'controls':cases,'commands':run.records});raise

def main():
 parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='command',required=True)
 p=sub.add_parser('prepare');p.add_argument('--libraries',type=Path,required=True);p.add_argument('--crypto-library',type=Path,required=True);p.add_argument('--crypto-prefix',type=Path,required=True);p.add_argument('--expected-version',choices=['3.6.0','3.6.4'],required=True);p.add_argument('--output',type=Path,required=True)
 p.add_argument('--cc',default='gcc');p.add_argument('--nm',default='nm');p.add_argument('--objdump',default='objdump');p.add_argument('--cpu',type=int,required=True);p.add_argument('--observer-cpu',type=int,required=True);p.add_argument('--iterations',type=int,default=20000);p.add_argument('--seed',type=int,default=20260925)
 for name in ('selftest','collect'):
  p=sub.add_parser(name);p.add_argument('--prepared',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
  if name=='collect':p.add_argument('--selftest',type=Path,required=True)
 a=parser.parse_args();prepare(a) if a.command=='prepare' else execute(a)
if __name__=='__main__':main()
