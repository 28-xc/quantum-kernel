"""Build/test the standalone canonical component or bind a real core archive.

prepare never collects timing. collect is explicitly supplemental, batch-mean
measurement of the prepared component, with every warmup and sample retained.
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
import argparse, csv, hashlib, record_io as json, os, platform, re, shutil, subprocess
ROOT=Path(__file__).resolve().parents[1]

def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def desc(p):return {'path':str(Path(p).resolve()),'sha256':sha(p)}
def read(p):return json.loads(Path(p).read_text(encoding='utf-8'))
def write(p,v):Path(p).write_text(json.dumps(v,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
def bound(d):
 p=Path(d['path'])
 if not p.is_file() or sha(p)!=d['sha256']:raise ValueError('Bound artifact changed: '+str(p))
 return p
def output(path):
 p=path.resolve()
 if p.exists() or (os.name=='nt' and p.drive.upper()!='D:'):raise ValueError('Fresh output required, on D: for Windows')
 p.mkdir(parents=True);(p/'tmp').mkdir();return p
class Runner:
 def __init__(self,path):
  self.path=path;self.records=[];self.env=os.environ.copy();self.env.update(TEMP=str(path/'tmp'),TMP=str(path/'tmp'),TMPDIR=str(path/'tmp'),PYTHONDONTWRITEBYTECODE='1')
 def run(self,cmd,label):
  cmd=list(map(str,cmd));r=subprocess.run(cmd,cwd=ROOT,env=self.env,capture_output=True,text=True,encoding='utf-8',errors='replace');p=self.path/(label+'.log');p.write_text(json.capture_text(r.stdout+r.stderr),encoding='utf-8');self.records.append({'argv':cmd,'exit_code':r.returncode,'log':desc(p)});write(self.path/'commands.xml',self.records)
  if r.returncode:raise RuntimeError(label+' failed; actual log preserved')
  return r.stdout

def symbols(text):
 result={}
 for line in text.splitlines():
  m=re.match(r'^([0-9a-fA-F]+)\s+(?:[0-9a-fA-F]+\s+)?([A-Za-z])\s+(\S+)$',line)
  if m and m[2] not in ('U','u'):result[m[3]]={'address':int(m[1],16),'type':m[2]}
 return result

def prepare(a):
 out=output(a.output);run=Runner(out);tools={k:shutil.which(getattr(a,k)) for k in ('cc','ar','nm','objdump')}
 if not all(tools.values()):raise ValueError('Compiler/archive/nm/objdump tools required')
 try:
  cc=tools['cc'];version=run.run([cc,'--version'],'compiler').splitlines()[0];target=run.run([cc,'-dumpmachine'],'target').strip()
  windows=any(x in target for x in ('mingw','windows','w64'))
  if windows!=(os.name=='nt'):raise ValueError('Execute this native test on its target OS')
  sources=[ROOT/p for p in ('include/lc_poly.h','src/backends/canonical.c','src/backends/canonical_template.inc','src/backends/canonical_generated.inc','tools/generate_arithmetic.py','tools/build_primitives.py','tests/property/test_poly.c','tests/primitive/test_canonical_contract.c','bench/primitive/actual_backend.h','bench/primitive/driver.c','bench/primitive/README.md')]
  for s in sources:
   d=out/'source_snapshot'/s.relative_to(ROOT);d.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(s,d)
  run.run([a.python,'-B',ROOT/'tools/generate_arithmetic.py','--check'],'generated_roots')
  regenerated=out/'canonical_regenerated.inc';run.run([a.python,'-B',ROOT/'tools/generate_arithmetic.py','--output',regenerated],'regenerate')
  if regenerated.read_text()!= (ROOT/'src/backends/canonical_generated.inc').read_text():raise ValueError('Root regeneration differs')
  flags=['-O3','-g','-std=c11','-Wall','-Wextra','-Werror','-ffunction-sections','-fdata-sections','-fno-lto','-I'+str(ROOT/'include')]
  run.run([cc,*flags,'-c',ROOT/'src/backends/canonical.c','-o',out/'canonical.o'],'canonical_compile')
  poly=out/'liblc_poly.a';run.run([tools['ar'],'rcs',poly,out/'canonical.o'],'canonical_archive')
  ext='.exe' if windows else '';link=['-Wl,--gc-sections'];extra=[];binding={};archive=None;build=None
  if a.mode=='backend':
   if not a.archive or not a.build_record:raise ValueError('Actual core archive and build record required')
   archive=a.archive.resolve();build=a.build_record.resolve();record=read(build)
   hashes=[record.get('binary',{}).get('static_sha256'),*[x.get('static_sha256') for x in record.get('binaries',[])]]
   if sha(archive) not in hashes or not record.get('source_hashes'):raise ValueError('Build record does not bind this static archive and sources')
   nm=run.run([tools['nm'],'-g','--defined-only',archive],'archive_nm');syms=symbols(nm)
   wrappers=['lc_base_mlk_poly_'+x for x in ('ntt','invntt_tomont','reduce','mulcache_compute')]+['lc_base_mlk'+str(k)+'_polyvec_basemul_acc_montgomery_cached' for k in (512,768,1024)]
   native=['lc_base_mlk_'+x for x in ('ntt_avx2_asm','invntt_avx2_asm','reduce_avx2_asm','poly_mulcache_compute_avx2_asm','qdata')]+['lc_base_mlk_polyvec_basemul_acc_montgomery_cached_k'+str(k)+'_avx2_asm' for k in (2,3,4)]
   dsa=['lcbase_poly_'+x for x in ('ntt','invntt_tomont','reduce','pointwise_montgomery')]
   direct=not all(s in syms for s in wrappers);selected=native if direct else wrappers
   if not all(s in syms for s in selected+dsa):raise ValueError('Required real retained arithmetic symbols unavailable; no substitute backend is built')
   perm=['lc_base_mlk_nttunpack_avx2_asm','lcbase_nttunpack_avx2_asm'];custom=all(s in syms for s in perm)
   if any(s in syms for s in perm)!=custom:raise ValueError('Mixed permutation layouts require an explicit adapter')
   if direct and not custom:raise ValueError('Direct AVX2 bindings require retained custom-order conversion')
   selected+=dsa+(perm if custom else []);binding={'symbols':{s:syms[s] for s in selected},'kem_direct_avx2':direct,'order':'avx2_custom' if custom else 'bitreversed','archive':desc(archive),'build_record':desc(build),'build_source_hashes':record['source_hashes'],'scope':'Retained symbols re-linked from the exact existing static archive; not a rebuild of core source, not the original DLL layout.'}
   extra=['-DLC_KEM_DIRECT_AVX2='+str(int(direct)),'-DLC_CUSTOM_AVX2='+str(int(custom))]
   if direct or custom:flags+=['-mavx2']
   if windows:link+=['-lbcrypt']
  exe=out/('primitive'+ext);mapfile=out/'primitive.map'
  if archive and record.get('lto'):
   # Keep the measurement/oracle driver outside LTO. The retained bitcode
   # archive uses its recorded optimization level at the final link.
   if record.get('optimization') not in ('O3','Os') or record.get('compiler')!=version:
    raise ValueError('LTO archive requires its recorded compiler and optimization')
   driver_object=out/'primitive_driver.o'
   run.run([cc,*flags,'-DLC_ACTUAL_BACKEND=1',*extra,'-c',ROOT/'bench/primitive/driver.c','-o',driver_object],'primitive_driver_compile')
   run.run([cc,'-'+record['optimization'],'-flto',driver_object,archive,poly,*link,'-Wl,-Map,'+str(mapfile),'-o',exe],'primitive_link')
   binding.update(archive_lto=True,relink_optimization=record['optimization'],driver_compiled_without_lto=True)
  else:
   run.run([cc,*flags,'-DLC_ACTUAL_BACKEND='+str(int(a.mode=='backend')),*extra,ROOT/'bench/primitive/driver.c',*([archive] if archive else []),poly,*link,'-Wl,-Map,'+str(mapfile),'-o',exe],'primitive_link')
  oracle=json.loads(run.run([exe,'--verify',a.cases,20260925],'primitive_oracle'));negative=json.loads(run.run([exe,'--negative-control'],'oracle_negative_control'))
  other=[]
  if a.mode=='canonical':
   for name,source in [('property',ROOT/'tests/property/test_poly.c'),('contract',ROOT/'tests/primitive/test_canonical_contract.c')]:
    test=out/(name+ext);run.run([cc,*flags,source,poly,*link,'-o',test],name+'_link');text=run.run([test],name+'_test');other.append({'name':name,'executable':desc(test),'records':[json.loads(line) for line in text.splitlines() if line.strip()]})
  final_nm=run.run([tools['nm'],'-n',exe],'linked_nm');final_syms=symbols(final_nm)
  if binding:
   if not all(s in final_syms for s in binding['symbols']):raise ValueError('Retained entry disappeared in actual executable')
   binding['linked_entities']={s:final_syms[s] for s in binding['symbols']};write(out/'bindings.xml',binding)
  run.run([tools['objdump'],'-d','-w',exe],'linked_disassembly')
  cases=[{'q':q,'op':op,'rank':k} for q in (3329,8380417) for op in range(2 if a.mode=='backend' else 0,6) for k in (range(2,5) if a.mode=='backend' and q==3329 and op==4 else [2])]
  result={'schema':'lattice.primitive.prepared.v1','status':'PASS_FUNCTIONAL_ORACLES_NOT_TIMED','component':'actual_archive_backend' if archive else 'canonical_research_component','sources':[desc(s) for s in sources],'compiler':version,'target':target,'tools':{k:desc(v) for k,v in tools.items()},'driver':desc(exe),'canonical_archive':desc(poly),'regenerated_roots':desc(regenerated),'host':platform.platform(),'oracle':oracle,'negative_control':negative,'additional_tests':other,'actual_bindings':desc(out/'bindings.xml') if binding else None,'link_map':desc(mapfile),'nm':desc(out/'linked_nm.log'),'disassembly':desc(out/'linked_disassembly.log'),'commands':desc(out/'commands.xml'),'cases':cases}
  write(out/'prepared.xml',result);print(str(out/'prepared.xml'))
 except Exception as e:write(out/'failure.xml',{'status':'FAIL','reason':str(e),'commands':run.records});raise

def collect(a):
 p=read(a.prepared)
 if p['schema']!='lattice.primitive.prepared.v1' or p['status']!='PASS_FUNCTIONAL_ORACLES_NOT_TIMED':raise ValueError('Successful functional oracles required')
 for d in p['sources']:bound(d)
 exe=bound(p['driver']);bound(p['canonical_archive'])
 if p['actual_bindings']:
  b=read(bound(p['actual_bindings']));bound(b['archive']);bound(b['build_record'])
 if not 1<=a.batches<=1000 or not 1<=a.calls<=1000 or not 0<a.seed<2**64 or a.cpu<0 or not a.session_label:raise ValueError('Invalid bounded collection plan')
 out=output(a.output);run=Runner(out);plan={'prepared':desc(a.prepared),'batches':a.batches,'warmups_retained':10,'calls':a.calls,'seed':a.seed,'cpu':a.cpu,'session_label':a.session_label,'cases':p['cases'],'statistic':'Raw batch means only, no individual-call p95 or end-to-end scores'};write(out/'plan.xml',plan);results=[]
 try:
  for c in p['cases']:
   label=f"q{c['q']}_op{c['op']}_rank{c['rank']}";raw=out/(label+'.csv');r=json.loads(run.run([exe,'--measure',c['q'],c['op'],c['rank'],a.batches,a.calls,a.seed,a.cpu,raw],label))
   with raw.open(newline='') as f:rows=list(csv.DictReader(f))
   if len(rows)!=a.batches+10 or r['status']!='PASS':raise ValueError('Incomplete/failing raw measurement')
   for i,row in enumerate(rows):
    if int(row['batch'])!=i-10 or int(row['warmup'])!=int(i<10) or int(row['calls'])!=a.calls or int(row['status']):raise ValueError('Raw sample loss/reorder/failure')
    if abs(float(row['batch_mean_ns'])-int(row['elapsed_ticks'])*1e9/int(row['tick_frequency'])/a.calls)>1e-5:raise ValueError('Raw timer identity mismatch')
   results.append({'case':c,'metadata':r,'raw':desc(raw)});write(out/'progress.xml',results)
  write(out/'results.xml',{'status':'PASS_RAW_SUPPLEMENTAL_COLLECTION','component':p['component'],'plan':desc(out/'plan.xml'),'cases':results,'all_warmups_retained':True,'sample_removal':False,'not_individual_percentiles':True,'not_end_to_end':True})
 except Exception as e:write(out/'failure.xml',{'status':'FAIL','reason':str(e),'completed':results,'commands':run.records});raise

def main():
 parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='action',required=True)
 p=sub.add_parser('prepare');p.add_argument('--mode',choices=['canonical','backend'],required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--archive',type=Path);p.add_argument('--build-record',type=Path);p.add_argument('--cases',type=int,default=100);p.add_argument('--python',default=os.sys.executable)
 for tool,default in [('cc','gcc'),('ar','ar'),('nm','nm'),('objdump','objdump')]:p.add_argument('--'+tool,default=default)
 p=sub.add_parser('collect');p.add_argument('--prepared',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--batches',type=int,default=100);p.add_argument('--calls',type=int,default=100);p.add_argument('--seed',type=int,default=20260925);p.add_argument('--cpu',type=int,required=True);p.add_argument('--session-label',required=True)
 a=parser.parse_args();prepare(a) if a.action=='prepare' else collect(a)
if __name__=='__main__':main()
