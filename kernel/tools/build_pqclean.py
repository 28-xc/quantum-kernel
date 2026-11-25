"""Build an explicitly checked PQClean clean comparison; original heap retained."""
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
import argparse, hashlib, record_io as json, os, platform, shutil, subprocess, sys
ROOT=Path(__file__).resolve().parents[1];BASE=ROOT/'baselines/pqclean'
sys.path.insert(0,str(ROOT/'tools'))
from binary_build_utils import pe_exports
PUBLIC=['lc_get_sizes','lc_context_init','lc_keypair','lc_encaps','lc_decaps','lc_sign','lc_verify','lc_error_string']
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def write(p,x):Path(p).write_bytes((json.dumps(x,indent=2)+'\n').encode())
def verify_sources():
 lock=json.loads((BASE/'source_lock.xml').read_text());expected={x['path'] for x in lock['files']}
 actual={p.relative_to(BASE).as_posix() for p in (BASE/'upstream').rglob('*') if p.is_file()}
 if actual!=expected:raise ValueError('Official source selection changed')
 for x in lock['files']:
  data=(BASE/x['path']).read_bytes()
  if hashlib.sha256(data).hexdigest()!=x['sha256'] or hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()!=x['git_blob']:raise ValueError('Official PQClean file changed: '+x['path'])
 return lock
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
 for k,d in [('cc','gcc'),('ar','ar'),('nm','nm'),('objdump','objdump'),('size','size')]:p.add_argument('--'+k,default=d)
 p.add_argument('--architecture',choices=['x86_64','aarch64','portable'],required=True);p.add_argument('--count',type=int,default=100);a=p.parse_args()
 if not 1<=a.count<=10000:raise ValueError('Count outside bounded functional range')
 out=a.output.resolve();lock=verify_sources()
 if out.exists() or (os.name=='nt' and out.drive.upper()!='D:'):raise ValueError('Fresh output required; Windows output must be on D:')
 tools={k:shutil.which(getattr(a,k)) for k in ('cc','ar','nm','objdump','size')}
 if not all(tools.values()):raise ValueError('Explicit compiler and binary tools required')
 out.mkdir(parents=True);(out/'obj').mkdir();(out/'generated').mkdir();(out/'tmp').mkdir()
 env=os.environ.copy();env.update(TEMP=str(out/'tmp'),TMP=str(out/'tmp'),TMPDIR=str(out/'tmp'),PYTHONDONTWRITEBYTECODE='1')
 calls=[];source_files={BASE/x['path'] for x in lock['files']}
 source_files.update([Path(__file__),BASE/'adapter.c',BASE/'nonce_guard.c.in',BASE/'source_lock.xml',BASE/'README.md',BASE/'.gitattributes',ROOT/'include/latticecore.h',ROOT/'include/lc_platform.h',ROOT/'src/platform/random.c',ROOT/'tests/pqclean/probe.c',ROOT/'tools/binary_build_utils.py'])
 source_hashes={p.relative_to(ROOT).as_posix():sha(p) for p in sorted(source_files)}
 def run(argv,label):
  argv=list(map(str,argv));r=subprocess.run(argv,cwd=ROOT,env=env,capture_output=True,text=True,encoding='utf-8',errors='replace')
  log=out/(label+'.log');log.write_bytes(json.capture_bytes((r.stdout+r.stderr).encode()));calls.append(dict(argv=argv,exit_code=r.returncode,log=log.name,sha256=sha(log)));write(out/'commands.xml',calls)
  if r.returncode:raise RuntimeError(label+' failed; logs retained')
  return r.stdout
 try:
  version=run([tools['cc'],'--version'],'compiler').splitlines()[0];target=run([tools['cc'],'-dumpmachine'],'target').strip();windows=any(t in target for t in ['mingw','windows','w64'])
  if a.architecture=='x86_64' and 'x86_64' not in target:raise ValueError('Wrong x86 target')
  if a.architecture=='aarch64' and 'aarch64' not in target:raise ValueError('Wrong ARM target')
  flags=['-O3','-g','-std=c11','-ffunction-sections','-fdata-sections','-fno-omit-frame-pointer','-fstack-usage','-Wall','-Wextra']
  if a.architecture=='x86_64':flags+=['-march=native']
  if a.architecture=='aarch64':flags+=['-mcpu=neoverse-n1']
  if not windows:flags+=['-fPIC','-fvisibility=hidden']
  includes=['-I'+str(ROOT/'include'),'-I'+str(BASE),'-I'+str(BASE/'upstream/common')]
  if not windows:
   # Public visibility is added only to declarations before adapter compilation.
   export_header=out/'generated/public_exports.h'
   export_header.write_bytes(('\n'.join('#pragma GCC visibility push(default)' if i==0 else '#include "latticecore.h"' if i==1 else '#pragma GCC visibility pop' for i in range(3))+'\n').encode())
  objects=[];compiled=[]
  def compile_one(src,extra=()):
   number=len(objects);obj=out/'obj'/f'{number:03d}.o';dep=obj.with_suffix('.d')
   run([tools['cc'],*flags,*includes,*extra,'-MMD','-MF',dep,'-c',src,'-o',obj],f'compile_{number:03d}')
   objects.append(obj);compiled.append(dict(source=str(src),source_sha256=sha(src),object=obj.relative_to(out).as_posix(),object_sha256=sha(obj),depfile=dep.relative_to(out).as_posix(),depfile_sha256=sha(dep)))
  for family,levels in [('crypto_kem',(512,768,1024)),('crypto_sign',(44,65,87))]:
   for level in levels:
    name=('ml-kem-' if level>100 else 'ml-dsa-')+str(level);directory=BASE/'upstream'/family/name/'clean'
    for source in sorted(directory.glob('*.c')):
     extra=[]
     if level<100 and source.name=='polyvec.c':extra=['-DPQCLEAN_MLDSA'+str(level)+'_CLEAN_polyvecl_uniform_gamma1=PQCLEAN_MLDSA'+str(level)+'_CLEAN_polyvecl_uniform_gamma1_original']
     compile_one(source,extra)
    if level<100:
     guard=out/'generated'/f'nonce_{level}.c';guard.write_bytes((BASE/'nonce_guard.c.in').read_text().replace('@PREFIX@','PQCLEAN_MLDSA'+str(level)+'_CLEAN').encode())
     compile_one(guard,['-I'+str(directory)])
  compile_one(BASE/'upstream/common/fips202.c');compile_one(ROOT/'src/platform/random.c')
  compile_one(BASE/'adapter.c',[] if windows else ['-include',export_header])
  archive=out/'liblatticecore.a';run([tools['ar'],'rcs',archive,*objects],'archive')
  lib=out/('latticecore.dll' if windows else 'liblatticecore.so');mapfile=out/'latticecore.map'
  if windows:
   export=out/'exports.def';export.write_bytes(('EXPORTS\n'+'\n'.join(PUBLIC)+'\n').encode());linkextra=[export,'-lbcrypt','-Wl,--out-implib,'+str(out/'liblatticecore.dll.a')]
  else:
   export=out/'exports.map';export.write_bytes(('{ global: '+'; '.join(PUBLIC)+'; local: *; };\n').encode());linkextra=['-Wl,-z,defs','-Wl,-z,noexecstack','-Wl,--version-script='+str(export)]
  runtime_link=['-static','-static-libgcc'] if windows else []
  run([tools['cc'],'-O3',*runtime_link,'-shared',*objects,*linkextra,'-Wl,--gc-sections','-Wl,-Map,'+str(mapfile),'-o',lib],'link')
  dynamic=run([tools['nm'],*([] if windows else ['-D']),'-g','--defined-only',lib],'symbols')
  exports=pe_exports(lib)['exports'] if windows else sorted(line.split()[-1] for line in dynamic.splitlines() if line.split())
  if sorted(exports)!=sorted(PUBLIC):raise ValueError('Unexpected public export set')
  run([tools['objdump'],'-p',lib],'binary_headers');run([tools['objdump'],'-d',lib],'disassembly');run([tools['size'],'-A',lib],'sections')
  probes=[]
  for linkage in ('shared','static'):
   exe=out/('probe_'+linkage+('.exe' if windows else ''));dep=out/('probe_'+linkage+'.d')
   link=[out/'liblatticecore.dll.a'] if windows and linkage=='shared' else [archive] if linkage=='static' else ['-L'+str(out),'-llatticecore','-Wl,-rpath,'+str(out)]
   if windows and linkage=='static':link+=['-lbcrypt']
   run([tools['cc'],*flags,*runtime_link,*includes,'-MMD','-MF',dep,ROOT/'tests/pqclean/probe.c',*link,'-o',exe],'build_probe_'+linkage)
   result=run([exe,a.count],'probe_'+linkage);rows=[json.loads(line) for line in result.splitlines() if line.startswith('{')]
   if len(rows)!=6 or any(x['status']!='PASS' for x in rows):raise ValueError('Incomplete probe')
   probes.append(dict(linkage=linkage,executable=exe.name,sha256=sha(exe),records=rows))
  if any(sha(ROOT/name)!=digest for name,digest in source_hashes.items()):raise ValueError('Source changed during build')
  verify_sources()
  record=dict(schema='pqclean.checked_clean.build.v1',status='PASS',upstream_commit=lock['commit'],compiler=version,target=target,host=platform.platform(),architecture=a.architecture,optimization='O3',lto=False,cflags=flags,source_hashes=source_hashes,compiled_objects=compiled,library={'path':str(lib),'sha256':sha(lib)},archive={'path':str(archive),'sha256':sha(archive)},exports=exports,link_map_sha256=sha(mapfile),commands_sha256=sha(out/'commands.xml'),functional_probes=probes,scope={'original_algorithm_files_unchanged':True,'original_common_heap_allocation_retained':True,'allocation_failure_behavior':'upstream exit(111), not LC_E_WORKSPACE recovery','caller_arena_used':False,'automatic_secret_stack_erasure_guaranteed':False,'nonce_attempt_guard':{'44':16382,'65':13106,'87':9361},'added_checks':['object/length/context/alias','caller RNG failure before algorithm','FIPS203 encapsulation-key modulus check','FIPS203 decapsulation-key hash check','public signing nonce bound']})
  write(out/'build.xml',record);print(json.dumps({'status':'PASS','library':record['library'],'compiler':version}))
 except Exception as e:write(out/'failure.xml',dict(status='FAIL',error=str(e),source_hashes=source_hashes,commands_sha256=sha(out/'commands.xml') if (out/'commands.xml').exists() else None));raise
if __name__=='__main__':main()
