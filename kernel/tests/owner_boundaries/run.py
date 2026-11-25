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
import argparse, datetime, hashlib, record_io as json, os, re, shutil, subprocess, sys

def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
p=argparse.ArgumentParser()
p.add_argument('--source-root',type=Path,required=True)
p.add_argument('--package',type=Path,required=True)
p.add_argument('--output',type=Path,required=True)
p.add_argument('--cc',default=shutil.which('gcc') or 'gcc')
a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
(out/'tmp').mkdir();env=dict(os.environ,TEMP=str(out/'tmp'),TMP=str(out/'tmp'),TMPDIR=str(out/'tmp'))
src=a.source_root.resolve();package=a.package.resolve();archive=package/'liblatticecore.a'
probe=Path(__file__).with_name('probe.c').resolve();exe=out/('probe.exe' if os.name=='nt' else 'probe')
record=dict(status='RUNNING',started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
 archive_sha256=sha(archive),build_json_sha256=sha(package/'build.xml'),probe_sha256=sha(probe),
 runner_sha256=sha(__file__),commands=[],coverage_guided=False,formal_timing=False,
 scope='Finite failure injection at each actual allocation ordinal; real cryptographic operations, deterministic recovery, output clearing, LIFO release and object-byte erasure observed. Only allocator/adapter translation units are recompiled with observational shims and without LTO; the remaining algorithm archive is unchanged. Validation binary is distinct from the released binary.')
def run(cmd):
 r=subprocess.run(list(map(str,cmd)),env=env,cwd=out,capture_output=True,text=True,encoding='utf-8',errors='replace')
 record['commands'].append(dict(argv=list(map(str,cmd)),exit_code=r.returncode,stdout=r.stdout,stderr=r.stderr))
 (out/'result.xml').write_text(json.dumps(record,indent=2)+'\n',encoding='utf-8')
 if r.returncode:raise RuntimeError(r.stderr[-4000:])
 return r.stdout
try:
 record['compiler_version']=run([a.cc,'--version']).splitlines()[0]
 commands=json.loads((package/'commands.xml').read_text(encoding='utf-8'))
 if isinstance(commands,dict):commands=commands['commands']
 injected=[];record['instrumented_translation_units']=[]
 for basename,family,atype in [('arena.c','lc_arena','lc_arena'),('adapter.c','lc_dsa','struct lc_dsa_arena')]:
  matches=[r['argv'] for r in commands if '-c' in r.get('argv',[]) and Path(r['argv'][r['argv'].index('-c')+1]).name==basename]
  assert len(matches)==1,(basename,len(matches))
  original=matches[0];original_source=Path(original[original.index('-c')+1]);body=original_source.read_text(encoding='utf-8')
  for suffix in ['alloc','free']:
   # Rename definitions only; ordinary callers continue to enter the shim.
   pattern=r'(?m)^(void\s*\*?\s*)'+family+'_'+suffix+r'(\s*\()'
   body,count=re.subn(pattern,r'\g<1>__real_'+family+'_'+suffix+r'\2',body)
   assert count==1,(basename,suffix,count)
  body+='\n/* Validation-only allocator observation boundary. */\n'
  body+=f'extern void *__wrap_{family}_alloc({atype} *, size_t);\n'
  body+=f'extern void __wrap_{family}_free({atype} *, void *, size_t);\n'
  body+=f'void *{family}_alloc({atype} *a,size_t n){{return __wrap_{family}_alloc(a,n);}}\n'
  body+=f'void {family}_free({atype} *a,void *p,size_t n){{__wrap_{family}_free(a,p,n);}}\n'
  modified=out/('observed_'+basename);modified.write_text(body,encoding='utf-8')
  obj=out/(basename+'.o');cmd=[a.cc];skip=False
  for i,arg in enumerate(original[1:],1):
   if skip:skip=False;continue
   if arg in ['-c','-o','-MF']:
    skip=True;continue
   if arg in ['-MMD','-flto','-fwhole-program'] or arg.startswith('-flto='):continue
   cmd.append(arg)
  cmd+=['-fno-lto','-I'+str(original_source.parent),'-c',str(modified),'-o',str(obj)]
  run(cmd);injected.append(obj)
  record['instrumented_translation_units'].append(dict(original=str(original_source),original_sha256=sha(original_source),modified=str(modified),modified_sha256=sha(modified),object_sha256=sha(obj)))
 flags=['-O2','-std=c11','-flto','-I'+str(src/'include'),'-I'+str(src/'src/dsa_packed')]
 links=[]
 if os.name=='nt':links+=['-lbcrypt']
 plain=out/('plain.exe' if os.name=='nt' else 'plain')
 run([a.cc,*flags,'-DLC_OWNER_PLAIN_CAPTURE=1',probe,archive,*links,'-o',plain])
 plain_text=run([plain]);plain_rows=[json.loads(line) for line in plain_text.splitlines() if line.startswith('{')]
 assert len(plain_rows)==18 and all(row['status']=='PASS' for row in plain_rows)
 run([a.cc,*flags,probe,*injected,archive,*links,'-o',exe])
 text=run([exe]);rows=[json.loads(line) for line in text.splitlines() if line.startswith('{')]
 assert len(rows)==19 and all(row['status']=='PASS' for row in rows)
 assert sha(archive)==record['archive_sha256']
 compared_bytes=0
 for observed,reference in zip(rows,plain_rows):
  assert (observed['parameter'],observed['operation'])==(reference['parameter'],reference['operation'])
  for key in ['output0','output1']:
   assert observed[key]==reference[key],(observed['parameter'],observed['operation'],key)
   compared_bytes+=len(bytes.fromhex(observed[key]))
 record.update(status='PASS',binary_sha256=sha(exe),plain_binary_sha256=sha(plain),uninstrumented_output_comparison_bytes=compared_bytes,rows=rows,plain_rows=plain_rows)
except Exception as error:
 record.update(status='FAIL_OR_INCOMPLETE',error=str(error));raise
finally:
 record['finished_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
 (out/'result.xml').write_text(json.dumps(record,indent=2)+'\n',encoding='utf-8')
print(json.dumps(rows[-1]))
