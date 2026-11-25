"""Compile locked pqm4 m4fstack sources and execute fixed M4 functional/stack cases.

One firmware per standard ML-DSA parameter. These are emulated ISA functional
and memory observations; no clock, hardware cycle or energy counter is read.
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
import argparse, hashlib, importlib.util, record_io as json, os, subprocess, sys
ROOT=Path(__file__).resolve().parents[2]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def module(p,name):
 s=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--pqm4',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
 ap.add_argument('--opt',choices=['Os','O3'],default='Os');ap.add_argument('--parameters',type=int,nargs='+',choices=[44,65,87],default=[44,65,87])
 ap.add_argument('--core-profile',choices=['rate','recompute']);ap.add_argument('--core-build',type=Path);a=ap.parse_args()
 if bool(a.core_profile)!=bool(a.core_build):raise ValueError('Core profile and its exact M4 build must be supplied together')
 pq=a.pqm4.resolve();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
 assert (pq/'SOURCE_COMMIT').read_text().strip()=='5e5cc76d0b072ee7077e58afcbc619a1a67a53b4'
 assert (pq/'mupq/SOURCE_COMMIT').read_text().strip()=='ddcccedb2db9d0250856bd58ee5c46c61e506c5d'
 target=module(ROOT/'tools/build_targets.py','target_recipe');vectors=module(ROOT/'tests/targets/generate_vectors.py','vector_selector')
 records=[];results=[]
 def run(argv,label,cwd=ROOT,timeout=180):
  p=subprocess.run(list(map(str,argv)),cwd=cwd,capture_output=True,text=True,timeout=timeout)
  log=out/(label+'.log');log.write_text(json.capture_text(p.stdout+p.stderr))
  records.append(dict(argv=list(map(str,argv)),label=label,exit_code=p.returncode,log_sha256=sha(log)))
  (out/'commands.xml').write_text(json.dumps(records,indent=2)+'\n')
  assert p.returncode==0,(label,p.stdout,p.stderr)
  return p.stdout
 compiler=run(['arm-none-eabi-gcc','--version'],'compiler');qemu=run(['qemu-system-arm','--version'],'qemu')
 shim=out/'fixture_include';shim.mkdir();(shim/'randombytes.h').write_text('#include <stddef.h>\n#include <stdint.h>\nint randombytes(uint8_t *,size_t);\n')
 for parameter in a.parameters:
  folder=out/str(parameter);folder.mkdir();(folder/'obj').mkdir();vectors.generate(ROOT,folder)
  algo=pq/'crypto_sign'/('ml-dsa-'+str(parameter))/'m4fstack'
  linker=(ROOT/'targets/common/image.ld.in').read_text()
  for k,v in dict(CODE_BASE='0x00000000',RAM_BASE='0x20000000',RAM_BYTES=65536,STACK_BYTES=16384,CONTROL_STACK_BYTES=2048).items():linker=linker.replace('@'+k+'@',str(v))
  (folder/'image.ld').write_text(linker)
  flags=['-mcpu=cortex-m4','-mthumb','-mfloat-abi=soft','-mfpu=fpv4-sp-d16','-'+a.opt,'-std=c11','-flto','-ffreestanding','-fno-builtin','-fno-omit-frame-pointer','-ffunction-sections','-fdata-sections','-fstack-usage','-fno-unwind-tables','-fno-asynchronous-unwind-tables']
  includes=['-I'+str(x) for x in [shim,algo,pq/'mupq/common',ROOT/'targets/include',ROOT/'include',ROOT/'targets/common',folder]]
  sources=sorted(p for p in algo.iterdir() if p.suffix in ('.c','.s','.S'))+[pq/'mupq/common/fips202.c',pq/'common/keccakf1600.S',ROOT/'targets/common/runtime.c',ROOT/'targets/m4/platform.c',ROOT/'targets/m4/start.S',ROOT/'tests/targets/pqm4_harness.c']
  core_identity=None
  if a.core_profile:
   sources=[ROOT/'targets/common/runtime.c',ROOT/'targets/m4/platform.c',ROOT/'targets/m4/start.S',ROOT/'tests/targets/pqm4_harness.c']
   core_identity=json.loads((a.core_build/'build.xml').read_text())
   assert core_identity['target']=='m4' and core_identity['source_recipe']=='portable_'+a.core_profile
   assert sha(a.core_build/'latticecore.elf')==core_identity['elf_sha256']
   capacity={44:7488,65:8672,87:10720}[parameter] if a.core_profile=='rate' else {44:3776,65:3808,87:3808}[parameter]
   includes+=['-DLC_REFERENCE_CORE=1','-DLC_COMPARISON_WORKSPACE='+str(capacity),'-DLC_COMPARISON_PROFILE="'+a.core_profile+'"']
  hashes={str(p.relative_to(pq)) if p.is_relative_to(pq) else 'core/'+p.relative_to(ROOT).as_posix():sha(p) for p in sources}
  objects=[]
  if a.core_profile:
   objects=sorted(p for p in (a.core_build/'obj').glob('*.o') if int(p.name.split('_')[0])<7)
   assert len(objects)==7
  for i,source in enumerate(sources):
   obj=folder/'obj'/('%02d.o'%i);extra=[]
   if source.suffix.lower()=='.s':extra=['-x','assembler-with-cpp']
   selected=flags.copy()
   if source.is_relative_to(ROOT):selected=[x for x in selected if x not in ('-flto','-fno-omit-frame-pointer')]+['-fomit-frame-pointer']
   run(['arm-none-eabi-gcc',*selected,*includes,*extra,'-DLC_PQM4_PARAMETER='+str(parameter),'-MMD','-MF',obj.with_suffix('.d'),'-c',source,'-o',obj],str(parameter)+'_compile_'+str(i),cwd=algo)
   objects.append(obj)
  elf=folder/'pqm4.elf'
  run(['arm-none-eabi-gcc','-mcpu=cortex-m4','-mthumb','-mfloat-abi=soft','-mfpu=fpv4-sp-d16','-'+a.opt,'-flto','-nostdlib','-nostartfiles','-Wl,--gc-sections','-Wl,--build-id=none','-Wl,-Map,'+str(folder/'image.map'),'-T',folder/'image.ld',*objects,'-lgcc','-o',elf],str(parameter)+'_link')
  syms=run(['arm-none-eabi-nm','-n',elf],str(parameter)+'_symbols');run(['arm-none-eabi-size','-A',elf],str(parameter)+'_sections')
  ledger=target.ledger(target.symbols(syms));(folder/'memory_ledger.xml').write_text(json.dumps(ledger,indent=2)+'\n')
  console=run(['qemu-system-arm','-M','mps2-an386','-cpu','cortex-m4','-display','none','-monitor','none','-serial','stdio','-semihosting-config','enable=on,target=native','-kernel',elf],str(parameter)+'_console')
  rows=[json.loads(line) for line in console.splitlines() if line.startswith('{')]
  summary=[r for r in rows if r['event']=='summary'];cases=[r for r in rows if r['event']=='case']
  assert len(summary)==1 and summary[0]['cases']==76 and not summary[0]['failures'] and len(cases)==76 and all(r['ok'] for r in cases)
  assert all(v<16384-32 for v in summary[0]['operation_stack_watermarks'])
  results.append(dict(parameter=parameter,elf_sha256=sha(elf),retained_public_entries=sorted(set(line.split()[-1] for line in syms.splitlines() if len(line.split())==3 and line.split()[-1] in ('lc_get_sizes','lc_context_init','lc_keypair','lc_sign','lc_verify','lc_encaps','lc_decaps','lc_error_string'))),source_hashes=hashes,flags=flags,memory=ledger,summary=summary[0],core_build_sha256=sha(a.core_build/'build.xml') if a.core_profile else None,core_source_identity=core_identity,object_sha256={p.name:sha(p) for p in objects},console_sha256=sha(out/(str(parameter)+'_console.log'))))
  print(parameter,'PASS',summary[0]['operation_stack_watermarks'],flush=True)
 (out/'observations.xml').write_text(json.dumps(dict(schema='lattice.pqm4_m4fstack_resource.v1',implementation=a.core_profile or 'pqm4-m4fstack',upstream_commit='5e5cc76d0b072ee7077e58afcbc619a1a67a53b4',mupq_commit='ddcccedb2db9d0250856bd58ee5c46c61e506c5d',compiler=compiler.splitlines()[0],qemu=qemu.splitlines()[0],target='mps2-an386/cortex-m4',individual_parameter_images=not bool(a.core_profile),input_core_objects_contain_all_six_parameters=bool(a.core_profile),linked_image_scope='ML-DSA three-operation test image; final retained public entries are listed per image',cases_per_parameter=76,positive_acvp_cells=3,negative_signature_cases=1,generated_roundtrips=24,stack_reservation=16384,stack_watermark='observed lower bound including function trampoline; full reservation in ledger',heap_bytes=0,timing_collected=False,results=results),indent=2)+'\n')
if __name__=='__main__':main()
