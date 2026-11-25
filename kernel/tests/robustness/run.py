"""Bounded local regression: actual DLLs or separately instrumented portable C.

Always use a fresh D: output. No remote targets, timing, retries or sample drops.
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
import json as wire_json
import argparse, datetime, hashlib, record_io as json, os, re, shutil, subprocess, time

ROOT=Path(__file__).resolve().parents[2]
HERE=Path(__file__).resolve().parent
SEEDS=['a127202609240001','a127202609240002','a127202609240003']
VC=Path('C:/Program Files/Microsoft Visual Studio/2022/Community/VC')
CL=VC/'Tools/MSVC/14.44.35207/bin/Hostx64/x64/cl.exe'
CLANG=ROOT.parents[1]/'toolchains/llvm-mingw-20260922-ucrt-x86_64/bin/clang.exe'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def write(p,obj):p.write_text(json.dumps(obj,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')

def run_msvc_utf8(command, cwd, env):
    """Capture cl in a private, hidden UTF-8 console without changing the caller."""
    import sys
    launcher = (
        "import ctypes, subprocess, sys\n"
        "kernel = ctypes.WinDLL('kernel32', use_last_error=True)\n"
        "if not kernel.SetConsoleOutputCP(65001): raise ctypes.WinError(ctypes.get_last_error())\n"
        "raise SystemExit(subprocess.run(sys.argv[1:]).returncode)"
    )
    startup = subprocess.STARTUPINFO()
    startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startup.wShowWindow = subprocess.SW_HIDE
    return subprocess.run([sys.executable, '-I', '-B', '-c', launcher, *command],
                          cwd=cwd, env=env, capture_output=True, startupinfo=startup,
                          creationflags=subprocess.CREATE_NEW_CONSOLE)


def msvc_streamed_dependencies(payload, destination, source):
    """Read cl's native stdout dependency object; return any following diagnostics."""
    if destination.exists():
        raise ValueError('Fresh dependency XML required')
    # cl writes UTF-8 JSON. Compiler diagnostics on the same pipe can use the
    # local Windows code page, so decode only the dependency object strictly.
    text = payload.decode('utf-8', errors='surrogateescape')
    def unique_fields(pairs):
        obj = dict(pairs)
        if len(obj) != len(pairs):
            raise ValueError('Duplicate MSVC dependency field')
        return obj
    value, end = wire_json.JSONDecoder(object_pairs_hook=unique_fields).raw_decode(text)
    consumed = len(text[:end].encode('utf-8'))
    if not isinstance(value, dict) or not isinstance(value.get('Data'), dict):
        raise ValueError('Invalid MSVC source dependency object')
    data = value['Data']
    if not isinstance(data.get('Source'), str) or Path(data['Source']).resolve() != Path(source).resolve():
        raise ValueError('MSVC dependency source mismatch')
    includes = data.get('Includes')
    if not isinstance(includes, list) or any(not isinstance(path, str) for path in includes):
        raise ValueError('Invalid MSVC include list')
    write(destination, value)
    if json.dumps(json.read(destination)) != json.dumps(value):
        raise ValueError('Dependency XML round trip differs')
    return payload[consumed:]


def msvc_output_parts(stdout):
    # Existing cl emits one top-level object after the file name and ordinary
    # diagnostics. A pragma message containing a brace is still a diagnostic.
    markers = list(re.finditer(rb'(?m)^(?:\xef\xbb\xbf)?(\{)\s*"(?:Version|Data)"\s*:', stdout))
    if not markers:
        return stdout, b'', ''
    first = markers[0]
    if len(markers) != 1:
        return stdout[:first.start()], b'', 'Multiple MSVC dependency records'
    return stdout[:first.start()], stdout[first.start(1):], ''


def msvc_declaration_view(droot, output):
    src = droot / 'src/sign.c'
    raw = src.read_bytes()
    old = raw.decode('utf-8')
    eol = '\r\n' if b'\r\n' in raw else '\n'
    code = old.replace('\r\n', '\n')
    guard = '#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE\n'
    host_head = 'static int lc_verify_segments(const uint8_t sig[MLDSA_CRYPTO_BYTES],\n'
    if code.count(host_head) != 1:
        raise ValueError('Expected one portable ML-DSA verify declaration')
    host_at = code.index(host_head)
    start = code.rindex(guard, 0, host_at)
    end_text = '                             MLD_CONFIG_CONTEXT_PARAMETER_TYPE context)\n'
    end = code.index(end_text, host_at) + len(end_text)
    original_declaration = code[start:end]
    arm_head, rest = original_declaration.removeprefix(guard).split('#else\n' + host_head + '#endif\n')
    if 'int mld_sign_verify_internal(' not in arm_head or not code[end:].startswith('{\n'):
        raise ValueError('Unsupported ML-DSA verify declaration')
    parameters, branches = rest.split(guard)
    arm_args, branches = branches.split('#else\n')
    host_args, tail = branches.split('#endif\n')
    # The selected C tokens stay the same for either value of the ARM profile guard.
    # Each invocation is now complete before a preprocessor directive is encountered.
    replacement = (guard + arm_head + parameters + arm_args + tail + '#else\n' +
                   host_head + parameters + host_args + tail + '#endif\n')
    if replacement.count('MLD_CONFIG_CONTEXT_PARAMETER_TYPE context)') != 2:
        raise ValueError('Unsupported ML-DSA context parameter layout')
    parent = output / 'obj' / 'msvc-declaration'
    (parent / 'src').mkdir(parents=True, exist_ok=False)
    shutil.copyfile(droot / 'mldsa_native.c', parent / 'mldsa_native.c')
    revised = (code[:start] + replacement + code[end:]).replace('\n', eol).encode()
    (parent / 'src/sign.c').write_bytes(revised)
    source_id = hashlib.sha256(raw).hexdigest()
    supplied_id = hashlib.sha256(revised).hexdigest()
    return parent, dict(declaration_source_sha256=source_id, declaration_view_sha256=supplied_id)


def main():
 global ROOT
 ap=argparse.ArgumentParser(description=__doc__)
 ap.add_argument('--mode',choices=['release','asan','ubsan'],required=True)
 ap.add_argument('--output',type=Path,required=True)
 ap.add_argument('--package',type=Path)
 ap.add_argument('--source-root',type=Path,help='Explicit immutable project source root; test harness remains in its own directory.')
 ap.add_argument('--clang',type=Path,default=CLANG,help='Explicit Clang toolchain for the separate UBSan executable.')
 ap.add_argument('--sequence-count',type=int,default=2048)
 ap.add_argument('--mutation-count',type=int,default=10000)
 ap.add_argument('--seeds',nargs='+',default=SEEDS)
 ap.add_argument('--cache',type=int,choices=[0,3,4,8,12,16,32,40,56],default=16)
 ap.add_argument('--match-package',type=Path,help='For sanitizer mode, bind the exact selected modified codec1/cache24 schedule and current source to its native build manifest.')
 a=ap.parse_args();out=a.output.resolve()
 if a.source_root:
  ROOT=a.source_root.resolve()
  if ROOT.drive.upper()!='D:' or not (ROOT/'include/latticecore.h').is_file():raise ValueError('Explicit source must be a local D: project root')
 if out.drive.upper()!='D:' or out.exists():raise ValueError('Fresh D: output required')
 if not 128<=a.sequence_count<=100000 or not 1<=a.mutation_count<=1000000:raise ValueError('Invalid bounded counts')
 if any(not re.fullmatch(r'[0-9a-fA-F]{1,16}',s) or not int(s,16) for s in a.seeds):raise ValueError('Invalid seed')
 out.mkdir(parents=True);(out/'tmp').mkdir();(out/'obj').mkdir()
 env=os.environ.copy();env.update(TMP=str(out/'tmp'),TEMP=str(out/'tmp'),TMPDIR=str(out/'tmp'),PYTHONDONTWRITEBYTECODE='1')
 commands=[];sources={};tool_sources={p.name:sha(p) for p in (HERE/'run.py',HERE/'sequence.c')};began=time.monotonic();result={'schema':'latticecore.robustness.r2.v1','mode':a.mode,'status':'RUNNING','seeds':a.seeds,'sequence_count':a.sequence_count,'mutation_count_each_parser':a.mutation_count,'created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'formal_timing':False,'source_root':str(ROOT),'regression_kind':'fixed-seed bounded API regression; not coverage-guided','tool_source_hashes':tool_sources}
 write(out/'plan.xml',result)
 def run(argv,label,cwd=None,allow_fail=False,dependency=None):
  start=datetime.datetime.now(datetime.timezone.utc).isoformat()
  command=list(map(str,argv))
  log=out/(label+'.log')
  details={}
  dependency_error=''
  if dependency is None:
   p=subprocess.run(command,cwd=cwd or out,env=env,capture_output=True,text=True,encoding='utf-8',errors='replace')
   log.write_text(json.capture_text(p.stdout+p.stderr),encoding='utf-8')
  else:
   destination,source=dependency
   p=run_msvc_utf8(command,cwd or out,env)
   diagnostics,payload,dependency_error=msvc_output_parts(p.stdout)
   if payload:
    try:
     diagnostics+=msvc_streamed_dependencies(payload,destination,source)
     details.update(dependency_xml=destination.relative_to(out).as_posix(),dependency_xml_sha256=sha(destination))
    except (ValueError, UnicodeError) as error:
     dependency_error=str(error)
   elif not dependency_error:
    details['dependency_emitted']=False
    if p.returncode==0:dependency_error='Compiler succeeded without a dependency record'
   if dependency_error:details['dependency_error']=dependency_error
   # Keep diagnostic bytes exactly, including localized errors on failed compiles.
   log.write_bytes(diagnostics+p.stderr)
  commands.append({'argv':command,'cwd':str(cwd or out),'started_utc':start,'ended_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'exit_code':p.returncode,'log':log.name,'log_sha256':sha(log),**details})
  write(out/'commands.xml',commands)
  if p.returncode and not allow_fail:raise RuntimeError(label+' exit '+str(p.returncode)+'; inspect preserved log')
  if dependency_error:raise ValueError(label+': '+dependency_error)
  return p
 def keep_source(p):
  p=p.resolve()
  if p.is_relative_to(ROOT):sources[p.relative_to(ROOT).as_posix()]=sha(p)
 try:
  for name in tool_sources:keep_source(HERE/name)
  kem_rows=kem_batch=1;sign_only=batch4=stream4=secret_prefix=0
  if a.match_package:
   if a.mode=='release':raise ValueError('--match-package is for separate sanitizer builds')
   selected=a.match_package.resolve();bound=json.loads((selected/'build.xml').read_text(encoding='utf-8'));cfg=bound['schedule']
   supported={'modified','reduce_ram','kem_rows','kem_batch','lowbits_codec','matrix_cache_polys','matrix_cache_bits','matrix_cache_sign_only','matrix_cache_batch4','matrix_stream_batch4','secret_prefix_polys'}
   if set(cfg)-supported:raise ValueError('Selected schedule has unsupported fields: '+str(sorted(set(cfg)-supported)))
   if not cfg['modified'] or not cfg['reduce_ram'] or cfg.get('lowbits_codec',0)!=1 or cfg.get('matrix_cache_bits',24)!=24:raise ValueError('Only actual modified codec1/cache24 schedules are supported by this runner')
   a.cache=cfg.get('matrix_cache_polys',0);kem_rows=cfg['kem_rows'];kem_batch=cfg['kem_batch']
   sign_only=cfg.get('matrix_cache_sign_only',0);batch4=cfg.get('matrix_cache_batch4',0)
   stream4=cfg.get('matrix_stream_batch4',0)
   secret_prefix=cfg.get('secret_prefix_polys',0)
   if sign_only not in (0,1) or batch4 not in (0,1) or stream4 not in (0,1):raise ValueError('Invalid staged-cache flags')
   if type(secret_prefix)!=int or not 0<=secret_prefix<=3:raise ValueError('Invalid secret-prefix size')
   if not 0<=a.cache<=56 or kem_rows not in (1,2) or kem_batch not in (1,4):raise ValueError('Unsupported selected schedule')
   if sha(selected/'latticecore.dll')!=bound['binary']['sha256']:raise ValueError('Selected DLL hash differs from build manifest')
   matched={}
   for rel,h in bound['source_hashes'].items():
    if Path(rel).suffix.lower() in ('.c','.h','.s','.inc'):
     if sha(ROOT/rel)!=h:raise ValueError('Selected source no longer matches: '+rel)
     matched[rel]=h
   result['matched_native_package']={'path':str(selected),'configuration':bound['configuration'],'dll_sha256':bound['binary']['sha256'],'build_json_sha256':sha(selected/'build.xml'),'source_hashes':matched,'scope':'Matched source and algorithm schedule; backend/compiler/RNG fallback differ in the explicitly separate portable sanitizer executable.'}
  if a.mode=='release':
   if not a.package:raise ValueError('--package required')
   package=a.package.resolve();dll=package/'latticecore.dll';manifest=package/'build.xml';lib=package/'liblatticecore.dll.a'
   metadata=json.loads(manifest.read_text(encoding='utf-8'));assert metadata['binary']['sha256']==sha(dll)
   result['package']={'path':str(package),'dll_sha256':sha(dll),'build_json_sha256':sha(manifest),'configuration':metadata['configuration'],'backend':metadata['backend'],'compiler':metadata['compiler']}
   shutil.copy2(dll,out/dll.name);cc=shutil.which('gcc');assert cc
   run([cc,'-O2','-std=c11','-Wall','-Wextra','-I'+str(ROOT/'include'),HERE/'sequence.c',lib,'-o',out/'sequence.exe'],'compile_sequence')
   result['compiler']=run([cc,'--version'],'compiler').stdout.splitlines()[0]
  else:
   native=False
   if a.mode=='asan':
    cmd=out/'vc_environment.cmd';cmd.write_text('@echo off\ncall "'+str(VC/'Auxiliary/Build/vcvars64.bat')+'" >nul\nset\n',encoding='utf-8')
    p=subprocess.run(['cmd.exe','/d','/c',str(cmd)],capture_output=True,text=True,encoding='utf-8',errors='replace',env=env)
    if p.returncode:raise RuntimeError('vcvars64 failed')
    env.update(dict(line.split('=',1) for line in p.stdout.splitlines() if '=' in line and not line.startswith('=')))
    env.update(TMP=str(out/'tmp'),TEMP=str(out/'tmp'),TMPDIR=str(out/'tmp'),ASAN_OPTIONS='halt_on_error=1:detect_leaks=0')
    # The portable Keccak source uses a GNU per-function optimization hint.
    # cl builds this ASan test with /O2. Unrecognized GNU attributes must still fail.
    msvc_header = out / 'obj' / 'msvc_asan_attributes.h'
    msvc_header.write_text(
        '#define __attribute__(args) LC_MSVC_ASAN_ATTRIBUTE args\n'
        '#define LC_MSVC_ASAN_ATTRIBUTE(attr) LC_MSVC_ASAN_ ## attr\n'
        '#define LC_MSVC_ASAN_optimize(level)\n'
        '#define LC_MSVC_ASAN_externally_visible __declspec(dllexport)\n', encoding='ascii')
    result['msvc_test_compatibility'] = {
        'file': 'obj/msvc_asan_attributes.h', 'sha256': sha(msvc_header),
        'optimization_hint': 'optimize', 'compiler_optimization': '/O2',
        'externally_visible': '__declspec(dllexport)',
        'translation_units': ['baselines/mlkem/all.c', 'src/common/public_api.c', 'src/platform/random.c', 'tests/robustness/sequence.c']}
    cc=str(CL);flags=['/nologo','/std:c11','/O2','/Zi','/fsanitize=address','/DLC_RNG_CALLBACK_ONLY=1'];prefix='/';ext='.obj'
    compiler_probe=run([cc], 'compiler',allow_fail=True)
    result['compiler']=(compiler_probe.stdout+compiler_probe.stderr).strip()
   else:
    cc=str(a.clang.resolve());assert a.clang.is_file(),str(a.clang)
    env['PATH']=str(a.clang.resolve().parent)+os.pathsep+env.get('PATH','')
    flags=['-O2','-g','-std=c11','-fsanitize=undefined','-fno-sanitize-recover=all','-DLC_RNG_CALLBACK_ONLY=1'];prefix='-';ext='.o'
    result['compiler']=run([cc,'--version'],'compiler').stdout.splitlines()[0]
   def inc(p):return prefix+'I'+str(p)
   def define(s):return prefix+'D'+s
   kroot=ROOT/'build/adapted_mlkem';droot=ROOT/'src/dsa_compact/build/sign_bitmap_stream_alias/adapted';dconfig=ROOT/'src/dsa_packed'
   general=[inc(ROOT/'include')]
   kflags=general+[inc(ROOT/'configs/hosted'),inc(kroot),inc(ROOT/'src/kem'),define('MLK_CONFIG_FILE="mlkem_config.h"'),define('LC_KEM_ROWS='+str(kem_rows)),define('LC_KEM_BATCH='+str(kem_batch)),define('LC_KEM_NOISE_CACHE=0')]
   dflags=general+[inc(dconfig),inc(droot),define('MLD_CONFIG_FILE="lc_dsa_config.h"')]+[define(x) for x in ['MLD_CONFIG_REDUCE_RAM','LC_DSA_ALIAS_SIGN_CP=1','LC_DSA_ALIAS_VERIFY_TMP=1','LC_DSA_STREAM_KEYGEN=1','LC_DSA_PACK_W0=1','LC_DSA_W0_CODEC=1','LC_DSA_A_CACHE_POLYS='+str(a.cache),'LC_DSA_A_CACHE_BITS=24']]
   dflags += [define('LC_DSA_A_CACHE_SIGN_ONLY='+str(sign_only)),define('LC_DSA_A_CACHE_BATCH4='+str(batch4)),define('LC_DSA_A_STREAM_BATCH4='+str(stream4)),define('LC_DSA_S1_CACHE_POLYS='+str(secret_prefix))]
   units=[(ROOT/'baselines/mlkem/all.c',kflags),(ROOT/'src/common/arena.c',general)]
   for i,level in enumerate([44,65,87]):units.append((droot/'mldsa_native.c',dflags+[define('MLD_CONFIG_PARAMETER_SET='+str(level)),define('MLD_CONFIG_MULTILEVEL_'+('WITH_SHARED' if i==0 else 'NO_SHARED'))]))
   units += [(dconfig/'adapter.c',dflags),(ROOT/'src/common/public_api.c',general+[inc(dconfig)]),(ROOT/'src/platform/random.c',general),(HERE/'sequence.c',general)]
   if a.mode=='asan':
    msvc_droot, receipt = msvc_declaration_view(droot, out)
    result['msvc_test_compatibility'].update(receipt)
    generated = [msvc_header, msvc_droot/'mldsa_native.c', msvc_droot/'src/sign.c']
    result['msvc_test_compatibility']['compiled_view_files'] = {
        file.relative_to(out).as_posix(): sha(file) for file in generated}
    if sha(msvc_droot/'mldsa_native.c') != sha(droot/'mldsa_native.c'):
     raise ValueError('ML-DSA aggregation source copy changed')
    keep_source(droot/'src/sign.c')
   objs=[]
   for i,(source,opts) in enumerate(units):
    keep_source(source);obj=out/'obj'/('%02d_%s%s'%(i,source.stem,ext));dep=obj.with_suffix('.xml' if a.mode=='asan' else '.d');objs.append(obj)
    if a.mode=='asan':
     if source in (ROOT/'baselines/mlkem/all.c', ROOT/'src/common/public_api.c', ROOT/'src/platform/random.c', HERE/'sequence.c'):
      opts = [*opts, '/FI'+str(msvc_header)]
     if source == droot/'mldsa_native.c':
      source = msvc_droot/'mldsa_native.c'
      opts = [*opts, inc(droot/'src')]
     run([cc,*flags,*opts,'/c',source,'/Fo'+str(obj),'/Fd'+str(out/'obj'/('%02d.pdb'%i)),'/sourceDependencies','-'],
         'compile_%02d'%i,dependency=(dep,source))
     for p in json.loads(dep.read_text(encoding='utf-8-sig'))['Data']['Includes']:keep_source(Path(p))
    else:
     run([cc,*flags,*opts,'-MMD','-MF',dep,'-c',source,'-o',obj],'compile_%02d'%i)
     names=dep.read_text().replace('\\\n',' ').split(': ',1)[1]
     for name in re.split(r'(?<!\\)\s+',names.strip()):
      p=Path(name.replace('\\ ',' '));keep_source(p if p.is_absolute() else out/p)
   exe=out/'sequence.exe'
   run([cc,*flags,*objs,*(['/Fe'+str(exe)] if a.mode=='asan' else ['-o',exe])],'link_sequence')
   control=out/'positive_control.c'
   if a.mode=='asan':control.write_text('#include <stdlib.h>\nint main(int argc,char**argv){volatile unsigned char*p=(unsigned char*)malloc(8);(void)argv;p[argc+15]=7;free((void*)p);return 0;}\n')
   else:control.write_text('#include <limits.h>\nint main(void){volatile int a=INT_MAX,b=1;volatile int c=a+b;return c==0;}\n')
   ctl=out/'positive_control.exe'
   run([cc,*flags,control,*(['/Fo'+str(out/'obj/control.obj'),'/Fd'+str(out/'obj/control.pdb'),'/Fe'+str(ctl)] if a.mode=='asan' else ['-o',ctl])],'compile_positive')
   check=run([ctl],'positive_control',allow_fail=True);diagnostic=check.stdout+check.stderr
   detected=check.returncode!=0 and (('AddressSanitizer' in diagnostic and 'heap-buffer-overflow' in diagnostic) if a.mode=='asan' else ('runtime error' in diagnostic and 'signed integer overflow' in diagnostic))
   result['positive_control']={'detected':detected,'exit_code':check.returncode,'log_sha256':sha(out/'positive_control.log'),'source_sha256':sha(control)}
   if not detected:raise RuntimeError('Sanitizer positive control was not detected')
   result['instrumented_configuration']={'backend':'portable','kem_rows':kem_rows,'kem_batch':kem_batch,'lowbits_codec':1,'matrix_cache_polys':a.cache,'matrix_cache_bits':24,'matrix_cache_sign_only':sign_only,'matrix_cache_batch4':batch4,'matrix_stream_batch4':stream4,'secret_prefix_polys':secret_prefix,'compiler_flags':flags,'rng':'explicit deterministic callback; OS fallback disabled','not_the_release_dll':True}
  records=[]
  for seed in a.seeds:
   runout=out/('seed-'+seed);runout.mkdir()
   p=run([out/'sequence.exe',seed,str(a.sequence_count),str(a.mutation_count)],'seed-'+seed,cwd=runout)
   rows=[json.loads(line) for line in p.stdout.splitlines() if line.startswith('{')]
   if len(rows)!=6 or [r['parameter'] for r in rows]!=[512,768,1024,44,65,87] or any(r['status']!='PASS' or r['seed']!=seed.lower().zfill(16) for r in rows):raise RuntimeError('Incomplete or malformed output')
   records+=rows
  if a.mode=='asan':
   for name, digest in result['msvc_test_compatibility']['compiled_view_files'].items():
    if sha(out/name) != digest:
     raise RuntimeError('ASan test input changed during verification: '+name)
  for name,h in sources.items():
   if sha(ROOT/name)!=h:raise RuntimeError('Source changed during verification: '+name)
  for name,h in tool_sources.items():
   if sha(HERE/name)!=h:raise RuntimeError('Test harness changed during verification: '+name)
  if a.match_package:
   if sha(selected/'latticecore.dll')!=result['matched_native_package']['dll_sha256']:raise RuntimeError('Selected native DLL changed during verification')
   for name,h in result['matched_native_package']['source_hashes'].items():
    if sha(ROOT/name)!=h:raise RuntimeError('Matched source changed during verification: '+name)
  if a.mode=='release':
   if sha(dll)!=result['package']['dll_sha256'] or sha(out/'latticecore.dll')!=sha(dll):raise RuntimeError('Release binary changed during verification')
  result.update(status='PASS',records=records,source_hashes=sources,exe_sha256=sha(out/'sequence.exe'),commands_sha256=sha(out/'commands.xml'),elapsed_seconds=time.monotonic()-began)
  write(out/'result.xml',result);print(json.dumps({'status':'PASS','mode':a.mode,'records':len(records),'output':str(out)}))
 except Exception as e:
  result.update(status='FAIL_OR_INCOMPLETE',error=str(e),elapsed_seconds=time.monotonic()-began);write(out/'result.xml',result);raise
if __name__=='__main__':main()
