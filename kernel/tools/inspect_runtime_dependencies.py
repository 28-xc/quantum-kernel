"""Record PE imports and explicit link-map runtime evidence without loading code."""
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
import argparse, hashlib, record_io as json, re, subprocess
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def inspect(name,path,objdump,map_path=None):
 p=Path(path);r=subprocess.run([objdump,'-p',str(p)],capture_output=True,text=True,check=True)
 imports=re.findall(r'DLL Name:\s*([^\r\n]+)',r.stdout)
 if not imports:raise ValueError('No PE import table found')
 system=lambda x: x.lower() in {'bcrypt.dll','kernel32.dll','msvcrt.dll','ucrtbase.dll','advapi32.dll','crypt32.dll','user32.dll','ws2_32.dll','ntdll.dll'} or x.lower().startswith(('api-ms-win-','ext-ms-win-'))
 out={'id':name,'filename':p.name,'sha256':sha(p),'imports':imports,
      'non_system_imports':[x for x in imports if not system(x)],
      'scope':'Static import table; explicit runtime LoadLibrary dependencies must also be supplied by the application configuration.'}
 if map_path:
  t=Path(map_path).read_text(encoding='utf-8',errors='strict')
  patterns={'mingw_crt':r'(?:libmingw(?:32|ex)|libucrt_extra|dllcrt2\.o|crt2\.o)',
   'gcc_runtime':r'(?:libgcc(?:_eh)?\.a\(|__emutls_get_address)',
   'winpthreads':r'(?:libwinpthread_la-|libpthread\.a\()',
   'llvm_compiler_rt':r'(?:libclang_rt\.|compiler-rt)'}
  out['link_map_sha256']=sha(map_path)
  out['runtime_link_map_matches']={k:sorted(set(re.findall(v,t))) for k,v in patterns.items()}
 return out
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--artifact',action='append',required=True,help='technical-id=PE-path');p.add_argument('--map',action='append',default=[],help='technical-id=link-map');p.add_argument('--objdump',default='objdump');p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 maps=dict(x.split('=',1) for x in a.map);rows=[];seen=set()
 for value in a.artifact:
  name,path=value.split('=',1)
  if not re.fullmatch('[A-Za-z0-9_.-]+',name) or name in seen:raise ValueError('Unique technical artifact identifiers required')
  seen.add(name);rows.append(inspect(name,path,a.objdump,maps.get(name)))
 if set(maps)-seen:raise ValueError('Map without registered PE')
 if a.output.exists():raise ValueError('Fresh output required')
 a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps({'schema':'lattice.pe_runtime_dependencies.v1','artifacts':rows},indent=2)+'\n',encoding='utf-8')
if __name__=='__main__':main()
