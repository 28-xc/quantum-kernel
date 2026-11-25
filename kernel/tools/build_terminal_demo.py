"""Build the native ARM demonstration bridge without changing either algorithm library."""
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
import argparse, hashlib, record_io as json, platform, shutil, subprocess, sys
ROOT=Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def write(p,d):p.write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
def main():
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('library','application-build','core-build','resources','output'):p.add_argument('--'+n,type=Path,required=True)
 p.add_argument('--cc',default='gcc');a=p.parse_args();out=a.output.resolve()
 if out.exists() or out.is_relative_to(ROOT) or platform.machine() not in ('aarch64','arm64'):raise ValueError('Fresh external directory and actual AArch64 host required')
 resource=json.loads(a.resources.read_text());core=json.loads(a.core_build.read_text());app=json.loads((a.application_build/'build.xml').read_text())
 if resource['library']['sha256']!=sha(a.library) or app['artifacts']['libapplication.so']!=sha(a.application_build/'libapplication.so'):raise ValueError('Qualified input identity differs')
 out.mkdir(parents=True);source=out/'source';source.mkdir();art=out/'artifacts';art.mkdir();logs=out/'logs';logs.mkdir()
 for name in ('terminal_bridge.c','application.h','latticecore.h'):shutil.copyfile(ROOT/'examples/enrollment_owner'/name,source/name)
 shutil.copyfile(ROOT/'tools/terminal_demo.py',out/'terminal_demo.py')
 shutil.copyfile(a.library,art/'liblatticecore.so');shutil.copyfile(a.application_build/'libapplication.so',art/'libapplication.so')
 records=[]
 def run(name,args):
  q=subprocess.run(args,cwd=out,capture_output=True,text=True,timeout=120);(logs/(name+'.stdout')).write_text(json.capture_text(q.stdout));(logs/(name+'.stderr')).write_text(q.stderr)
  records.append(dict(label=name,argv=args,exit_code=q.returncode,stdout_sha256=sha(logs/(name+'.stdout')),stderr_sha256=sha(logs/(name+'.stderr'))));write(out/'commands.xml',records)
  if q.returncode:raise RuntimeError(name+' failed; see logs')
  return q.stdout
 compiler=run('compiler',[a.cc,'--version'])
 run('compile',[a.cc,'-std=c11','-Os','-Wall','-Wextra','-fPIC','-shared','-Wl,-z,relro,-z,now,-z,noexecstack','source/terminal_bridge.c','-ldl','-o','artifacts/libterminal_demo.so'])
 bridge_file=run('bridge-file',['file','artifacts/libterminal_demo.so']);core_file=run('core-file',['file','artifacts/liblatticecore.so'])
 if 'ARM aarch64' not in bridge_file or 'ARM aarch64' not in core_file:raise ValueError('Native ELF architecture differs')
 run('bridge-sections',['readelf','-W','-S','-l','artifacts/libterminal_demo.so']);run('bridge-size',['size','-A','artifacts/libterminal_demo.so'])
 cpu=Path('/proc/cpuinfo').read_text();(logs/'cpuinfo.txt').write_text(cpu)
 environment=dict(system=platform.system(),release=platform.release(),architecture=platform.machine(),cpu_fields=sorted({line.strip() for line in cpu.splitlines() if line.startswith(('CPU implementer','CPU architecture','CPU variant','CPU part','CPU revision','Features'))}))
 build=dict(status='PASS',compiler=compiler,bridge_file=bridge_file,core_file=core_file,environment=environment,
  source={str(p.relative_to(out)):sha(p) for p in sorted(source.iterdir())},cli_sha256=sha(out/'terminal_demo.py'),
  qualified_core_build_sha256=sha(a.core_build),qualified_resources_sha256=sha(a.resources),application_build_sha256=sha(a.application_build/'build.xml'),commands_sha256=sha(out/'commands.xml'))
 write(out/'build.xml',build)
 config=dict(schema='lattice.terminal_demo_configuration.v1',workspace_bytes=resource['W'],backend=str(core.get('backend','AArch64 (compiled native recipe)')),
  resources={k:resource[k] for k in ('W','S','C','G','H','R','P')},artifacts={n:dict(path='artifacts/'+f,sha256=sha(art/f),file_bytes=(art/f).stat().st_size) for n,f in [('bridge','libterminal_demo.so'),('library','liblatticecore.so'),('application','libapplication.so')]})
 write(out/'configuration.xml',config);print(json.dumps(dict(status='PASS',library_sha256=sha(art/'liblatticecore.so'),bridge_sha256=sha(art/'libterminal_demo.so'))))
if __name__=='__main__':main()
