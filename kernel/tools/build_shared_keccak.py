"""Build the portable shared Keccak profile and its matched compact control.

The measured Windows artifact uses GCC 15.2.0, -Os and LTO. This command
rebuilds from the caller's source tree and records new artifact identities.
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
import argparse, hashlib, record_io as json, os, shutil, subprocess, sys

ROOT = Path(__file__).resolve().parents[1]

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--cc', default='gcc')
    p.add_argument('--ar', default='gcc-ar')
    p.add_argument('--nm', default='nm')
    p.add_argument('--objdump', default='objdump')
    a = p.parse_args()
    out = a.output.resolve()
    if out.exists():
        raise ValueError('Use a fresh output directory')
    out.mkdir(parents=True)
    (out/'tmp').mkdir()
    env = os.environ.copy()
    env.update(TEMP=str(out/'tmp'), TMP=str(out/'tmp'), TMPDIR=str(out/'tmp'),
               PYTHONDONTWRITEBYTECODE='1')
    commands = []
    def run(argv, label):
        proc = subprocess.run(list(map(str, argv)), cwd=ROOT, env=env,
                              capture_output=True, text=True, encoding='utf-8', errors='replace')
        log = out/(label+'.log')
        log.write_text(json.capture_text(proc.stdout+proc.stderr), encoding='utf-8')
        commands.append(dict(command=list(map(str, argv)), exit_code=proc.returncode,
                             log=log.name, log_sha256=sha(log)))
        (out/'commands.xml').write_text(json.dumps(commands, indent=2)+'\n')
        if proc.returncode:
            raise RuntimeError(label+' failed: '+str(log))
    run([sys.executable, '-B', ROOT/'tools/size_variants.py', '--output', out/'control',
         '--configuration', 'compact-fixed', '--scope', 'all', '--backend', 'portable',
         '--opt', 'Os', '--lto', '--cc', a.cc, '--ar', a.ar, '--nm', a.nm,
         '--objdump', a.objdump], 'control')
    run([sys.executable, '-B', ROOT/'tests/pruning/shared_keccak_compact/build_candidate.py',
         '--source-root', ROOT, '--control', out/'control', '--output', out/'shared',
         '--provider', 'single', '--nm', a.nm, '--objdump', a.objdump], 'shared')
    library_name = 'latticecore.dll' if os.name == 'nt' else 'liblatticecore.so'
    for name in ('control', 'shared'):
        directory = out/name
        result_path = directory/'result.xml'
        result = json.loads(result_path.read_text())
        image = result['candidate_image'] if name == 'shared' else result['inspections']['shared_library']
        manifest = dict(schema='latticecore.bound-shared-build.v1', configuration='compact-'+name,
                        backend='portable', sanitizer='none',
                        binary=dict(file=library_name, sha256=sha(directory/library_name)),
                        result_sha256=sha(result_path), compiler=result['compiler'],
                        program_bytes=image['readonly_allocated_bytes']+image['data_bytes'],
                        parameters=[512, 768, 1024, 44, 65, 87])
        (directory/'build.xml').write_text(json.dumps(manifest, indent=2)+'\n')
        if os.name == 'nt':
            shutil.copyfile(directory/'latticecore.dll.a', directory/'liblatticecore.dll.a')
    print(json.dumps(dict(status='PASS', control=sha(out/'control'/library_name),
                          shared=sha(out/'shared'/library_name))))

if __name__ == '__main__':
    main()
