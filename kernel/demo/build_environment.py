"""Prepare an independent ASCII build view only after the user requests a build."""
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
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
import ctypes, hashlib, record_io as json, os, shutil, tempfile

def normalized(path):
    text=str(Path(path).resolve())
    if os.name=='nt' and text.startswith('\\\\?\\'):text=text[4:]
    return Path(text)

def prepare(source,folder):
    source=normalized(source);package=source.parents[1]
    entry=package/'03_复现环境与运行程序/软件演示程序/入口'
    manifest=json.loads((entry/'prepared/build-inputs.xml').read_text(encoding='utf-8'))
    root=normalized(tempfile.mkdtemp(prefix='lattice-build-'))
    (Path(folder)/'build-input-location.xml').write_text(json.dumps(dict(path=str(root)),ensure_ascii=False),encoding='utf-8')
    inputs = []
    for row in manifest['files']:
        src = normalized(package / row['path'])
        dst = normalized(root / row['target'])
        if not src.is_relative_to(package) or not dst.is_relative_to(root):
            raise ValueError(f'Build dependency path is outside its root: {src}, {package}, {dst}, {root}')
        inputs.append((row, src, dst))

    # Create shared directory parents before workers copy into them.
    for parent in sorted({dst.parent for _, _, dst in inputs}):
        parent.mkdir(parents=True, exist_ok=True)

    def copy(item):
        row, src, dst = item
        data = src.read_bytes()
        if len(data) != row['bytes'] or hashlib.sha256(data).hexdigest() != row['sha256']:
            raise ValueError('Build dependency changed: ' + row['path'])
        dst.write_bytes(data)
        if hashlib.sha256(dst.read_bytes()).hexdigest() != row['sha256']:
            raise ValueError('Build copy verification failed')
        return dict(path=row['target'], sha256=row['sha256'])

    with ThreadPoolExecutor(max_workers=8) as pool:
        copied = list(pool.map(copy, inputs))
    codec=source/'record_io.py'
    identity=next((row for row in manifest['files'] if row['target']=='source/record_io.py'),None)
    if identity is None:raise ValueError('Typed record reader is missing from the build manifest')
    # The shipped embedded interpreter has an isolated module path. Only this
    # package-external interpreter copy is adapted for build subprocesses.
    pth=next((root/'runtime').glob('python*._pth'))
    original=hashlib.sha256(pth.read_bytes()).hexdigest()
    pth.write_text('python313.zip\n.\n../source\n../source/tools\n',encoding='ascii')
    (root/'build-inputs.xml').write_text(json.dumps(dict(status='COPIED_AND_VERIFIED',files=copied,original_pth_sha256=original,adapted_pth_sha256=hashlib.sha256(pth.read_bytes()).hexdigest(),algorithms_modified=False),indent=2),encoding='utf-8')
    if not str(root).isascii() and os.name=='nt':
        buffer=ctypes.create_unicode_buffer(32768)
        n=ctypes.windll.kernel32.GetShortPathNameW(str(root),buffer,len(buffer))
        if n and buffer.value.isascii():root=Path(buffer.value)
    if not str(root).isascii():raise ValueError('编译工具需要英文路径。请用启动参数 --output 指定包外英文目录；密码演示不受此限制。')
    return root/'runtime/python.exe',root/'source'
