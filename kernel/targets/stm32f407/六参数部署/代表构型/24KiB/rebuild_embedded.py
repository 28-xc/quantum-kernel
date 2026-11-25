"""Build an embedded image in an empty directory, from a self-contained XML
recipe and source files. Only the two external compiler tool paths are needed.
End-of-build artifact identities are optional assertions, never input objects.
"""
import argparse
import concurrent.futures
import hashlib
from pathlib import Path
import shutil
import subprocess
import xml.etree.ElementTree as ET

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()

def rebuild(recipe, out, llvm, gas):
    root=ET.parse(recipe).getroot(); origin=recipe.parent
    if out.exists() and any(out.iterdir()): raise ValueError(f'build dir must be empty: {out}')
    out.mkdir(exist_ok=True,parents=True)
    sources={n.get('id'):origin/n.get('path') for n in root.find('sources')}
    for n in root.find('sources'):
        src=sources[n.get('id')]
        if sha(src)!=n.get('sha256'): raise ValueError(f'source hash: {src}')
    nodes={u.get('id'):u for u in root.find('build')}; done=set()
    def run(i):
        node=nodes[i]; mode=node.get('tool'); tool=gas if mode=='arm-none-eabi-as' else llvm/(mode+'.exe')
        target=out/node.get('file'); target.parent.mkdir(parents=True,exist_ok=True)
        argv=[]; cwd=out
        for e in node:
            if e.tag=='arg': argv.append(e.text)
            elif e.tag=='source': argv.append((e.get('prefix') or '')+str(sources[e.get('id')]))
            elif e.tag=='input': argv.append(str(out/nodes[e.get('id')].get('file')))
            elif e.tag=='output': argv.append(str(target))
            elif e.tag=='map': argv.append('-Map='+str(target.with_suffix('.map')))
            else: raise ValueError(e.tag)
        if mode=='arm-none-eabi-as':
            src=Path(argv[-1]);cwd=target.parent;shutil.copyfile(src,cwd/src.name)
            argv[-1]=src.name;argv[argv.index('-o')+1]=target.name
        r=subprocess.run([str(tool),*argv],cwd=cwd,capture_output=True)
        if r.returncode:raise ValueError((i,r.stderr.decode(errors='replace')))
        expected=node.get('check')
        if expected and sha(target)!=expected:raise ValueError((i,target,sha(target),expected))
        return i
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        while len(done)<len(nodes):
            ready=[i for i,u in nodes.items() if i not in done and all(e.get('id') in done for e in u.findall('input'))]
            if not ready:raise ValueError('cycle')
            done.update(pool.map(run,ready))
    result=out/'stm32f407-unified.bin'
    print(f'{len(nodes)} source build steps; {len(sources)} source files; {result.stat().st_size} B; SHA256 {sha(result)}')
if __name__=='__main__':
    ap=argparse.ArgumentParser()
    for name in ('recipe','out','llvm','gas'):ap.add_argument(name,type=Path)
    a=ap.parse_args(); rebuild(a.recipe.resolve(),a.out.resolve(),a.llvm.resolve(),a.gas.resolve())
