"""Recompute actual image sections and retained entities from public files."""
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
import argparse, hashlib, importlib.util, record_io as json, sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tools'))
from publicschemas.program_space_v1 import validate,need,IMAGE_FIELDS
from size_variants import binary_info,entity_table
spec=importlib.util.spec_from_file_location('public_keccak_reachability',ROOT/'tests/pruning/shared_keccak/reachability.py')
reachability=importlib.util.module_from_spec(spec);spec.loader.exec_module(reachability)

def sha(p):
    h=hashlib.sha256()
    with p.open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''):h.update(block)
    return h.hexdigest()
def read(p):
    def pairs(items):
        out={}
        for k,v in items:need(k not in out,'Duplicate JSON field');out[k]=v
        return out
    return json.loads(p.read_text(encoding='utf-8'),object_pairs_hook=pairs,
        parse_constant=lambda _:(_ for _ in ()).throw(ValueError('Nonfinite JSON')))
def recompute(path):
    path=Path(path).resolve();base=path.parent;data=validate(read(path));cache={}
    def bound(d):
        p=(base/d['path']).resolve();need(p.is_relative_to(base),'Artifact escaped dataset')
        need(p.is_file() and sha(p)==d['sha256'],'Artifact changed: '+d['path']);return p
    for row in data['images']:
        image=binary_info(bound(row['binary']));need(image==row['image'],'Actual PE/ELF sections differ')
        nm=bound(row['nm']).read_text(encoding='utf-8');disasm=bound(row['disassembly']).read_text(encoding='utf-8')
        entities=read(bound(row['entities']));actual=entity_table(nm,image)
        need(all(entities[k]==v for k,v in actual.items()),'Retained entity table differs from nm')
        cache[row['id']]={'entities':entities,'disassembly':disasm}
    shared=[]
    for row in data['sharing']:
        actual=reachability.analyze(cache[row['candidate']]['entities']['entities'],cache[row['candidate']]['disassembly'])
        expected=read(bound(row['machine_paths']));need(actual==expected,'Machine call/tail-call witnesses changed')
        shared.append(dict(id=row['id'],readonly_delta_bytes=row['readonly_delta_bytes'],family_paths=len(actual['witnesses'])))
    return dict(schema='lattice.program_space_recomputation.v1',observations_sha256=sha(path),
        source_sha256=sha(Path(__file__)),images_checked=len(cache),pruning_groups=len(data['pruning']),sharing=shared,
        scope='Actual PE/ELF bytes and retained nm entities; direct same-image call/tail-call witnesses. External OS/runtime payload is listed separately.')
def main():
    p=argparse.ArgumentParser();p.add_argument('--observations',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    need(not a.output.exists(),'Fresh recomputation output required');value=recompute(a.observations)
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8');print('Program images and shared-entity paths recomputed')
if __name__=='__main__':main()
