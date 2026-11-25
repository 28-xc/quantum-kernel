"""Bind recorded resource points to explicit, verified source snapshots.

The input mapping is a local execution file. Public outputs contain relative
file identities and hashes; local input paths are retained by the caller.
"""
from pathlib import Path
import argparse
import hashlib
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
import record_io as json
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from publicschemas import resources
from publicschemas.resource_identity_v3 import read, sha, file_map, SOURCE_SCHEMA, BUILD_SCHEMA
from publicschemas.verification_v2 import need, keys

def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False)+'\n', encoding='utf-8')

def store(root, folder, value):
    payload=(json.dumps(value,indent=2,sort_keys=True,ensure_ascii=False)+'\n').encode('utf-8')
    digest=hashlib.sha256(payload).hexdigest();relative=folder+'/'+digest+'.xml';p=root/relative
    p.parent.mkdir(exist_ok=True)
    if p.exists():need(p.read_bytes()==payload,'Conflicting source identity')
    else:p.write_bytes(payload)
    return dict(path=relative,sha256=digest)

def project(old_path, mapping_path, output):
    old=resources.load(old_path);need(old['schema']==resources.SCHEMA,'Expected historical resource version')
    mapping=read(mapping_path);keys(mapping,('points',));need(type(mapping['points']) is list,'Explicit source mappings required')
    mapped={}
    for item in mapping['points']:
        keys(item,('id','source','source_manifest','build','library'))
        need(item['id'] not in mapped,'Duplicate source mapping');mapped[item['id']]=item
    need(set(mapped)=={p['id']for p in old['points']},'Source mappings differ from resource points')
    prepared=[]
    for point in old['points']:
        item=mapped[point['id']];source=Path(item['source']).resolve();manifest=read(item['source_manifest'])['files']
        if type(manifest) is list:
            names=[row['path']for row in manifest];need(len(names)==len(set(names)),'Duplicate source paths')
            manifest={row['path']:row['sha256']for row in manifest}
        file_map(manifest)
        for name,digest in manifest.items():
            p=source/name
            need(p.is_file() and p.resolve().is_relative_to(source) and not p.is_symlink(),'Missing source file')
            need(sha(p)==digest,'Source snapshot differs from its manifest')
        build=read(item['build'])
        need(sha(item['build'])==point['source_sha256']['build'],'Actual build-record identity differs')
        need(sha(item['library'])==build['binary']['sha256']==point['binary_sha256'],'Actual algorithm image differs')
        need({k:build[k]for k in point['build']}==point['build']and build['parameters']==point['parameters'],'Actual build configuration differs')
        consumed={}
        for name,digest in build['source_hashes'].items():
            p=Path(name);relative=p.relative_to(source).as_posix()if p.is_absolute()else p.as_posix()
            need(relative not in consumed and manifest.get(relative)==digest,'Build consumes another source snapshot')
            consumed[relative]=digest
        file_map(consumed)
        need(not build.get('generated_source_hashes'),'This projector requires explicitly archived generated sources')
        prepared.append((point,manifest,consumed))
    output=Path(output);need(not output.exists(),'Output directory already exists');output.mkdir(parents=True)
    result={k:v for k,v in old.items()if k not in ('core_source_commit','verification_sha256')};result['schema']=resources.SCHEMA_V3;result['points']=[]
    for point,manifest,consumed in prepared:
        full=store(output,'sources',dict(schema=SOURCE_SCHEMA,files=manifest))
        binding=store(output,'builds',dict(schema=BUILD_SCHEMA,binary_sha256=point['binary_sha256'],
            build_record_sha256=point['source_sha256']['build'],source_manifest_sha256=full['sha256'],
            build=point['build'],parameters=point['parameters'],consumed_files=consumed,generated_files={}))
        result['points'].append(dict(point,source_identity=dict(binary_sha256=point['binary_sha256'],
            build_record_sha256=point['source_sha256']['build'],manifest=full,build_binding=binding)))
    save(output/'resources.xml',result);resources.load(output/'resources.xml')
    return dict(status='PASS',resource_points=len(result['points']),resources_sha256=sha(output/'resources.xml'))

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--resources',type=Path,required=True)
    p.add_argument('--mapping',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    print(json.dumps(project(a.resources,a.mapping,a.output)))
if __name__=='__main__':main()
