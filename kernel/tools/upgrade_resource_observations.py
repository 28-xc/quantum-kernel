"""Upgrade source identities while preserving recorded measurement bytes."""
from pathlib import Path
import argparse
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
import shutil
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from publicschemas import resources, common_context_v1, resource_watermarks_v1
from publicschemas.resource_identity_v3 import read, sha, point_binding
from publicschemas.verification_v2 import need

def upgrade(kind, source, old_resources, new_resources, output):
    source=Path(source).resolve();output=Path(output)
    model=common_context_v1 if kind=='common'else resource_watermarks_v1
    old=resources.load(old_resources);new=resources.load(new_resources)
    need(old['schema']==resources.SCHEMA and new['schema']==resources.SCHEMA_V3,'Wrong resource versions')
    old_points={p['id']:p for p in old['points']};new_points={p['id']:p for p in new['points']}
    need(set(old_points)==set(new_points),'Measured resource set changed')
    for name,p in new_points.items():
        need({k:v for k,v in p.items()if k!='source_identity'}==old_points[name],'Measured resource point changed')
    model.recompute(source,old_resources)
    observation=read(source);need(observation['schema']==model.SCHEMA,'Only the original observation version is accepted')
    paths={a['raw']['path']:a['raw']['sha256']for a in observation['artifacts']}
    for method in observation['method_sources']:paths[method['path']]=method['sha256']
    need(not output.exists(),'Output exists');output.mkdir(parents=True)
    for name,digest in paths.items():
        p=source.parent/name;need(p.resolve().is_relative_to(source.parent)and sha(p)==digest,'Raw source changed')
        destination=output/name;destination.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,destination)
        need(sha(destination)==digest,'Copied measurement bytes differ')
    observation.pop('core_source_commit');observation['schema']=model.SCHEMA_V2;observation['resources_sha256']=sha(new_resources)
    for artifact in observation['artifacts']:
        artifact['source_build_binding_sha256']=point_binding(new_points[artifact['resource_id']])
    target=output/'observations.xml';target.write_text(json.dumps(observation,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    summary=model.recompute(target,new_resources)
    (output/'summary.xml').write_text(json.dumps(summary,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    return dict(status='PASS',raw_and_method_files=len(paths),observations_sha256=sha(target))

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--kind',choices=['common','watermarks'],required=True)
    for name in ['input','old-resources','new-resources','output']:p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();print(json.dumps(upgrade(a.kind,a.input,a.old_resources,a.new_resources,a.output)))
if __name__=='__main__':main()
