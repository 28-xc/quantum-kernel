"""Check original collector/driver provenance without changing scientific files."""
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
import argparse, importlib.util, record_io as json, sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from publicschemas.method_inventory_v1 import validate,descriptors,need
from publicschemas.archived_images_v1 import validate as validate_images
_helper=Path(__file__).with_name('recompute_archived_images.py')
_spec=importlib.util.spec_from_file_location('archived_image_consumer',_helper)
_module=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(_module)
header,sha=_module.header,_module.sha


def recompute(path):
    path=Path(path).resolve()
    def pairs(values):
        out={}
        for k,v in values:need(k not in out,'Repeated JSON key');out[k]=v
        return out
    def read(p):return json.loads(p.read_text(encoding='utf-8'),object_pairs_hook=pairs)
    data=validate(read(path));checked={}
    for d in descriptors(data):
        file=(path.parent/d['path']).resolve();need(file.is_relative_to(path.parent) and file.is_file(),'Missing/outside technical source')
        need(sha(file)==d['sha256'],'Technical source identity differs');checked[d['path']]=file
    for row in data['independent_binaries']:
        file=checked[row['artifact']['path']];need(file.stat().st_size==row['bytes'] and header(file)==(row['format'],row['machine']),'Actual independent image differs')
    for row in data['datasets']:
        observations=read(checked[row['observations']['path']])
        need(observations['dataset_id']==row['dataset_id'],'Observation dataset differs')
        need(observations['driver_sha256']==row['driver']['sha256'] and observations['crypto_library_sha256']==row['crypto_runtime']['sha256'],'Driver/runtime differs from actual observations')
        for field,role in [('driver','benchmark_driver'),('crypto_runtime','benchmark_runtime')]:
            matches=[x for x in data['independent_binaries'] if x['artifact']==row[field]]
            need(len(matches)==1 and matches[0]['category']==role and matches[0]['platform']==observations['platform'],'Unregistered or wrong-platform measurement binary')
    core=validate_images(read(checked[data['core_images']['path']]))
    return dict(schema='lattice.observation_methods_checked.v1',observations_sha256=sha(path),source_sha256=sha(Path(__file__)),helper_sha256=sha(_helper),
                descriptors_checked=len(checked),core_images=len(core['images']),independent_binaries=len(data['independent_binaries']),datasets=len(data['datasets']),executed_images=0)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--observations',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    need(not a.output.exists(),'Fresh output required');result=recompute(a.observations);a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8');print(json.dumps(result))


if __name__=='__main__':main()
