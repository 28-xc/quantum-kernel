"""Create a functional-only config from registered local deployment descriptors."""
from pathlib import Path
import argparse
import copy
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

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from demo.server import checked_file, read
from publicschemas.demo import validate_config


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input', type=Path, required=True)
    p.add_argument('--library', action='append', required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    if a.output.exists() or len(a.library) != len(set(a.library)):
        raise ValueError('Fresh output and unique library IDs required')
    config = validate_config(read(a.input))
    selected = [copy.deepcopy(x) for x in config['libraries'] if x['id'] in a.library]
    if len(selected) != len(a.library):
        raise ValueError('Unknown library')
    result = dict(schema=4, kind='local_lattice_demo', libraries=selected,
                  datasets=[], scientific_views=[], pooled_views=[],
                  deployment_profiles=copy.deepcopy(config['deployment_profiles']))
    if 'host_probe' in config:
        result['host_probe'] = copy.deepcopy(config['host_probe'])
    descriptors = [result['deployment_profiles']]
    if 'host_probe' in result:
        descriptors.append(result['host_probe'])
    for item in selected:
        descriptors.append(item['artifact'])
        if 'derivation' in item:
            descriptors.append(item['derivation'])
        # Historical timing correspondence is not a live functional dependency.
        item.pop('measurement_reuse', None)
    for item in descriptors:
        item['path'] = str(checked_file(item, a.input.resolve().parent))
    validate_config(result)
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf8')


if __name__ == '__main__':
    main()
