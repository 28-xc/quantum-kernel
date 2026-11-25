"""Create and verify identities of the supplied statistical source modules."""
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
import argparse, hashlib, record_io as json

ROOT = Path(__file__).resolve().parents[1]
FILES = tuple(sorted([
    'analysis/block_model.py', 'analysis/pooled_conditions.py',
    'analysis/pooled_model.py', 'analysis/pooled_shards.py',
    'analysis/pooled_statistics.py', 'analysis/pooled_view.py',
    'publicschemas/pooled_block_model.py', 'publicschemas/pooled_conditions.py',
    'publicschemas/pooled_model.py', 'publicschemas/pooled_shards.py',
    'tools/statistics_source_manifest.py',
]))

def current(root=ROOT):
    return {
        'schema': 'lattice.statistical_source_identity.v2',
        'scope': 'SHA256 identities of the supplied statistical calculation, validation and export modules.',
        'files': [{'path': name, 'sha256': hashlib.sha256((root/name).read_bytes()).hexdigest()}
                  for name in FILES],
    }

def verify(value, root=ROOT):
    if value != current(root):
        raise ValueError('Statistical source identities are stale or incomplete')
    return len(FILES)

def read(path):
    def unique(pairs):
        out={}
        for key,value in pairs:
            if key in out: raise ValueError('Duplicate JSON key')
            out[key]=value
        return out
    return json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=unique)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    modes=parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--write', type=Path, help='New manifest path')
    modes.add_argument('--verify', type=Path, help='Manifest to check against supplied sources')
    args=parser.parse_args()
    if args.write:
        args.write.parent.mkdir(parents=True, exist_ok=True)
        with args.write.open('x', encoding='utf-8', newline='\n') as out:
            json.dump(current(),out,ensure_ascii=False,indent=2);out.write('\n')
        print('Created source identities for',len(FILES),'modules')
    else:
        print('Verified source identities for',verify(read(args.verify)),'modules')

if __name__=='__main__':main()
