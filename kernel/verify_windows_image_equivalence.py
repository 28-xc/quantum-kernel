"""Recheck PE image equivalence from preserved measured-image derivations."""
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


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--manifest',type=Path,default=Path(__file__).with_name('pairs.xml'))
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    sys.dont_write_bytecode=True
    sys.path.insert(0,str(args.source.resolve()))
    from publicschemas.windows_image_equivalence import verify_equivalence, SCHEMA
    raw=args.manifest.read_bytes(); document=json.loads(raw)
    if document.get('schema')!=SCHEMA:
        raise ValueError('Unsupported manifest')
    digest=hashlib.sha256(raw).hexdigest()
    result=dict(status='PASS',manifest_sha256=digest,pairs=[verify_equivalence(args.manifest,old_measured_sha256=p['old']['measured_sha256'],new_measured_sha256=p['new']['measured_sha256'],receipt_sha256=digest) for p in document['pairs']])
    out=args.output.resolve(); root=args.manifest.parent.resolve()
    if out.exists() or out.is_relative_to(root) or out.is_relative_to(args.source.resolve()):
        raise ValueError('Use a fresh result path outside source and evidence directories')
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(status='PASS',pairs=len(result['pairs']))))


if __name__=='__main__':
    main()
