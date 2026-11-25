"""Verify archived image bytes and PE/ELF target headers without executing them."""
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
import struct
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from publicschemas.archived_images_v1 import validate, need


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            h.update(block)
    return h.hexdigest()


def header(path):
    with path.open('rb') as stream:
        start = stream.read(64)
        if start[:2] == b'MZ':
            need(len(start) == 64, 'Truncated DOS header')
            offset = struct.unpack_from('<I', start, 60)[0]
            need(offset <= path.stat().st_size - 24, 'PE offset outside image')
            stream.seek(offset); pe = stream.read(24)
            need(pe[:4] == b'PE\0\0', 'Invalid PE signature')
            machine = struct.unpack_from('<H', pe, 4)[0]
            need(machine == 0x8664, 'Unexpected PE machine')
            return 'PE', 'x86_64'
        need(start[:4] == b'\x7fELF' and len(start) >= 20, 'Unrecognized image')
        need(start[4] in (1, 2) and start[5] == 1, 'Expected little-endian ELF')
        machine = struct.unpack_from('<H', start, 18)[0]
        need(machine in (40, 183, 243), 'Unexpected ELF machine')
        need((machine == 183 and start[4] == 2) or (machine in (40, 243) and start[4] == 1), 'ELF class/machine mismatch')
        return 'ELF', {40: 'arm', 183: 'aarch64', 243: 'riscv'}[machine]


def recompute(path):
    path = Path(path).resolve()
    def pairs(rows):
        obj = {}
        for key, value in rows:
            need(key not in obj, 'Duplicate JSON key'); obj[key] = value
        return obj
    data = validate(json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=pairs))
    records = []
    for image in data['images']:
        file = (path.parent / image['artifact']['path']).resolve()
        need(file.is_relative_to(path.parent) and file.is_file() and not file.is_symlink(), 'Image escaped dataset')
        need(file.stat().st_size == image['bytes'] and sha(file) == image['artifact']['sha256'], 'Image identity differs')
        need(header(file) == (image['format'], image['machine']), 'Actual image target differs')
        records.append({'id': image['id'], 'sha256': image['artifact']['sha256'], 'bytes': image['bytes'], 'format': image['format'], 'machine': image['machine']})
    return {'schema': 'lattice.archived_images_checked.v1', 'observations_sha256': sha(path), 'source_sha256': sha(Path(__file__)),
            'image_count': len(records), 'executed_images': 0, 'images': records}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--observations', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(); need(not args.output.exists(), 'Fresh output required')
    result = recompute(args.observations); args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'image_count': result['image_count'], 'executed_images': 0}))


if __name__ == '__main__':
    main()
