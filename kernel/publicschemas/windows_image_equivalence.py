"""Check measured-image reuse through two independently bound PE deployment images."""
from pathlib import Path
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
import json as canonical_json
import struct

from publicschemas.deployment_image import load_deployment_image
from tools.relink_pe import PE


SCHEMA = 'lattice.windows_image_equivalence.v1'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def normalized_view(path):
    pe = PE(path)
    data = bytearray(pe.data)
    rva, size = pe.directories[5]
    at = pe.offset(rva, size) if size else 0
    end = at + size
    relocations = []
    while at < end:
        page, length = struct.unpack_from('<II', data, at)
        if length < 8 or length % 2 or at + length > end:
            raise ValueError('Malformed PE relocation block')
        for pos in range(at + 8, at + length, 2):
            item = struct.unpack_from('<H', data, pos)[0]
            kind, target = item >> 12, page + (item & 4095)
            if kind == 0:
                continue
            if kind != 10:
                raise ValueError('Only PE32+ DIR64 relocations are supported')
            slot = pe.offset(target, 8)
            value = struct.unpack_from('<Q', data, slot)[0]
            struct.pack_into('<Q', data, slot, (value - pe.imagebase) % (1 << 64))
            relocations.append(target)
        at += length
    if at != end or len(relocations) != len(set(relocations)):
        raise ValueError('Overlapping or malformed relocations')
    export_rva, export_bytes = pe.directories[0]
    if export_bytes:
        offset = pe.offset(export_rva + 4, 4)
        data[offset:offset + 4] = bytes(4)
    sections = {}
    for name, section in pe.sections.items():
        debug = name.startswith('.debug') and section['flags'] & 0x02000000 and not section['flags'] & 0x20000000
        if debug:
            continue
        start = section['raw_pointer']
        size = min(section['size'], section['raw_size'])
        sections[name] = dict(rva=section['va'], virtual_bytes=section['size'], flags=section['flags'], initialized_bytes=size, sha256=sha(data[start:start + size]))
    coff = struct.unpack_from('<I', data, 60)[0]
    optional = coff + 24
    return dict(machine=pe.machine,
                characteristics=struct.unpack_from('<H', data, coff + 22)[0] & ~0x0200,
                entry_and_code_rva=data[optional + 16:optional + 24].hex(),
                alignment_and_versions=data[optional + 32:optional + 56].hex(),
                subsystem_dll_flags=data[optional + 68:optional + 72].hex(),
                stack_heap_loader_flags=data[optional + 72:optional + 112].hex(),
                directories={str(i): list(value) for i, value in enumerate(pe.directories) if i not in (4, 6)},
                relocations=relocations, sections=sections)


def checked_ref(root, ref):
    if set(ref) != {'path', 'sha256'}:
        raise ValueError('Unexpected file reference')
    name = ref['path']
    if not isinstance(name, str) or ':' in name or '\\' in name or '..' in Path(name).parts or Path(name).is_absolute():
        raise ValueError('File reference must remain relative')
    path = (root / name).resolve()
    if not path.is_relative_to(root.resolve()) or not path.is_file() or path.is_symlink():
        raise ValueError('File reference escapes data directory')
    if sha(path.read_bytes()) != ref['sha256']:
        raise ValueError('Equivalence evidence file digest differs')
    return path


def verify_pair(pair, root, *, old_measured_sha256, new_measured_sha256):
    if set(pair) != {'configuration', 'old', 'new', 'normalized_view_sha256'}:
        raise ValueError('Unexpected image pair')
    views = []
    results = []
    for side, expected in [('old', old_measured_sha256), ('new', new_measured_sha256)]:
        item = pair[side]
        if set(item) != {'measured_sha256', 'image', 'derivation'} or item['measured_sha256'] != expected:
            raise ValueError('Requested measured image does not match pair')
        image = checked_ref(root, item['image'])
        receipt = checked_ref(root, item['derivation'])
        result = load_deployment_image(image, receipt, item['derivation']['sha256'], measured_sha256=expected, binary_sha256=item['image']['sha256'])
        views.append(normalized_view(image))
        results.append(result)
    if views[0] != views[1]:
        raise ValueError('Loadable code, constants or execution metadata differ')
    digest = sha(canonical_json.dumps(views[0], sort_keys=True, separators=(',', ':')).encode())
    if digest != pair['normalized_view_sha256']:
        raise ValueError('Normalized view digest differs')
    return dict(status='PASS', configuration=pair['configuration'], old_measured_sha256=old_measured_sha256, new_measured_sha256=new_measured_sha256, normalized_view_sha256=digest)


def verify_equivalence(receipt_path, *, old_measured_sha256, new_measured_sha256, receipt_sha256):
    path = Path(receipt_path)
    raw = path.read_bytes()
    if sha(raw) != receipt_sha256:
        raise ValueError('Equivalence manifest identity differs')
    document = json.loads(raw)
    if set(document) != {'schema', 'pairs'} or document['schema'] != SCHEMA:
        raise ValueError('Unknown equivalence manifest')
    pairs = [pair for pair in document['pairs'] if pair['old']['measured_sha256'] == old_measured_sha256 and pair['new']['measured_sha256'] == new_measured_sha256]
    if len(pairs) != 1:
        raise ValueError('Expected exactly one requested measured-image pair')
    return verify_pair(pairs[0], path.parent, old_measured_sha256=old_measured_sha256, new_measured_sha256=new_measured_sha256)
