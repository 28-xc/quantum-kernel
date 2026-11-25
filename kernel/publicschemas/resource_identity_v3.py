"""Per-image source identity and checked, portable source manifests."""
from pathlib import Path, PurePosixPath
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
import re
from .verification_v2 import need, keys, digest

SCHEMA = 'lattice.deployment_resources.v3'
SOURCE_SCHEMA = 'lattice.source_manifest.v1'
BUILD_SCHEMA = 'lattice.consumed_source_binding.v1'

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def read(path):
    def pairs(items):
        result = {}
        for name, value in items:
            need(name not in result, 'Duplicate source-identity field')
            result[name] = value
        return result
    return json.loads(Path(path).read_text(encoding='utf-8-sig'), object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite identity value')))

def file_map(value):
    need(type(value) is dict and value, 'Source file list required')
    for name, value_hash in value.items():
        need(type(name) is str and len(name) <= 1024 and '\\' not in name and ':' not in name
             and '\0' not in name and not name.startswith('/') and name == PurePosixPath(name).as_posix()
             and all(part not in ('', '.', '..') for part in name.split('/')), 'Invalid relative source path')
        digest(value_hash)
    return value

def descriptor(value, folder):
    keys(value, ('path', 'sha256')); digest(value['sha256'])
    need(value['path'] == folder + '/' + value['sha256'] + '.xml', 'Identity descriptor path/hash differs')

def checked(base, value):
    root = Path(base).resolve(); candidate = root / value['path']
    need(candidate.is_file() and candidate.resolve().is_relative_to(root), 'Missing or escaping identity file')
    current = candidate
    while current != root:
        need(not current.is_symlink(), 'Symlink in identity path'); current = current.parent
    need(candidate.stat().st_size <= 32 * 1024 * 1024 and sha(candidate) == value['sha256'], 'Identity file digest differs')
    return read(candidate)

def validate_identities(data, base=None):
    for point in data['points']:
        value = point['source_identity']
        keys(value, ('binary_sha256', 'build_record_sha256', 'manifest', 'build_binding'))
        digest(value['binary_sha256']); digest(value['build_record_sha256'])
        need(value['binary_sha256'] == point['binary_sha256'] and
             value['build_record_sha256'] == point['source_sha256']['build'], 'Point/build source identity differs')
        descriptor(value['manifest'], 'sources'); descriptor(value['build_binding'], 'builds')
        if base is None:
            continue
        manifest = checked(base, value['manifest']); binding = checked(base, value['build_binding'])
        keys(manifest, ('schema', 'files')); need(manifest['schema'] == SOURCE_SCHEMA, 'Unknown source manifest')
        files = file_map(manifest['files'])
        keys(binding, ('schema', 'binary_sha256', 'build_record_sha256', 'source_manifest_sha256',
                       'build', 'parameters', 'consumed_files', 'generated_files'))
        need(binding['schema'] == BUILD_SCHEMA, 'Unknown build-source binding')
        need(binding['binary_sha256'] == value['binary_sha256'] and
             binding['build_record_sha256'] == value['build_record_sha256'] and
             binding['source_manifest_sha256'] == value['manifest']['sha256'], 'Build/manifests cross-reference differs')
        need(binding['build'] == point['build'] and binding['parameters'] == point['parameters'], 'Build configuration differs')
        consumed = file_map(binding['consumed_files'])
        need(all(files.get(name) == digest_value for name, digest_value in consumed.items()), 'Consumed source differs from complete manifest')
        need(type(binding['generated_files']) is dict, 'Generated source map required')
        if binding['generated_files']:
            file_map(binding['generated_files'])
    return data

def point_binding(point):
    return point['source_identity']['build_binding']['sha256']
