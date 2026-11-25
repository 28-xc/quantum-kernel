"""Verified, dataset-specific association of archived measurements with selected images."""
import csv
import io
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
from urllib.parse import urlencode
from .observations import require, SHA, TOKEN

PURPOSE_SCHEMAS = {
    'instruction_samples': {'lattice.instruction_samples.recomputed.v1'},
    'layout_ablation': {'lattice.mean_tail_statistics.v1', 'lattice.pooled_median_statistics.v2'},
}
LAYOUT_CONFIGURATIONS = {
    'lattice-compact-native', 'dense-secret-decoding', 'retained-high-bits',
    'dense-secret-retained-high', 'retained-vector32', 'staged-matrix-sampling',
}


def validate_requests(rows):
    require(type(rows) is list and len(rows) <= 8, 'Explicit bounded measurement associations required')
    seen = set()
    for row in rows:
        require(type(row) is dict and set(row) == {'dataset_id', 'purpose', 'measured_binary_sha256', 'equivalence'}, 'Unknown measurement association fields')
        require(type(row['dataset_id']) is str and TOKEN.fullmatch(row['dataset_id']), 'Invalid associated dataset')
        require(row['dataset_id'] not in seen, 'Duplicate associated dataset')
        seen.add(row['dataset_id'])
        require(row['purpose'] in PURPOSE_SCHEMAS, 'Unsupported measurement association purpose')
        require(type(row['measured_binary_sha256']) is str and SHA.fullmatch(row['measured_binary_sha256']), 'Invalid measured image identity')
        ref = row['equivalence']
        require(type(ref) is dict and set(ref) == {'path', 'sha256'}, 'Explicit equivalence receipt required')
        require(type(ref['path']) is str and 0 < len(ref['path']) < 1024 and '\x00' not in ref['path'], 'Invalid receipt path')
        require(type(ref['sha256']) is str and SHA.fullmatch(ref['sha256']), 'Invalid receipt identity')


def verify(row, library, data, receipt_path):
    from .windows_image_equivalence import verify_equivalence
    validate_requests([row])
    require(data['dataset_id'] == row['dataset_id'] and data['schema'] in PURPOSE_SCHEMAS[row['purpose']], 'Association dataset or purpose mismatch')
    require(library['platform'] == data['platform'] == 'windows_x86_64', 'PE association requires matching Windows platform')
    measured = row['measured_binary_sha256']
    current = library.get('measured_binary_sha256', library['binary_sha256'])
    require(measured != current, 'Exact-image data require no alias')
    if row['purpose'] == 'instruction_samples':
        subjects = {cell['binary_sha256'] for cell in data['cells']}
    else:
        require({c['id'] for c in data['configurations']} == LAYOUT_CONFIGURATIONS and
                all(c['provider'] == 'lattice' for c in data['configurations']),
                'Only the registered six-arm representation study permits layout reuse')
        subjects = {c['library_sha256'] for c in data['configurations'] if c['provider'] == 'lattice'}
    require(measured in subjects, 'Associated image is absent from actual observations')
    checked = verify_equivalence(receipt_path, old_measured_sha256=measured,
                                 new_measured_sha256=current, receipt_sha256=row['equivalence']['sha256'])
    return {'mode': 'verified_load_image_equivalence', 'purpose': row['purpose'],
            'selected_library': library['id'], 'selected_binary_sha256': library['binary_sha256'],
            'selected_measured_binary_sha256': current, 'measured_binary_sha256': measured,
            'equivalence_receipt_sha256': row['equivalence']['sha256'],
            'normalized_view_sha256': checked['normalized_view_sha256'],
            'equivalence_receipt_url': '/export/image-equivalence.xml?' + urlencode({'library': library['id'], 'dataset': row['dataset_id']})}


def independent_archive_binding(library, configurations):
    return {'mode': 'independent_arithmetic_archive', 'selected_library': library['id'],
            'selected_binary_sha256': library['binary_sha256'],
            'selected_measured_binary_sha256': library.get('measured_binary_sha256', library['binary_sha256']),
            'measured_binary_sha256': None,
            'measured_archives': [{k: c[k] for k in ('id', 'archive_sha256', 'driver_sha256', 'build_record_sha256')}
                                  for c in configurations]}


def selected_csv(view):
    """Export a selected technical view with unchanged observations and explicit association."""
    binding = view.get('measurement_binding', {})
    rows = view.get('cells', [])
    require(bool(rows), 'Selected result has no tabular observations')
    prefix = {key: value for key, value in binding.items() if key != 'measured_archives'}
    archives = {c['id']: c for c in binding.get('measured_archives', [])}
    enriched = []
    for cell in rows:
        row = dict(cell)
        row.update({'selection_' + key: value for key, value in prefix.items()})
        if archives:
            row.update({'measurement_' + key: value for key, value in archives[cell['configuration']].items() if key != 'id'})
        enriched.append({key: json.dumps(value, ensure_ascii=False, separators=(',', ':')) if isinstance(value, (dict, list)) else value
                         for key, value in row.items()})
    fields = list(dict.fromkeys(key for row in enriched for key in row))
    stream = io.StringIO(newline='')
    writer = csv.DictWriter(stream, fieldnames=fields)
    writer.writeheader()
    writer.writerows(enriched)
    return stream.getvalue().encode('utf-8-sig')
