"""Hash-checked, lossless technical view of the fixed ML-KEM phase study."""
from pathlib import Path, PurePosixPath
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
import argparse, csv, hashlib, record_io as json, math, re

SCHEMA = 'lattice.security_phase_observations.v1'
SUMMARY = 'lattice.security_phase_summary.v1'
DATASET = 'security-phase-controls-v1'
JOB = re.compile(r'[0-2]_(?:selected|vnni)_(?:original|field)\Z')

def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))

def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

def keys(value, expected):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ValueError('Unexpected schema fields')

def finite(value):
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError('Non-finite scientific value')
    if isinstance(value, dict):
        for item in value.values(): finite(item)
    elif isinstance(value, list):
        for item in value: finite(item)

def validate_image_derivation(root, relative, measured_sha256, measured_bytes=None):
    from publicschemas.deployment_image import load_deployment_image
    root=Path(root).resolve()
    mapping=read(root/'image-derivations.xml')
    keys(mapping, ('schema','images'))
    if mapping['schema']!='lattice.phase_image_derivations.v1' or set(mapping['images'])!={'images/selected.dll','images/vnni.dll'}:
        raise ValueError('Unexpected image derivation map')
    record=mapping['images'][relative]
    keys(record, ('receipt','receipt_sha256'))
    receipt=root/record['receipt']
    if not receipt.resolve().is_relative_to(root) or ':' in record['receipt'] or '\\' in record['receipt']:
        raise ValueError('Unsafe derivation receipt path')
    proof=read(receipt)
    if measured_bytes is not None and proof['original_bytes']!=measured_bytes:
        raise ValueError('Measured image size differs')
    load_deployment_image(root/relative,receipt,record['receipt_sha256'],measured_sha256=measured_sha256)
    return root/relative


def validate_ref(root, value):
    keys(value, ('path', 'sha256', 'bytes'))
    relative = PurePosixPath(value['path'])
    if relative.is_absolute() or '..' in relative.parts or '\\' in value['path'] or ':' in value['path']:
        raise ValueError('Expected a safe relative data path')
    path = (root / Path(*relative.parts)).resolve()
    if not path.is_relative_to(root.resolve()) or not path.is_file():
        raise ValueError('Missing or escaped scientific input')
    if not re.fullmatch('[0-9a-f]{64}', value['sha256']) or type(value['bytes']) is not int:
        raise ValueError('Invalid digest or byte count')
    if path.stat().st_size != value['bytes'] or sha(path) != value['sha256']:
        if value['path'] not in ('images/selected.dll','images/vnni.dll'):
            raise ValueError('Scientific input digest mismatch: ' + value['path'])
        validate_image_derivation(root,value['path'],value['sha256'],value['bytes'])
    return path

def recompute(observations):
    """Re-derive the public view from pinned results; replay.py recomputes raw statistics."""
    observations = Path(observations).resolve(); root = observations.parent
    manifest = read(observations)
    keys(manifest, ('schema', 'dataset_id', 'files'))
    if manifest['schema'] != SCHEMA or manifest['dataset_id'] != DATASET:
        raise ValueError('Unsupported phase-study dataset')
    files = {}
    for item in manifest['files']:
        if item['path'] in files: raise ValueError('Duplicate scientific input')
        files[item['path']] = validate_ref(root, item)
    protocol = read(files['protocol.xml']); measurement = read(files['measurement.xml'])
    analysis = read(files['analysis/summary.xml']); controls = read(files['controls/summary.xml'])
    if protocol['schema'] != 'scientific.phase-field-controls.v1' or measurement['status'] != 'PASS':
        raise ValueError('Phase-study protocol or acquisition failed validation')
    if len(protocol['jobs']) != 12 or analysis['formal_samples'] != 6600000 or analysis['removed_samples'] != 0:
        raise ValueError('Incomplete fixed acquisition')
    if len(analysis['primary']) != 4 or len(analysis['pooled_all']) != 80 or len(controls['jobs']) != 12:
        raise ValueError('Missing primary or control contrasts')
    for binding in protocol['bindings']:
        if sha(files[binding['path']]) != binding['sha256']:
            if binding['path'] not in ('images/selected.dll','images/vnni.dll'):
                raise ValueError('Protocol binding mismatch')
            validate_image_derivation(root,binding['path'],binding['sha256'])
    for binding in (measurement['protocol'],analysis['protocol'],analysis['measurement'],analysis['analysis_code']):
        if sha(files[binding['path']]) != binding['sha256']: raise ValueError('Statistical provenance mismatch')
    if [r['job'] for r in measurement['records']] != protocol['jobs']:
        raise ValueError('Acquisition differs from the fixed protocol')
    required = {'protocol.xml', 'measurement.xml', 'analysis/summary.xml', 'controls/summary.xml',
                'historical/observations.xml', 'historical/tail_contributions.xml',
                'historical/factorial_protocol_v1.xml', 'historical/factorial_analysis_v1/blocks.csv',
                'analysis/historical_multiplicity.xml', 'analysis/bootstrap_draws.npy',
                'recompute.py', 'recompute_controls.py', 'recompute_historical_tails.py',
                'verify_tail_statistics.py',
                'machine/final/binding.xml'}
    required.update(b['path'] for b in protocol['bindings'])
    images = []
    for name in ('selected', 'vnni'):
        value = protocol['images'][name]
        keys(value, ('path', 'sha256', 'workspace', 'rva', 'parameter', 'history'))
        if sha(files[value['path']]) != value['sha256']:
            validate_image_derivation(root,value['path'],value['sha256'])
        images.append(dict(label=name, image_sha256=value['sha256'], parameter=value['parameter'],
                           history_precall=value['history'], helper_rva=value['rva']))
        required.add(value['path'])
    runs = []
    seen = set()
    for job in protocol['jobs']:
        jid = job['id']
        if not JOB.fullmatch(jid) or jid in seen: raise ValueError('Unknown or duplicate fixed acquisition')
        seen.add(jid); required.add(job['raw'])
        for clock in ('elapsed_tsc', 'thread_cycles'):
            required.add('analysis/' + jid + '_' + clock + '_blocks.npy')
        required.update(('analysis/' + jid + '.xml', 'controls/' + jid + '.xml'))
        result = read(files['analysis/' + jid + '.xml'])
        keys(result, ('id', 'raw', 'validated_samples', 'fields'))
        if result['id'] != jid or result['validated_samples'] != job['formal_calls']:
            raise ValueError('Acquisition row identity mismatch')
        if result['raw']['sha256'] != sha(files[job['raw']]):
            raise ValueError('Analysis raw-data identity mismatch')
        if set(result['fields']) != {'elapsed_tsc', 'thread_cycles'}:
            raise ValueError('Required timing clocks are missing')
        expected_contrasts = 9 if job['kind'] == 'original' else 11
        for field in result['fields'].values():
            keys(field, ('conditions_mean', 'conditions_median', 'maximum', 'contrasts', 'slot_effects',
                         'position_strata', 'predecessor_strata'))
            if len(field['contrasts']) != expected_contrasts:
                raise ValueError('A measured control contrast was dropped')
        runs.append(dict(image=job['image'], method=job['kind'], repeat=job['repeat'],
                         formal_calls=job['formal_calls'], result=result,
                         controls=read(files['controls/' + jid + '.xml'])))
    if [r['controls'] for r in runs] != controls['jobs']:
        raise ValueError('Control summary differs from individual records')
    required.update(('historical/raw-05.bin', 'historical/raw-15.bin'))
    if not required.issubset(files): raise ValueError('Required evidence is missing')
    machine_symbols = ('lc_hj_xor', 'lc_hj_matrix_init', 'lc_kem_interleaved_permute',
                       'lc_kem_hj_prefix', 'lc_kem_reject8', 'lc_keccak_x4_interleaved')
    allowed = required | {'machine/dataflow.xml'} | {
        'machine/final/' + profile + '_' + symbol + '.txt'
        for profile in ('measured_compact', 'cache40', 'cache56') for symbol in machine_symbols}
    if set(files) != allowed: raise ValueError('Unrecognized evidence file')
    raw = [item for item in manifest['files'] if item['path'].startswith('raw/') or item['path'].startswith('historical/raw-')]
    if len(raw) != 14: raise ValueError('Raw acquisition manifest must contain all 14 files')
    view = dict(schema=SUMMARY, dataset_id=DATASET, observations_sha256=sha(observations),
                measurement_unit='TSC counts; thread_cycles stored separately',
                measured_images=images, formal_samples=analysis['formal_samples'], removed_samples=0,
                historical_samples=600000, raw_files=raw, method=protocol['analysis'],
                primary=analysis['primary'], pooled_all=analysis['pooled_all'], runs=runs,
                address_interactions=controls['address_interactions'],
                historical_observations=read(files['historical/observations.xml']),
                historical_multiplicity=read(files['analysis/historical_multiplicity.xml']),
                historical_tail_contributions=read(files['historical/tail_contributions.xml']),
                static_binding=read(files['machine/final/binding.xml']),
                evidence_files=manifest['files'])
    finite(view)
    return view

def export_csv(view, path):
    """Every scalar is exported under its full JSON pointer; no interval or slow sample is filtered."""
    def walk(value, pointer=''):
        if isinstance(value, dict):
            for key, item in value.items():
                token = str(key).replace('~', '~0').replace('/', '~1')
                yield from walk(item, pointer + '/' + token)
        elif isinstance(value, list):
            for index, item in enumerate(value): yield from walk(item, pointer + '/' + str(index))
        elif value is not None:
            yield (pointer, type(value).__name__, value)
    with Path(path).open('w', newline='', encoding='utf-8-sig') as stream:
        writer = csv.writer(stream); writer.writerow(('json_pointer', 'type', 'value'))
        writer.writerows(walk(view))

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('observations', type=Path); p.add_argument('--output', type=Path, required=True)
    p.add_argument('--csv', type=Path); p.add_argument('--check', type=Path); a=p.parse_args()
    view=recompute(a.observations)
    if a.check and view != read(a.check): raise ValueError('Technical view differs from pinned output')
    if a.output.exists(): raise FileExistsError(a.output)
    a.output.write_text(json.dumps(view, ensure_ascii=False, indent=2, allow_nan=False)+'\n',encoding='utf-8')
    if a.csv:
        if a.csv.exists(): raise FileExistsError(a.csv)
        export_csv(view,a.csv)
    print('PASS: all 14 raw files, four primary contrasts, and every control preserved')

if __name__=='__main__': main()
