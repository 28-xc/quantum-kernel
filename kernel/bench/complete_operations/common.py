"""Public complete-operation protocol validation and exact artifact binding."""
from pathlib import Path
import csv
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
import math


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON field: '+key)
        result[key] = value
    return result


def constant(value):
    raise ValueError('Non-finite JSON constant: '+value)


def load_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8'),
                      object_pairs_hook=unique, parse_constant=constant)


def validate_csv(path, summary):
    with Path(path).open(newline='', encoding='utf-8') as stream:
        rows = list(csv.DictReader(stream))
    count, warmups = summary['samples'], summary['warmups']
    if len(rows) != count+warmups or summary['raw_rows'] != count+warmups:
        raise ValueError('Raw sample count mismatch')
    for i, row in enumerate(rows):
        if row['case_id'] != f"{summary['seed']:016x}-{summary['parameter']}-{summary['operation']}-{i}":
            raise ValueError('Case identity mismatch/duplication')
        if int(row['iteration']) != i-warmups or int(row['warmup']) != (i<warmups) or int(row['status']) != 0:
            raise ValueError('Missing/out-of-order/failing sample')
        for key in ('entropy_sha256','message_sha256','context_sha256'):
            if len(row[key]) != 64 or any(c not in '0123456789abcdef' for c in row[key]):
                raise ValueError('Invalid input identity')
        if summary['mode'] == 'measure':
            ns, ticks, frequency = float(row['elapsed_ns']), int(row['elapsed_ticks']), int(row['tick_frequency'])
            if not math.isfinite(ns) or ns < 0 or ticks < 0 or frequency != summary['frequency'] or abs(ns-ticks*1e9/frequency)>0.001:
                raise ValueError('Invalid elapsed time')
        elif any(row[key] for key in ('elapsed_ns','elapsed_ticks','tick_frequency')):
            raise ValueError('Unexpected timing in verification mode')
    return rows


def verify_prepared(configuration):
    path = Path(configuration['prepared']).resolve()
    prepared = load_json(path)
    if prepared['schema'] != 'lattice.complete_operation_driver.v1' or prepared['status'] != 'PASS':
        raise ValueError('A functionally checked driver is required')
    if prepared['boundary'] != configuration['boundary'] or prepared['expected_version'] != configuration['expected_version']:
        raise ValueError('Prepared driver boundary or OpenSSL version differs')
    for name in ('driver','crypto_library'):
        artifact = Path(configuration[name]).resolve()
        expected = Path(prepared[name]['path']).resolve()
        if not artifact.is_file() or not artifact.samefile(expected) or sha(artifact) != prepared[name]['sha256']:
            raise ValueError('Prepared artifact differs: '+name)
    for source in prepared['sources']:
        artifact = (path.parent/source['path']).resolve()
        if not artifact.is_relative_to(path.parent) or sha(artifact) != source['sha256']:
            raise ValueError('Prepared source snapshot changed')
    if prepared['verified_operation_cells'] != 18 or not prepared['all_input_output_sequences_match']:
        raise ValueError('Incomplete driver functional preparation')
