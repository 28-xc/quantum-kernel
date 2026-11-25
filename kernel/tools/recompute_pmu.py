"""Recompute full PMU leaf fractions from integer public CSV, not percentages."""
from pathlib import Path
import argparse
import csv
import hashlib
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
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from publicschemas.pmu_v1 import COLUMNS, SUMMARY_SCHEMA, need, validate_manifest, validate_summary


def sha_bytes(data): return hashlib.sha256(data).hexdigest()


def read_leaves(root, cell):
    raw = cell['leaf_csv']; p = root/raw['file']
    need(p.is_file() and not p.is_symlink() and p.resolve().is_relative_to(root.resolve()) and
         not p.parent.is_symlink() and not p.parent.parent.is_symlink(), 'Missing/escaping PMU artifact')
    data = p.read_bytes()
    need(len(data) == raw['bytes'] and sha_bytes(data) == raw['sha256'], 'PMU CSV identity differs')
    reader = csv.DictReader(io.StringIO(data.decode('utf-8'), newline=''))
    need(reader.fieldnames == COLUMNS, 'Changed PMU fields')
    rows = []
    for index, row in enumerate(reader):
        need(None not in row and all(v is not None for v in row.values()), 'Malformed PMU CSV')
        need(row['resolved'] in ('0', '1') and row['target_module'] in ('0', '1'), 'Invalid flag text')
        for k in ('leaf_id', 'samples', 'period'):
            need(row[k].isdigit(), 'Noninteger PMU count')
        value = {k: (int(v) if k in ('leaf_id', 'samples', 'period') else
                     bool(int(v)) if k in ('resolved', 'target_module') else v) for k, v in row.items()}
        need(value['leaf_id'] == index and value['samples'] > 0, 'Missing/reordered leaf')
        rows.append(value)
    need(len(rows) == raw['rows'] and sum(r['samples'] for r in rows) == cell['total_samples'] and
         sum(r['period'] for r in rows) == cell['total_period'], 'Integer counts/leaf rows not conserved')
    return rows


def recompute(path):
    path = Path(path).resolve(); raw_manifest = path.read_bytes()
    observations = json.loads(raw_manifest); validate_manifest(observations)
    result = dict(schema=SUMMARY_SCHEMA, dataset_id=observations['dataset_id'],
        observations_sha256=sha_bytes(raw_manifest), recompute_source_sha256=sha_bytes(Path(__file__).read_bytes()),
        cells=[], total_samples=0, total_period=0, lost_samples=0, leaf_rows=0, rows_removed=0, not_elapsed_time=True)
    for cell in observations['cells']:
        rows = read_leaves(path.parent, cell)
        target_samples = sum(r['samples'] for r in rows if r['target_module'])
        target_period = sum(r['period'] for r in rows if r['target_module'])
        for row in rows:
            row.update(sample_fraction_all=row['samples']/cell['total_samples'],
                period_fraction_all=row['period']/cell['total_period'],
                sample_fraction_target=row['samples']/target_samples if row['target_module'] and target_samples else None,
                period_fraction_target=row['period']/target_period if row['target_module'] and target_period else None)
        out = {k: cell[k] for k in ('configuration', 'parameter', 'operation', 'total_samples', 'total_period', 'lost_samples')}
        out.update(leaf_csv_sha256=cell['leaf_csv']['sha256'], target_samples=target_samples,
            outside_samples=cell['total_samples']-target_samples, target_period=target_period,
            outside_period=cell['total_period']-target_period, leaves=rows)
        result['cells'].append(out)
        for k in ('total_samples', 'total_period', 'lost_samples'): result[k] += cell[k]
        result['leaf_rows'] += len(rows)
    validate_summary(result, observations)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__); p.add_argument('--manifest', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True); a = p.parse_args()
    need(not a.output.exists(), 'Fresh summary path required')
    result = recompute(a.manifest); a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(result, indent=2, allow_nan=False)+'\n', encoding='utf-8')
    print(json.dumps({k:result[k] for k in ('dataset_id', 'total_samples', 'total_period', 'lost_samples', 'leaf_rows', 'rows_removed')}))


if __name__ == '__main__': main()
