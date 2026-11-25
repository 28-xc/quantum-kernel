"""Recompute all finite timing-screen checkpoints from public CSV only.

Reads one record at a time. Does not load DLLs, run cryptographic tests, access
private evidence paths, or convert nondetection into a security certification.
"""
from pathlib import Path
import argparse
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
import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from publicschemas.timing_v1 import (
    SCHEMA, SUMMARY_SCHEMA, STATISTICS, close, need, validate, validate_summary)


def sha_bytes(value):
    return hashlib.sha256(value).hexdigest()


def read_raw(root, record, conditions):
    ref = record['raw']; path = root / ref['file']
    need(path.is_file() and not path.is_symlink(), 'Missing CSV or symlink')
    need(path.resolve().is_relative_to(root.resolve()), 'CSV resolves outside public directory')
    # Refuse directory aliases too; no hidden private/local-file dependency.
    need(not any(p.is_symlink() for p in (path.parent, path.parent.parent)), 'Symlinked CSV directory')
    data = path.read_bytes()
    need(len(data) == ref['bytes'] and sha_bytes(data) == ref['sha256'], 'CSV size or SHA differs')
    lines = data.splitlines()
    need(len(lines) == ref['rows'] + 1 and lines[0].decode('ascii') == ','.join(ref['columns']),
         'Wrong physical row count/header; no blank or discarded observation rows allowed')
    a = np.loadtxt(io.BytesIO(data), delimiter=',', skiprows=1, dtype=np.float64, comments=None)
    need(a.shape == (ref['rows'], 3) and np.isfinite(a).all() and
         np.isin(a[:, 0], [0, 1]).all() and np.isin(a[:, 2], [0, 1]).all() and
         ((a[:, 1] >= 0) & (a[:, 1] <= 2**53)).all() and
         (a[:, 1] == np.floor(a[:, 1])).all(), 'Invalid class/time/norm observation')
    batch = conditions['class_batch_size']
    need((a[:, 0].reshape(-1, batch).sum(axis=1) == batch // 2).all(), 'Unbalanced class block')
    counts = [int(a[a[:, 0] == c, 2].sum()) for c in (0, 1)]
    need(counts == record['norm_one_counts_by_class'], 'Norm counts differ from complete raw observations')
    return a


def compute_history(a, conditions):
    result = []
    for n in conditions['checkpoints']:
        x = a[:n]; center = x[:, 1].mean()
        values = [x[:, 1], (x[:, 1] - center)**2]
        for name, z in zip(STATISTICS, values):
            u = z[x[:, 0] == 0]; v = z[x[:, 0] == 1]
            need(len(u) == len(v) == n // 2, 'Checkpoint class counts differ')
            denominator = np.sqrt(u.var(ddof=1) / len(u) + v.var(ddof=1) / len(v))
            need(np.isfinite(denominator) and denominator > 0, 'Degenerate or nonfinite variance')
            t = float((u.mean() - v.mean()) / denominator)
            need(np.isfinite(t), 'Nonfinite Welch statistic')
            result.append(dict(samples=n, statistic=name, welch_t=t, n0=len(u), n1=len(v),
                               mean0=float(u.mean()), mean1=float(v.mean())))
    return result


def recompute(manifest_path):
    manifest_path = Path(manifest_path).resolve()
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes); validate(manifest)
    result = dict(schema=SUMMARY_SCHEMA, dataset_id=manifest['dataset_id'],
                  observations_sha256=sha_bytes(manifest_bytes),
                  recompute_source_sha256=sha_bytes(Path(__file__).read_bytes()),
                  raw_files_checked=0, raw_rows_checked=0, deleted_rows=0,
                  studies=[], analysis_scope='finite_input_group_timing')
    for study in manifest['studies']:
        rows = []
        for job, record in zip(study['jobs'], study['records']):
            a = read_raw(manifest_path.parent, record, study['conditions'])
            h = compute_history(a, study['conditions'])
            for computed, reported in zip(h, record['reported_history']):
                for k in ('welch_t', 'mean0', 'mean1'):
                    need(close(computed[k], reported[k]), 'Retained checkpoint statistic does not match raw data')
            detected = any(abs(x['welch_t']) >= study['conditions']['threshold_abs_t'] for x in h)
            need(detected == record['reported_detected'], 'Detection result differs from raw data')
            last = h[-2]
            rows.append(dict(**job, raw_sha256=record['raw']['sha256'], history=h, detected=detected,
                             final_mean_class0=last['mean0'], final_mean_class1=last['mean1'],
                             final_class1_minus_class0=last['mean1'] - last['mean0'],
                             max_abs_t=max(abs(x['welch_t']) for x in h),
                             norm_one_counts_by_class=record['norm_one_counts_by_class'],
                             input_fnv64=record['input_fnv64'], original_record=record['original_record']))
            result['raw_files_checked'] += 1; result['raw_rows_checked'] += len(a)
        controls = [r for r in rows if r['positive_control']]
        targets = [r for r in rows if not r['positive_control']]
        out = {k: study[k] for k in ('study_id', 'platform', 'configuration', 'phase', 'repeat_of',
                                    'artifact_sha256', 'environment_events')}
        out.update(unit=study['conditions']['unit'], records=rows, target_records=len(targets),
                   target_differences_detected=sum(r['detected'] for r in targets),
                   positive_controls=len(controls), positive_controls_detected=sum(r['detected'] for r in controls))
        result['studies'].append(out)
    validate_summary(result, manifest)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--manifest', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    need(not args.output.exists(), 'Use a fresh output; retained summaries are not overwritten')
    result = recompute(args.manifest)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, allow_nan=False) + '\n', encoding='utf-8')
    print(json.dumps({k: result[k] for k in ('dataset_id', 'raw_files_checked', 'raw_rows_checked', 'deleted_rows')}))


if __name__ == '__main__':
    main()
