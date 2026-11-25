"""Recompute equal-frequency complete-service time directly from raw call observations."""
from pathlib import Path
import argparse
import hashlib
import sys
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'analysis'))
import pooled_statistics as shared
from publicschemas import equal_frequency_model as model

def sources(): return {p: shared.sha(ROOT / p) for p in model.SOURCES}
def ci(values): return [shared.q7(values, .025), shared.q7(values, .975)]

def analyze(data, pairs, observations_sha256, resamples=10000,
            seed=20261005279045, base_dir=None):
    model.integer(resamples, 1); model.need(resamples <= 100000, 'Resample bound exceeded')
    model.integer(seed); model.digest(observations_sha256)
    labels, arrays = shared.observations_arrays(data, base_dir)
    model.comparisons(pairs, labels)
    e = data['experiment']; counts, draw_hash = shared.draws(e['blocks'], resamples, seed)
    cell_replicates = np.empty((len(labels), 18, resamples), dtype=np.float64)
    points = []
    for li, label in enumerate(labels):
        cell_points = []
        for cell, (parameter, operation) in enumerate(model.CELLS):
            block_means = np.mean(arrays[label, parameter, operation], axis=1)
            cell_replicates[li, cell] = np.einsum('ij,j->i', counts, block_means) / e['blocks']
            cell_points.append(float(np.mean(block_means)))
        points.append(sum(cell_points))
    totals = cell_replicates.sum(axis=1)
    summary = dict(
        schema=model.SCHEMA, dataset_id=data['dataset_id'], platform=data['platform'],
        observations_sha256=observations_sha256, source_code_hashes=sources(),
        configuration_order=labels, configurations=data['configurations'],
        cell_order=[list(c) for c in model.CELLS],
        method=dict(estimator='ratio_of_sums_of_18_mean_operation_times',
                    ratio_direction='candidate_over_reference', calls_per_cell=1,
                    bootstrap_unit=model.BOOTSTRAP_UNIT, bootstrap_rng='PCG64',
                    bootstrap_seed=seed, resamples=resamples,
                    interval='pointwise_percentile_0.025_0.975',
                    block_draws_sha256=draw_hash,
                    replicate_values_sha256=hashlib.sha256(totals.astype('<f8', copy=False).tobytes()).hexdigest(),
                    slow_observation_policy='retain_all',
                    warmup_policy='retain_in_observations_exclude_only_from_statistics'),
        counts=dict(blocks=e['blocks'], samples_per_run=e['samples_per_run'],
                    warmups_per_run=e['warmups_per_run'], raw_rows=data['completeness']['sample_rows'],
                    measured_rows=e['blocks'] * e['samples_per_run'] * 18 * len(labels),
                    warmup_rows=e['blocks'] * e['warmups_per_run'] * 18 * len(labels), deleted_rows=0),
        totals=[dict(configuration=label, sum_18_mean_ns=points[i], ci95_ns=ci(totals[i]))
                for i, label in enumerate(labels)], comparisons=[])
    for pair in pairs:
        left, right = labels.index(pair['candidate']), labels.index(pair['reference'])
        summary['comparisons'].append(dict(**pair, sum_mean_time_ratio=points[left] / points[right],
                                           ci95=ci(totals[left] / totals[right])))
    model.validate(summary, data)
    return summary

def recompute(data, summary, observations_sha256, base_dir=None):
    model.validate(summary, data)
    model.need(summary['observations_sha256'] == observations_sha256, 'Observation bytes changed')
    model.need(summary['source_code_hashes'] == sources(), 'Statistical source changed')
    pairs = [{k: p[k] for k in ('id', 'candidate', 'reference')} for p in summary['comparisons']]
    actual = analyze(data, pairs, observations_sha256, summary['method']['resamples'],
                     summary['method']['bootstrap_seed'], base_dir)
    model.need(actual == summary, 'Equal-frequency reconstruction differs')
    return dict(status='EXACT_PUBLIC_EQUAL_FREQUENCY_RECOMPUTED', dataset_id=data['dataset_id'],
                configurations=len(summary['totals']), comparisons=len(pairs),
                sample_rows=summary['counts']['raw_rows'])

def main():
    p = argparse.ArgumentParser(description=__doc__); sub = p.add_subparsers(dest='action', required=True)
    for action in ('derive', 'recompute'):
        s = sub.add_parser(action); s.add_argument('--observations', type=Path, required=True)
        if action == 'derive':
            s.add_argument('--comparisons', type=Path, required=True); s.add_argument('--output', type=Path, required=True)
            s.add_argument('--resamples', type=int, default=10000); s.add_argument('--seed', type=int, default=20261005279045)
        else: s.add_argument('--summary', type=Path, required=True)
    a = p.parse_args(); data = shared.read_observations(a.observations); identity = shared.sha(a.observations)
    if a.action == 'derive':
        result = analyze(data, shared.read(a.comparisons), identity, a.resamples, a.seed, a.observations.resolve().parent)
        shared.write(a.output, result)
        print(shared.json.dumps(dict(status='PUBLIC_EQUAL_FREQUENCY_DERIVED', summary_sha256=shared.sha(a.output))))
    else: print(shared.json.dumps(recompute(data, shared.read(a.summary), identity, a.observations.resolve().parent)))

if __name__ == '__main__': main()
