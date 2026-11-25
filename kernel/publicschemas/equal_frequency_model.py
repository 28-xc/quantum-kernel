"""Closed schema for one call to each of the eighteen operation cells."""
from .pooled_model import public_observations, comparisons, CELLS, BOOTSTRAP_UNIT
from .pooled_block_model import keys, need, integer, digest
from .mean_tail_model import positive, interval

SCHEMA = 'lattice.equal_frequency_statistics.v1'
SOURCES = ('analysis/equal_frequency_statistics.py', 'publicschemas/equal_frequency_model.py',
           'analysis/pooled_statistics.py', 'analysis/pooled_model.py',
           'analysis/pooled_conditions.py', 'analysis/pooled_shards.py', 'analysis/block_model.py',
           'publicschemas/pooled_model.py', 'publicschemas/pooled_block_model.py',
           'publicschemas/pooled_conditions.py', 'publicschemas/pooled_shards.py',
           'publicschemas/mean_tail_model.py')

def validate(summary, observations):
    public_observations(observations)
    keys(summary, ['schema', 'dataset_id', 'platform', 'observations_sha256',
                   'source_code_hashes', 'configuration_order', 'configurations',
                   'cell_order', 'method', 'counts', 'totals', 'comparisons'])
    need(summary['schema'] == SCHEMA, 'Unknown equal-frequency schema')
    for key in ('dataset_id', 'platform', 'configurations'):
        need(summary[key] == observations[key], 'Observation identity differs')
    digest(summary['observations_sha256'])
    keys(summary['source_code_hashes'], SOURCES)
    for value in summary['source_code_hashes'].values(): digest(value)
    labels = [c['id'] for c in observations['configurations']]
    need(summary['configuration_order'] == labels, 'Configuration order differs')
    need(summary['cell_order'] == [list(c) for c in CELLS], 'Operation set differs')
    method = summary['method']
    keys(method, ['estimator', 'ratio_direction', 'calls_per_cell', 'bootstrap_unit',
                  'bootstrap_rng', 'bootstrap_seed', 'resamples', 'interval',
                  'block_draws_sha256', 'replicate_values_sha256',
                  'slow_observation_policy', 'warmup_policy'])
    expected = dict(estimator='ratio_of_sums_of_18_mean_operation_times',
                    ratio_direction='candidate_over_reference', calls_per_cell=1,
                    bootstrap_unit=BOOTSTRAP_UNIT, bootstrap_rng='PCG64',
                    interval='pointwise_percentile_0.025_0.975',
                    slow_observation_policy='retain_all',
                    warmup_policy='retain_in_observations_exclude_only_from_statistics')
    need(all(method[k] == v for k, v in expected.items()), 'Changed estimator')
    integer(method['bootstrap_seed']); integer(method['resamples'], 1)
    need(method['resamples'] <= 100000, 'Resample bound exceeded')
    for key in ('block_draws_sha256', 'replicate_values_sha256'): digest(method[key])
    e = observations['experiment']; counts = summary['counts']
    keys(counts, ['blocks', 'samples_per_run', 'warmups_per_run', 'raw_rows',
                  'measured_rows', 'warmup_rows', 'deleted_rows'])
    need(counts == dict(blocks=e['blocks'], samples_per_run=e['samples_per_run'],
                       warmups_per_run=e['warmups_per_run'],
                       raw_rows=observations['completeness']['sample_rows'],
                       measured_rows=e['blocks'] * e['samples_per_run'] * 18 * len(labels),
                       warmup_rows=e['blocks'] * e['warmups_per_run'] * 18 * len(labels),
                       deleted_rows=0), 'Sample counts differ')
    need(type(summary['totals']) is list and
         [r.get('configuration') for r in summary['totals']] == labels, 'Missing total')
    for row in summary['totals']:
        keys(row, ['configuration', 'sum_18_mean_ns', 'ci95_ns'])
        positive(row['sum_18_mean_ns']); interval(row['ci95_ns'])
    pairs = summary['comparisons']
    need(type(pairs) is list, 'Comparison list required')
    comparisons([{k: p[k] for k in ('id', 'reference', 'candidate')} for p in pairs], labels)
    for row in pairs:
        keys(row, ['id', 'candidate', 'reference', 'sum_mean_time_ratio', 'ci95'])
        positive(row['sum_mean_time_ratio']); interval(row['ci95'])
    return summary
