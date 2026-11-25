"""Closed observations of timing distributions for explicitly defined inputs.

The manifest records the planned job matrix separately from observations, so
missing positive controls, omitted seeds and incomplete repeats are visible.
Only public relative CSV paths and technical identities are accepted.
"""
import math
import re
from pathlib import PurePosixPath

SCHEMA = 'lattice.timing_observations.v1'
SUMMARY_SCHEMA = 'lattice.timing_statistics.v2'
STATISTICS = ['raw_mean', 'centered_second_moment']
PHASES = {'registered_screen', 'repeat_screen', 'public_matrix_diagnostic',
          'public_fields_diagnostic'}
PATH = re.compile(r'(?i)(?:[a-z]:[\\/]|/(?:home|root|Users)/|[\\/]\.ssh[\\/]|'
                  r'\b(?:\d{1,3}\.){3}\d{1,3}\b|BEGIN [A-Z ]*PRIVATE KEY)')


def need(value, message):
    if not value:
        raise ValueError(message)


def keys(value, expected):
    need(type(value) is dict and set(value) == set(expected),
         'Unexpected or missing public timing fields')


def integer(value, minimum=0):
    need(type(value) is int and value >= minimum, 'Invalid integer')


def number(value):
    need(type(value) in (int, float) and math.isfinite(value), 'Nonfinite number')


def boolean(value):
    need(type(value) is bool, 'Expected boolean')


def token(value):
    need(type(value) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', value),
         'Invalid public identifier')


def digest(value):
    need(type(value) is str and re.fullmatch('[a-f0-9]{64}', value), 'Invalid SHA-256')


def text(value):
    need(type(value) is str and 0 < len(value) <= 4096 and not PATH.search(value),
         'Nonpublic path/address or invalid scientific description')


def relative_csv(value):
    need(type(value) is str and '\\' not in value, 'CSV path must use public / separators')
    p = PurePosixPath(value)
    need(not p.is_absolute() and len(p.parts) == 3 and p.parts[0] == 'raw' and
         all(x not in ('.', '..', '') for x in p.parts) and
         p.suffix == '.csv' and p.as_posix() == value, 'Invalid relative CSV path')
    for item in (p.parts[1], p.stem):
        token(item)


def job(value):
    keys(value, ['record_id', 'mode', 'parameter', 'seed', 'positive_control'])
    token(value['record_id']); token(value['mode']); integer(value['seed'])
    need(value['parameter'] in (512, 768, 1024, 44, 65, 87), 'Unknown parameter')
    boolean(value['positive_control'])


def reference(value):
    if value is not None:
        keys(value, ['study_id', 'record_id'])
        token(value['study_id']); token(value['record_id'])


def history(value, conditions):
    need(type(value) is list, 'Invalid checkpoint history')
    wanted = [(n, s) for n in conditions['checkpoints'] for s in STATISTICS]
    need([(r.get('samples'), r.get('statistic')) for r in value] == wanted,
         'Missing, repeated or reordered checkpoint/statistic')
    for row in value:
        keys(row, ['samples', 'statistic', 'welch_t', 'n0', 'n1', 'mean0', 'mean1'])
        for k in ('samples', 'n0', 'n1'):
            integer(row[k], 1)
        need(row['n0'] == row['n1'] == row['samples'] // 2, 'Unbalanced checkpoint')
        for k in ('welch_t', 'mean0', 'mean1'):
            number(row[k])
        need(row['mean0'] >= 0 and row['mean1'] >= 0, 'Negative time or squared moment')


def validate(data):
    keys(data, ['schema', 'dataset_id', 'study_order', 'studies', 'limitations'])
    need(data['schema'] == SCHEMA, 'Wrong timing schema'); token(data['dataset_id'])
    need(type(data['study_order']) is list and len(data['study_order']) > 0 and
         len(set(data['study_order'])) == len(data['study_order']), 'Invalid study closure')
    need(type(data['studies']) is list and
         [s.get('study_id') for s in data['studies']] == data['study_order'],
         'Missing or reordered complete study')
    need(type(data['limitations']) is list and len(data['limitations']) >= 1,
         'Scientific limits required')
    for item in data['limitations']:
        text(item)
    all_records = {}; all_jobs = {}; all_paths = set(); studies = {}
    for s in data['studies']:
        keys(s, ['study_id', 'platform', 'configuration', 'phase', 'repeat_of',
                 'artifact_sha256', 'core_source_sha256', 'source_identity',
                 'conditions', 'families', 'jobs', 'records', 'environment_events',
                 'scope'])
        token(s['study_id']); token(s['configuration']); studies[s['study_id']] = s
        need(s['platform'] in ('windows_x86_64', 'linux_aarch64', 'synthetic'),
             'Unregistered target platform')
        need(s['phase'] in PHASES, 'Unknown scientific phase')
        if s['repeat_of'] is not None:
            token(s['repeat_of'])
        need((s['phase'] == 'repeat_screen') == (s['repeat_of'] is not None),
             'Repeat must identify its preserved original study')
        digest(s['artifact_sha256']); digest(s['core_source_sha256'])
        identity = s['source_identity']
        keys(identity, ['protocol_sha256', 'results_sha256', 'driver_sha256',
                        'runner_sha256', 'executable_sha256', 'bindings_sha256',
                        'validation_sha256', 'base_driver_sha256', 'public_header_sha256'])
        for k, v in identity.items():
            if k in ('bindings_sha256', 'base_driver_sha256', 'public_header_sha256') and v is None:
                continue
            digest(v)
        c = s['conditions']
        keys(c, ['timer', 'unit', 'cpu_logical', 'samples_per_record', 'warmup_before_record',
                 'class_batch_size', 'class_assignment', 'checkpoints', 'threshold_abs_t',
                 'statistics', 'slow_observation_policy', 'checkpoint_policy',
                 'difference_direction', 'welch_numerator', 'second_moment_center',
                 'familywise_error_probability_claimed', 'positive_control_definition'])
        text(c['positive_control_definition'])
        need(c['timer'] in ('lfence-rdtsc-lfence', 'CLOCK_MONOTONIC_RAW', 'synthetic'),
             'Unknown timing method')
        need(c['unit'] in ('tsc_ticks', 'ns', 'synthetic_units'), 'Unknown unit')
        need((s['platform'], c['timer'], c['unit']) in (
            ('windows_x86_64', 'lfence-rdtsc-lfence', 'tsc_ticks'),
            ('linux_aarch64', 'CLOCK_MONOTONIC_RAW', 'ns'),
            ('synthetic', 'synthetic', 'synthetic_units')), 'Inconsistent platform/timer/unit')
        for k in ('cpu_logical', 'warmup_before_record'):
            integer(c[k])
        integer(c['samples_per_record'], 2); integer(c['class_batch_size'], 2)
        need(c['class_batch_size'] % 2 == 0 and
             c['samples_per_record'] % c['class_batch_size'] == 0,
             'Class block or sample count differs')
        need(c['class_assignment'] == 'balanced_fisher_yates_xorshift64_per_block',
             'Unknown class assignment')
        need(type(c['checkpoints']) is list and len(c['checkpoints']) > 0 and
             c['checkpoints'] == sorted(set(c['checkpoints'])) and
             c['checkpoints'][-1] == c['samples_per_record'], 'Incomplete checkpoint plan')
        for n in c['checkpoints']:
            integer(n, 2); need(n % c['class_batch_size'] == 0, 'Partial class block checkpoint')
        number(c['threshold_abs_t']); need(c['threshold_abs_t'] > 0, 'Nonpositive threshold')
        need(c['statistics'] == STATISTICS and c['slow_observation_policy'] == 'retain_all' and
             c['checkpoint_policy'] == 'all_registered_checkpoints_no_significance_early_stop' and
             c['difference_direction'] == 'class1_minus_class0' and
             c['welch_numerator'] == 'class0_minus_class1' and
             c['second_moment_center'] == 'pooled_mean_at_each_checkpoint' and
             c['familywise_error_probability_claimed'] is False, 'Changed statistic interpretation')
        need(type(s['families']) is list and len(s['families']) > 0, 'Missing input family')
        modes = []
        for f in s['families']:
            keys(f, ['mode', 'class_definition', 'timed_region', 'input_validity', 'limits'])
            token(f['mode']); modes.append(f['mode'])
            for k in ('class_definition', 'timed_region', 'input_validity', 'limits'):
                text(f[k])
        need(len(modes) == len(set(modes)), 'Repeated family')
        need(type(s['jobs']) is list and len(s['jobs']) > 0, 'Missing planned jobs')
        for j in s['jobs']:
            job(j); need(j['mode'] in modes, 'Job family absent')
        jobids = [j['record_id'] for j in s['jobs']]
        identities = [(j['mode'], j['parameter'], j['seed'], j['positive_control']) for j in s['jobs']]
        need(len(set(jobids)) == len(jobids) and len(set(identities)) == len(identities),
             'Repeated job or repeated semantic cell')
        if s['phase'] in ('registered_screen', 'repeat_screen'):
            need(any(j['positive_control'] for j in s['jobs']), 'Registered screen lacks detector controls')
        need(type(s['records']) is list and [r.get('record_id') for r in s['records']] == jobids,
             'Missing, extra or reordered measured job')
        for planned, r in zip(s['jobs'], s['records']):
            keys(r, ['record_id', 'raw', 'reported_history', 'reported_detected',
                     'norm_one_counts_by_class', 'input_fnv64', 'actual_input_fnv64',
                     'public_segment_fnv64', 'key_pool_size', 'actual_module_checked',
                     'original_record', 'input_identity_sha256', 'log_sha256'])
            reference(r['original_record']); digest(r['log_sha256'])
            for k in ('input_fnv64', 'actual_input_fnv64', 'public_segment_fnv64'):
                need(r[k] is None or type(r[k]) is str and re.fullmatch('[a-f0-9]{16}', r[k]),
                     'Invalid stream checksum')
            need(r['input_fnv64'] is not None, 'Missing measured input sequence checksum')
            integer(r['key_pool_size'], 1); need(r['actual_module_checked'] is True,
                                              'Actual module identity was not checked')
            ids = r['input_identity_sha256']
            keys(ids, ['public_pool', 'ciphertext', 'key_indices', 'public_rhos', 'polynomials'])
            for value in ids.values():
                if value is not None:
                    digest(value)
            raw = r['raw']; keys(raw, ['file', 'sha256', 'bytes', 'rows', 'columns'])
            relative_csv(raw['file']); digest(raw['sha256']); integer(raw['bytes'], 1)
            need(raw['file'].casefold() not in all_paths, 'CSV filename reused or case-aliased across observations')
            all_paths.add(raw['file'].casefold())
            need(raw['rows'] == c['samples_per_record'] and raw['columns'] ==
                 ['class', 'elapsed_ns' if c['unit'] == 'ns' else 'tsc_ticks', 'norm_result'],
                 'Wrong sample count/CSV field convention')
            history(r['reported_history'], c); boolean(r['reported_detected'])
            need(r['reported_detected'] == any(abs(v['welch_t']) >= c['threshold_abs_t']
                                              for v in r['reported_history']), 'Flag/history mismatch')
            need(type(r['norm_one_counts_by_class']) is list and
                 len(r['norm_one_counts_by_class']) == 2, 'Wrong norm counts')
            for value in r['norm_one_counts_by_class']:
                integer(value); need(value <= raw['rows'] // 2, 'Norm count exceeds observations')
            all_records[(s['study_id'], r['record_id'])] = r
            all_jobs[(s['study_id'], r['record_id'])] = planned
        need(type(s['environment_events']) is list, 'Missing environment-event list')
        for event in s['environment_events']:
            keys(event, ['kind', 'scope', 'time_precision', 'description', 'source_record_sha256'])
            need(event['kind'] in ('possible_concurrent_local_work', 'documented_concurrent_local_work',
                                   'other_recorded_environment_event'),
                 'Unrecognized technical environment event')
            need(event['scope'] == 'entire_original_study_retained', 'Rows may not be selectively deleted')
            need(event['time_precision'] in ('recorded_interval', 'bounded_interval', 'not_recorded'),
                 'Unknown event timestamp precision')
            text(event['description']); digest(event['source_record_sha256'])
        text(s['scope'])
    for s in data['studies']:
        if s['repeat_of'] is not None:
            need(s['repeat_of'] in studies, 'Repeated original study omitted')
            origin = studies[s['repeat_of']]
            need(origin['phase'] == 'registered_screen' and
                 origin['artifact_sha256'] == s['artifact_sha256'] and
                 origin['jobs'] == s['jobs'] and origin['conditions'] == s['conditions'],
                 'Repeat changed artifact, input-family matrix or statistical plan')
            need([r['input_fnv64'] for r in origin['records']] ==
                 [r['input_fnv64'] for r in s['records']], 'Repeat input sequence differs')
        if s['phase'].endswith('_diagnostic'):
            need(all(r['original_record'] is not None for r in s['records']) and
                 not any(j['positive_control'] for j in s['jobs']), 'Diagnostic must preserve its original links')
            origins = {r['original_record']['study_id'] for r in s['records']}
            need(len(origins) == 1 and next(iter(origins)) in studies, 'Missing unique original study')
            origin = studies[next(iter(origins))]
            need(origin['artifact_sha256'] == s['artifact_sha256'] and
                 origin['platform'] == s['platform'], 'Diagnostic changed loaded artifact or platform')
            wanted = {j['record_id'] for j in origin['jobs'] if j['mode'] == 'decaps_key' and not j['positive_control']}
            need(wanted and {r['original_record']['record_id'] for r in s['records']} == wanted and
                 len(s['records']) == len(wanted), 'Diagnostic selected only a subset of original full-key cells')
        for r in s['records']:
            link = r['original_record']
            if link is not None:
                need((link['study_id'], link['record_id']) in all_records, 'Diagnostic original omitted')
                original = all_records[(link['study_id'], link['record_id'])]
                need(original['input_fnv64'] == r['input_fnv64'], 'Diagnostic replay checksum differs')
                current_job = all_jobs[(s['study_id'], r['record_id'])]
                original_job = all_jobs[(link['study_id'], link['record_id'])]
                need(current_job['parameter'] == original_job['parameter'] and
                     current_job['seed'] == original_job['seed'], 'Diagnostic parameter/seed differs')
    return data


def close(a, b):
    return math.isclose(a, b, rel_tol=1e-11, abs_tol=1e-9)


def validate_summary(summary, observations):
    """Validate the public summary's shape and manifest identities, without I/O.

    Raw numerical authenticity requires tools/recompute_timing.py once, followed
    by a caller-verified summary hash. This function does not claim to reread CSV.
    """
    validate(observations)
    keys(summary, ['schema', 'dataset_id', 'observations_sha256', 'recompute_source_sha256',
                   'raw_files_checked', 'raw_rows_checked', 'deleted_rows', 'studies',
                   'analysis_scope'])
    need(summary['schema'] == SUMMARY_SCHEMA and
         summary['dataset_id'] == observations['dataset_id'], 'Wrong timing-summary identity')
    digest(summary['observations_sha256']); digest(summary['recompute_source_sha256'])
    need(summary['analysis_scope'] == 'finite_input_group_timing' and summary['deleted_rows'] == 0,
         'Changed analysis scope or sample deletion')
    expected_files = sum(len(s['records']) for s in observations['studies'])
    expected_rows = sum(len(s['records']) * s['conditions']['samples_per_record']
                        for s in observations['studies'])
    need(summary['raw_files_checked'] == expected_files and summary['raw_rows_checked'] == expected_rows,
         'Incomplete raw-data accounting')
    need(type(summary['studies']) is list and len(summary['studies']) == len(observations['studies']),
         'Missing summary study')
    for out, source in zip(summary['studies'], observations['studies']):
        keys(out, ['study_id', 'platform', 'configuration', 'phase', 'repeat_of', 'artifact_sha256',
                   'unit', 'environment_events', 'records', 'target_records', 'target_differences_detected',
                   'positive_controls', 'positive_controls_detected'])
        for k in ('study_id', 'platform', 'configuration', 'phase', 'repeat_of', 'artifact_sha256',
                  'environment_events'):
            need(out[k] == source[k], 'Summary source identity or environment changed')
        need(out['unit'] == source['conditions']['unit'], 'Changed measurement unit')
        need(type(out['records']) is list and len(out['records']) == len(source['records']),
             'Incomplete summary records')
        for row, original, planned in zip(out['records'], source['records'], source['jobs']):
            keys(row, ['record_id', 'mode', 'parameter', 'seed', 'positive_control', 'raw_sha256',
                       'history', 'detected', 'final_mean_class0', 'final_mean_class1',
                       'final_class1_minus_class0', 'max_abs_t', 'norm_one_counts_by_class',
                       'input_fnv64', 'original_record'])
            for k in ('record_id', 'mode', 'parameter', 'seed', 'positive_control'):
                need(row[k] == planned[k], 'Changed summary job')
            need(row['raw_sha256'] == original['raw']['sha256'] and
                 row['norm_one_counts_by_class'] == original['norm_one_counts_by_class'] and
                 row['input_fnv64'] == original['input_fnv64'] and
                 row['original_record'] == original['original_record'], 'Changed observation identity')
            history(row['history'], source['conditions'])
            for a, b in zip(row['history'], original['reported_history']):
                for k in ('welch_t', 'mean0', 'mean1'):
                    need(close(a[k], b[k]), 'Numerical history differs from retained record')
            need(row['detected'] == original['reported_detected'], 'Changed detection result')
            last = row['history'][-2]
            for name, expected in (
                ('final_mean_class0', last['mean0']), ('final_mean_class1', last['mean1']),
                ('final_class1_minus_class0', last['mean1'] - last['mean0']),
                ('max_abs_t', max(abs(v['welch_t']) for v in row['history']))):
                number(row[name]); need(close(row[name], expected), 'Inconsistent effect/checkpoint statistic')
        controls = [r for r in out['records'] if r['positive_control']]
        targets = [r for r in out['records'] if not r['positive_control']]
        need(out['target_records'] == len(targets) and
             out['target_differences_detected'] == sum(r['detected'] for r in targets) and
             out['positive_controls'] == len(controls) and
             out['positive_controls_detected'] == sum(r['detected'] for r in controls),
             'Incorrect detection counts')
    return summary


validate_manifest = validate
