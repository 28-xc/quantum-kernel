"""Exact integer PMU leaf observations, separate from latency measurements."""
from pathlib import PurePosixPath
import re
from .timing_v1 import need, keys, token, digest, integer, text, number, close

SCHEMA = 'lattice.pmu_leaf_observations.v1'
SUMMARY_SCHEMA = 'lattice.pmu_leaf_statistics.v1'
CELLS = [(p, o) for p in (512, 768, 1024, 44, 65, 87) for o in range(3)]
COLUMNS = ['leaf_id', 'dso', 'symbol', 'symbol_context', 'resolved', 'samples', 'period', 'target_module']


def leaf_identity(leaf, target_dso):
    text(leaf['dso']); text(leaf['symbol'])
    need(re.fullmatch(r'[A-Za-z0-9_.+\[\]-]+', leaf['dso']) is not None, 'Private or malformed DSO name')
    need(re.fullmatch(r'[A-Za-z0-9_.$@+\[\]()-]+', leaf['symbol']) is not None, 'Private or malformed technical symbol')
    need(leaf['symbol_context'] in ('user', 'kernel', 'unknown'), 'Unrecognized perf symbol context')
    need(type(leaf['resolved']) is bool and type(leaf['target_module']) is bool, 'Invalid leaf flags')
    need(leaf['target_module'] == (leaf['dso'] == target_dso), 'Target-module attribution differs')
    if not leaf['resolved']:
        need(leaf['symbol'] == f"unresolved-leaf-{leaf['leaf_id']}", 'Unresolved address must use a stable leaf identifier')


def validate_manifest(data):
    keys(data, ['schema', 'dataset_id', 'platform', 'method', 'configuration_order',
                'configurations', 'cells', 'limitations', 'source_export_sha256', 'exporter_sha256'])
    need(data['schema'] == SCHEMA and data['platform'] in ('linux_aarch64', 'synthetic'), 'Wrong PMU identity')
    token(data['dataset_id'])
    digest(data['source_export_sha256']); digest(data['exporter_sha256'])
    method = data['method']
    keys(method, ['event', 'sampling_mode', 'frequency_hz', 'cpu_index', 'attribution', 'percent_limit',
                  'recorded_call_graph', 'perf_version', 'count_meaning', 'population', 'elapsed_time_measurement'])
    need(method['event'] == 'cycles:u' and method['sampling_mode'] == 'frequency' and
         method['attribution'] == 'leaf_self_no_children' and method['percent_limit'] == 0 and
         method['recorded_call_graph'] == 'dwarf_4096_private_not_published' and
         method['count_meaning'] == 'retained_samples_and_sampled_event_periods' and
         method['population'] == 'recorded_process_including_setup_and_external_code' and
         method['elapsed_time_measurement'] is False, 'Changed PMU attribution/interpretation')
    integer(method['frequency_hz'], 1); integer(method['cpu_index']); text(method['perf_version'])
    order = data['configuration_order']
    need(type(order) is list and order and len(order) == len(set(order)), 'Repeated/missing configurations')
    need(type(data['configurations']) is list and [c.get('id') for c in data['configurations']] == order,
         'Missing configuration identity')
    for c in data['configurations']:
        keys(c, ['id', 'library_sha256', 'crypto_sha256', 'driver_sha256', 'source_hashes', 'source_profile_result_sha256', 'target_dso'])
        token(c['id'])
        token(c['target_dso'])
        for k in ('library_sha256', 'crypto_sha256', 'driver_sha256', 'source_profile_result_sha256'):
            digest(c[k])
        keys(c['source_hashes'], ['profile_driver.c', 'driver.c', 'profile_linux.py', 'latticecore.h'])
        for value in c['source_hashes'].values(): digest(value)
    need(type(data['cells']) is list and
         [(c.get('configuration'), c.get('parameter'), c.get('operation')) for c in data['cells']] ==
         [(configuration, p, o) for configuration in order for p, o in CELLS], 'Incomplete/reordered 18-cell profile')
    paths = set()
    for c in data['cells']:
        keys(c, ['configuration', 'parameter', 'operation', 'iterations', 'seed', 'workload',
                  'source_perf_data_sha256', 'source_report_sha256', 'source_stderr_sha256',
                  'total_samples', 'total_period', 'lost_samples', 'exact_header_samples',
                  'report_event_period', 'leaf_csv'])
        integer(c['parameter'], 1); integer(c['operation']); integer(c['iterations'], 1); integer(c['seed'])
        need(c['workload'] == 'fixed_serialized_input_key_and_message_fresh_operation_entropy', 'Changed profiling input family')
        for k in ('source_perf_data_sha256', 'source_report_sha256', 'source_stderr_sha256'): digest(c[k])
        integer(c['total_samples'], 1); integer(c['total_period'], 1); integer(c['lost_samples'])
        if c['exact_header_samples'] is not None:
            need(type(c['exact_header_samples']) is int and c['exact_header_samples'] == c['total_samples'], 'Sample count mismatch')
        if c['report_event_period'] is not None:
            need(type(c['report_event_period']) is int and c['report_event_period'] == c['total_period'], 'Event-period count mismatch')
        raw = c['leaf_csv']; keys(raw, ['file', 'sha256', 'bytes', 'rows', 'columns'])
        path = PurePosixPath(raw['file'])
        need(not path.is_absolute() and path.parts == ('raw', c['configuration'], f'{c["parameter"]}_{c["operation"]}.csv') and
             path.as_posix() == raw['file'], 'Unexpected public PMU CSV path')
        need(raw['file'].casefold() not in paths, 'CSV path reused'); paths.add(raw['file'].casefold())
        digest(raw['sha256']); integer(raw['bytes'], 1); integer(raw['rows'], 1)
        need(raw['columns'] == COLUMNS and raw['rows'] <= c['total_samples'], 'Wrong leaf rows/columns')
    need(type(data['limitations']) is list and data['limitations'], 'PMU limitations required')
    for item in data['limitations']: text(item)
    return data


def validate_summary(summary, observations):
    """Pure shape/binding check; numerical authenticity is a separate raw scan."""
    validate_manifest(observations)
    keys(summary, ['schema', 'dataset_id', 'observations_sha256', 'recompute_source_sha256',
                   'cells', 'total_samples', 'total_period', 'lost_samples', 'leaf_rows',
                   'rows_removed', 'not_elapsed_time'])
    need(summary['schema'] == SUMMARY_SCHEMA and summary['dataset_id'] == observations['dataset_id'], 'Wrong PMU summary')
    digest(summary['observations_sha256']); digest(summary['recompute_source_sha256'])
    need(summary['not_elapsed_time'] is True and summary['rows_removed'] == 0, 'Changed PMU interpretation')
    need(type(summary['cells']) is list and len(summary['cells']) == len(observations['cells']), 'Missing PMU summary cell')
    configs = {c['id']: c for c in observations['configurations']}
    for out, original in zip(summary['cells'], observations['cells']):
        keys(out, ['configuration', 'parameter', 'operation', 'leaf_csv_sha256', 'total_samples', 'total_period',
                   'lost_samples', 'target_samples', 'outside_samples', 'target_period', 'outside_period', 'leaves'])
        for k in ('configuration', 'parameter', 'operation', 'total_samples', 'total_period', 'lost_samples'):
            need(out[k] == original[k], 'PMU summary identity/count changed')
        for k in ('parameter', 'operation', 'total_samples', 'total_period', 'lost_samples',
                  'target_samples', 'outside_samples', 'target_period', 'outside_period'):
            integer(out[k])
        need(out['leaf_csv_sha256'] == original['leaf_csv']['sha256'], 'Changed leaf artifact')
        need(type(out['leaves']) is list and len(out['leaves']) == original['leaf_csv']['rows'], 'Missing leaf')
        for i, leaf in enumerate(out['leaves']):
            keys(leaf, COLUMNS + ['sample_fraction_all', 'period_fraction_all',
                                  'sample_fraction_target', 'period_fraction_target'])
            need(type(leaf['leaf_id']) is int and leaf['leaf_id'] == i, 'Leaf order changed')
            leaf_identity(leaf, configs[out['configuration']]['target_dso'])
            integer(leaf['samples'], 1); integer(leaf['period'])
            for key, num, den in [('sample_fraction_all', leaf['samples'], out['total_samples']),
                                 ('period_fraction_all', leaf['period'], out['total_period'])]:
                number(leaf[key]); need(close(leaf[key], num/den), 'Incorrect integer-derived fraction')
            for key, num, den in [('sample_fraction_target', leaf['samples'], out['target_samples']),
                                 ('period_fraction_target', leaf['period'], out['target_period'])]:
                if not leaf['target_module'] or den == 0:
                    need(leaf[key] is None, 'Outside leaf given target-conditional fraction')
                else:
                    number(leaf[key]); need(close(leaf[key], num/den), 'Incorrect target-conditional fraction')
        for field in ('samples', 'period'):
            target = sum(v[field] for v in out['leaves'] if v['target_module'])
            outside = sum(v[field] for v in out['leaves'] if not v['target_module'])
            need(out['target_'+field] == target and out['outside_'+field] == outside and
                 target + outside == out['total_'+field], 'Target/outside counts do not conserve all leaves')
    for k in ('total_samples', 'total_period', 'lost_samples'):
        integer(summary[k])
        need(summary[k] == sum(c[k] for c in summary['cells']), 'Aggregate counts differ')
    integer(summary['leaf_rows']); integer(summary['rows_removed'])
    need(summary['leaf_rows'] == sum(len(c['leaves']) for c in summary['cells']), 'Wrong leaf count')
    return summary
