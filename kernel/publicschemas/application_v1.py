"""Closed schema and independent arithmetic audit for fixed-pool applications.

This module reads measurements only. It neither loads a cryptographic library
nor starts an experiment. Original record identities survive public projection.
"""
from collections import Counter
from pathlib import Path
import argparse
import hashlib
import json as wire_json
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
import re

XML_DIGEST_RULE = 'sha256 of each typed XML record serialized in UTF-8 with one LF'
OBSERVATIONS_SCHEMA = 'lattice.application_pool_observations.v1'
SUMMARY_SCHEMA = 'lattice.application_pool_statistics.v1'
LIBRARIES = ('native-full', 'native-low', 'native-fast', 'native-balanced',
             'portable-low', 'portable-compact', 'portable-minimum', 'portable-shared')
PAIRS = ((512, 44), (768, 65), (1024, 87))
BUDGETS = (32768, 65536, 131072, 262144)
SEED = 20260927901
REPEATS = 24
OPERATIONS = ('dsa_keypair', 'kem_keypair', 'sign_kem_public_key',
              'verify_certificate', 'encaps', 'decaps_and_match')
SCOPE = {
    'application': 'six_step_device_enrollment_and_kem_exchange',
    'charged': ['fixed_mutable_pool', 'protected_stack',
                'library_writable_image_and_one_tls_copy', 'application_dispatch_pointer'],
    'pool_contents': ['persistent_application_state', 'serialized_keys_ciphertext_signature',
                      'two_shared_secrets', 'reused_algorithm_workspace', 'alignment_padding'],
    'external_instrumentation': ['guard_canaries', 'loaded_module_controller',
                                 'reference_transcript', 'logging', 'os_mappings',
                                 'heap_accounting_instrumentation'],
    'timing_collected': False,
}
RESULT_FIELDS = ('event', 'status', 'kem', 'dsa', 'seed', 'control', 'rc',
    'completed_operations', 'transcript_matches', 'total_budget_bytes',
    'charged_bytes', 'pool_bytes', 'application_state_bytes',
    'serialized_object_bytes', 'workspace_bytes', 'workspace_high_water_bytes',
    'stack_reserved_bytes', 'stack_watermark_bytes', 'globals_and_tls_bytes',
    'application_pointer_bytes', 'external_heap_peak_bytes', 'canaries_ok',
    'guard_error', 'heap_errors', 'os_stack_mapping_bytes')
ROW_FIELDS = ('ordinal', 'configuration', 'binary_sha256', 'kem', 'dsa',
    'budget_bytes', 'stack_bytes', 'seed', 'control', 'purpose', 'exit_code',
    'classification', 'events', 'result', 'stderr', 'source_record_sha256',
    'source_stdout_sha256', 'source_stderr_sha256')


def need(condition, message):
    if not condition:
        raise ValueError(message)


def keys(value, fields):
    need(type(value) is dict and set(value) == set(fields), 'Unexpected scientific fields')


def integer(value, minimum=0):
    need(type(value) is int and value >= minimum, 'Invalid integer')


def digest(value):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None,
         'Invalid SHA256 identity')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, 'Duplicate JSON field: ' + key)
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError('Non-finite JSON constant: ' + value)


def _finite_float(value):
    number = float(value)
    need(math.isfinite(number), 'Non-finite JSON number')
    return number


def loads(value):
    return json.loads(value, object_pairs_hook=_unique_object,
                      parse_constant=_reject_constant, parse_float=_finite_float)


def read(path):
    text = Path(path).read_text(encoding='utf-8-sig')
    need(text.lstrip().startswith('<'), 'Expected a typed XML document')
    return loads(text)


def capture_stdout(text):
    """Represent the collector's compact event lines as typed fields with exact endings."""
    records = []
    for line in text.splitlines(keepends=True):
        body = line.rstrip('\r\n')
        ending = line[len(body):]
        if body.startswith('{'):
            value = loads(body)
            need(wire_json.dumps(value, ensure_ascii=False, separators=(',', ':')) == body,
                 'Unexpected collector event encoding')
            records.append(dict(event=value, ending=ending))
        else:
            records.append(dict(text=body, ending=ending))
    return records


def restore_stdout(stored):
    if isinstance(stored, str):
        return stored
    need(isinstance(stored, list), 'Invalid collector stream')
    lines = []
    for record in stored:
        need(isinstance(record, dict), 'Invalid collector line')
        if 'event' in record:
            keys(record, ('event', 'ending'))
            body = wire_json.dumps(record['event'], ensure_ascii=False, separators=(',', ':'))
        else:
            keys(record, ('text', 'ending'))
            body = record['text']
        need(isinstance(body, str) and record['ending'] in ('', '\n', '\r', '\r\n'), 'Invalid line ending')
        lines.append(body + record['ending'])
    return ''.join(lines)


def align32(value):
    return (value + 31) & ~31


def serialized_bytes(kem, dsa):
    k = {512: (800, 1632, 768), 768: (1184, 2400, 1088), 1024: (1568, 3168, 1568)}[kem]
    d = {44: (1312, 2560, 2420), 65: (1952, 4032, 3309), 87: (2592, 4896, 4627)}[dsa]
    return sum(k) + sum(d) + 64


def validate_observations(data):
    keys(data, ('schema', 'dataset_id', 'platform', 'scope', 'method',
                'configurations', 'collector', 'provenance', 'raw'))
    need(data['schema'] == OBSERVATIONS_SCHEMA, 'Wrong application schema')
    need(data['platform'] in ('windows_x86_64', 'linux_aarch64'), 'Unknown platform')
    need(data['dataset_id'] == data['platform'] + '_fixed_pool_application', 'Wrong dataset identity')
    need(data['scope'] == SCOPE, 'Changed application accounting scope')
    m = data['method']
    keys(m, ('parameters', 'budgets_bytes', 'seeds_per_cell', 'base_seed',
             'seed_formula', 'operation_order', 'domain_utf8', 'application_stack_extra_bytes',
             'pool_alignment_bytes', 'controls_per_configuration'))
    need(m == dict(parameters=[list(x) for x in PAIRS], budgets_bytes=list(BUDGETS),
                   seeds_per_cell=REPEATS, base_seed=SEED,
                   seed_formula='base_seed + kem * 65537 + repeat * 131071',
                   operation_order=list(OPERATIONS), domain_utf8='A1-27 device enrollment v1',
                   application_stack_extra_bytes=768, pool_alignment_bytes=32,
                   controls_per_configuration=4), 'Changed fixed experiment contract')
    need(type(data['configurations']) is list and
         [c.get('id') for c in data['configurations']] == list(LIBRARIES),
         'Missing, duplicated or reordered configuration')
    for c in data['configurations']:
        keys(c, ('id', 'binary_sha256', 'core_stack_bytes', 'application_stack_bytes',
                 'globals_and_tls_bytes', 'resource_evidence_sha256',
                 'algorithm_workspace_by_parameter', 'algorithm_common_workspace_bytes'))
        digest(c['binary_sha256']); digest(c['resource_evidence_sha256'])
        for key in ('core_stack_bytes', 'application_stack_bytes', 'globals_and_tls_bytes'):
            integer(c[key], 1)
        need(c['core_stack_bytes'] % 256 == 0 and
             c['application_stack_bytes'] == c['core_stack_bytes'] + 768,
             'Changed core-to-application stack reservation')
        need(type(c['algorithm_workspace_by_parameter']) is list and
             [item.get('parameter') for item in c['algorithm_workspace_by_parameter']] == [512,768,1024,44,65,87],
             'Missing independent algorithm workspace')
        for item in c['algorithm_workspace_by_parameter']:
            keys(item, ('parameter','workspace_bytes'))
            integer(item['workspace_bytes'], 1)
            need(item['workspace_bytes'] % 32 == 0, 'Unaligned algorithm workspace')
        need(type(c['algorithm_common_workspace_bytes']) is int and
             c['algorithm_common_workspace_bytes'] == max(item['workspace_bytes'] for item in c['algorithm_workspace_by_parameter']),
             'Incorrect six-parameter common algorithm workspace')
    need(len({c['binary_sha256'] for c in data['configurations']}) == len(LIBRARIES),
         'Distinct configurations require their actual binary identities')
    collector = data['collector']
    keys(collector, ('binary_sha256', 'compiler', 'source_sha256'))
    digest(collector['binary_sha256'])
    need(type(collector['compiler']) is str and 0 < len(collector['compiler']) < 200 and
         '\n' not in collector['compiler'], 'Invalid compiler identity')
    need(type(collector['source_sha256']) is dict and len(collector['source_sha256']) == 7,
         'Missing collector source identities')
    source_names = {
        'tests/application_workload/resource_probe.c', 'tests/application_workload/resources.py',
        'tests/resources/probe.c', 'tests/resources/image_inventory.py', 'include/latticecore.h',
    }
    source_names.update(('tests/resources/stack_windows_x64.S',
                         'tests/resources/windows_heap_audit.h') if data['platform']=='windows_x86_64' else
                        ('tests/resources/stack_aarch64.S','tests/resources/linux_heap_audit.c'))
    need(set(collector['source_sha256']) == source_names, 'Collector source set differs from the platform method')
    for name, value in collector['source_sha256'].items():
        need(re.fullmatch(r'(?:tests/(?:application_workload|resources)|include)/[A-Za-z0-9_.]+', name)
             is not None and '..' not in name, 'Unexpected collector source path')
        digest(value)
    provenance = data['provenance']
    keys(provenance, ('protocol_sha256', 'trials_sha256', 'result_sha256',
                      'original_trial_count', 'all_original_records_retained',
                      'original_record_digest_rule', 'projection'))
    for name in ('protocol_sha256', 'trials_sha256', 'result_sha256'):
        digest(provenance[name])
    need(provenance['original_trial_count'] == 2336 and
         provenance['all_original_records_retained'] is True and
         provenance['original_record_digest_rule'] in ('sha256 of original JSONL line including line ending', XML_DIGEST_RULE) and
         provenance['projection'] == 'scientific fields selected; command paths excluded; numerical events unchanged',
         'Changed record-retention contract')
    raw = data['raw']
    keys(raw, ('path', 'sha256', 'bytes', 'rows'))
    need(raw['path'] == 'trials.records.xml' and raw['rows'] == 2336, 'Changed raw file contract')
    digest(raw['sha256']); integer(raw['bytes'], 1)
    return True


def expected_conditions(data):
    for c in data['configurations']:
        for control, stack in ((1, 4096), (2, 4096), (2, 65536), (3, 16384)):
            yield c, 512, 44, 262144, stack, SEED, control, 'instrument_control'
        for kem, dsa in PAIRS:
            for budget in BUDGETS:
                for repeat in range(REPEATS):
                    yield c, kem, dsa, budget, c['application_stack_bytes'], \
                        SEED + kem * 65537 + repeat * 131071, 0, 'fixed_application_budget'


def _validate_event(event):
    need(type(event) is dict, 'Invalid measurement event')
    if event.get('event') == 'application_start':
        keys(event, ('event', 'budget_bytes', 'pool_bytes', 'stack_bytes', 'control'))
        for name in ('budget_bytes', 'pool_bytes', 'stack_bytes', 'control'):
            integer(event[name])
    elif event.get('event') == 'application_result':
        keys(event, RESULT_FIELDS)
        for name in RESULT_FIELDS:
            if name not in ('event', 'status', 'transcript_matches', 'canaries_ok'):
                integer(event[name], -7 if name == 'rc' else 0)
        need(type(event['transcript_matches']) is bool and type(event['canaries_ok']) is bool,
             'Invalid Boolean measurement')
        need(event['status'] in ('PASS', 'WORKSPACE_INSUFFICIENT'), 'Unexpected application status')
    elif event.get('event') == 'stack_fault':
        keys(event, ('event', 'protected_region_hit', 'address_hex'))
        need(type(event['protected_region_hit']) is bool and
             re.fullmatch('[0-9a-f]{16}', event['address_hex']) is not None,
             'Invalid protected-stack event')
    else:
        keys(event, ('status', 'budget_bytes', 'pool_bytes'))
        need(event['status'] == 'POOL_TOO_SMALL', 'Unknown collector event')
        integer(event['budget_bytes']); integer(event['pool_bytes'])


def validate_rows(data, rows):
    validate_observations(data)
    need(len(rows) == 2336, 'Missing or added trial')
    for index, (row, condition) in enumerate(zip(rows, expected_conditions(data))):
        keys(row, ROW_FIELDS)
        c, kem, dsa, budget, stack, seed, control, purpose = condition
        for name in ('ordinal', 'kem', 'dsa', 'budget_bytes', 'stack_bytes', 'seed', 'control'):
            integer(row[name])
        expected = dict(ordinal=index, configuration=c['id'], binary_sha256=c['binary_sha256'],
                        kem=kem, dsa=dsa, budget_bytes=budget, stack_bytes=stack,
                        seed=seed, control=control, purpose=purpose)
        need(all(row[key] == value for key, value in expected.items()),
             'Missing, reordered or changed trial condition at ' + str(index))
        for name in ('source_record_sha256', 'source_stdout_sha256', 'source_stderr_sha256'):
            digest(row[name])
        integer(row['exit_code'], -255)
        need(type(row['stderr']) is str and len(row['stderr']) < 8192 and
             re.search(r'(?:[A-Za-z]:[\\/]|/(?:home|Users|tmp)/)', row['stderr']) is None,
             'Diagnostic contains a private execution path')
        need(hashlib.sha256(row['stderr'].encode()).hexdigest() == row['source_stderr_sha256'],
             'Changed diagnostic text')
        need(type(row['events']) is list, 'Invalid event sequence')
        for event in row['events']:
            _validate_event(event)
        starts = [e for e in row['events'] if e.get('event') == 'application_start']
        ends = [e for e in row['events'] if e.get('event') == 'application_result']
        faults = [e for e in row['events'] if e.get('event') == 'stack_fault']
        pool = (budget - stack - c['globals_and_tls_bytes'] - 8) & ~31
        if row['classification'] == 'POOL_TOO_SMALL':
            need(control == 0 and row['exit_code'] == 0 and row['result'] is None and
                 row['events'] == [dict(status='POOL_TOO_SMALL', budget_bytes=budget, pool_bytes=pool)],
                 'Invalid small-pool outcome')
            need(pool < align32(align32(296) + serialized_bytes(kem, dsa)) + 32,
                 'Pool outcome requires allocation-failure attribution beyond the byte budget')
            continue
        need(starts == [dict(event='application_start', budget_bytes=budget,
                             pool_bytes=pool, stack_bytes=stack, control=control)],
             'Start event differs from fixed-pool condition')
        if control == 2 and stack == 4096:
            need(not ends and row['result'] is None, 'Overflow control completed unexpectedly')
            if data['platform'] == 'windows_x86_64':
                need(row['classification'] == 'PROTECTED_STACK_EXIT' and
                     (row['exit_code'] & 0xffffffff) in (0xc0000005, 0xc00000fd) and not faults,
                     'Missing Windows protected-stack positive control')
            else:
                need(row['classification'] == 'PROTECTED_STACK_FAULT' and
                     row['exit_code'] in (139, 135, -11, -7) and len(faults) == 1 and
                     faults[0]['protected_region_hit'], 'Missing Linux protected-stack positive control')
            need(len(row['events']) == 1 + len(faults), 'Unexpected overflow event')
            continue
        need(row['exit_code'] == 0 and len(ends) == 1 and not faults and
             len(row['events']) == 2 and row['result'] == ends[0], 'Missing application result')
        r = row['result']
        need(row['classification'] == r['status'], 'Outcome differs from collector result')
        expected_result = dict(kem=kem, dsa=dsa, seed=seed, control=control,
            total_budget_bytes=budget, stack_reserved_bytes=stack, pool_bytes=pool,
            globals_and_tls_bytes=c['globals_and_tls_bytes'], application_pointer_bytes=8,
            serialized_object_bytes=serialized_bytes(kem, dsa))
        need(all(r[key] == value for key, value in expected_result.items()), 'Changed budget components')
        need(r['application_state_bytes'] == 296, 'Unexpected 64-bit application-state ABI')
        work_offset = align32(align32(r['application_state_bytes']) + r['serialized_object_bytes'])
        need(r['workspace_bytes'] == pool - work_offset and
             r['charged_bytes'] == pool + stack + c['globals_and_tls_bytes'] + 8 and
             0 <= budget - r['charged_bytes'] < 32,
             'Incorrect pool alignment or charged-byte equation')
        need(r['workspace_high_water_bytes'] <= r['workspace_bytes'] and
             r['stack_watermark_bytes'] <= stack and r['canaries_ok'] and
             r['guard_error'] == r['heap_errors'] == 0 and r['os_stack_mapping_bytes'] >= stack,
             'Invalid protected resource measurement')
        if control:
            need(r['status'] == 'PASS' and r['rc'] == 0 and r['completed_operations'] == 0 and
                 r['workspace_high_water_bytes'] == 0 and r['transcript_matches'] is False,
                 'Control was confused with a cryptographic operation')
            need(r['external_heap_peak_bytes'] == (96 if control == 3 else 0),
                 'Missing measured 96-byte heap positive control')
            if control == 2:
                need(r['stack_watermark_bytes'] >= 49152, 'Large-stack overflow control was not observed')
        elif r['status'] == 'PASS':
            need(r['rc'] == 0 and r['completed_operations'] == 6 and
                 r['transcript_matches'] and r['external_heap_peak_bytes'] == 0,
                 'Incomplete successful six-step exchange')
        else:
            need(r['status'] == 'WORKSPACE_INSUFFICIENT' and r['rc'] == -5 and
                 0 <= r['completed_operations'] < 6 and not r['transcript_matches'] and
                 r['external_heap_peak_bytes'] == 0, 'Invalid workspace failure semantics')
    need(len({r['source_record_sha256'] for r in rows}) == 2336, 'Repeated original record identity')
    return True


def summarize(data, rows, observations_sha256):
    validate_rows(data, rows); digest(observations_sha256)
    cells = []
    for c in data['configurations']:
        for kem, dsa in PAIRS:
            for budget in BUDGETS:
                group = [r for r in rows if r['configuration'] == c['id'] and
                         (r['kem'], r['dsa'], r['budget_bytes'], r['control']) == (kem, dsa, budget, 0)]
                need(len(group) == 24, 'Incomplete repeated budget cell')
                results = [r['result'] for r in group if r['result'] is not None]
                counts = dict(sorted(Counter(r['classification'] for r in group).items()))
                cells.append(dict(configuration=c['id'], binary_sha256=c['binary_sha256'],
                    kem=kem, dsa=dsa, budget_bytes=budget, trials=24,
                    ordinals=[r['ordinal'] for r in group], status_counts=counts,
                    all_exchanges_passed=counts == {'PASS': 24},
                    application_stack_bytes=c['application_stack_bytes'],
                    globals_and_tls_bytes=c['globals_and_tls_bytes'],
                    algorithm_common_workspace_bytes=c['algorithm_common_workspace_bytes'],
                    parameter_pair_algorithm_workspace_bytes=max(item['workspace_bytes'] for item in c['algorithm_workspace_by_parameter'] if item['parameter'] in (kem,dsa)),
                    serialized_object_bytes=serialized_bytes(kem, dsa),
                    pool_bytes=(budget-c['application_stack_bytes']-c['globals_and_tls_bytes']-8)&~31,
                    workspace_bytes=None if not results else results[0]['workspace_bytes'],
                    maximum_workspace_high_water_bytes=max((r['workspace_high_water_bytes'] for r in results), default=0),
                    maximum_stack_watermark_bytes=max((r['stack_watermark_bytes'] for r in results), default=0),
                    maximum_external_heap_peak_bytes=max((r['external_heap_peak_bytes'] for r in results), default=0),
                    minimum_completed_operations=min((r['completed_operations'] for r in results), default=0)))
    configuration_budgets = []
    for c in data['configurations']:
        feasible = [b for b in BUDGETS if all(x['all_exchanges_passed'] for x in cells
                    if x['configuration'] == c['id'] and x['budget_bytes'] == b)]
        configuration_budgets.append(dict(configuration=c['id'], binary_sha256=c['binary_sha256'],
            all_parameter_feasible_tested_budgets=feasible,
            minimum_feasible_tested_budget_bytes=min(feasible) if feasible else None))
    return dict(schema=SUMMARY_SCHEMA, dataset_id=data['dataset_id'], platform=data['platform'],
        observations_sha256=observations_sha256, raw_sha256=data['raw']['sha256'], scope=data['scope'],
        counts=dict(trials=len(rows), application_trials=2304, instrumentation_controls=32,
                    application_cells=96, repetitions_per_cell=24,
                    classifications=dict(sorted(Counter(r['classification'] for r in rows).items()))),
        cells=cells, configuration_budgets=configuration_budgets,
        instrumentation=[{key:r[key] for key in ('ordinal','configuration','binary_sha256',
             'control','stack_bytes','classification','exit_code','events','result')}
                         for r in rows if r['control']])


def recompute(observations_path):
    path = Path(observations_path).resolve(); data = read(path)
    validate_observations(data)
    raw = path.parent / data['raw']['path']
    need(raw.is_file() and raw.stat().st_size == data['raw']['bytes'] and
         sha(raw) == data['raw']['sha256'], 'Raw observations changed')
    rows = read(raw)
    need(type(rows) is list, 'Expected a list of trial records')
    need(len(rows) == 2336, 'Missing observation record')
    return summarize(data, rows, sha(path)), rows


def validate_summary(summary, observations_path):
    expected, _ = recompute(observations_path)
    need(summary == expected, 'Statistics differ from complete retained observations')
    return True


def write_outputs(summary, rows, output):
    output = Path(output); output.mkdir(parents=True, exist_ok=False)
    (output/'summary.xml').write_text(json.dumps(summary, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    return output


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('observations', type=Path); parser.add_argument('output', type=Path)
    args = parser.parse_args(); summary, rows = recompute(args.observations)
    write_outputs(summary, rows, args.output)
    print(json.dumps(summary['counts']))
