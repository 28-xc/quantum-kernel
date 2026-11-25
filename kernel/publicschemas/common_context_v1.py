"""Public observations of fixed six-parameter contexts; no security verdict.

Recomputes every interleaved sequence, expected OOM, budget and instrument
control from closed numeric records. Filesystem paths and fault addresses are
not part of this schema. No compilation or new experiment is performed.
"""
from collections import Counter
from pathlib import Path
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
import re

from .resources import validate as validate_resources,load as load_resources,SCHEMA_V3 as RESOURCE_V3
from .verification_v2 import need, keys, integer, digest, token

SCHEMA = 'lattice.common_context_observations.v1'
SCHEMA_V2 = 'lattice.common_context_observations.v2'
SUMMARY_SCHEMA = 'lattice.common_context_statistics.v1'
ORDERS = [[512, 44, 768, 65, 1024, 87], [87, 1024, 65, 768, 44, 512]]
BUDGETS = [16384, 32768, 65536, 131072, 262144]
ARG_KEYS = ('arena_bytes', 'stack_bytes', 'seed', 'order', 'parameter_count', 'control')
PROTOCOL = dict(orders=ORDERS, seeds_per_order=24, workspace_quantum_bytes=32,
    budgets_bytes=BUDGETS, trial_count=68, message_bytes=1024,
    context_initializations_within_sequence=1,
    recovery='reinitialize_same_context_after_sequence_then_check_full_sequence')
PURPOSES = {'instrument_control', 'interleaving_selfcheck', 'common_fixed_reservation',
            'lower_common_arena_oom', 'fixed_total_budget'}
CLASSES = {'SUCCESS', 'WORKSPACE_OOM', 'PROTECTED_STACK_FAULT', 'WINDOWS_ACCESS_OR_STACK_EXIT'}
NEGATIVE_FIELDS = ['context_init_calls', 'context_and_arena_identity_stable',
                   'completed_operations', 'canaries_ok', 'same_context_reinitialized_recovery_ok', 'heap_errors']
INTS = ('rc', 'worker_rc', 'guard_error', 'arena_reserved_bytes', 'stack_enforced_bytes',
    'context_bytes', 'context_init_calls', 'completed_operations', 'expected_operations',
    'arena_high_water_observed_bytes', 'stack_watermark_observed_bytes',
    'outside_heap_calls', 'outside_heap_peak_requested_bytes', 'heap_errors',
    'os_stack_mapping_reserved_bytes', 'os_enabled_stack_pages_bytes', 'order',
    'parameter_count', 'seed', 'control', 'init_rc', 'allocation_failures')
BOOLS = ('context_in_measured_stack', 'context_and_arena_identity_stable', 'canaries_ok',
    'same_context_reinitialized_recovery_ok', 'physical_RAM_measured', 'recovery_executed')
WIN = ('heap_positive_control_mode', 'heap_hooks', 'heap_unhandled_imports')
HEAP_MODES = {'standalone_accounting_no_target_allocator_imports', 'target_allocator_IAT_or_no_control'}
SOURCE_NAMES = {'probe_common.c', 'probe.c', 'run_common.py', 'stack_aarch64.S',
                'stack_windows_x64.S', 'linux_heap_audit.c', 'windows_heap_audit.h', 'latticecore.h'}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def strict_line(text):
    def pairs(items):
        out = {}
        for k, v in items:
            need(k not in out, 'Duplicate JSON key')
            out[k] = v
        return out
    def constant(_):
        raise ValueError('Nonfinite JSON constant')
    return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)


def read(path):
    return strict_line(Path(path).read_text(encoding='utf-8'))


def result_validate(r, platform):
    if r is None:
        return
    extra = WIN if platform == 'windows_x86_64' else ()
    keys(r, ('event', 'schema', 'rows', *INTS, *BOOLS, *extra))
    need(r['event'] == 'common_result' and r['schema'] == 'resources.common_context.r2.v1', 'Wrong probe result')
    for k in INTS:
        integer(r[k], -2147483648 if k in ('rc', 'worker_rc', 'guard_error', 'init_rc') else 0)
    for k in BOOLS:
        need(type(r[k]) is bool, 'Boolean observation required')
    need(r['physical_RAM_measured'] is False, 'Cannot infer physical RAM')
    if extra:
        need(r['heap_positive_control_mode'] in HEAP_MODES, 'Unknown Windows heap mode')
        integer(r['heap_hooks']); integer(r['heap_unhandled_imports'])
    need(type(r['rows']) is list, 'Operation rows required')
    for row in r['rows']:
        keys(row, ('parameter', 'operation', 'rc', 'output_matches', 'failure_outputs_cleared',
                   'arena_high_water_bytes', 'stack_watermark_bytes', 'changed_nonzero_released_bytes'))
        for k in ('parameter', 'operation', 'arena_high_water_bytes', 'stack_watermark_bytes', 'changed_nonzero_released_bytes'):
            integer(row[k])
        integer(row['rc'], -2147483648)
        need(row['parameter'] in ORDERS[0] and row['operation'] in (0, 1, 2), 'Unknown operation')
        need(type(row['output_matches']) is bool, 'Output comparison flag required')
        need(row['failure_outputs_cleared'] is None or type(row['failure_outputs_cleared']) is bool, 'Bad conditional clearing flag')


def trial_validate(t, platform, ordinal):
    keys(t, ('id', 'purpose', 'arguments', 'exit_code', 'classification', 'result', 'fault',
             'source_record_canonical_sha256'))
    integer(t['id']); need(t['id'] == ordinal, 'Missing, repeated or reordered trial')
    need(t['purpose'] in PURPOSES and t['classification'] in CLASSES, 'Unknown trial condition')
    digest(t['source_record_canonical_sha256']); integer(t['exit_code'], -2147483648)
    a = t['arguments']; keys(a, ARG_KEYS)
    for value in a.values(): integer(value)
    need(a['arena_bytes'] > 0 and a['stack_bytes'] > 0 and a['order'] in (0, 1) and
         a['parameter_count'] in (3, 6) and a['control'] in (0, 1, 2, 3), 'Wrong request')
    f = t['fault']
    if f is not None:
        keys(f, ('event', 'protected_region_hit'))
        need(f['event'] == 'stack_fault' and type(f['protected_region_hit']) is bool, 'Wrong fault record')
    result_validate(t['result'], platform)
    r = t['result']
    if r is None:
        need(t['purpose'] == 'instrument_control' and a['control'] == 2 and a['stack_bytes'] == 4096,
             'Unexpected missing result outside low-stack positive control')
        if platform == 'linux_aarch64':
            need(f == {'event': 'stack_fault', 'protected_region_hit': True} and
                 t['exit_code'] in (139, 135, -11, -7), 'Unknown Linux fault')
            derived = 'PROTECTED_STACK_FAULT'
        else:
            need(f is None and t['exit_code'] & 0xffffffff in (0xc0000005, 0xc00000fd), 'Unknown Windows failure')
            derived = 'WINDOWS_ACCESS_OR_STACK_EXIT'
    else:
        need(f is None and t['exit_code'] == 0, 'Result/fault/exit conflict')
        for k in ('order', 'parameter_count', 'seed', 'control'):
            need(r[k] == a[k], 'Result/request identity differs')
        need(r['arena_reserved_bytes'] == a['arena_bytes'] and r['stack_enforced_bytes'] == a['stack_bytes'], 'Capacity differs')
        need(r['context_bytes'] == 64 and not r['context_in_measured_stack'] and r['context_init_calls'] == 1 and
             r['context_and_arena_identity_stable'], 'Context replaced or reinitialized in sequence')
        need(r['worker_rc'] == r['guard_error'] == r['init_rc'] == r['heap_errors'] == 0 and r['canaries_ok'], 'Guard or heap error')
        need(r['arena_high_water_observed_bytes'] <= a['arena_bytes'] and r['stack_watermark_observed_bytes'] <= a['stack_bytes'], 'Observed bound exceeded')
        need(r['expected_operations'] == 3 * a['parameter_count'], 'Wrong expected operation count')
        if a['control']:
            need(r['rc'] == 0 and r['completed_operations'] == 0 and not r['rows'] and not r['recovery_executed'], 'Invalid instrument control')
            if a['control'] == 3:
                need(r['outside_heap_calls'] > 0 and r['outside_heap_peak_requested_bytes'] == 96, 'Heap positive missing')
            derived = 'SUCCESS'
        else:
            need(r['recovery_executed'] and r['same_context_reinitialized_recovery_ok'], 'Sequence recovery failed')
            need(r['outside_heap_calls'] == r['outside_heap_peak_requested_bytes'] == 0, 'Unexpected core heap allocation')
            expected = [(p, o) for p in ORDERS[a['order']][:a['parameter_count']] for o in range(3)]
            rows = r['rows']
            need(len(rows) == r['completed_operations'] and len(rows) <= len(expected), 'Wrong completed count')
            need([(x['parameter'], x['operation']) for x in rows] == expected[:len(rows)], 'Wrong interleaving')
            for x in rows:
                need(x['arena_high_water_bytes'] <= a['arena_bytes'] and x['stack_watermark_bytes'] <= a['stack_bytes'] and
                     x['changed_nonzero_released_bytes'] == 0, 'Component bound or release clearing failed')
                need((x['rc'] == 0 and x['output_matches']) or
                     (x['rc'] == -5 and x['failure_outputs_cleared'] is True), 'Output or failure clearing failed')
            if r['rc'] == 0:
                need(len(rows) == len(expected) and all(x['rc'] == 0 for x in rows), 'Incomplete successful sequence')
                derived = 'SUCCESS'
            else:
                need(r['rc'] == -5 and r['allocation_failures'] > 0 and rows and rows[-1]['rc'] == -5 and
                     all(x['rc'] == 0 for x in rows[:-1]), 'Unknown sequence failure')
                derived = 'WORKSPACE_OOM'
    need(t['classification'] == derived, 'Recorded classification differs from actual observations')
    return derived


def expected_plan(point, seed):
    c = point['reserved_components']; w = c['workspace_bytes']; s = c['stack_bytes']
    overhead = c['external_context_bytes'] + c['globals_bytes'] + c['outside_heap_bytes']
    plan = []
    def add(purpose, arena, stack, order, count, control, trialseed, want):
        plan.append((purpose, dict(zip(ARG_KEYS, (arena, stack, trialseed, order, count, control))), want))
    for ctl, stack, want in ((1, 4096, 'SUCCESS'), (2, 4096, 'FAULT'), (2, 65536, 'SUCCESS'), (3, 16384, 'SUCCESS')):
        add('instrument_control', 262144, stack, 0, 6, ctl, seed, want)
    for count in (3, 6):
        for order in (0, 1): add('interleaving_selfcheck', w, s, order, count, 0, seed + 71, 'SUCCESS')
    for i in range(24):
        for order in (0, 1): add('common_fixed_reservation', w, s, order, 6, 0, seed + 1009 + i * 65537, 'SUCCESS')
    for order in (0, 1): add('lower_common_arena_oom', w - 32, s, order, 6, 0, seed + 97, 'WORKSPACE_OOM')
    for budget in BUDGETS:
        cap = (budget - s - overhead) // 32 * 32
        need(cap >= 32, 'This protocol requires positive budget arenas')
        for order in (0, 1): add('fixed_total_budget', cap, s, order, 6, 0, seed + 113, 'SUCCESS_OR_OOM')
    return plan


def shard(root, descriptor):
    keys(descriptor, ('path', 'sha256', 'rows'))
    need(type(descriptor['path']) is str and re.fullmatch(r'raw/artifact_[0-9]{2,4}\.records.xml', descriptor['path']), 'Invalid raw path')
    digest(descriptor['sha256']); need(type(descriptor['rows']) is int and descriptor['rows'] == 68, 'Raw closure differs')
    root = Path(root).resolve(); p = root / descriptor['path']
    need(p.is_file() and not p.is_symlink() and not p.parent.is_symlink() and p.resolve().is_relative_to(root), 'Escaping/missing raw file')
    need(sha(p) == descriptor['sha256'], 'Raw identity differs')
    rows = list(json.read_records(p))
    need(len(rows) == descriptor['rows'], 'Raw row count differs')
    return rows


def derive_artifact(a, point, rows):
    need(a['binary_sha256'] == point['binary_sha256'] and a['platform'] == point['platform'], 'Wrong actual image')
    need(a['source_sha256']['result'] == point['source_sha256']['common_context_result'], 'Common result binding differs')
    need(a['source_sha256']['resource'] == point['source_sha256']['resource'], 'Resource source binding differs')
    need(a['reported_reserved_components'] == point['reserved_components'] and
         a['reported_core_reserved_bytes'] == point['core_reserved_bytes'], 'Reserved accounting differs')
    need(point['reserved_components']['outside_heap_bytes'] == 0, 'Unknown heap budget model')
    need(a['negative_record_rejections'] == NEGATIVE_FIELDS, 'Missing evidence-parser controls')
    plan = expected_plan(point, a['seed_base'])
    need(len(rows) == len(plan) == 68, 'Complete 68-trial sequence required')
    counts = Counter(); purposes = Counter(); fixed = []; budgets = []
    for i, (t, (purpose, args, want)) in enumerate(zip(rows, plan)):
        derived = trial_validate(t, a['platform'], i)
        need(t['purpose'] == purpose and t['arguments'] == args, 'Changed, repeated or omitted planned trial')
        if want == 'FAULT': need(derived in ('WINDOWS_ACCESS_OR_STACK_EXIT', 'PROTECTED_STACK_FAULT'), 'Missing stack positive')
        elif want == 'SUCCESS_OR_OOM': need(derived in ('SUCCESS', 'WORKSPACE_OOM'), 'Unknown budget result')
        else: need(derived == want, 'Planned witness did not hold')
        counts[derived] += 1; purposes[purpose] += 1
        if purpose == 'common_fixed_reservation': fixed.append(t)
        if purpose == 'fixed_total_budget':
            budget = BUDGETS[(i - 58) // 2]
            c = point['reserved_components']
            charged = args['arena_bytes'] + c['stack_bytes'] + c['external_context_bytes'] + c['globals_bytes'] + c['outside_heap_bytes']
            need(charged <= budget and budget - charged < 32, 'Budget charge differs')
            budgets.append(dict(budget_bytes=budget, arena_bytes=args['arena_bytes'], charged_core_bytes=charged,
                                order=args['order'], status=derived, trial=i))
    need(budgets == a['reported_budget_trials'], 'Reported budget table differs from raw observations')
    maxima = []
    for p in ORDERS[0]:
        for op in range(3):
            found = [r for t in fixed for r in t['result']['rows'] if (r['parameter'], r['operation']) == (p, op)]
            need(len(found) == 48, 'Missing per-cell confirmation observation')
            maxima.append(dict(parameter=p, operation=op, observations=48,
                arena_high_water_observed_bytes=max(r['arena_high_water_bytes'] for r in found),
                stack_watermark_observed_bytes=max(r['stack_watermark_bytes'] for r in found),
                changed_nonzero_released_bytes=max(r['changed_nonzero_released_bytes'] for r in found)))
    return dict(resource_id=a['resource_id'], binary_sha256=a['binary_sha256'], trials=68,
        classification_counts=dict(counts), purpose_counts=dict(purposes),
        fixed_reservation_sequences=len(fixed), fixed_reservation_operation_observations=sum(len(t['result']['rows']) for t in fixed),
        fixed_reservation_cells=maxima, lower_arena_expected_oom=2, instrument_controls=4,
        stack_positive_controls=1, heap_positive_controls=1, parser_negative_controls=len(NEGATIVE_FIELDS),
        reserved_components=point['reserved_components'], core_reserved_bytes=point['core_reserved_bytes'],
        budget_trials=budgets, simultaneous_observed_peak_bytes=None, physical_RAM_measured=False)


def validate_manifest(data, resources):
    modern=data.get('schema')==SCHEMA_V2
    fields=('schema','dataset_id','resources_sha256','protocol','artifacts','method_sources')
    keys(data,fields if modern else fields+('core_source_commit',))
    need(data['schema'] in (SCHEMA,SCHEMA_V2) and json.dumps(data['protocol'], sort_keys=True) == json.dumps(PROTOCOL, sort_keys=True), 'Unknown common-context protocol')
    token(data['dataset_id']); digest(data['resources_sha256'])
    need((resources['schema']==RESOURCE_V3)==modern,'Different resource identity version')
    if not modern:
        need(data['core_source_commit'] == resources['core_source_commit'], 'Different core source')
    validate_resources(resources)
    need(type(data['artifacts']) is list, 'Artifacts required')
    points = {p['id']: p for p in resources['points']}; seen = set(); paths = set(); methods = set()
    for a in data['artifacts']:
        keys(a, ('resource_id', 'platform', 'binary_sha256', 'source_sha256', 'method_sha256',
                 'seed_base', 'reported_reserved_components', 'reported_core_reserved_bytes',
                 'reported_budget_trials', 'negative_record_rejections', 'raw')+(('source_build_binding_sha256',) if modern else ()))
        token(a['resource_id']); digest(a['binary_sha256']); integer(a['seed_base'], 1)
        need(a['resource_id'] in points and a['resource_id'] not in seen, 'Duplicate/unknown resource')
        seen.add(a['resource_id'])
        if modern:
            from .resource_identity_v3 import point_binding
            need(a['source_build_binding_sha256']==point_binding(points[a['resource_id']]),'Common-context source binding differs')
        need(a['platform'] in ('windows_x86_64', 'linux_aarch64'), 'Unknown platform')
        keys(a['source_sha256'], ('result', 'trials', 'resource', 'probe', 'commands'))
        for h in a['source_sha256'].values(): digest(h)
        need(type(a['method_sha256']) is dict and set(a['method_sha256']) <= SOURCE_NAMES and
             {'probe_common.c', 'probe.c', 'run_common.py', 'latticecore.h'} <= set(a['method_sha256']), 'Unexpected method source')
        for name, h in a['method_sha256'].items(): digest(h); methods.add((name, h))
        keys(a['reported_reserved_components'], points[a['resource_id']]['reserved_components'])
        for value in a['reported_reserved_components'].values(): integer(value)
        integer(a['reported_core_reserved_bytes'])
        need(type(a['reported_budget_trials']) is list and len(a['reported_budget_trials']) == 10, 'Budget rows required')
        for b in a['reported_budget_trials']:
            keys(b, ('budget_bytes', 'arena_bytes', 'charged_core_bytes', 'order', 'status', 'trial'))
            for k in ('budget_bytes', 'arena_bytes', 'charged_core_bytes', 'order', 'trial'): integer(b[k])
            need(b['status'] in ('SUCCESS', 'WORKSPACE_OOM'), 'Wrong budget status')
        keys(a['raw'], ('path', 'sha256', 'rows'))
        need(type(a['raw']['path']) is str, 'Wrong raw path type')
        need(a['raw']['path'] not in paths, 'Shared raw file across artifacts'); paths.add(a['raw']['path'])
    need(seen == set(points), 'Resource set incomplete')
    need(type(data['method_sources']) is list, 'Exact method sources required')
    archived = set()
    for m in data['method_sources']:
        keys(m, ('name', 'path', 'sha256')); digest(m['sha256'])
        need(m['name'] in SOURCE_NAMES and m['path'] == f"methods/{m['sha256']}/{m['name']}", 'Invalid method path/name')
        key = (m['name'], m['sha256'])
        need(key not in archived, 'Duplicate method source'); archived.add(key)
    need(archived == methods, 'Missing or extra actual method versions')
    return data


def recompute(observations_path, resources_path):
    observations_path = Path(observations_path); resources_path = Path(resources_path)
    data = read(observations_path); resources = load_resources(resources_path)
    need(data['resources_sha256'] == sha(resources_path), 'Resources identity differs')
    validate_manifest(data, resources)
    root = observations_path.parent.resolve()
    for m in data['method_sources']:
        p = root / m['path']
        need(p.is_file() and not p.is_symlink() and not p.parent.is_symlink() and not p.parent.parent.is_symlink()
             and p.resolve().is_relative_to(root), 'Missing/escaping method source')
        need(sha(p) == m['sha256'], 'Actual method source changed')
    points = {p['id']: p for p in resources['points']}
    artifacts = [derive_artifact(a, points[a['resource_id']], shard(observations_path.parent, a['raw'])) for a in data['artifacts']]
    classifications = Counter(); purposes = Counter()
    for a in artifacts:
        classifications.update(a['classification_counts']); purposes.update(a['purpose_counts'])
    return dict(schema=SUMMARY_SCHEMA, dataset_id=data['dataset_id'], observations_sha256=sha(observations_path),
        resources_sha256=sha(resources_path), recompute_source_sha256=sha(__file__), artifacts=artifacts,
        summary=dict(artifacts=len(artifacts), trials=sum(a['trials'] for a in artifacts),
            classification_counts=dict(classifications), purpose_counts=dict(purposes),
            fixed_reservation_sequences=sum(a['fixed_reservation_sequences'] for a in artifacts),
            fixed_reservation_operation_observations=sum(a['fixed_reservation_operation_observations'] for a in artifacts),
            stack_positive_controls=sum(a['stack_positive_controls'] for a in artifacts),
            heap_positive_controls=sum(a['heap_positive_controls'] for a in artifacts),
            parser_negative_controls=sum(a['parser_negative_controls'] for a in artifacts),
            removed_trials=0, physical_RAM_measured=False),
        limitations=['Fixed-input finite interleaved observations are not an all-input bound.',
          'Fixed reservation and separate watermarks are not simultaneous active peak or physical RAM.',
          'Recovery is checked after the sequence with the same context storage reinitialized.',
          'Released-state check counts changed nonzero bytes; it is not whole-program secret erasure.',
          'Windows positive stack control records access-or-stack exit, not a protected-address oracle.'])
