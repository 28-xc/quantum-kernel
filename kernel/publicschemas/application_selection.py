"""Choose among measured complete applications with matching deployment images."""
import copy
from .application_owner_v1 import SUMMARY, PAIRS
from .deployment import permits
from .verification_v2 import keys, need, integer


def select(summaries, profiles, request):
    keys(request, ['platform', 'ram_bytes', 'program_bytes', 'kem', 'dsa', 'flows', 'fresh_identity'])
    for k in ('ram_bytes', 'program_bytes', 'kem', 'dsa', 'flows'):
        integer(request[k], 1)
    integer(request['fresh_identity'])
    need(request['platform'] in ('windows_x86_64', 'linux_aarch64'), 'Unknown platform')
    need((request['kem'], request['dsa']) in PAIRS and request['flows'] in (1, 200)
         and request['fresh_identity'] in (0, 1), 'Select a measured complete application workload')
    result = dict(schema='lattice.application_selection.v1', request=dict(request), candidates=[], excluded=[],
                  selected=None, method='minimum_measured_complete_batch_mean_under_application_RAM_and_program_limits',
                  resource_scope='complete_application_pool_stack_globals_TLS_and_external_heap',
                  time_scope='initialization_identity_preparation_all_flows_finish_and_final_pool_clearing')
    seen = set()
    for summary in summaries:
        need(summary['schema'] in (SUMMARY, 'lattice.application_owner_summary.v1'), 'Expected a replayed application summary')
        if summary['platform'] != request['platform']:
            continue
        configurations = {c['id']: c for c in summary['configurations']}
        for cell in summary['cells']:
            if any(cell[k] != request[k] for k in ('kem', 'dsa', 'flows', 'fresh_identity')):
                continue
            cfg = configurations[cell['configuration']]
            if not permits(profiles, summary['platform'], cfg['binary_sha256'], cfg['workspace_bytes']):
                continue
            resources = [r for r in summary['resources'] if all(r[k] == cell[k] for k in ('configuration', 'kem', 'dsa', 'layout'))]
            need(len(resources) == 1, 'Missing or duplicated application resource cell')
            resource = resources[0]
            identity = (cfg['binary_sha256'], cfg['application_sha256'], cell['layout'])
            # Repeated studies of the same image must be resolved in the data catalogue,
            # rather than selecting the fastest repeat here.
            need(identity not in seen, 'Multiple studies of one application image require an explicit choice')
            seen.add(identity)
            candidate = dict(binary_sha256=cfg['binary_sha256'],
                             application_sha256=cfg['application_sha256'], dataset_id=summary['dataset_id'],
                             observations_sha256=summary['observations_sha256'], **copy.deepcopy(cell))
            candidate.update(application_ram_bytes=resource['charged_bytes'], application_program_bytes=resource['program_bytes'],
                             resource=copy.deepcopy(resource))
            reasons = []
            if resource['charged_bytes'] > request['ram_bytes']:
                reasons.append('APPLICATION_RAM_BUDGET_EXCEEDED')
            if resource['program_bytes'] > request['program_bytes']:
                reasons.append('APPLICATION_PROGRAM_BUDGET_EXCEEDED')
            if reasons:
                result['excluded'].append(dict(candidate, reasons=reasons))
            else:
                result['candidates'].append(candidate)
    result['candidates'].sort(key=lambda x: (x['mean_batch_ns'], x['application_ram_bytes'], x['configuration'], x['layout']))
    if result['candidates']:
        result['selected'] = result['candidates'][0]
    return result
