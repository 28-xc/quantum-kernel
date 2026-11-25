"""Recompute measured component watermarks from every retained resource trial."""
from pathlib import Path
from collections import Counter
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
import record_io as json, math, re
from .profiling_v1 import read, sha
from .verification_v2 import need, keys, integer, digest, token, source_map
from .resources import validate as validate_resources, load as load_resources, SCHEMA_V3 as RESOURCE_V3, PARAMETERS

SCHEMA = 'lattice.resource_watermarks.v1'
SCHEMA_V2 = 'lattice.resource_watermarks.v2'
PROTOCOL = dict(stack_grid_bytes=list(range(256, 16385, 256)), stack_margin_bytes=256,
                confirmation_seeds_per_parameter=24, workspace_quantum_bytes=32,
                budgets_bytes=[16384,32768,65536,131072,262144], message_bytes=1024,
                observation='maximum_individual_component_watermark_over_confirmation_sequences')
REASONS = {'instrument_control','workspace_discovery','parameter_fixed_workspace',
           'workspace_lower_failure','stack_grid','fixed_workspace_stack_new_seed_sequence',
           'explicit_total_budget'}
CLASSES = {'SUCCESS','PROTECTED_STACK_FAULT','WORKSPACE_OOM','WINDOWS_ACCESS_OR_STACK_EXIT'}
ARG_KEYS = ('parameter','operation','arena_bytes','stack_bytes','seed','control')
RESULT_STRINGS = {'event': {'trial_result'}, 'schema': {'resources.r2.v1'},
    'rng_mode': {'caller_supplied_test_entropy'},
    'platform_stack_model': {'Linux mmap independent stack and protected lower region',
                             'Windows dedicated thread with protected lower region'},
    'heap_positive_control_mode': {'standalone_accounting_no_target_allocator_imports',
                                   'target_allocator_IAT_or_no_control'}}
RESULT_LISTS = ('step_rc','step_outputs_match','step_failure_outputs_zero','step_arena_high_water',
                'step_stack_watermark','step_released_prefix_zero','step_nonzero_bytes',
                'step_changed_nonzero_bytes')
RESULT_BOOLS = ('context_in_measured_stack','canaries_ok','released_prefix_all_zero',
                'recovery_full_sequence_ok','physical_ram_measured')
RESULT_INTS = ('parameter','operation','control','seed','rc','worker_rc','guard_error','init_rc',
    'arena_reserved_bytes','arena_high_water_bytes','arena_alignment_bytes','context_bytes',
    'stack_enforced_bytes','stack_watermark_observed_bytes','init_watermark_bytes',
    'os_stack_or_guard_mapping_reserved_bytes','os_enabled_or_committed_stack_pages_bytes',
    'protected_lower_bytes','os_page_bytes','allocation_failures','outside_heap_calls',
    'outside_heap_frees','outside_heap_live_requested_bytes','outside_heap_peak_requested_bytes',
    'heap_audit_errors','message_bytes','released_prefix_changed_nonzero_bytes')
MAPPING_FIELDS = ('os_original_stack_limit_bytes','image_mapped_bytes',
                  'image_writable_mapping_bytes','image_readonly_mapping_bytes')
WIN_FIELDS = ('image_committed_bytes','heap_hooks','heap_unhandled_imports')
ARM_FIELDS = ('original_stack_mapped_bytes','signal_alternate_stack_bytes')

def result_validate(r, platform):
    if r is None: return
    extra = MAPPING_FIELDS + (WIN_FIELDS if platform == 'windows_x86_64' else ARM_FIELDS)
    strings = {k:v for k,v in RESULT_STRINGS.items() if k!='heap_positive_control_mode'}
    optional = ('heap_positive_control_mode',) if platform=='windows_x86_64' else ()
    keys(r, (*strings,*RESULT_LISTS,*RESULT_BOOLS,*RESULT_INTS,*extra), optional)
    if 'heap_positive_control_mode' in r:
        need(r['heap_positive_control_mode'] in RESULT_STRINGS['heap_positive_control_mode'], 'Unknown heap control instrument')
    for k, choices in strings.items(): need(r[k] in choices, 'Unexpected probe text')
    for k in RESULT_BOOLS: need(type(r[k]) is bool, 'Boolean probe value required')
    for k in (*RESULT_INTS,*extra):
        if k == 'os_original_stack_limit_bytes' and r[k] is None: continue
        integer(r[k], -2147483648 if k in ('rc','worker_rc','guard_error','init_rc') else 0)
    for k in RESULT_LISTS:
        need(type(r[k]) is list and len(r[k])==3, 'Three operation observations required')
        for v in r[k]:
            if v is not None: integer(v, -2147483648 if k == 'step_rc' else 0)
    need(r['parameter'] in PARAMETERS and r['operation'] in range(4), 'Wrong parameter/operation')
    need(r['arena_alignment_bytes']==32 and r['message_bytes']==1024, 'Changed probe contract')

def trial_validate(t, platform, ordinal):
    keys(t, ('trial','reason','arguments','exit_code','elapsed_wall_seconds',
             'classification','result','fault','source_record_sha256'))
    need(t['trial']==ordinal and type(t['trial']) is int, 'Trial omission or reorder')
    need(t['reason'] in REASONS and t['classification'] in CLASSES, 'Unknown trial condition')
    digest(t['source_record_sha256']);integer(t['exit_code'],-2147483648)
    v=t['elapsed_wall_seconds'];need(type(v) in (int,float) and math.isfinite(v) and v>=0, 'Invalid wall-clock observation')
    args=t['arguments'];keys(args,ARG_KEYS)
    for v in args.values():integer(v)
    need(args['parameter'] in PARAMETERS and args['operation'] in range(4) and args['control'] in range(4), 'Wrong trial request')
    fault=t['fault']
    if fault is not None:
        keys(fault,('event','protected_region_hit'))
        need(fault['event']=='stack_fault' and type(fault['protected_region_hit']) is bool,'Invalid stack-fault observation')
    result_validate(t['result'],platform)
    r=t['result']
    if r is not None:
        for k in ('parameter','operation','seed','control'):need(r[k]==args[k], 'Result/request disagreement')
        need(r['arena_reserved_bytes']==args['arena_bytes'] and r['stack_enforced_bytes']==args['stack_bytes'], 'Result reservation differs')
        need(t['exit_code']==0 and fault is None and r['canaries_ok'] and r['recovery_full_sequence_ok'] and
             r['guard_error']==0 and r['init_rc']==0 and r['heap_audit_errors']==0 and
             r['arena_high_water_bytes']<=r['arena_reserved_bytes'] and
             r['released_prefix_changed_nonzero_bytes']==0,'Resource or recovery guard failed')
        if r['rc']==0:
            need(t['classification']=='SUCCESS' and r['worker_rc']==0,'Invalid success classification')
        else:
            need(t['classification']=='WORKSPACE_OOM' and r['rc']==-5 and r['allocation_failures']>0 and
                 -5 in r['step_rc'] and all(v in (None,1) for v in r['step_failure_outputs_zero']),
                 'Invalid allocation-failure classification')
    elif platform=='linux_aarch64':
        need(t['classification']=='PROTECTED_STACK_FAULT' and fault is not None and
             fault['protected_region_hit'] and t['exit_code'] in (139,135,-11,-7),'Unverified protected-stack fault')
    else:
        need(t['classification']=='WINDOWS_ACCESS_OR_STACK_EXIT' and fault is None and
             t['exit_code']&0xffffffff in (0xc0000005,0xc00000fd),'Unverified Windows fault exit')

def strict_line(line):
    def pairs(items):
        out={}
        for k,v in items:need(k not in out,'Duplicate JSON key');out[k]=v
        return out
    return json.loads(line,object_pairs_hook=pairs,
        parse_constant=lambda s:(_ for _ in ()).throw(ValueError('Nonfinite JSON')))

def shard(root, desc):
    keys(desc,('path','sha256','rows'));digest(desc['sha256']);integer(desc['rows'],1)
    need(type(desc['path']) is str and re.fullmatch(r'raw/[a-z0-9_-]+\.records.xml',desc['path']), 'Invalid public shard path')
    p=(root/desc['path']).resolve();need(p.is_relative_to(root.resolve()) and p.is_file() and not p.is_symlink(),'Missing or escaping raw shard')
    need(sha(p)==desc['sha256'],'Raw resource observations changed')
    rows=list(json.read_records(p))
    need(len(rows)==desc['rows'],'Raw resource row count differs')
    return rows

def derive_artifact(artifact, point, rows):
    platform=artifact['platform'];counts=Counter()
    need(len(rows)==1348,'Complete fixed resource study requires 1348 trials')
    for i,t in enumerate(rows):trial_validate(t,platform,i);counts[t['classification']]+=1
    need(Counter(t['reason'] for t in rows)=={'instrument_control':4,'workspace_discovery':6,
        'parameter_fixed_workspace':6,'workspace_lower_failure':6,'stack_grid':1152,
        'fixed_workspace_stack_new_seed_sequence':144,'explicit_total_budget':30},'Incomplete resource design')
    controls=[t for t in rows if t['reason']=='instrument_control']
    need([(t['arguments']['control'],t['arguments']['stack_bytes']) for t in controls]==[(1,4096),(2,4096),(2,65536),(3,16384)],'Changed control design')
    need([t['classification'] for t in controls]==['SUCCESS','WINDOWS_ACCESS_OR_STACK_EXIT' if platform=='windows_x86_64' else 'PROTECTED_STACK_FAULT','SUCCESS','SUCCESS'],'Control detector outcome differs')
    heap=controls[3]['result'];need(heap['outside_heap_calls']>0 and heap['outside_heap_peak_requested_bytes']==96 and heap['outside_heap_live_requested_bytes']==0,'Heap positive control differs')
    need(all(t['arguments']['control']==0 for t in rows if t['reason']!='instrument_control'),'Control result used as production trial')
    cells=[];parameters=[]
    for parameter in PARAMETERS:
        rr=[t for t in rows if t['arguments']['parameter']==parameter and t['reason']!='instrument_control']
        def group(reason):return [t for t in rr if t['reason']==reason]
        fixed=group('parameter_fixed_workspace');lower=group('workspace_lower_failure')
        need(len(fixed)==len(lower)==1 and fixed[0]['classification']=='SUCCESS' and
             lower[0]['classification']=='WORKSPACE_OOM','Fixed workspace boundary witness differs')
        w=fixed[0]['arguments']['arena_bytes'];need(w-lower[0]['arguments']['arena_bytes']==32,'Workspace boundary quantum differs')
        conf=group('fixed_workspace_stack_new_seed_sequence')
        need(len(conf)==24 and len({t['arguments']['seed'] for t in conf})==24,'Missing confirmation seeds')
        ss={t['arguments']['stack_bytes'] for t in conf};need(len(ss)==1,'Mixed confirmation stack budgets');s=next(iter(ss))
        need(all(t['classification']=='SUCCESS' and t['arguments']['operation']==3 and
                 t['arguments']['arena_bytes']==w and t['result']['step_rc']==[0,0,0] and
                 t['result']['step_outputs_match']==[1,1,1] and t['result']['step_changed_nonzero_bytes']==[0,0,0]
                 for t in conf),'Incomplete three-operation confirmation')
        minima=[]
        for op in range(3):
            scan=[t for t in group('stack_grid') if t['arguments']['operation']==op]
            need([t['arguments']['stack_bytes'] for t in scan]==PROTOCOL['stack_grid_bytes'],'Changed stack scan grid')
            need(all(t['arguments']['arena_bytes']==w for t in scan),'Mixed stack-scan workspace')
            first=next((i for i in range(len(scan)) if all(t['classification']=='SUCCESS' for t in scan[i:])),None)
            need(first is not None,'No contiguous successful stack interval');minima.append(scan[first]['arguments']['stack_bytes'])
            arena=max(t['result']['step_arena_high_water'][op] for t in conf)
            stack=max(t['result']['step_stack_watermark'][op] for t in conf)
            need(arena<=w and stack<=s,'Observed component exceeds enforced reservation')
            cells.append(dict(parameter=parameter,operation=op,arena_high_water_observed_bytes=arena,
                stack_watermark_observed_bytes=stack,arena_reserved_bytes=w,stack_enforced_reserved_bytes=s,
                full_core_simultaneous_observed_peak_bytes=None,observation_trial_ids=[t['trial'] for t in conf]))
        need(s==max(minima)+256,'Protected stack margin differs')
        global_parts=point['reserved_components'];ctx=fixed[0]['result']['context_bytes']
        need(ctx==global_parts['external_context_bytes'],'Context charge differs')
        budget_rows=group('explicit_total_budget');need(len(budget_rows)==5,'Missing budget cases')
        budgets=[]
        for budget,t in zip(PROTOCOL['budgets_bytes'],budget_rows):
            need(t['arguments']['operation']==3 and t['arguments']['stack_bytes']==s and t['arguments']['control']==0,
                 'Budget trial uses a different operation or stack reservation')
            charge=t['arguments']['arena_bytes']+s+ctx+global_parts['globals_bytes']+global_parts['outside_heap_bytes']
            need(charge<=budget and budget-charge<32,'Budget accounting differs')
            budgets.append(dict(budget_bytes=budget,charged_core_bytes=charge,arena_bytes=t['arguments']['arena_bytes'],
                                classification=t['classification'],trial=t['trial']))
        parameters.append(dict(parameter=parameter,workspace_bytes=w,stack_reserved_bytes=s,
            stack_minimum_contiguous_success_by_operation=minima,context_bytes=ctx,
            globals_bytes=global_parts['globals_bytes'],outside_heap_bytes=global_parts['outside_heap_bytes'],
            core_reserved_bytes=w+s+ctx+global_parts['globals_bytes']+global_parts['outside_heap_bytes'],
            workspace_success_trial=fixed[0]['trial'],workspace_lower_oom_trial=lower[0]['trial'],budget_trials=budgets))
    need(max(x['workspace_bytes'] for x in parameters)==point['reserved_components']['workspace_bytes'] and
         max(x['stack_reserved_bytes'] for x in parameters)==point['reserved_components']['stack_bytes'],
         'Parameter resources disagree with whole-package reservation')
    return dict(resource_id=artifact['resource_id'],platform=platform,binary_sha256=artifact['binary_sha256'],
                trials=len(rows),classification_counts=dict(sorted(counts.items())),parameters=parameters,cells=cells)

def validate_method_sources(root, descriptors):
    root=Path(root).resolve()
    need(type(descriptors) is list and descriptors,'Measurement source descriptors required')
    methods={}
    for m in descriptors:
        keys(m,('name','path','sha256'));digest(m['sha256'])
        need(re.fullmatch(r'[A-Za-z0-9_]+\.(?:c|h|py|S)',m['name']) is not None,'Unknown measurement source')
        need(m['path']=='methods/'+m['sha256']+'/'+m['name'],'Unexpected source archive path')
        f=(root/m['path']).resolve()
        need(f.is_relative_to(root) and f.is_file() and not f.is_symlink() and sha(f)==m['sha256'],'Measurement source bytes differ')
        pair=(m['name'],m['sha256']);need(pair not in methods,'Duplicate archived source');methods[pair]=True
    return methods

def recompute(path, resources_path):
    path=Path(path).resolve();data=read(path);resources=load_resources(resources_path)
    modern=data.get('schema')==SCHEMA_V2
    fields=('schema','dataset_id','resources_sha256','protocol','method_sources','artifacts')
    keys(data,fields if modern else fields+('core_source_commit',))
    need(data['schema'] in (SCHEMA,SCHEMA_V2),'Unexpected resource-watermark schema');token(data['dataset_id'])
    need((resources['schema']==RESOURCE_V3)==modern,'Different resource identity version')
    need(data['resources_sha256']==sha(resources_path),'Resource identity differs')
    if not modern:
        need(data['core_source_commit']==resources['core_source_commit'],'Core identity differs')
    need(data['protocol']==PROTOCOL,'Changed observation protocol')
    methods=validate_method_sources(path.parent,data['method_sources'])
    points={p['id']:p for p in resources['points']};seen=set();out=[];used_methods=set()
    for a in data['artifacts']:
        keys(a,('resource_id','platform','binary_sha256','source_sha256','method_sha256','raw')+(('source_build_binding_sha256',) if modern else ()))
        need(a['resource_id'] in points and a['resource_id'] not in seen,'Unknown or duplicate resource');seen.add(a['resource_id'])
        p=points[a['resource_id']];need(a['platform']==p['platform'] and a['binary_sha256']==p['binary_sha256'],'Resource artifact binding differs')
        if modern:
            from .resource_identity_v3 import point_binding
            need(a['source_build_binding_sha256']==point_binding(p),'Watermark source binding differs')
        need(a['platform'] in ('windows_x86_64','linux_aarch64'),'Unknown platform')
        keys(a['source_sha256'],('resource','dataset_result','raw_trials','protocol'))
        for h in a['source_sha256'].values():digest(h)
        need(a['source_sha256']['resource']==p['source_sha256']['resource'],'Different resource measurement')
        source_map(a['method_sha256'])
        for name,h in a['method_sha256'].items():
            if name=='method.md':continue
            need((name,h) in methods,'Actual historical measurement source missing');used_methods.add((name,h))
        out.append(derive_artifact(a,p,shard(path.parent,a['raw'])))
    need(seen==set(points),'Resource artifact omission')
    need(used_methods==set(methods),'Unreferenced measurement source')
    counts=Counter()
    for x in out:counts.update(x['classification_counts'])
    return dict(schema='lattice.resource_watermarks_summary.v1',dataset_id=data['dataset_id'],
        observations_sha256=sha(path),resources_sha256=sha(resources_path),artifacts=out,
        summary=dict(library_images=len(out),trials=sum(x['trials'] for x in out),
                     operation_cells=sum(len(x['cells']) for x in out),
                     classification_counts=dict(sorted(counts.items()))))
