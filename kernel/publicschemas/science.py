"""Closed public views only: no raw-source importer, directory search or gate state."""
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
import csv, io, record_io as json
from .block_model import SCHEMA as BLOCK,validate as validate_block
from .verification_model import SCHEMA as VALIDATION,validate as validate_validation
from .verification_v2 import SCHEMA as VERIFICATION,validate as validate_verification,recompute
from .resources import SCHEMA as RESOURCE,SCHEMAS as RESOURCE_SCHEMAS,validate as validate_resources,load as load_resources
POOLED='lattice.pooled_median_statistics.v2'
MEAN_TAIL='lattice.mean_tail_statistics.v1'
TIMING='lattice.timing_statistics.v2'
LIMITS='lattice.resource_limit_statistics.v1'
FOOTPRINT='lattice.process_footprint_statistics.v1'
SHARED='latticecore.shared_keccak.v1'
ATTRIBUTION='latticecore.timing_attribution.v1'
APPLICATION='lattice.application_pool_statistics.v1'
APPLICATION_LATENCY='lattice.application_latency_statistics.v1'
PRIMITIVES='lattice.primitive_samples_statistics.v1'
APPLICATION_OWNER='lattice.application_owner_summary.v2'
INSTRUCTION='lattice.instruction_samples.recomputed.v1'
COMPARISON_RESOURCES='lattice.comparison_resource_view.v1'

def validate(data):
    if type(data) is not dict:raise ValueError('Scientific object required')
    if data.get('schema')==SHARED:
        from .shared_keccak_v1 import validate as check
        check(data);return data
    if data.get('schema')==ATTRIBUTION:
        from .timing_attribution_v1 import validate as check
        check(data);return data
    if data.get('schema')==BLOCK:return validate_block(data)
    if data.get('schema')==VALIDATION:return validate_validation(data)
    if data.get('schema')==VERIFICATION:return validate_verification(data)
    if data.get('schema') in RESOURCE_SCHEMAS:return validate_resources(data)
    raise ValueError('Unregistered public scientific schema')

def load(path):
    def pairs(items):
        result={}
        for key,value in items:
            if key in result:raise ValueError('Duplicate scientific JSON field')
            result[key]=value
        return result
    data=json.loads(path.read_text(encoding='utf-8-sig'),object_pairs_hook=pairs,
        parse_constant=lambda _:(_ for _ in ()).throw(ValueError('Nonfinite scientific number')))
    if data.get('schema')==COMPARISON_RESOURCES:
        from .comparison_resources import load as load_comparison
        return load_comparison(path)
    return load_resources(path) if data.get('schema') in RESOURCE_SCHEMAS else validate(data)

def summary(data,library=None):
    if data['schema']=='lattice.signing_pipeline_qualification_summary.v1':
        profiles=data['profiles']
        if library is not None:
            profiles=[p for p in profiles if p['production_image_sha256']==library['binary_sha256']]
            if not profiles:return None
        return dict(data,kind='verification_profiles',profiles=profiles)
    if data['schema']=='latticecore.verification_summary.v1':
        runs=data['runs']
        if library is not None:
            runs=[r for r in runs if library['binary_sha256'] in r['images'] and r['platform'].replace('-','_')==library['platform']]
            if not runs:return None
        return dict(data,dataset_id='standard-functional-verification',kind='verification_records',runs=runs,raw_files_checked=data['run_count'])
    if data['schema']==INSTRUCTION:
        cells=data['cells']
        if library is not None:
            cells=[x for x in cells if x['binary_sha256']==library['binary_sha256'] and data['platform']==library['platform']]
            if not cells:return None
        return dict(data,kind='instruction_samples',cells=cells,raw_files_checked=len(data['cells'])+len({c['binary_sha256'] for c in data['cells']}))
    if data['schema']==COMPARISON_RESOURCES:
        from .comparison_resources import summary as resource_summary
        return resource_summary(data,library)
    if data['schema'] in (APPLICATION_OWNER,'lattice.application_owner_summary.v1'):
        from .application_owner_v1 import selected
        return selected(data,library)
    if data['schema'] in (APPLICATION_LATENCY,PRIMITIVES):
        # These archives describe a complete application or a separately linked
        # arithmetic collector. They are displayed under all measured results.
        if library is not None and (data['schema']!=PRIMITIVES or data['platform']!=library['platform']):return None
        return dict(data,kind='application_latency' if data['schema']==APPLICATION_LATENCY else 'primitive_samples',
                    raw_files_checked=data['counts']['processes' if data['schema']==APPLICATION_LATENCY else 'independent_processes'])
    if data['schema']==APPLICATION:
        # These whole-application experiments allocate a different algorithm
        # workspace for each pool budget. Keep every budget in the archive view.
        if library is not None:return None
        cells=data['cells'];budgets=data['configuration_budgets']
        return dict(dataset_id=data['dataset_id'],kind='application_resources',platform=data['platform'],
                    counts=data['counts'],cells=cells,configuration_budgets=budgets,scope=data['scope'],
                    raw_files_checked=1,observations_sha256=data['observations_sha256'])
    if data['schema']==SHARED:
        if library is not None and (data['profile']['library_sha256']!=library['binary_sha256'] or
                data['platform']!=library['platform'] or
                data['profile']['workspace_bytes']!=library['workspace_bytes']):return None
        return dict(dataset_id=data['dataset_id'],kind='shared_keccak',platform=data['platform'],profile=data['profile'],
                    comparisons=data['comparisons'],measurements={k:v for k,v in data['measurements'].items() if k!='jobs'},
                    common_context=data['common_context'],resources=[{k:r[k] for k in ('profile','status','dll_sha256','program_bytes')} for r in data['resources']],
                    scope=data['scope'],raw_files_checked=len(data['measurements']['jobs']))
    if data['schema']==ATTRIBUTION:
        if library is not None:return None
        studies=[{k:v for k,v in s.items() if k!='jobs'} for s in data['studies']]
        files=[r for s in data['studies'] for j in s['jobs'] for r in (j['files'].values() if 'files' in j else [j['raw']])]
        return dict(dataset_id=data['dataset_id'],kind='timing_attribution',platform=data['platform'],studies=studies,
                    retained_samples=data['retained_samples'],method=data['method'],raw_files_checked=len(files))
    if data['schema']==FOOTPRINT:
        if library is not None:return None
        return dict(dataset_id=data['dataset_id'],kind='process_footprint',platform=data['platform'],
                    counts=data['counts'],method=data['method'],operations=data['operations'],
                    configuration_ranges=data['configuration_ranges'],observations_sha256=data['observations_sha256'])
    if data['schema']==LIMITS:
        if library is not None:return None
        return dict(dataset_id=data['dataset_id'],kind='resource_limits',platform=data['platform'],
                    counts=data['counts'],method=data['method'],cpu_quota_effects=data['cpu_quota_effects'],
                    operation_conditions=data['operation_conditions'],failed_jobs=data['failed_jobs'],
                    observations_sha256=data['observations_sha256'])
    if data['schema']==TIMING:
        # This schema identifies the timing-screen image and input groups, but
        # has no deployment capacity. Retain it in the complete archive view.
        if library is not None:return None
        studies=data['studies']
        return dict(dataset_id=data['dataset_id'],kind='timing_distributions',
                    studies=studies,raw_files_checked=data['raw_files_checked'],
                    raw_rows_checked=data['raw_rows_checked'],deleted_rows=data['deleted_rows'],
                    observations_sha256=data['observations_sha256'],
                    analysis_scope=data['analysis_scope'])
    if data['schema']==VERIFICATION:
        suites=data['suites'];libraries=data['libraries']
        if library is not None:
            h=library['binary_sha256']
            libraries=[x for x in libraries if x['sha256']==h]
            if not libraries:return None
            # A cross-image comparison is one joint observation. Its complete
            # subject list stays visible instead of attributing it to one image.
            suites=[dict(s,records=[r for r in s['records'] if r['library_sha256']==h])
                    if s['kind']=='standard_vectors' else s
                    for s in suites if h in s['library_sha256']]
        rows=dict(data,libraries=libraries,suites=suites)
        return dict(dataset_id=data['dataset_id'],kind='verification',
            summary=recompute(rows),libraries=libraries,
            suites=[{k:s[k] for k in ('id','kind','subject_scope','library_sha256','status','scope')}|
                    {'record_count':len(s['records'])} for s in suites],
            counting_scope=data['counting_scope'],limits=data['limits'])
    if data['schema'] in RESOURCE_SCHEMAS:
        points=data['points']
        if library is not None:
            points=[p for p in points if p['binary_sha256']==library['binary_sha256'] and
                    p['platform']==library['platform'] and
                    p['reserved_components']['workspace_bytes']==library['workspace_bytes']]
            if not points:return None
        return dict(dataset_id=data['dataset_id'],kind='deployment_resources',
                    points=points,measurement_scope=data['measurement_scope'])
    if data['schema'] in (POOLED,MEAN_TAIL):
        configurations=data['configurations']
        if library is not None:
            if data['platform']!=library['platform']:return None
            configurations=[c for c in configurations if c['provider']=='lattice' and
                            c['library_sha256']==library['binary_sha256'] and
                            (data['schema']==MEAN_TAIL or c['workspace_reserved']==library['workspace_bytes'])]
            if not configurations:return None
        ids={c['id'] for c in configurations}
        return dict(dataset_id=data['dataset_id'],kind='mean_tail_measurements' if data['schema']==MEAN_TAIL else 'pooled_measurements',
            platform=data['platform'],execution=data['execution'],target_machine=data['target_machine'],
            configurations=configurations,method=data['method'],counts=data['counts'],
            cells=[r for r in data['cells'] if r['configuration'] in ids],
            comparisons=[r for r in data['comparisons'] if r['candidate'] in ids or r['reference'] in ids],
            observations_sha256=data['observations_sha256'])
    if data['schema']==VALIDATION:
        if library is not None:return None
        return dict(dataset_id=data['dataset_id'],kind='validation',
            extracted_probes=len(data['representation_probes']),signature_differentials=len(data['signature_differentials']),
            emulated_targets=len(data['emulated_targets']),failed_attempts=len(data['failed_attempts']),limits=data['limits'])
    selected=data['configurations']
    if library is not None:
        if data['platform']!=library['platform']:return None
        selected=[c for c in selected if c['provider']=='lattice' and
            c['library_sha256']==library['binary_sha256'] and c['id']==library['configuration'] and
            c['workspace_reserved']==library['workspace_bytes']]
        if not selected:return None
    ids={c['id'] for c in selected};analysis=data['analysis']
    return dict(dataset_id=data['dataset_id'],kind='blocked_measurements',
        platform=data['platform'],execution=data['execution'],experiment=data['experiment'],
        configurations=selected,completeness=data['completeness'],
        cells=[c for c in analysis['cells'] if c['configuration'] in ids] if analysis else [],
        ratios=[c for c in analysis['ratios'] if c['configuration'] in ids] if analysis else [],
        analysis_available=analysis is not None,
        export_scope='Exports retain the complete registered study, all controls, warmups, failed and incomplete observations.')

def samples_csv(data):
    if data['schema']==COMPARISON_RESOURCES:
        from .comparison_resources import samples_csv as export
        return export(data)
    if data['schema'] in (APPLICATION_OWNER,'lattice.application_owner_summary.v1'):
        from .application_owner_v1 import samples_csv as export
        return export(data).encode('utf-8-sig')
    if data['schema']==MEAN_TAIL:
        out=io.StringIO(newline='')
        fields=['configuration','parameter','operation','pooled_samples','minimum_ns','maximum_ns']
        for name in ('mean','median','p95','p99'):fields.extend([name+'_ns',name+'_ci95_low_ns',name+'_ci95_high_ns'])
        writer=csv.DictWriter(out,fieldnames=fields);writer.writeheader()
        for cell in data['cells']:
            row={k:cell[k] for k in fields if k in cell}
            for name,value in cell['statistics'].items():
                row.update({name+'_ns':value['ns'],name+'_ci95_low_ns':value['ci95_ns'][0],name+'_ci95_high_ns':value['ci95_ns'][1]})
            writer.writerow(row)
        return out.getvalue().encode('utf-8-sig')
    if data['schema'] in (APPLICATION_LATENCY,PRIMITIVES):
        out=io.StringIO(newline='')
        rows=data['cells'];fields=[k for k in rows[0] if not isinstance(rows[0][k],(dict,list))]
        if data['schema']==PRIMITIVES:
            names={'native-balanced':'原生算术后端','portable-compact':'可移植算术后端'}
            fields=fields+['configuration_title']
            rows=[dict(r,configuration_title=names.get(r['configuration'],r['configuration'])) for r in rows]
        writer=csv.DictWriter(out,fieldnames=fields);writer.writeheader()
        writer.writerows({k:r[k] for k in fields} for r in rows)
        return out.getvalue().encode('utf-8-sig')
    if data['schema']==APPLICATION:
        out=io.StringIO(newline='');fields=['configuration','binary_sha256','kem','dsa','budget_bytes',
            'trials','successes','workspace_insufficient','pool_too_small','application_stack_bytes',
            'globals_and_tls_bytes','serialized_object_bytes','pool_bytes','workspace_bytes',
            'maximum_workspace_high_water_bytes','maximum_stack_watermark_bytes',
            'maximum_external_heap_peak_bytes','minimum_completed_operations']
        writer=csv.DictWriter(out,fieldnames=fields);writer.writeheader()
        for r in data['cells']:
            row={k:r[k] for k in fields if k in r}
            row.update(successes=r['status_counts'].get('PASS',0),
                workspace_insufficient=r['status_counts'].get('WORKSPACE_INSUFFICIENT',0),
                pool_too_small=r['status_counts'].get('POOL_TOO_SMALL',0))
            writer.writerow(row)
        return out.getvalue().encode('utf-8-sig')
    if data['schema']==SHARED:
        out=io.StringIO(newline='');rows=data['measurements']['cells'];fields=[k for k in rows[0] if k!='paired_block_ratios']
        writer=csv.DictWriter(out,fieldnames=fields);writer.writeheader();writer.writerows({k:r[k] for k in fields} for r in rows)
        return out.getvalue().encode('utf-8-sig')
    if data['schema']==FOOTPRINT:
        out=io.StringIO(newline='');rows=data['operations']
        writer=csv.DictWriter(out,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
        return out.getvalue().encode('utf-8-sig')
    if data['schema']==LIMITS:
        out=io.StringIO(newline='');rows=data['operation_conditions']
        writer=csv.DictWriter(out,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
        return out.getvalue().encode('utf-8-sig')
    if data['schema']==POOLED:
        out=io.StringIO(newline='');columns=['configuration','parameter','operation','pooled_samples',
            'pooled_mean_ns','pooled_median_ns','pooled_p95_ns','pooled_p99_ns','minimum_ns','maximum_ns']
        writer=csv.DictWriter(out,fieldnames=columns);writer.writeheader();writer.writerows(data['cells'])
        return out.getvalue().encode('utf-8-sig')
    if data['schema']!=BLOCK:raise ValueError('Validation data are exported as structured JSON')
    out=io.StringIO(newline='');columns=['run_ordinal','block','parameter','operation','configuration',
        'driver_exit_code','driver_status','case_id','iteration','warmup','elapsed_ticks','tick_frequency','elapsed_ns',
        'status','entropy_sha256','message_sha256','context_sha256']
    writer=csv.DictWriter(out,fieldnames=columns);writer.writeheader()
    for run in data['runs']:
        slot=data['schedule'][run['ordinal']]
        for row in run['samples']:
            writer.writerow(dict(run_ordinal=run['ordinal'],block=slot['block'],parameter=slot['parameter'],
                operation=slot['operation'],configuration=slot['configuration'],
                driver_exit_code=run['driver_exit_code'],driver_status=run['driver_status'],**row))
    return out.getvalue().encode('utf-8-sig')
