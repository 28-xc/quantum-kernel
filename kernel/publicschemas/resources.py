"""Closed resource observations and finite, measured configuration selection."""
import math
from .verification_v2 import keys, need, integer, digest, token, text

SCHEMA='lattice.deployment_resources.v2'
SCHEMA_V3='lattice.deployment_resources.v3'
SCHEMAS=(SCHEMA,SCHEMA_V3)
PARAMETERS=[512,768,1024,44,65,87]
CELLS={(p,o) for p in PARAMETERS for o in range(3)}
COMPONENTS=('workspace_bytes','stack_bytes','external_context_bytes','globals_bytes','outside_heap_bytes')
TIMING_SCHEMAS=('lattice.pooled_median_statistics.v2','lattice.mean_tail_statistics.v1')

def operation_mean(row,schema):
    """Read the full-sample arithmetic mean from either validated timing view."""
    need(schema in TIMING_SCHEMAS,'Unsupported timing schema')
    value=(row['statistics']['mean']['ns'] if schema==TIMING_SCHEMAS[1]
           else row['pooled_mean_ns'])
    need(type(value) in (int,float) and math.isfinite(value) and value>0,'Invalid operation mean')
    return value

def validate(data,base=None):
    need(type(data) is dict and data.get('schema') in SCHEMAS,'Unknown resource schema')
    modern=data['schema']==SCHEMA_V3
    fields=['schema','dataset_id','points','measurement_scope']
    keys(data,fields if modern else fields+['core_source_commit','verification_sha256'])
    token(data['dataset_id'])
    if not modern:
        need(type(data['core_source_commit']) is str and len(data['core_source_commit'])==40 and all(c in '0123456789abcdef' for c in data['core_source_commit']),'Source commit missing')
        digest(data['verification_sha256'])
    need(type(data['points']) is list,'Resource points required');seen=set()
    for point in data['points']:
        keys(point,['id','configuration','platform','binary_sha256','parameters','build','program_bytes',
                    'reserved_components','core_reserved_bytes','common_context_validated','source_sha256','scope']+(['source_identity'] if modern else []))
        for k in ('id','configuration','platform'):token(point[k])
        need(point['id'] not in seen,'Duplicate resource identity');seen.add(point['id']);digest(point['binary_sha256'])
        need(point['parameters']==PARAMETERS,'Budget query requires all six parameters in one image')
        build=point['build'];keys(build,['backend','compiler','optimization','lto','target'])
        for k in ('backend','optimization','target'):token(build[k])
        text(build['compiler']);need(type(build['lto']) is bool,'Explicit LTO setting required')
        integer(point['program_bytes'],1);integer(point['core_reserved_bytes']);need(type(point['common_context_validated']) is bool,'Explicit context witness required')
        reserved=point['reserved_components'];keys(reserved,COMPONENTS)
        for k in COMPONENTS:integer(reserved[k])
        need(reserved['workspace_bytes']>0 and reserved['workspace_bytes']%32==0,'32-byte aligned nonzero workspace required')
        need(point['core_reserved_bytes']==sum(reserved.values()),'Reserved RAM decomposition differs')
        sources=point['source_sha256'];keys(sources,['image','build','resource','audit','common_context_result','common_context_audit'])
        for name in ('image','build','resource','audit'):digest(sources[name])
        need(sources['image']==point['binary_sha256'],'Resource image identity differs')
        common_sources=[sources['common_context_result'],sources['common_context_audit']]
        if point['common_context_validated']:
            for value in common_sources:digest(value)
        else:
            need(all(value is None for value in common_sources),'Unperformed common-context experiment requires null evidence fields')
        need(type(point['scope']) is list,'Scope list required')
        for value in point['scope']:text(value)
    need(type(data['measurement_scope']) is list,'Measurement scope list required')
    for value in data['measurement_scope']:text(value)
    if modern:
        from .resource_identity_v3 import validate_identities
        validate_identities(data,base)
    return data

def load(path):
    from pathlib import Path
    from .resource_identity_v3 import read
    return validate(read(path),Path(path).resolve().parent)

def select(data,statistics,request,deployment_profiles=None):
    """Rank only exact-image, exact-workspace complete 18-operation observations.

    The supplied statistics must already have passed its public schema validator.
    No interpolation, source-size estimate, sample trimming or platform pooling.
    """
    validate(data)
    need(statistics.get('schema') in TIMING_SCHEMAS,'Unsupported timing schema')
    keys(request,['platform','timing_dataset','ram_bytes','program_bytes'])
    token(request['platform']);token(request['timing_dataset'])
    for k in ('ram_bytes','program_bytes'):integer(request[k])
    need(statistics['dataset_id']==request['timing_dataset'],'Different registered timing study')
    need(statistics['platform']==request['platform'] and statistics['execution']=='native','Different platform/execution')
    candidates=[];excluded=[]
    if deployment_profiles is not None:
        from .deployment import validate as validate_profiles,permits
        validate_profiles(deployment_profiles)
    for point in data['points']:
        if point['platform']!=request['platform']:continue
        reasons=[]
        if deployment_profiles is not None and not permits(deployment_profiles,point['platform'],point['binary_sha256'],point['reserved_components']['workspace_bytes']):
            reasons.append('DEPLOYMENT_PROFILE_UNAVAILABLE')
        if not point['common_context_validated']:reasons.append('COMMON_CONTEXT_NOT_VALIDATED')
        if point['core_reserved_bytes']>request['ram_bytes']:reasons.append('RAM_BUDGET_EXCEEDED')
        if point['program_bytes']>request['program_bytes']:reasons.append('PROGRAM_BUDGET_EXCEEDED')
        matched=[c for c in statistics['configurations'] if c['provider']=='lattice' and
                 c['library_sha256']==point['binary_sha256'] and
                 c['workspace_reserved']==point['reserved_components']['workspace_bytes']]
        if not matched:reasons.append('NO_EXACT_IMAGE_WORKSPACE_MEASUREMENT')
        if reasons:
            excluded.append(dict(resource_id=point['id'],binary_sha256=point['binary_sha256'],reasons=reasons));continue
        for configuration in matched:
            rows=[r for r in statistics['cells'] if r['configuration']==configuration['id']]
            need(len(rows)==18 and {(r['parameter'],r['operation']) for r in rows}==CELLS,'Incomplete operation mixture')
            means=[operation_mean(r,statistics['schema']) for r in rows]
            candidates.append(dict(resource_id=point['id'],configuration=configuration['id'],
                binary_sha256=point['binary_sha256'],platform=point['platform'],
                workspace_bytes=point['reserved_components']['workspace_bytes'],
                core_reserved_bytes=point['core_reserved_bytes'],program_bytes=point['program_bytes'],
                equal_weight_18_operation_mean_ns=math.fsum(means)/18,
                resource_evidence_sha256=point['source_sha256']))
    candidates.sort(key=lambda r:(r['equal_weight_18_operation_mean_ns'],r['core_reserved_bytes'],r['program_bytes'],r['resource_id'],r['configuration']))
    measured={(p['binary_sha256'],p['reserved_components']['workspace_bytes']) for p in data['points'] if p['platform']==request['platform']}
    unmeasured=[dict(configuration=c['id'],provider=c['provider'],binary_sha256=c['library_sha256'],
        workspace_argument_bytes=c['workspace_reserved'],reason='RESOURCE_MEASUREMENT_UNAVAILABLE')
        for c in statistics['configurations'] if c['provider']!='lattice' or (c['library_sha256'],c['workspace_reserved']) not in measured]
    result=dict(schema='lattice.budget_query.v1',request=request,resource_dataset=data['dataset_id'],
                method='equal_weight_arithmetic_mean_of_18_pooled_operation_means',
                outcome='MATCHES_AVAILABLE' if candidates else 'NO_MEASURED_CONFIGURATION_FITS',
                selected=candidates[0] if candidates else None,candidates=candidates,excluded=excluded,unmeasured_configurations=unmeasured)
    if deployment_profiles is not None:result['deployment_scope']=deployment_profiles
    return result
