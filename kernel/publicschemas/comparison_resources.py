"""Actual-image resource tables joined to independently validated complete-operation data."""
import csv
import hashlib
import io
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
from pathlib import Path, PurePosixPath
from .resources import CELLS, operation_mean
from .verification_v2 import keys, need, digest, integer, token

SCHEMA='lattice.comparison_resource_view.v1'
COMPONENTS={'W':'workspace_bytes','S':'stack_bytes','C':'external_context_bytes',
            'G':'globals_bytes','H':'outside_heap_bytes'}

def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))

def checked(base,item):
    keys(item,['path','sha256']);digest(item['sha256'])
    name=item['path'];need(type(name) is str and ':' not in name and '\\' not in name,'Relative data path required')
    p=PurePosixPath(name);need(bool(name) and not p.is_absolute() and '..' not in p.parts and p.as_posix()==name,'Canonical data path required')
    path=(base/p).resolve()
    need(path.is_relative_to(base.resolve()),'Data path leaves its package directory')
    need(path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest()==item['sha256'],'Resource input identity differs')
    return path

def load(path):
    path=Path(path);d=read(path)
    keys(d,['schema','dataset_id','studies','deployment_configurations'])
    need(d['schema']==SCHEMA,'Unknown comparison resource view');token(d['dataset_id'])
    need(type(d['studies']) is list and 0<len(d['studies'])<=8,'Bounded study list required')
    need(type(d['deployment_configurations']) is list,'Explicit deployment list required')
    from .mean_tail_model import validate as validate_statistics
    points=[];seen=set()
    for study in d['studies']:
        keys(study,['resources','statistics','observations'])
        r=read(checked(path.parent,study['resources']))
        s=read(checked(path.parent,study['statistics']))
        o=read(checked(path.parent,study['observations']))
        need(r['schema']=='lattice.comparison_resources.v1','Unsupported resource records')
        need(s['observations_sha256']==study['observations']['sha256'],'Statistics input differs')
        validate_statistics(s,o)
        configs={c['id']:c for c in s['configurations']}
        for row in r['configurations']:
            ident=row['configuration'];need(ident in configs,'Resource configuration absent from timing')
            c=configs[ident];need(row['library_sha256']==c['library_sha256'],'Different measured image')
            common=row['common'];keys(common,['P','W','S','C','G','H','R'])
            for value in common.values():integer(value)
            need(common['W']>0 and common['W']%32==0,'Invalid workspace')
            need(common['R']==sum(common[k] for k in COMPONENTS),'Core reservation does not add up')
            need(len(row['cells'])==18 and {(x['parameter'],x['operation']) for x in row['cells']}==CELLS,'Incomplete resource operations')
            for cell in row['cells']:
                need(cell['R']==sum(cell[k] for k in COMPONENTS),'Operation reservation does not add up')
                need(all(cell[k]<=common[k] for k in COMPONENTS),'Common reservation below operation requirement')
            key=(s['platform'],ident,row['library_sha256']);need(key not in seen,'Duplicate resource point');seen.add(key)
            rows=[x for x in s['cells'] if x['configuration']==ident]
            need(len(rows)==18,'Incomplete timing cells')
            sources=row['source_record_sha256']
            if isinstance(sources,str):digest(sources)
            permit=next((x for x in d['deployment_configurations'] if
                x['platform']==s['platform'] and x['configuration']==ident and x['binary_sha256']==row['library_sha256']),None)
            points.append(dict(id=s['platform']+'-'+ident,configuration=ident,platform=s['platform'],
                binary_sha256=row['library_sha256'],reserved_components={v:common[k] for k,v in COMPONENTS.items()},
                core_reserved_bytes=common['R'],program_bytes=common['P'],
                measurement_workspace_bytes=c['workspace_reserved'],statistics_dataset=s['dataset_id'],
                statistics_sha256=study['statistics']['sha256'],resources_sha256=study['resources']['sha256'],
                source_record_sha256=sources,equal_weight_18_operation_mean_ns=math.fsum(operation_mean(x,s['schema']) for x in rows)/18,
                cells=row['cells'],families=row['families'],deployment_recipe=permit['recipe'] if permit else None,
                common_context_verified=bool(permit and permit.get('common_context'))))
    for item in d['deployment_configurations']:
        keys(item,['platform','configuration','binary_sha256','recipe','common_context'])
        for k in ('platform','configuration','recipe'):token(item[k])
        digest(item['binary_sha256'])
        need(any(p['platform']==item['platform'] and p['configuration']==item['configuration'] and p['binary_sha256']==item['binary_sha256'] for p in points),'Deployment point absent')
        if item['common_context'] is not None:
            witness_path=checked(path.parent,item['common_context']);w=read(witness_path)
            keys(w,['schema','binary_sha256','workspace_bytes','stack_bytes','context_bytes','sequences','operations','source_result_sha256','raw'])
            need(w['schema']=='lattice.common_context_witness.v1' and w['binary_sha256']==item['binary_sha256'],'Different common-context image')
            digest(w['source_result_sha256'])
            point=next(p for p in points if p['platform']==item['platform'] and p['configuration']==item['configuration'])
            need(w['workspace_bytes']==point['reserved_components']['workspace_bytes'] and w['stack_bytes']==point['reserved_components']['stack_bytes'] and w['context_bytes']==point['reserved_components']['external_context_bytes'],'Common-context reservation differs')
            need(w['sequences']==48 and w['operations']==864 and len(w['raw'])==48,'Complete common-context records required')
            seen_sequences=set()
            for entry in w['raw']:
                raw=checked(witness_path.parent,entry).read_text(encoding='utf-8')
                events=[json.loads(line) for line in json.record_lines(raw) if line.startswith(('{','<record'))]
                rows=[r for r in events if r.get('event')=='common_result'];need(len(rows)==1,'One common result per sequence required')
                r=rows[0];key=(r['seed'],r['order']);need(key not in seen_sequences,'Duplicate context sequence');seen_sequences.add(key)
                need(r['control']==0 and r['rc']==0 and r['worker_rc']==0 and r['guard_error']==0 and r['allocation_failures']==0,'Normal common-context execution failed')
                need(r['canaries_ok'] and r['same_context_reinitialized_recovery_ok'] and r['context_and_arena_identity_stable'] and r['context_init_calls']==1,'Context or cleanup witness failed')
                need(r['arena_reserved_bytes']==w['workspace_bytes'] and r['stack_enforced_bytes']==w['stack_bytes'] and r['context_bytes']==w['context_bytes'],'Observed common reservation differs')
                need(r['completed_operations']==18 and r['expected_operations']==18 and len(r['rows'])==18 and {(x['parameter'],x['operation']) for x in r['rows']}==CELLS,'Incomplete common-context operations')
                need(all(x['rc']==0 and x['output_matches'] and x['changed_nonzero_released_bytes']==0 for x in r['rows']),'Common output or cleanup differs')
            need({order for _,order in seen_sequences}=={0,1},'Both operation orders required')
            need(len({seed for seed,_ in seen_sequences})==24 and all((seed,order) in seen_sequences for seed,_ in seen_sequences for order in (0,1)),'Each context input requires both orders')
    return dict(d,points=points)

def summary(data,library=None):
    points=data['points']
    if library is not None:
        points=[p for p in points if p['platform']==library['platform'] and p['binary_sha256']==library['binary_sha256']]
        if not points:return None
    return dict(dataset_id=data['dataset_id'],kind='comparison_resources',points=points,
                measurement_scope=['Algorithm reservation is the sum of workspace, reserved stack, context, writable globals and outside heap.',
                                   'Timing workspace arguments and verified algorithm resource requirements are recorded separately.'])

def select(data,statistics,request,profiles):
    keys(request,['platform','timing_dataset','ram_bytes','program_bytes'])
    for key in ('ram_bytes','program_bytes'):integer(request[key])
    need(statistics['dataset_id']==request['timing_dataset'] and statistics['platform']==request['platform'],'Different timing platform or study')
    from .deployment import permits
    candidates=[];excluded=[]
    for p in data['points']:
        if p['platform']!=request['platform'] or p['statistics_dataset']!=statistics['dataset_id']:continue
        reasons=[]
        if not p['deployment_recipe']:reasons.append('REFERENCE_OR_METHOD_COMPARISON')
        if not p['common_context_verified']:reasons.append('COMMON_CONTEXT_EVIDENCE_UNAVAILABLE')
        if not permits(profiles,p['platform'],p['binary_sha256'],p['reserved_components']['workspace_bytes']):reasons.append('DEPLOYMENT_PROFILE_UNAVAILABLE')
        if p['core_reserved_bytes']>request['ram_bytes']:reasons.append('RAM_BUDGET_EXCEEDED')
        if p['program_bytes']>request['program_bytes']:reasons.append('PROGRAM_BUDGET_EXCEEDED')
        if reasons:excluded.append(dict(resource_id=p['id'],reasons=reasons));continue
        candidates.append(dict(resource_id=p['id'],configuration=p['configuration'],binary_sha256=p['binary_sha256'],
            platform=p['platform'],workspace_bytes=p['reserved_components']['workspace_bytes'],
            measurement_workspace_bytes=p['measurement_workspace_bytes'],core_reserved_bytes=p['core_reserved_bytes'],
            program_bytes=p['program_bytes'],equal_weight_18_operation_mean_ns=p['equal_weight_18_operation_mean_ns'],
            recipe=p['deployment_recipe'],resource_evidence_sha256=p['resources_sha256']))
    candidates.sort(key=lambda x:(x['equal_weight_18_operation_mean_ns'],x['core_reserved_bytes'],x['program_bytes'],x['configuration']))
    return dict(schema='lattice.budget_query.v1',request=request,resource_dataset=data['dataset_id'],
                method='equal_weight_arithmetic_mean_of_18_pooled_operation_means',
                outcome='MATCHES_AVAILABLE' if candidates else 'NO_MEASURED_CONFIGURATION_FITS',
                selected=candidates[0] if candidates else None,candidates=candidates,excluded=excluded,
                unmeasured_configurations=[],deployment_scope=profiles)

def samples_csv(data):
    out=io.StringIO(newline='');fields=['platform','configuration','binary_sha256','program_bytes','core_reserved_bytes','measurement_workspace_bytes','equal_weight_18_operation_mean_ns']+list(COMPONENTS.values())
    writer=csv.DictWriter(out,fieldnames=fields);writer.writeheader()
    for p in data['points']:writer.writerow({k:(p['reserved_components'][k] if k in COMPONENTS.values() else p[k]) for k in fields})
    return out.getvalue().encode('utf-8-sig')
