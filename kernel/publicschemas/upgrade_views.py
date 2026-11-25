"""Read-only bindings for original paired upgrade statistics and resource evidence.

The original summary, manifest, command records and raw bytes remain unchanged.
Point estimates and exact image/workspace identities are checked here; bootstrap
intervals are shown from the hash-bound analysis, not recomputed by the browser.
"""
import copy
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
import math
from pathlib import Path
from .observations import require, TOKEN
from .demo import descriptor

CELLS={(p,o) for p in (512,768,1024,44,65,87) for o in range(3)}

def validate_request(item):
    require(type(item) is dict and set(item)=={'id','title','platform','summary','manifest','commands','bindings','resources'},'Explicit upgrade binding required')
    for key in ('id','platform'):require(type(item[key]) is str and TOKEN.fullmatch(item[key]),'Invalid upgrade identity')
    require(type(item['title']) is str and 0<len(item['title'])<=80,'Invalid upgrade title')
    for key in ('summary','manifest','commands'):descriptor(item[key])
    require(type(item['bindings']) is list and 0<len(item['bindings'])<=4,'Upgrade image bindings required')
    for row in item['bindings']:
        require(type(row) is dict and set(row)=={'library','label'},'Upgrade library and measured label required')
        require(all(type(x) is str and TOKEN.fullmatch(x) for x in row.values()),'Invalid measured label')
    require(type(item['resources']) is list and len(item['resources'])<=4,'Explicit resource evidence list required')
    for row in item['resources']:
        require(type(row) is dict and set(row)=={'library','result','observations','commands'},'Explicit resource binding required')
        for key in ('result','observations','commands'):descriptor(row[key])
    return item

def _bytes(ref,base):
    path=(base/ref['path']).resolve();blob=path.read_bytes()
    require(hashlib.sha256(blob).hexdigest()==ref['sha256'],'Upgrade evidence fingerprint changed')
    return path,blob

def _read(ref,base):
    path,blob=_bytes(ref,base)
    return path,json.loads(blob)

def close(a,b):
    require(type(a) in (int,float) and type(b) in (int,float) and math.isfinite(a) and math.isfinite(b)
            and math.isclose(a,b,rel_tol=1e-8,abs_tol=1e-8),'Inconsistent upgrade estimate')

def load(item,base,libraries):
    validate_request(item);base=Path(base)
    summary_path,summary=_read(item['summary'],base)
    manifest_path,manifest=_read(item['manifest'],base)
    commands_path,commands=_read(item['commands'],base)
    require(summary.get('schema')=='lattice.upgrade.paired_summary.v1' and manifest.get('schema')=='latticecore.blocked.v1','Unsupported upgrade evidence')
    require(summary['source_manifest_sha256']==item['manifest']['sha256'] and summary['commands_sha256']==item['commands']['sha256'],'Upgrade summary provenance mismatch')
    require(summary['binary_sha256']==manifest['binary_sha256'],'Upgrade image list mismatch')
    method=summary['method'];experiment=manifest['configuration'];configurations=experiment['configurations']
    require(method['estimator']=='ratio_of_sums_of_18_complete_operation_means' and method['replication_unit']=='complete_randomized_paired_block'
            and method['interval']=='pointwise_percentile_95_not_simultaneous' and method['trimmed_rows']==0,'Unsupported paired statistical scope')
    require(method['blocks']==experiment['blocks'] and method['samples_per_cell_per_block']==experiment['samples'],'Upgrade replication mismatch')
    measured={x['label']:x for x in configurations};require(len(measured)==len(configurations),'Repeated measured labels')
    expected={(b,p,o,label) for b in range(experiment['blocks']) for p,o in CELLS for label in measured}
    actual={(r['block'],r['parameter'],r['operation'],r['label']) for r in commands}
    require(actual==expected and len(commands)==len(expected) and all(r['exit_code']==0 for r in commands),'Incomplete paired commands')
    require(method['raw_rows']==len(commands)*(experiment['samples']+experiment['warmups']),'Raw row count mismatch')
    bindings=[]
    for binding in item['bindings']:
        lib=libraries[binding['library']];row=measured[binding['label']]
        digest=manifest['binary_sha256'][row['library']]
        require(lib['platform']==item['platform'] and digest==lib['binary_sha256'],'Upgrade measured image does not match library')
        require(row['workspace'] in lib.get('workspace_options',[lib['workspace_bytes']]),'Upgrade measured workspace does not match library')
        bindings.append(dict(binding,binary_sha256=digest,workspace_bytes=row['workspace'],title=lib['title']))
    means={}
    for row in commands:
        key=(row['label'],row['parameter'],row['operation']);means.setdefault(key,[]).append(row['mean_ns']/1000)
    means={k:sum(v)/len(v) for k,v in means.items()}
    for comparison in summary['comparisons']:
        candidate,reference=comparison['candidate'],comparison['reference']
        require(candidate in measured and reference in measured,'Unknown compared label')
        require({(x['parameter'],x['operation']) for x in comparison['cells']}==CELLS and len(comparison['cells'])==18,'Incomplete 18-operation comparison')
        for row in comparison['cells']+[comparison['equal_frequency']]:
            if 'parameter' in row:
                a,b=row['candidate_mean_us'],row['reference_mean_us']
                close(a,means[(candidate,row['parameter'],row['operation'])]);close(b,means[(reference,row['parameter'],row['operation'])])
            else:
                a,b=row['candidate_sum_18_us'],row['reference_sum_18_us']
                close(a,sum(means[(candidate,p,o)] for p,o in CELLS));close(b,sum(means[(reference,p,o)] for p,o in CELLS))
            require(a>0 and b>0,'Invalid paired time')
            close(row['time_ratio'],a/b);close(row['time_change_percent'],(a/b-1)*100)
            lo,hi=row['ratio_ci95'];require(0<lo<=hi,'Invalid paired confidence interval')
            close(row['time_change_percent_ci95'][0],(lo-1)*100);close(row['time_change_percent_ci95'][1],(hi-1)*100)
    resources=[]
    for record in item['resources']:
        _,result=_read(record['result'],base);_read(record['observations'],base);_read(record['commands'],base)
        lib=libraries[record['library']]
        require(result['schema']=='lattice.normal_resource_measurement.v1' and result['status']=='PASS','Unqualified resource evidence')
        require(result['library_sha256']==lib['binary_sha256'] and result['W'] in lib.get('workspace_options',[lib['workspace_bytes']]),'Resource image/workspace mismatch')
        require(result['observations_sha256']==record['observations']['sha256'] and result['commands_sha256']==record['commands']['sha256'],'Resource provenance mismatch')
        require(result['R']==sum(result[x] for x in ('W','S','C','G','H')),'Resource accounting mismatch')
        resources.append(dict(library=record['library'],title=lib['title'],**{k:result[k] for k in ('W','S','C','G','H','R','P','library_sha256','scope')}))
    for row in commands:
        raw=(manifest_path.parent/row['raw_csv']).resolve()
        require(raw.is_relative_to(manifest_path.parent),'Raw observation outside registered directory')
        _bytes(dict(path=row['raw_csv'],sha256=row['raw_sha256']),manifest_path.parent)
    return dict(request=copy.deepcopy(item),base=base,summary=summary,manifest=manifest,commands=commands,
                raw_base=manifest_path.parent,bindings=bindings,resources=resources)

def view(entry,library=None):
    bindings=[x for x in entry['bindings'] if library is None or x['library']==library]
    if not bindings:return None
    labels={x['label'] for x in bindings};summary=entry['summary'];item=entry['request']
    comparisons=[x for x in summary['comparisons'] if x['candidate'] in labels]
    titles={x['label']:x['title']+' · '+format(x['workspace_bytes'],',')+' B 工作区' for x in entry['bindings']}
    for row in entry['manifest']['configuration']['configurations']:
        titles.setdefault(row['label'],{'native-matched':'成熟优化实现（同编译条件）','native':'成熟优化实现（同编译条件）','old-low-memory':'升级前低内存','old-low':'升级前低内存','old-full':'升级前性能布局（57024 B）','old-partial':'升级前性能布局（42944 B）','new-low-memory':'低内存'}.get(row['label'],row['label']))
    return dict(kind='upgrade_paired',dataset_id=item['id'],title=item['title'],platform=item['platform'],method=summary['method'],
                comparisons=comparisons,bindings=bindings,label_titles=titles,raw_files_checked=len(entry['commands']),
                resources=[x for x in entry['resources'] if library is None or x['library']==library],
                boundary=entry['manifest']['measured_boundary'],message_bytes=entry['manifest']['configuration']['message_bytes'],
                context_bytes=entry['manifest']['configuration']['context_bytes'])

def export(entry,name,ordinal=None):
    if name in ('summary','manifest','commands'):
        return _bytes(entry['request'][name],entry['base'])[1]
    if name=='raw':
        require(type(ordinal) is int and 0<=ordinal<len(entry['commands']),'Invalid raw observation ordinal')
        row=entry['commands'][ordinal];path=(entry['raw_base']/row['raw_csv']).resolve()
        require(path.is_relative_to(entry['raw_base']),'Raw observation outside registered directory')
        return _bytes(dict(path=row['raw_csv'],sha256=row['raw_sha256']),entry['raw_base'])[1]
    if name in ('resource-result','resource-observations','resource-commands'):
        require(type(ordinal) is int and 0<=ordinal<len(entry['request']['resources']),'Invalid resource evidence ordinal')
        return _bytes(entry['request']['resources'][ordinal][name.removeprefix('resource-')],entry['base'])[1]
    raise ValueError('Unknown upgrade export')
