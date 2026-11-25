"""Closed, replayable fixed-owner application measurements (no target execution).

Batch latency includes final close. A 200-flow batch is one observation, not
200 latency samples. Resources include serialized I/O and the entire pool.
"""
from pathlib import Path
import argparse
import csv
import hashlib
import io
import random
import re
from .application_v1 import need, keys, integer, digest, read, loads, sha

SCHEMA = 'lattice.application_owner_observations.v2'
SUMMARY = 'lattice.application_owner_summary.v2'
LEGACY_SCHEMA = 'lattice.application_owner_observations.v1'
PAIRS = ((512, 44), (768, 65), (1024, 87))
TIME_SCOPE = 'app_open and context initialization, app_prepare, complete app_flow calls, app_finish and final app_close clearing the entire fixed pool'
OUTSIDE_SCOPE = 'module loading, symbol lookup, physical pool allocation and release, wide-workspace transcript oracle, post-call whole-pool zero and memory-guard checks'
RESULT_FIELDS = ('status kem dsa layout fresh_identity rc iterations completed_flows last_flow_operations transcript transcript_matches seed pool_bytes workspace_bytes guards_ok cleared timed batch_ticks frequency cpu heap_instrumented final_close_included').split()
RESOURCE_FIELDS = ('status kem dsa layout fresh_identity rc iterations completed_flows last_flow_operations transcript transcript_matches seed pool_bytes application_state_bytes serialized_owner_bytes workspace_bytes workspace_high_water stack_reserved_bytes stack_watermark_bytes library_globals_tls_bytes application_globals_bytes application_module_globals_bytes charged_bytes outside_heap_peak guards_ok cleared timed batch_ticks frequency heap_errors').split()
HEAP_FIELDS = ('event reserved_bound peak_requested retained_requested allocations frees tls_slot_allocations hooks unsupported').split()
CELL_FIELDS = ('kem dsa layout pool_bytes application_state_bytes serialized_owner_bytes workspace_bytes stack_reserved_bytes library_globals_tls_bytes application_globals_bytes application_module_globals_bytes charged_bytes maximum_stack_watermark maximum_workspace_high_water maximum_observed_heap heap_reserved_bytes flows').split()
JOB_FIELDS = ('index block configuration kem dsa fresh_identity flows layout seed').split()


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


def save(path, data):
    import record_io as json
    Path(path).write_text(json.dumps(data, ensure_ascii=False, indent=2, allow_nan=False)+'\n', encoding='utf-8')


def relative(value):
    need(type(value) is str and re.fullmatch(r'[A-Za-z0-9_./-]+', value) and
         not value.startswith('/') and all(x not in ('', '.', '..') for x in value.split('/')),
         'Invalid relative observation path')


def schedule(seed, ids):
    integer(seed, 1); need(2 <= len(ids) <= 10 and len(set(ids)) == len(ids), 'Two to ten distinct configurations required')
    rng = random.Random(seed); rows = []
    for block in range(9):
        cells = [(k, d, f, n) for k, d in PAIRS for f in (0, 1) for n in (1, 200)]
        rng.shuffle(cells)
        for k, d, fresh, flows in cells:
            arms = [(c, layout) for c in ids for layout in (0, 1)]; rng.shuffle(arms)
            for c, layout in arms:
                rows.append(dict(index=len(rows), block=block, configuration=c, kem=k, dsa=d,
                                 fresh_identity=fresh, flows=flows, layout=layout,
                                 seed=seed+block*104729+k*97+fresh*7919+flows*31))
    return rows


def descriptor(x):
    keys(x, ('path', 'sha256', 'bytes')); relative(x['path']); digest(x['sha256']); integer(x['bytes'])


def validate_observations(d):
    keys(d, ('schema', 'dataset_id', 'platform', 'method', 'configurations', 'provenance', 'resources', 'jobs', 'raw_files'))
    need(d['schema'] in (SCHEMA, LEGACY_SCHEMA) and d['platform'] in ('windows_x86_64', 'linux_aarch64'), 'Unknown application observations')
    need(d['dataset_id'] == d['platform']+'_fixed_owner_application', 'Changed dataset identity')
    m = d['method']
    keys(m, ('blocks', 'seed', 'cpu', 'clock', 'timed_scope', 'outside_scope', 'statistics', 'unit', 'transcript_scope'))
    need(m['blocks'] == 9 and m['timed_scope'] == TIME_SCOPE and m['outside_scope'] == OUTSIDE_SCOPE, 'Changed measurement boundary')
    need(m['unit'] == 'complete initialized and closed application batch' and
         m['transcript_scope'] == 'paired 64-bit full-output transcripts; complete-byte equivalence qualified separately', 'Changed sample or comparison scope')
    integer(m['cpu']); integer(m['seed'], 1)
    need(m['clock'] == ('QueryPerformanceCounter' if d['platform'] == 'windows_x86_64' else 'CLOCK_MONOTONIC_RAW'), 'Unexpected platform clock')
    s=m['statistics']; keys(s, ('bootstrap_seed', 'replicates', 'generator', 'interval', 'resampled_unit', 'ratio'))
    integer(s['bootstrap_seed'], 1)
    need(s == dict(bootstrap_seed=s['bootstrap_seed'], replicates=50000, generator='PCG64', interval='percentile 95%', resampled_unit='paired complete blocks', ratio='ratio of arithmetic mean batch times'), 'Changed statistical boundary')
    need(type(d['configurations']) is list and 2 <= len(d['configurations']) <= (8 if d['schema'] == LEGACY_SCHEMA else 10), 'Incomplete configurations')
    for c in d['configurations']:
        keys(c, ('id', 'binary_sha256', 'application_sha256', 'workspace_bytes', 'core_program_bytes', 'application_program_bytes', 'source_sha256'))
        need(type(c['id']) is str and re.fullmatch('[a-z0-9][a-z0-9_-]*',c['id']), 'Invalid configuration identity')
        for k in ('binary_sha256', 'application_sha256'): digest(c[k])
        for k in ('workspace_bytes', 'core_program_bytes', 'application_program_bytes'): integer(c[k], 1)
        need(c['workspace_bytes'] % 32 == 0, 'Unaligned workspace')
        need(type(c['source_sha256']) is dict and c['source_sha256'], 'Missing compiled sources')
        for p,h in c['source_sha256'].items(): relative(p); digest(h)
    need(len({c['application_sha256'] for c in d['configurations']}) == 1, 'Different application modules')
    p=d['provenance']; keys(p, ('plan_sha256','result_sha256','records_sha256','application_build_sha256','driver_sha256','collector_sha256','driver_binary_sha256','compiler_sha256','driver_source_sha256','all_records_retained'))
    for k,v in p.items():
        if k not in ('all_records_retained','driver_source_sha256'): digest(v)
    keys(p['driver_source_sha256'], ('timing.c','application.h','latticecore.h'))
    for value in p['driver_source_sha256'].values():digest(value)
    need(p['all_records_retained'] is True, 'Trimmed observations')
    ids=[c['id'] for c in d['configurations']]
    expected=schedule(m['seed'],ids)
    need(type(d['jobs']) is list and len(d['jobs']) == 216*len(ids), 'Incomplete timing runs')
    used=[]
    for j,e in zip(d['jobs'], expected, strict=True):
        keys(j, (*JOB_FIELDS, 'exit_code', 'raw', 'stderr'))
        need({k:j[k] for k in JOB_FIELDS} == e and type(j['exit_code']) is int and j['exit_code'] == 0, 'Changed schedule or failed process')
        for k in JOB_FIELDS:
            if k != 'configuration': integer(j[k])
        for k in ('raw','stderr'): descriptor(j[k]); used.append(j[k])
    need(type(d['resources']) is list and [r['configuration'] for r in d['resources']] == ids, 'Missing resource configurations')
    for r in d['resources']:
        keys(r, ('configuration','result_sha256','commands_sha256','cells','records'))
        digest(r['result_sha256']); digest(r['commands_sha256'])
        need(len(r['cells']) == 6 and {(c['kem'],c['dsa'],c['layout']) for c in r['cells']} == {(k,p,l) for k,p in PAIRS for l in (0,1)}, 'Incomplete resource cells')
        for c in r['cells']:
            keys(c,CELL_FIELDS)
            for v in c.values(): integer(v)
        need(len(r['records']) in (50,62), 'Incomplete resource records')
        for n,row in enumerate(r['records']):
            keys(row, ('ordinal','label','exit_code','raw','stderr'))
            need(type(row['ordinal']) is int and row['ordinal'] == n and row['label'] in ('instrument-control','heap-control','normal','insufficient','restored'), 'Invalid resource record')
            need(type(row['exit_code']) is int and row['exit_code'] == 0, 'Failed resource process')
            for k in ('raw','stderr'): descriptor(row[k]); used.append(row[k])
    need(d['raw_files'] == used and len({x['path'] for x in used}) == len(used), 'Missing, reused or reordered raw files')
    return d


def raw_rows(base, spec):
    descriptor(spec); p=(base/spec['path']).resolve()
    need(p.is_relative_to(base.resolve()) and p.is_file() and p.stat().st_size == spec['bytes'] and sha(p) == spec['sha256'], 'Observation bytes changed')
    import record_io
    if not p.read_bytes().strip(): return []
    return list(record_io.read_records(p))


def _resource_replay(d, base):
    cells=[]; counts={'resource_processes':0,'resource_flows':0,'capacity_failures':0,'capacity_restorations':0}
    paired={}
    for data,cfg in zip(d['resources'], d['configurations'], strict=True):
        groups={}; labels={}; recover={}; normal_conditions=set()
        for row in data['records']:
            values=raw_rows(base,row['raw']); need(not raw_rows(base,row['stderr']), 'Resource stderr is not empty')
            need(len(values) == 2, 'Expected result and heap lifetime')
            r,h=values; keys(r,RESOURCE_FIELDS); keys(h,HEAP_FIELDS)
            for k in RESOURCE_FIELDS:
                if k not in ('status','transcript','transcript_matches','guards_ok','cleared','timed','rc'): integer(r[k])
            for k in HEAP_FIELDS:
                if k != 'event': integer(h[k])
            need(h['event']=='heap_lifetime' and h['unsupported']==h['tls_slot_allocations']==r['heap_errors']==0, 'Unaccounted allocator state')
            need((row['label']=='heap-control' or h['peak_requested']<=h['reserved_bound']) and h['retained_requested']<=h['peak_requested'], 'Heap reservation exceeded')
            need(r['guards_ok'] is True and r['cleared'] is True and r['timed'] is False and r['batch_ticks']==0, 'Invalid cleanup or resource boundary')
            need(r['charged_bytes']==r['pool_bytes']+r['stack_reserved_bytes']+r['library_globals_tls_bytes']+r['application_globals_bytes']+r['application_module_globals_bytes']+h['reserved_bound'], 'Incomplete RAM accounting')
            need(r['outside_heap_peak']==h['peak_requested'] and r['workspace_high_water']<=r['workspace_bytes'] and r['stack_watermark_bytes']+256<=r['stack_reserved_bytes'], 'Observed resource exceeds reservation')
            label=row['label']; labels[label]=labels.get(label,0)+1; counts['resource_processes']+=1
            need((r['kem'],r['dsa']) in PAIRS and r['layout'] in (0,1) and r['fresh_identity'] in (0,1), 'Unknown resource condition')
            key=(r['kem'],r['dsa'],r['layout'])
            if label=='normal':
                need(r['status']=='PASS' and r['rc']==0 and r['transcript_matches'] is True and r['iterations']==r['completed_flows']==4 and r['last_flow_operations']==5+r['fresh_identity'], 'Incomplete normal flow')
                need(r['workspace_bytes']==cfg['workspace_bytes'], 'Resource image/workspace mismatch')
                groups.setdefault(key,[]).append((r,h)); counts['resource_flows']+=4
                condition=(*key,r['fresh_identity'],r['seed'])
                need(condition not in normal_conditions,'Duplicate resource input'); normal_conditions.add(condition)
                pair=(r['kem'],r['dsa'],r['fresh_identity'],r['seed'])
                need(paired.setdefault(pair,r['transcript']) == r['transcript'], 'Different resource output transcript')
            elif label in ('insufficient','restored'):
                need(r['fresh_identity']==1 and r['iterations']==1 and r['seed']==202610041615+r['kem'], 'Invalid recovery workload')
                if label=='insufficient':
                    need(r['status']=='WORKSPACE_INSUFFICIENT' and r['rc']==-5 and r['workspace_bytes']==32 and r['completed_flows']==0, 'Wrong capacity outcome')
                    counts['capacity_failures']+=1
                else:
                    need(r['status']=='PASS' and r['rc']==0 and r['transcript_matches'] is True and r['completed_flows']==1 and r['workspace_bytes']==cfg['workspace_bytes'], 'Restored capacity did not complete')
                    counts['capacity_restorations']+=1
                need(label not in recover.setdefault(key,{}), 'Duplicate recovery input')
                recover[key][label]=r
            else:
                need(r['status']=='PASS' and r['rc']==0 and r['completed_flows']==0 and r['stack_reserved_bytes']==16384, 'Invalid legal instrument control')
                need(h['peak_requested']==(96 if label=='heap-control' else 0), 'Instrument control not observed')
        need(normal_conditions=={(k,p,l,f,202610031612+i*104729+k) for k,p in PAIRS for l in (0,1) for f in (0,1) for i in range(4)},'Changed normal resource inputs')
        need(labels.get('normal')==48 and labels.get('instrument-control')==labels.get('heap-control')==1, 'Incomplete resource design')
        need(labels.get('insufficient',0)==labels.get('restored',0) and labels.get('restored',0) in (0,6), 'Incomplete recovery records')
        need(set(recover)==({(k,p,l) for k,p in PAIRS for l in (0,1)} if labels.get('restored',0) else set()), 'Incomplete recovery input coverage')
        for v in recover.values(): need(set(v)=={'insufficient','restored'} and v['insufficient']['seed']==v['restored']['seed'], 'Recovery input mismatch')
        for c in data['cells']:
            object_bytes={512:9556,768:14029,1024:18483}[c['kem']] - (({512:768,768:1088,1024:1568}[c['kem']]+64) if c['layout'] else 0)
            if d['schema'] == SCHEMA and c['layout']:
                object_bytes -= {512:800,768:1184,1024:1568}[c['kem']]
            need(c['application_state_bytes']==352 and c['serialized_owner_bytes']==object_bytes and c['pool_bytes']==((352+object_bytes+31)&~31)+cfg['workspace_bytes'],'Changed fixed-pool layout')
            group=groups[(c['kem'],c['dsa'],c['layout'])]
            need(len(group)==8 and len({(r['fresh_identity'],r['seed']) for r,h in group})==8, 'Incomplete resource repetitions')
            for r,h in group:
                for k in ('pool_bytes','application_state_bytes','serialized_owner_bytes','workspace_bytes','stack_reserved_bytes','library_globals_tls_bytes','application_globals_bytes','application_module_globals_bytes','charged_bytes'):
                    need(r[k]==c[k], 'Resource summary mismatch: '+k)
                need(h['reserved_bound']==c['heap_reserved_bytes'], 'Changed heap bound')
            need(c['maximum_stack_watermark']==max(r['stack_watermark_bytes'] for r,h in group) and
                 c['maximum_workspace_high_water']==max(r['workspace_high_water'] for r,h in group) and
                 c['maximum_observed_heap']==max(h['peak_requested'] for r,h in group) and c['flows']==32, 'Changed observed maxima')
            cells.append(dict(c,configuration=cfg['id'],binary_sha256=cfg['binary_sha256'],application_sha256=cfg['application_sha256'],
                              program_bytes=cfg['core_program_bytes']+cfg['application_program_bytes'],
                              maximum_retained_heap=max(h['retained_requested'] for r,h in group)))
    return cells,counts


def recompute(path):
    import numpy as np
    path=Path(path).resolve(); d=validate_observations(read(path)); base=path.parent
    resources,counts=_resource_replay(d,base)
    lookup={(r['configuration'],r['kem'],r['dsa'],r['layout']):r for r in resources}
    vectors={}; paired={}; frequencies=set()
    for j in d['jobs']:
        raw=raw_rows(base,j['raw']); need(len(raw)==1 and not raw_rows(base,j['stderr']), 'Invalid timing process output')
        r=raw[0]; keys(r,RESULT_FIELDS)
        for k in ('kem','dsa','layout','fresh_identity','seed'): need(type(r[k]) is int and r[k]==j[k], 'Timing input mismatch')
        for k in ('pool_bytes','workspace_bytes','batch_ticks','frequency','cpu','iterations','completed_flows','last_flow_operations'): integer(r[k])
        need(r['status']=='PASS' and type(r['rc']) is int and r['rc']==0 and r['iterations']==r['completed_flows']==j['flows'] and r['last_flow_operations']==5+j['fresh_identity'], 'Incomplete timed application')
        need(all(r[k] is True for k in ('transcript_matches','guards_ok','cleared','timed','final_close_included')) and r['heap_instrumented'] is False, 'Changed measured boundary or cleanup')
        need(r['cpu']==d['method']['cpu'] and r['batch_ticks']>0 and r['frequency']>0, 'Invalid clock/CPU')
        need(type(r['transcript']) is str and re.fullmatch('[0-9a-f]{16}',r['transcript']), 'Invalid transcript')
        c=lookup[(j['configuration'],j['kem'],j['dsa'],j['layout'])]
        need(r['pool_bytes']==c['pool_bytes'] and r['workspace_bytes']==c['workspace_bytes'], 'Timing resources do not match measured image')
        pair=tuple(j[k] for k in ('block','kem','dsa','fresh_identity','flows'))
        need(paired.setdefault(pair,r['transcript'])==r['transcript'], 'Mismatched paired transcripts')
        key=tuple(j[k] for k in ('configuration','layout','kem','dsa','fresh_identity','flows'))
        group=vectors.setdefault(key,{})
        need(j['block'] not in group, 'Duplicate timing block'); group[j['block']]=r['batch_ticks']*1e9/r['frequency']; frequencies.add(r['frequency'])
    need(len(frequencies)==1 and len(paired)==108, 'Incomplete clock/pairing')
    stats=d['method']['statistics']; draws=np.random.Generator(np.random.PCG64(stats['bootstrap_seed'])).integers(0,9,size=(stats['replicates'],9))
    cells=[]; boot={}
    for key,group in sorted(vectors.items()):
        need(sorted(group)==list(range(9)), 'Missing timing block')
        v=np.asarray([group[b] for b in range(9)]); vectors[key]=v; boot[key]=v[draws].mean(axis=1)
        ci=np.quantile(boot[key],[.025,.975]).tolist(); mean=float(v.mean())
        cells.append(dict(zip(('configuration','layout','kem','dsa','fresh_identity','flows'),key),
                          independent_batches=9,mean_batch_ns=mean,ci95_batch_ns=ci,block_batch_ns=v.tolist(),
                          complete_flows_per_second=key[-1]*1e9/mean,
                          ci95_flows_per_second=[key[-1]*1e9/ci[1],key[-1]*1e9/ci[0]]))
    comparisons=[]; arms=[(c['id'],l) for c in d['configurations'] for l in (0,1)]
    for k,p in PAIRS:
        for fresh in (0,1):
            for n in (1,200):
                for i,a in enumerate(arms):
                    for b in arms[i+1:]:
                        ak=(*a,k,p,fresh,n); bk=(*b,k,p,fresh,n)
                        comparisons.append(dict(numerator=dict(configuration=a[0],layout=a[1]),denominator=dict(configuration=b[0],layout=b[1]),kem=k,dsa=p,fresh_identity=fresh,flows=n,
                                                mean_time_ratio=float(vectors[ak].mean()/vectors[bk].mean()),ci95=np.quantile(boot[ak]/boot[bk],[.025,.975]).tolist()))
    counts.update(processes=len(d['jobs']),target_flows=sum(j['flows'] for j in d['jobs']),oracle_flows=sum(j['flows'] for j in d['jobs']),resource_cells=len(resources),timing_cells=len(cells),paired_comparisons=len(comparisons),trimmed_processes=0)
    return dict(schema=SUMMARY if d['schema'] == SCHEMA else 'lattice.application_owner_summary.v1',dataset_id=d['dataset_id'],platform=d['platform'],observations_sha256=sha(path),
                configurations=d['configurations'],method=d['method'],resources=resources,cells=cells,comparisons=comparisons,counts=counts,
                raw_files_checked=len(d['raw_files']),bootstrap_indices_sha256=hashlib.sha256(draws.astype('<i8').tobytes()).hexdigest(),
                scope='Resource watermarks summarize the executed input set. Latency observations and confidence intervals describe complete initialized and closed application batches.')


def selected(data, library=None):
    view=dict(data,kind='application_owner')
    if library is None: return view
    matches=[c['id'] for c in data['configurations'] if data['platform']==library['platform'] and c['binary_sha256']==library['binary_sha256'] and c['workspace_bytes']==library['workspace_bytes'] and c['id']==library['configuration']]
    if not matches:return None
    view['resources']=[r for r in data['resources'] if r['configuration'] in matches]
    view['cells']=[r for r in data['cells'] if r['configuration'] in matches]
    view['comparisons']=[r for r in data['comparisons'] if r['numerator']['configuration'] in matches or r['denominator']['configuration'] in matches]
    view['selected_configurations']=matches
    return view


def samples_csv(data):
    out=io.StringIO(newline='')
    fields=['record_type','configuration','binary_sha256','application_sha256','kem','dsa','layout','fresh_identity','flows','program_bytes','charged_bytes','pool_bytes','workspace_bytes','stack_reserved_bytes','mean_batch_ns','ci95_low','ci95_high','complete_flows_per_second','denominator_configuration','denominator_layout','mean_time_ratio']
    w=csv.DictWriter(out,fields,extrasaction='ignore'); w.writeheader()
    ids={c['id']:c for c in data['configurations']}
    for r in data['resources']:w.writerow(dict(r,record_type='resource'))
    for r in data['cells']:w.writerow(dict(r,record_type='timing',binary_sha256=ids[r['configuration']]['binary_sha256'],application_sha256=ids[r['configuration']]['application_sha256'],ci95_low=r['ci95_batch_ns'][0],ci95_high=r['ci95_batch_ns'][1]))
    for r in data['comparisons']:w.writerow(dict(r,record_type='paired_ratio',configuration=r['numerator']['configuration'],layout=r['numerator']['layout'],denominator_configuration=r['denominator']['configuration'],denominator_layout=r['denominator']['layout'],ci95_low=r['ci95'][0],ci95_high=r['ci95'][1]))
    return out.getvalue()


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('observations',type=Path);p.add_argument('--output',type=Path);p.add_argument('--check',type=Path);a=p.parse_args()
    result=recompute(a.observations)
    if a.check: need(read(a.check)==result,'Published application summary differs from exact recomputation')
    if a.output: save(a.output,result)
    print(f"PASS: {result['counts']['processes']} retained batches, {len(result['cells'])} latency cells, {len(result['comparisons'])} paired comparisons; complete resource replay")


if __name__=='__main__':main()
