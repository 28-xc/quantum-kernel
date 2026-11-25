"""Validate and recompute cgroup resource-limit measurements from public data."""
from pathlib import Path
from collections import Counter, defaultdict
import argparse
import csv
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
import re

OBSERVATIONS_SCHEMA='lattice.resource_limit_observations.v1'
SUMMARY_SCHEMA='lattice.resource_limit_statistics.v1'
PARAMETERS=(512,768,1024,44,65,87)
CSV_FIELDS=('iteration','wall_ns','cpu_ns','return_code','workspace_used')

def need(value,message):
    if not value:raise ValueError(message)

def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def read(path):return json.loads(Path(path).read_text(encoding='utf-8-sig'))

def digest(value):need(type(value) is str and re.fullmatch(r'[0-9a-f]{64}',value) is not None,'Invalid SHA256 identity')

def integer(value,minimum=0):need(type(value) is int and value>=minimum,'Invalid integer')

def keys(value,fields):need(type(value) is dict and set(value)==set(fields),'Unexpected scientific fields')

def public_path(value):
    need(type(value) is str and re.fullmatch(r'(?:raw|functional)/[0-9]{4}(?:\.memory\.xml|\.csv)',value) is not None,'Invalid raw path')

def validate_observations(data):
    keys(data,('schema','dataset_id','platform','configurations','method','environment','source_identity','jobs','raw_files','functional_checks'))
    need(data['schema']==OBSERVATIONS_SCHEMA and data['dataset_id'] in ('aarch64_resource_limits','aarch64_memory_boundary') and data['platform']=='linux_aarch64','Wrong resource-limit dataset')
    configs={c['id']:c for c in data['configurations']}
    need(len(configs)==len(data['configurations']),'Duplicate configuration')
    for c in configs.values():
        keys(c,('id','binary_sha256','workspace_bytes','compiler','code_generation'));digest(c['binary_sha256']);integer(c['workspace_bytes'],1)
    filemap={f['path']:f for f in data['raw_files']}
    need(len(filemap)==len(data['raw_files']),'Repeated raw path')
    for f in filemap.values():
        keys(f,('path','sha256','bytes','rows','kind'));public_path(f['path']);digest(f['sha256']);integer(f['rows']);integer(f['bytes'])
        need(f['kind'] in ('operation_samples','memory_series','functional_samples'),'Unknown scientific file')
    for ordinal,j in enumerate(data['jobs']):
        keys(j,('ordinal','experiment','experiment_record','configuration','binary_sha256','parameter','operation','repeat','requested_samples','workspace_bytes','seed','memory_max_bytes','cpu_max','file_cache_policy','cpu_logical','exit_code','timed_out','elapsed_wall_seconds','cgroup_before','cgroup_after','sampled_memory_peak_bytes','memory_observation_count','workload','raw','memory_series','source_record_sha256','status'))
        need(j['ordinal']==ordinal,'Missing or reordered job')
        need(j['experiment'] in ('memory_capacity','memory_latency','cpu_quota','memory_boundary'),'Unknown experimental variable')
        need(j['configuration'] in configs and j['binary_sha256']==configs[j['configuration']]['binary_sha256'],'Library identity mismatch')
        need(j['parameter'] in PARAMETERS and j['operation'] in range(3),'Wrong parameter or operation')
        for key in ('requested_samples','workspace_bytes','memory_max_bytes','cpu_logical','seed','repeat','memory_observation_count','sampled_memory_peak_bytes'):integer(j[key])
        integer(j['exit_code'],-255);digest(j['source_record_sha256'])
        need(type(j['timed_out']) is bool and isinstance(j['elapsed_wall_seconds'],(int,float)) and math.isfinite(j['elapsed_wall_seconds']),'Invalid execution result')
        need(j['cpu_max'] in ('max 10000','10000 10000','5000 10000','2500 10000'),'Unknown CPU quota')
        need(j['file_cache_policy'] in ('warm_shared_files','discard_project_file_cache_before_launch'),'Unknown cache condition')
        need(j['status'] in ('PASS','CGROUP_OOM','CONTROLLER_TIMEOUT','WORKSPACE_RETURN','PROCESS_FAILURE'),'Unknown process result')
        for key in ('raw','memory_series'):
            r=j[key]
            if r is None:need(key=='raw' and j['exit_code']!=0,'Missing successful measurement');continue
            public_path(r['path']);need(filemap[r['path']]==r,'Raw descriptor mismatch')
        need(j['memory_series']['rows']==j['memory_observation_count'],'Missing memory observations')
        if j['exit_code']==0:
            need(j['status']=='PASS' and j['raw']['rows']==j['requested_samples'],'Incomplete successful operation')
            w=j['workload'];need(w is not None and w['samples']==j['requested_samples'] and w['warmup']==32,'Changed workload contract')
            need(w['cpu_logical']==j['cpu_logical'] and w['parameter']==j['parameter'] and w['operation']==j['operation'],'Workload differs from condition')
        if j['status']=='CGROUP_OOM':need(j['cgroup_after']['memory_events']['oom_kill']>0,'OOM classification lacks kernel event')
        if j['status']=='CONTROLLER_TIMEOUT':need(j['timed_out'],'Timeout classification lacks controller event')
    for i,f in enumerate(data['functional_checks']):
        keys(f,('ordinal','configuration','binary_sha256','parameter','operation','workload','raw'))
        need(f['ordinal']==i and f['configuration'] in configs,'Functional check identity differs')
        need(f['binary_sha256']==configs[f['configuration']]['binary_sha256'],'Functional library identity differs')
        need(filemap[f['raw']['path']]==f['raw'] and f['raw']['rows']==f['workload']['samples'],'Functional sample identity differs')
    return True

def validate_summary(summary,observations):
    validate_observations(observations)
    keys(summary,('schema','dataset_id','platform','observations_sha256','counts','method','cpu_quota_effects','operation_conditions','failed_jobs'))
    need(summary['schema']==SUMMARY_SCHEMA and summary['dataset_id']==observations['dataset_id'] and summary['platform']==observations['platform'],'Wrong summary identity')
    digest(summary['observations_sha256'])
    jobs=observations['jobs'];counts=summary['counts']
    need(counts['jobs']==len(jobs),'Job count differs')
    need(counts['retained_samples']==sum(j['raw']['rows'] for j in jobs if j['status']=='PASS'),'Sample count differs')
    need(counts['partial_process_samples']==sum(j['raw']['rows'] for j in jobs if j['status']!='PASS' and j['raw'] is not None),'Partial process samples omitted')
    need(counts['all_recorded_operation_samples']==counts['retained_samples']+counts['partial_process_samples'],'Recorded operation sample count differs')
    need(counts['functional_samples']==sum(f['raw']['rows'] for f in observations['functional_checks']),'Functional sample count differs')
    need(counts['functional_checks']==len(observations['functional_checks']),'Functional check count differs')
    need(counts['status_counts']==dict(Counter(j['status'] for j in jobs)),'Process outcomes differ')
    failed=[j['ordinal'] for j in jobs if j['status']!='PASS']
    need([j['ordinal'] for j in summary['failed_jobs']]==failed,'Failure omitted')
    need(counts['operation_conditions']==len(summary['operation_conditions']),'Condition count differs')
    need(counts['cpu_quota_comparisons']==len(summary['cpu_quota_effects']),'Quota comparison count differs')
    for row in summary['cpu_quota_effects']:
        need(row['complete_operations']==18 and row['process_repetitions']==4,'Changed quota pairing')
        need(row['cpu_fraction'] in (.25,.5),'Wrong compared quota')
        for key in ('gm_mean_wall_ratio','gm_mean_process_cpu_ratio','gm_p95_wall_ratio','gm_batch_wall_ratio','gm_batch_process_cpu_ratio','ci95_low','ci95_high','batch_ci95_low','batch_ci95_high'):
            need(isinstance(row[key],(int,float)) and math.isfinite(row[key]) and row[key]>0,'Invalid quota statistic')
    return True

def recompute(observations_path):
    import numpy as np
    path=Path(observations_path).resolve();root=path.parent;data=read(path)
    validate_observations(data)
    memory_sequences={}
    for descriptor in data['raw_files']:
        p=root/descriptor['path'];need(p.is_file() and p.stat().st_size==descriptor['bytes'] and sha(p)==descriptor['sha256'],'Raw data changed')
        if descriptor['kind']=='memory_series':
            sequence=read(p);need(len(sequence)==descriptor['rows'],'Memory series length differs')
            need(all(type(a) in (float,int) and math.isfinite(a) and a>=0 and type(b) is int and b>=0 for a,b in sequence),'Invalid memory observation')
            memory_sequences[descriptor['path']]=sequence
    def samples(descriptor):
        raw=root/descriptor['path']
        with raw.open(encoding='utf-8-sig',newline='') as f:
            rows=list(csv.reader(f))
        if not rows:
            need(descriptor['rows']==0 and descriptor['bytes']==0,'Changed empty interrupted file')
            return np.empty((0,5),dtype=np.int64)
        need(rows and tuple(rows[0])==CSV_FIELDS,'Changed sample columns')
        x=np.asarray([[int(v) for v in row] for row in rows[1:]],dtype=np.int64).reshape((-1,5))
        need(len(x)==descriptor['rows'] and np.array_equal(x[:,0],np.arange(len(x))),'Incomplete or reordered samples')
        need(bool((x[:,1:3]>0).all() and (x[:,3]==0).all()),'Failed or invalid timed call')
        return x
    for check in data['functional_checks']:
        x=samples(check['raw'])
        need(bool((x[:,4]==check['workload']['workspace_peak']).all()),'Changed functional workspace peak')
    jobs=[];groups=defaultdict(list)
    for j in data['jobs']:
        sequence=memory_sequences[j['memory_series']['path']]
        need(max((x[1] for x in sequence),default=0)==j['sampled_memory_peak_bytes'],'Memory peak differs from series')
        cpu=j['cgroup_after']['cpu_stat'];mem=j['cgroup_after']['memory_events']
        row={k:j[k] for k in ('experiment','ordinal','configuration','binary_sha256','parameter','operation','repeat','memory_max_bytes','cpu_max','file_cache_policy','status','exit_code')}
        row.update(samples=0,median_wall_ns=None,mean_wall_ns=None,p95_wall_ns=None,maximum_wall_ns=None,median_cpu_ns=None,mean_cpu_ns=None,p95_cpu_ns=None,workspace_peak_run=None,sampled_cgroup_peak_bytes=j['sampled_memory_peak_bytes'],memory_max_events=mem['max'],oom_kill=mem['oom_kill'],cpu_nr_periods=cpu['nr_periods'],cpu_nr_throttled=cpu['nr_throttled'],cpu_throttled_usec=cpu['throttled_usec'],batch_wall_ns=None,batch_cpu_ns=None,raw_sha256=None if j['raw'] is None else j['raw']['sha256'])
        x=None if j['raw'] is None else samples(j['raw'])
        if j['exit_code']==0:
            need(x.shape==(j['requested_samples'],5) and np.array_equal(x[:,0],np.arange(j['requested_samples'])),'Incomplete or reordered samples')
            need(bool((x[:,1:3]>0).all() and (x[:,3]==0).all()),'Failed or invalid timed call')
            need(bool((x[:,4]==j['workload']['workspace_peak']).all()),'Changed repeated workspace peak')
            row.update(samples=len(x),median_wall_ns=float(np.median(x[:,1])),mean_wall_ns=float(x[:,1].mean()),p95_wall_ns=float(np.quantile(x[:,1],.95)),maximum_wall_ns=int(x[:,1].max()),median_cpu_ns=float(np.median(x[:,2])),mean_cpu_ns=float(x[:,2].mean()),p95_cpu_ns=float(np.quantile(x[:,2],.95)),workspace_peak_run=j['workload']['workspace_peak'],batch_wall_ns=j['workload']['session_wall_ns'],batch_cpu_ns=j['workload']['session_cpu_ns'])
            key=tuple(j[k] for k in ('experiment','configuration','parameter','operation','memory_max_bytes','cpu_max'))
            groups[key].append((row,x[:,1:3]))
        jobs.append(row)
    conditions=[]
    for key,group in sorted(groups.items()):
        x=np.concatenate([x for _,x in group])
        row=dict(zip(('experiment','configuration','parameter','operation','memory_max_bytes','cpu_max'),key))
        row.update(repetitions=len(group),samples=len(x),median_wall_ns=float(np.median(x[:,0])),mean_wall_ns=float(x[:,0].mean()),p95_wall_ns=float(np.quantile(x[:,0],.95)),maximum_wall_ns=int(x[:,0].max()),median_cpu_ns=float(np.median(x[:,1])),mean_cpu_ns=float(x[:,1].mean()),p95_cpu_ns=float(np.quantile(x[:,1],.95)),cpu_nr_throttled=sum(y['cpu_nr_throttled'] for y,_ in group),memory_max_events=sum(y['memory_max_events'] for y,_ in group),sampled_cgroup_peak_bytes=max(y['sampled_cgroup_peak_bytes'] for y,_ in group))
        conditions.append(row)
    index={(r['configuration'],r['parameter'],r['operation'],r['repeat'],r['cpu_max']):r for r in jobs if r['experiment']=='cpu_quota' and r['status']=='PASS'}
    rng=np.random.Generator(np.random.PCG64(2026092707));draws=rng.integers(0,4,size=(10000,4));quota=[]
    for config in sorted({k[0] for k in index}):
        for cap in ('5000 10000','2500 10000'):
            wall=[];process=[];p95=[];batchwall=[];batchcpu=[];throttle=0
            for rep in range(4):
                wr=[];pr=[];qr=[];bw=[];bc=[]
                for parameter in PARAMETERS:
                    for op in range(3):
                        base=index[config,parameter,op,rep,'10000 10000'];target=index[config,parameter,op,rep,cap]
                        wr.append(target['mean_wall_ns']/base['mean_wall_ns']);pr.append(target['mean_cpu_ns']/base['mean_cpu_ns']);qr.append(target['p95_wall_ns']/base['p95_wall_ns']);throttle+=target['cpu_nr_throttled']
                        bw.append(target['batch_wall_ns']/base['batch_wall_ns']);bc.append(target['batch_cpu_ns']/base['batch_cpu_ns'])
                wall.append(float(np.log(wr).mean()));process.append(float(np.log(pr).mean()));p95.append(float(np.log(qr).mean()));batchwall.append(float(np.log(bw).mean()));batchcpu.append(float(np.log(bc).mean()))
            logs=np.array(wall);boot=np.exp(logs[draws].mean(axis=1));b=np.array(batchwall);batch_boot=np.exp(b[draws].mean(axis=1))
            quota.append(dict(configuration=config,cpu_fraction=int(cap.split()[0])/10000,complete_operations=18,process_repetitions=4,gm_mean_wall_ratio=float(np.exp(logs.mean())),ci95_low=float(np.quantile(boot,.025)),ci95_high=float(np.quantile(boot,.975)),gm_mean_process_cpu_ratio=float(np.exp(np.mean(process))),gm_p95_wall_ratio=float(np.exp(np.mean(p95))),cpu_nr_throttled=throttle,repetition_gm_mean_wall_ratios=[float(np.exp(y)) for y in wall],gm_batch_wall_ratio=float(np.exp(b.mean())),batch_ci95_low=float(np.quantile(batch_boot,.025)),batch_ci95_high=float(np.quantile(batch_boot,.975)),gm_batch_process_cpu_ratio=float(np.exp(np.mean(batchcpu)))))
    complete_samples=sum(r['samples'] for r in jobs)
    partial_samples=sum(j['raw']['rows'] for j in data['jobs'] if j['status']!='PASS' and j['raw'] is not None)
    summary=dict(schema=SUMMARY_SCHEMA,dataset_id=data['dataset_id'],platform=data['platform'],observations_sha256=sha(path),counts=dict(jobs=len(jobs),retained_samples=complete_samples,partial_process_samples=partial_samples,all_recorded_operation_samples=complete_samples+partial_samples,status_counts=dict(Counter(j['status'] for j in data['jobs'])),operation_conditions=len(conditions),cpu_quota_comparisons=len(quota),functional_checks=len(data['functional_checks']),functional_samples=sum(f['raw']['rows'] for f in data['functional_checks'])),method=data['method'],cpu_quota_effects=quota,operation_conditions=conditions,failed_jobs=[j for j in data['jobs'] if j['status']!='PASS'])
    validate_summary(summary,data)
    return summary,jobs

def write_outputs(summary,jobs,out):
    out=Path(out);out.mkdir(parents=True,exist_ok=False)
    (out/'summary.xml').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    for name,rows in [('all_jobs.csv',jobs),('operation_conditions.csv',summary['operation_conditions']),('cpu_quota_effects.csv',summary['cpu_quota_effects'])]:
        if not rows:continue
        with (out/name).open('w',encoding='utf-8-sig',newline='') as f:
            writer=csv.DictWriter(f,fieldnames=list(rows[0]));writer.writeheader()
            for row in rows:writer.writerow({k:';'.join(str(x) for x in v) if isinstance(v,list) else v for k,v in row.items()})

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('observations',type=Path);parser.add_argument('output',type=Path);args=parser.parse_args()
    summary,jobs=recompute(args.observations);write_outputs(summary,jobs,args.output)
    print(json.dumps(summary['counts']))
