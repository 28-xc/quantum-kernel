"""Independent complete-application latency and paired-block statistics."""
from pathlib import Path
from itertools import combinations
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
import random
from publicschemas.application_v1 import need, keys, digest, integer, read, sha, LIBRARIES, PAIRS, serialized_bytes

SCHEMA='lattice.application_latency_observations.v1'
SUMMARY='lattice.application_latency_statistics.v1'
BOOTSTRAP_SEED=20260927940
LATENCY_SCOPE='Context initialization, device KEM key generation, certificate signing and verification, encapsulation, decapsulation, secret comparison and secret cleanup; fresh mode also generates the authority identity per call'
BATCH_SCOPE='Measured application calls plus in-memory sample recording, transcript checksums and loop/timer overhead; CSV emission follows the batch timer'
RESULT_FIELDS=('status','workload','kem','dsa','samples','warmup','fresh_authority_identity',
 'workspace_bytes','serialized_object_bytes','context_bytes','test_entropy','entropy_requests',
 'entropy_bytes','batch_wall_ns','transcript_fnv64','certificate_message_bytes','domain_bytes')


def validate_observations(data):
    keys(data,('schema','dataset_id','platform','method','configurations','collector','provenance','jobs'))
    need(data['schema']==SCHEMA and data['platform'] in ('windows_x86_64','linux_aarch64'),'Unknown latency dataset')
    need(data['dataset_id']==data['platform']+'_complete_application_latency','Wrong dataset identity')
    method=data['method'];keys(method,('blocks','samples','warmups','cpu','seed','parameter_pairs','fresh_identity_modes','latency_scope','batch_scope','timing_unit','replication_unit','bootstrap'))
    need((method['blocks'],method['samples'],method['warmups'],method['seed'])==(10,200,16,20260927072),'Changed application design')
    integer(method['cpu']);need(method['parameter_pairs']==[list(p) for p in PAIRS] and method['fresh_identity_modes']==[False,True],'Changed application cells')
    need(method['timing_unit']=='complete application call' and method['replication_unit']=='complete randomized block','Changed statistical unit')
    need(method['latency_scope']==LATENCY_SCOPE and method['batch_scope']==BATCH_SCOPE,'Changed measured application boundary')
    need(method['bootstrap']==dict(seed=BOOTSTRAP_SEED,replicates=10000,generator='PCG64',resampled_unit='whole paired block',interval='percentile 95%',quantile_method='linear'),'Changed interval definition')
    need([x['id'] for x in data['configurations']]==list(LIBRARIES),'Changed configuration set')
    for c in data['configurations']:
        keys(c,('id','binary_sha256','workspace_bytes'));digest(c['binary_sha256']);integer(c['workspace_bytes'],32)
    keys(data['collector'],('binary_sha256','compiler','source_sha256'))
    digest(data['collector']['binary_sha256'])
    need(set(data['collector']['source_sha256'])=={'enrollment.c','latticecore.h','run.py'},'Unexpected collector sources')
    for d in data['collector']['source_sha256'].values():digest(d)
    keys(data['provenance'],('protocol_sha256','observations_sha256','tasks_sha256','all_original_records_retained'))
    for k in ('protocol_sha256','observations_sha256','tasks_sha256'):digest(data['provenance'][k])
    need(data['provenance']['all_original_records_retained'] is True and len(data['jobs'])==480,'Incomplete application collection')
    randomizer=random.Random(method['seed']);expected=[]
    for block in range(10):
        cells=[(k,d,f) for k,d in PAIRS for f in (0,1)];randomizer.shuffle(cells)
        for kem,dsa,fresh in cells:
            variants=list(data['configurations']);randomizer.shuffle(variants)
            seed=method['seed']+block*1000003+kem*17+fresh
            for config in variants:expected.append((block,kem,dsa,bool(fresh),seed,config))
    paired={}
    for ordinal,(job,condition) in enumerate(zip(data['jobs'],expected,strict=True)):
        keys(job,('ordinal','block','configuration','binary_sha256','kem','dsa','fresh_identity','seed','exit_code','result','raw','source_record_sha256'))
        for field in ('ordinal','block','kem','dsa','seed','exit_code'):integer(job[field])
        need(type(job['fresh_identity']) is bool,'Invalid identity lifecycle flag')
        block,kem,dsa,fresh,seed,c=condition
        need((job['ordinal'],job['block'],job['configuration'],job['binary_sha256'],job['kem'],job['dsa'],job['fresh_identity'],job['seed'],job['exit_code'])==
             (ordinal,block,c['id'],c['binary_sha256'],kem,dsa,fresh,seed,0),'Changed randomized application schedule')
        digest(job['source_record_sha256']);keys(job['raw'],('path','sha256','bytes','rows'))
        need(job['raw']['path']==f'raw/{ordinal:05d}.csv' and job['raw']['rows']==216,'Changed sample indexing')
        digest(job['raw']['sha256']);integer(job['raw']['bytes'],1)
        r=job['result'];keys(r,RESULT_FIELDS)
        need(type(r['fresh_authority_identity']) is bool and type(r['test_entropy']) is bool,'Invalid workload flags')
        expected_result=dict(status='PASS',workload='certificate_then_kem_exchange',kem=kem,dsa=dsa,samples=200,warmup=16,
            fresh_authority_identity=fresh,workspace_bytes=c['workspace_bytes'],serialized_object_bytes=serialized_bytes(kem,dsa),
            context_bytes=64,test_entropy=True,entropy_requests=864 if fresh else 649,
            entropy_bytes=34560 if fresh else 27680,certificate_message_bytes={512:800,768:1184,1024:1568}[kem],domain_bytes=26)
        need(all(r[k]==v for k,v in expected_result.items()),'Changed complete workload or entropy consumption')
        integer(r['batch_wall_ns'],1)
        need(type(r['transcript_fnv64']) is str and len(r['transcript_fnv64'])==16 and all(c in '0123456789abcdef' for c in r['transcript_fnv64']),'Invalid transcript identity')
        key=(block,kem,dsa,fresh);identity=(r['transcript_fnv64'],r['entropy_requests'],r['entropy_bytes'])
        if key in paired:need(paired[key]==identity,'Different input/output transcript across paired libraries')
        paired[key]=identity
    return True


def recompute(path):
    import numpy as np
    path=Path(path).resolve();root=path.parent;data=read(path);validate_observations(data)
    groups={};block_means={};all_rows=0
    for job in data['jobs']:
        descriptor=job['raw'];file=root/descriptor['path']
        need(file.is_file() and file.stat().st_size==descriptor['bytes'] and sha(file)==descriptor['sha256'],'Application samples changed')
        with file.open(encoding='utf-8',newline='') as stream:
            reader=csv.DictReader(stream);need(reader.fieldnames==['iteration','phase','elapsed_ns','workspace_used_bytes'],'Changed sample columns');rows=list(reader)
        need(len(rows)==216,'Incomplete application process')
        values=[]
        for i,row in enumerate(rows):
            need(set(row)==set(reader.fieldnames) and all(type(x) is str for x in row.values()),'Malformed application CSV record')
            iteration=int(row['iteration']);value=int(row['elapsed_ns']);workspace=int(row['workspace_used_bytes'])
            need(iteration==i-16 and row['phase']==('warmup' if i<16 else 'measurement') and value>0 and
                 0<=workspace<=job['result']['workspace_bytes'],'Missing, changed or invalid application sample')
            if i>=16:values.append(value)
        key=(job['configuration'],job['kem'],job['dsa'],job['fresh_identity'])
        vector=np.asarray(values,dtype=np.float64)
        groups.setdefault(key,[]).append((job['block'],vector,job['result']['batch_wall_ns']))
        block_means[(key,job['block'])]=float(vector.mean());all_rows+=len(rows)
    cells=[]
    for key,group in sorted(groups.items()):
        need(sorted(b for b,_,_ in group)==list(range(10)),'Incomplete paired blocks')
        values=np.concatenate([v for _,v,_ in group]);wall=sum(t for _,_,t in group)
        cells.append(dict(configuration=key[0],kem=key[1],dsa=key[2],fresh_identity=key[3],blocks=10,samples=2000,
            mean_ns=float(values.mean()),median_ns=float(np.median(values)),p95_ns=float(np.quantile(values,.95,method='linear')),
            p99_ns=float(np.quantile(values,.99,method='linear')),minimum_ns=float(values.min()),maximum_ns=float(values.max()),
            aggregate_applications_per_second=2000/(wall*1e-9),batch_wall_ns=wall,
            block_mean_ns=[block_means[(key,b)] for b in range(10)]))
    draws=np.random.Generator(np.random.PCG64(BOOTSTRAP_SEED)).integers(0,10,size=(10000,10))
    def estimate(logs):
        logs=np.asarray(logs);bootstrap=np.exp(logs[draws].mean(axis=1))
        return dict(geometric_mean_speedup=float(np.exp(logs.mean())),
            ci95_low=float(np.quantile(bootstrap,.025,method='linear')),ci95_high=float(np.quantile(bootstrap,.975,method='linear')),
            paired_block_speedups=[float(x) for x in np.exp(logs)])
    comparisons=[];aggregates=[]
    for baseline,candidate in combinations(LIBRARIES,2):
        for fresh in (False,True):
            total=[]
            for kem,dsa in PAIRS:
                logs=[math.log(block_means[((baseline,kem,dsa,fresh),b)]/block_means[((candidate,kem,dsa,fresh),b)]) for b in range(10)]
                total.append(logs)
                comparisons.append(dict(baseline=baseline,candidate=candidate,kem=kem,dsa=dsa,fresh_identity=fresh,**estimate(logs)))
            aggregates.append(dict(baseline=baseline,candidate=candidate,fresh_identity=fresh,parameter_pairs=3,
                **estimate(np.asarray(total).mean(axis=0))))
    return dict(schema=SUMMARY,dataset_id=data['dataset_id'],platform=data['platform'],observations_sha256=sha(path),
        counts=dict(processes=480,blocks=10,conditions=48,measured_calls=96000,warmup_calls=7680,retained_rows=all_rows),
        statistical_definition='Distribution summaries pool 2000 individual complete-application latencies per cell; ratios use paired block means; three-pair aggregates average log ratios within each block',
        bootstrap=data['method']['bootstrap'],bootstrap_indices_sha256=hashlib.sha256(draws.astype('<i8').tobytes()).hexdigest(),
        cells=cells,paired_cell_comparisons=comparisons,paired_three_parameter_comparisons=aggregates)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('observations',type=Path);parser.add_argument('output',type=Path)
    args=parser.parse_args();need(not args.output.exists(),'Fresh statistics output required')
    result=recompute(args.observations);args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result['counts']))
