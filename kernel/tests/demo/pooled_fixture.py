"""Synthetic UI/schema fixture; never an experimental observation or estimate."""
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
import csv, hashlib, io, record_io as json
from publicschemas.pooled_model import CELLS,BOOTSTRAP_UNIT
from publicschemas.pooled_conditions import SEMANTICS
from publicschemas.pooled_shards import CSV_FIELDS

def write(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    return {'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}

def fixture(library,base):
    h='1'*64;labels=['synthetic_subject','synthetic_reference']
    configs=[dict(id=name,provider='lattice',import_pct='none',workspace_reserved=library['workspace_bytes'],
        library_sha256=library['artifact']['sha256'] if i==0 else '2'*64,
        supplied_lattice_library_sha256=library['artifact']['sha256'] if i==0 else '2'*64) for i,name in enumerate(labels)]
    data=dict(schema='lattice.block_observation_shards.v2',dataset_id='synthetic_schema4_only',
        platform=library['platform'],execution='native',target_machine='x86_64',driver_sha256=h,crypto_library_sha256=h,
        experiment=dict(blocks=2,samples_per_run=1,warmups_per_run=0,seed=100,message_bytes=1024,context_bytes=0,cpu_index=0,
            replication_unit='randomized_complete_block',timing_boundary='fresh_serialized_key_service'),
        configurations=configs,schedule=[],runs=[],analysis=None,sample_format=dict(type='csv',encoding='utf-8',columns=CSV_FIELDS))
    for block in range(2):
        for p,o in CELLS:
            for name in labels:
                i=len(data['runs']);seed=100+block*10000+p*3+o
                data['schedule'].append(dict(ordinal=i,block=block,parameter=p,operation=o,configuration=name,seed=seed))
                row=dict(case_id=f'{seed:016x}-{p}-{o}-0',iteration=0,warmup=0,elapsed_ticks=100,
                    tick_frequency=1000000000,elapsed_ns=100,status=0,entropy_sha256=h,message_sha256=h,context_sha256=h)
                text=io.StringIO(newline='');w=csv.DictWriter(text,fieldnames=CSV_FIELDS);w.writeheader();w.writerow(row)
                blob=text.getvalue().encode();relative=f'raw/{i:08d}.csv';path=base/relative;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(blob)
                digest=hashlib.sha256(blob).hexdigest()
                data['runs'].append(dict(ordinal=i,driver_exit_code=0,driver_status='PASS',source_csv_sha256=digest,
                    source_log_sha256=h,source_stderr_sha256=h,input_sequence_sha256=h,output_sequence_sha256=h,
                    timer='QueryPerformanceCounter',frequency=1000000000,workspace_highwater=0,
                    entropy_mode='supplied_test_entropy',implementation_metadata=dict(SEMANTICS),
                    sample_shard=dict(path=relative,sha256=digest,rows=1)))
    data['completeness']=dict(planned_runs=72,recorded_runs=72,missing_runs=0,sample_rows=72,
        failed_sample_rows=0,failed_runs=0,archive_status='COMPLETE')
    descriptor=write(base/'observations.xml',data)
    method=dict(estimator='ratio_of_pooled_individual_medians',ratio_direction='reference_over_candidate',quantile='linear_type7',
        bootstrap_unit=BOOTSTRAP_UNIT,bootstrap_rng='PCG64',bootstrap_seed=1,resamples=2,
        interval='percentile_0.025_0.975',block_draws_sha256=h,replicate_values_sha256=h,
        weighting='equal_18_operation_cells',slow_observation_policy='retain_all',
        warmup_policy='retain_in_observations_exclude_only_from_statistics',mixture_estimator='arithmetic_mean_of_component_pooled_means',
        interval_scope='pointwise_no_simultaneous_coverage_claim')
    summary=dict(schema='lattice.pooled_median_statistics.v2',**{k:data[k] for k in ('dataset_id','platform','execution','target_machine','configurations')},
        observations_sha256=descriptor['sha256'],ordered_observations_digest=h,source_code_sha256=h,
        configuration_order=labels,cell_order=[list(c) for c in CELLS],method=method,
        counts=dict(blocks=2,samples_per_run=1,raw_rows=72,measured_rows=72,warmup_rows=0,deleted_rows=0),
        cells=[dict(configuration=l,parameter=p,operation=o,pooled_samples=2,pooled_mean_ns=100.,pooled_median_ns=100.,
            pooled_p95_ns=100.,pooled_p99_ns=100.,minimum_ns=100.,maximum_ns=100.) for l in labels for p,o in CELLS],
        comparisons=[dict(id='synthetic_pair',reference=labels[1],candidate=labels[0],
            cells=[dict(parameter=p,operation=o,pooled_median_ratio=1.,paired_complete_block_ci95=[1.,1.]) for p,o in CELLS],
            equal_weight_18_cell_median_ratio_geomean=1.,paired_complete_block_ci95=[1.,1.],
            families={f:dict(median_ratio_geomean=1.,paired_complete_block_ci95=[1.,1.]) for f in ('ML-KEM','ML-DSA')},
            reference_equal_weight_mean_ns=100.,candidate_equal_weight_mean_ns=100.)],runtime=dict(python='test',numpy='test'))
    return {'summary':write(base/'summary.xml',summary),'observations':descriptor},data,summary
