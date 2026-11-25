"""Small synthetic observations for schema/UI controls, never actual measurements."""
from publicschemas.science import validate
def fixture(library):
    h='1'*64
    configs=[dict(id=library['configuration'],provider='lattice',import_pct='none',workspace_reserved=library['workspace_bytes'],
        library_sha256=library['binary_sha256'],supplied_lattice_library_sha256=library['binary_sha256']),
        dict(id='synthetic_reference',provider='openssl',import_pct='none',workspace_reserved=262144,
            library_sha256=h,supplied_lattice_library_sha256=library['binary_sha256'])]
    schedule=[];runs=[]
    for p in (512,768,1024,44,65,87):
        for op in range(3):
            for config in configs:
                n=len(schedule);seed=100+n
                schedule.append(dict(ordinal=n,block=0,parameter=p,operation=op,configuration=config['id'],seed=seed))
                failed=n==0
                rows=[]
                for j in range(2):
                    ticks=99999999 if failed and j==1 else 1
                    rows.append(dict(case_id=f'{seed:016x}-{p}-{op}-{j}',iteration=j-1,warmup=j==0,
                        elapsed_ticks=ticks,tick_frequency=1000000000,elapsed_ns=ticks,status=-5 if failed and j==1 else 0,
                        entropy_sha256=h,message_sha256=h,context_sha256=h))
                runs.append(dict(ordinal=n,driver_exit_code=1 if failed else 0,driver_status='FAIL' if failed else 'PASS',
                    source_csv_sha256=h,source_log_sha256=h,source_stderr_sha256=h,input_sequence_sha256=h,
                    output_sequence_sha256=h,timer='QueryPerformanceCounter',frequency=1000000000,
                    workspace_highwater=1234,entropy_mode='supplied_test_entropy',implementation_metadata={},samples=rows))
    return validate(dict(schema='lattice.block_observations.v2',dataset_id='synthetic_schema_boundary_only',
        platform=library['platform'],execution='native',target_machine='x86_64',driver_sha256=h,crypto_library_sha256=h,
        experiment=dict(blocks=1,samples_per_run=1,warmups_per_run=1,seed=100,message_bytes=1024,context_bytes=0,cpu_index=0,
            replication_unit='randomized_complete_block',timing_boundary='fresh_serialized_key_service'),
        configurations=configs,schedule=schedule,runs=runs,analysis=None,
        completeness=dict(planned_runs=36,recorded_runs=36,missing_runs=0,sample_rows=72,failed_sample_rows=1,failed_runs=1,archive_status='COMPLETE')))
