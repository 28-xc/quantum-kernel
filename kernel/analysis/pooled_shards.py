"""Closed, path-portable observation manifest with byte-exact CSV shards.

No private acquisition path is needed. One run is materialized at a time;
original warmups, failures, order, numeric text and source hashes are retained.
"""
from pathlib import Path,PurePosixPath
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
import csv, hashlib, record_io as json, math, re
import block_model as base

SCHEMA='lattice.block_observation_shards.v2'
CSV_FIELDS=['case_id','iteration','warmup','elapsed_ticks','tick_frequency','elapsed_ns','status',
            'entropy_sha256','message_sha256','context_sha256']
RUN_FIELDS={'ordinal','driver_exit_code','driver_status','source_csv_sha256','source_log_sha256',
            'source_stderr_sha256','input_sequence_sha256','output_sequence_sha256','timer','frequency',
            'workspace_highwater','entropy_mode','implementation_metadata','sample_shard'}
TOP_FIELDS={'schema','dataset_id','platform','execution','target_machine','driver_sha256',
            'crypto_library_sha256','experiment','configurations','schedule','runs','analysis','completeness','sample_format'}
PATH=re.compile(r'(?i)(?:[a-z]:[\\/]|/(?:home|root|Users)/|[\\/]\.ssh[\\/])')

def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for part in iter(lambda:f.read(1024*1024),b''):h.update(part)
    return h.hexdigest()

def validate_manifest(data):
    base.keys(data,TOP_FIELDS);base.need(data['schema']==SCHEMA,'Wrong sharded observations schema')
    base.need(data['analysis'] is None,'Statistics must use a separate schema')
    base.need(data['sample_format']==dict(type='csv',encoding='utf-8',columns=CSV_FIELDS),'Changed raw columns/encoding')
    # Reuse the closed scientific identity and complete schedule validator without
    # fabricating public observations: this transient object validates metadata.
    skeleton={k:v for k,v in data.items() if k!='sample_format'}
    skeleton.update(schema=base.SCHEMA,runs=[],completeness=dict(planned_runs=len(data['schedule']),recorded_runs=0,
        missing_runs=len(data['schedule']),sample_rows=0,failed_sample_rows=0,failed_runs=0,archive_status='INCOMPLETE'))
    base.validate(skeleton)
    base.need(type(data['runs']) is list and len(data['runs'])<=len(data['schedule']),'Unexpected recorded run count')
    rows=0;failed_runs=0;paths=set()
    for i,run in enumerate(data['runs']):
        base.keys(run,RUN_FIELDS);base.need(run['ordinal']==i,'Run order changed')
        base.integer(run['driver_exit_code'],-2147483648)
        base.need(run['driver_status'] in (None,'PASS','FAIL','ERROR','INTERRUPTED'),'Wrong driver status')
        for k in ('source_csv_sha256','source_log_sha256','source_stderr_sha256','input_sequence_sha256','output_sequence_sha256'):
            if run[k] is not None:base.digest(run[k])
        base.need(run['timer'] in (None,'QueryPerformanceCounter','QueryPerformanceCounter; verified P-core',
                    'CLOCK_MONOTONIC_RAW; explicit sched_setaffinity'),'Unexpected clock')
        for k in ('frequency','workspace_highwater'):
            if run[k] is not None:base.integer(run[k])
        base.need(run['entropy_mode'] in (None,'supplied_test_entropy'),'Unexpected entropy mode')
        meta=run['implementation_metadata'];base.need(type(meta) is dict and set(meta)<=base.IMPLEMENTATION_FIELDS,'Unknown implementation metadata')
        for k,v in meta.items():
            if k in ('openssl_version','openssl_cflags','openssl_platform','provider','property_query'):
                base.need(type(v) is str and len(v)<=4096 and '\0' not in v and PATH.search(v) is None,'Private/invalid implementation text')
            elif k in ('operation_entropy_bytes','input_transcript_preparation_entropy_bytes','message_encoding','mu','retained_key_import_ticks'):base.integer(v)
            else:base.need(type(v) is bool,'Wrong implementation flag')
        if run['driver_status']=='PASS':
            from pooled_conditions import validate_metadata
            validate_metadata(meta,data['experiment']['timing_boundary'],data['schedule'][i]['operation'])
        shard=run['sample_shard']
        if shard is None:
            base.need(run['source_csv_sha256'] is None and (run['driver_exit_code']!=0 or run['driver_status']!='PASS'),
                      'Missing successful raw artifact')
            failed_runs+=1
            continue
        base.keys(shard,['path','sha256','rows'])
        base.need(type(shard['path']) is str and re.fullmatch(r'raw/[0-9]{8}\.csv',shard['path']) is not None,'Unsafe shard path')
        base.need(shard['path'] not in paths,'Reused shard path');paths.add(shard['path'])
        base.digest(shard['sha256']);base.need(shard['sha256']==run['source_csv_sha256'],'CSV bytes differ from original source identity')
        base.integer(shard['rows']);base.need(shard['rows']<=data['experiment']['samples_per_run']+data['experiment']['warmups_per_run'],'Too many rows')
        rows+=shard['rows'];failed_runs+=run['driver_exit_code']!=0 or run['driver_status']!='PASS'
    c=data['completeness'];base.keys(c,['planned_runs','recorded_runs','missing_runs','sample_rows','failed_sample_rows','failed_runs','archive_status'])
    for k in ('planned_runs','recorded_runs','missing_runs','sample_rows','failed_sample_rows','failed_runs'):base.integer(c[k])
    base.need(c['planned_runs']==len(data['schedule']) and c['recorded_runs']==len(data['runs']) and
              c['missing_runs']==len(data['schedule'])-len(data['runs']) and c['sample_rows']==rows and c['failed_runs']==failed_runs,
              'Manifest completeness counts changed')
    complete=len(data['runs'])==len(data['schedule']) and all(r['sample_shard'] is not None and r['sample_shard']['rows']==
             data['experiment']['samples_per_run']+data['experiment']['warmups_per_run'] for r in data['runs'])
    base.need(c['archive_status']==('COMPLETE' if complete else 'INCOMPLETE'),'Completeness overstated')
    return data

def parse_rows(path,schedule,run,experiment):
    """Parse and validate one original run; do not discard nonzero statuses."""
    rows=[];warmups=experiment['warmups_per_run']
    with Path(path).open(newline='',encoding='utf-8') as f:
        reader=csv.DictReader(f)
        if reader.fieldnames is None and run['sample_shard']['rows']==0 and (run['driver_exit_code']!=0 or run['driver_status']!='PASS'):
            return rows
        base.need(reader.fieldnames==CSV_FIELDS,'Raw CSV columns changed')
        for j,raw in enumerate(reader):
            base.need(None not in raw and all(v is not None for v in raw.values()),'Malformed CSV row')
            base.need(raw['warmup'] in ('0','1'),'Wrong warmup flag')
            row={k:(bool(int(v)) if k=='warmup' else int(v) if k in ('iteration','status') else
                 None if v=='' and k in ('elapsed_ticks','tick_frequency','elapsed_ns') else
                 float(v) if k=='elapsed_ns' else int(v) if k in ('elapsed_ticks','tick_frequency') else v)
                 for k,v in raw.items()}
            base.need(row['case_id']==f"{schedule['seed']:016x}-{schedule['parameter']}-{schedule['operation']}-{j}",
                      'Case identity/order changed')
            base.need(row['iteration']==j-warmups and row['warmup']==(j<warmups),'Warmup/iteration changed')
            for k in ('entropy_sha256','message_sha256','context_sha256'):base.digest(row[k])
            absent=[row[k] is None for k in ('elapsed_ticks','tick_frequency','elapsed_ns')]
            base.need(all(absent) or not any(absent),'Partial timing value')
            if not all(absent):
                base.integer(row['elapsed_ticks']);base.integer(row['tick_frequency'],1);base.number(row['elapsed_ns'])
                base.need(abs(row['elapsed_ns']-row['elapsed_ticks']*1e9/row['tick_frequency'])<=.0011,'Changed clock conversion')
                if run['frequency'] is not None:base.need(row['tick_frequency']==run['frequency'],'Run clock changed')
            else:base.need(row['status']!=0,'Missing successful timing')
            rows.append(row)
    base.need(len(rows)==run['sample_shard']['rows'],'Missing/extra raw rows')
    return rows

def iter_runs(data,root):
    validate_manifest(data);root=Path(root).resolve();total=0;failed=0
    expected={PurePosixPath(r['sample_shard']['path']).name for r in data['runs'] if r['sample_shard'] is not None}
    raw=root/'raw';entries=list(raw.iterdir()) if raw.exists() else []
    # Compare names before resolution: an undeclared symlink to an existing
    # shard must not disappear when two resolved targets collapse into a set.
    base.need({p.name for p in entries}==expected and all(p.is_file() for p in entries),
              'Undeclared or missing public raw shard')
    for schedule,run in zip(data['schedule'],data['runs']):
        if run['sample_shard'] is None:
            yield schedule,run,[]
            continue
        path=(root/PurePosixPath(run['sample_shard']['path'])).resolve()
        base.need(path.is_relative_to(root) and path.is_file(),'Missing/escaping public shard')
        base.need(sha(path)==run['sample_shard']['sha256'],'Changed CSV shard bytes')
        rows=parse_rows(path,schedule,run,data['experiment']);total+=len(rows);failed+=sum(r['status']!=0 for r in rows)
        yield schedule,run,rows
        del rows
    base.need(total==data['completeness']['sample_rows'] and failed==data['completeness']['failed_sample_rows'],
              'Raw status/count differs from manifest')

def validate_archive(data,root):
    runs=rows=0
    for _,_,samples in iter_runs(data,root):runs+=1;rows+=len(samples)
    return dict(status='EXACT_CSV_SHARDS_VALIDATED',recorded_runs=runs,sample_rows=rows)
