"""Validate and recompute executable address-space footprint measurements."""
from pathlib import Path
from collections import Counter
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
import re
import statistics

def need(value,message):
    if not value:raise ValueError(message)
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def read(path):return json.loads(Path(path).read_text(encoding='utf-8-sig'))
def keys(value,expected):need(type(value) is dict and set(value)==set(expected),'Unexpected scientific fields')
def digest(value):need(type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None,'Invalid source digest')

def validate_observations(data):
    keys(data,('schema','dataset_id','platform','configurations','method','source_identity','driver','jobs','raw_files'))
    need(data['schema']=='lattice.process_footprint_observations.v1' and data['dataset_id']=='aarch64_process_footprint' and data['platform']=='linux_aarch64','Wrong footprint dataset')
    configs={c['id']:c for c in data['configurations']}
    need(len(configs)==len(data['configurations']),'Duplicate configuration')
    files={f['path']:f for f in data['raw_files']}
    need(len(files)==len(data['raw_files']),'Duplicate sample file')
    digest(data['driver']['binary_sha256'])
    for source in data['driver']['source_files']:
        keys(source,('path','sha256'));digest(source['sha256'])
        need(re.fullmatch(r'methods/sampler/(?:footprint\.c|workload\.c|latticecore\.h)',source['path']) is not None,'Invalid sampler source path')
    for f in files.values():
        keys(f,('path','sha256','bytes','rows','kind'))
        need(re.fullmatch(r'raw/[0-9]{4}\.csv',f['path']) is not None and f['kind']=='operation_samples','Invalid sample path')
        digest(f['sha256'])
    for i,j in enumerate(data['jobs']):
        keys(j,('ordinal','configuration','binary_sha256','driver_sha256','parameter','operation','workspace_bytes','seed','exit_code','status','workload','mm','raw','source_record_sha256'))
        need(j['ordinal']==i and j['configuration'] in configs,'Missing process identity')
        need(j['binary_sha256']==configs[j['configuration']]['binary_sha256'] and j['driver_sha256']==data['driver']['binary_sha256'],'Changed executable identity')
        need(j['parameter'] in (512,768,1024,44,65,87) and j['operation'] in (0,1,2),'Unknown operation')
        need(j['exit_code']==0 and j['status']=='PASS','Failed footprint operation')
        need(j['raw']==files[j['raw']['path']] and j['raw']['rows']==64,'Changed sample descriptor')
        w=j['workload'];need(w['samples']==64 and w['warmup']==32 and w['parameter']==j['parameter'] and w['operation']==j['operation'],'Changed workload')
        keys(j['mm'],('status','vmhwm_kib','vmrss_after_cleanup_kib','vmpeak_kib'))
        need(j['mm']['status']=='MM_FOOTPRINT','Invalid memory observation')
        for k in ('vmhwm_kib','vmrss_after_cleanup_kib','vmpeak_kib'):
            need(type(j['mm'][k]) is int and j['mm'][k]>0,'Invalid footprint counter')
        digest(j['source_record_sha256'])
    return True

def validate_summary(summary,observations):
    validate_observations(observations)
    keys(summary,('schema','dataset_id','platform','observations_sha256','counts','method','operations','configuration_ranges'))
    need(summary['schema']=='lattice.process_footprint_statistics.v1' and summary['dataset_id']==observations['dataset_id'] and summary['platform']==observations['platform'],'Wrong footprint summary')
    digest(summary['observations_sha256'])
    need(summary['counts']=={'jobs':len(observations['jobs']),'recorded_samples':sum(j['raw']['rows'] for j in observations['jobs']),'status_counts':dict(Counter(j['status'] for j in observations['jobs']))},'Footprint counts differ')
    need(len(summary['operations'])==len(observations['jobs']),'Footprint observation omitted')
    for row,j in zip(summary['operations'],observations['jobs']):
        for k in ('ordinal','configuration','binary_sha256','parameter','operation','workspace_bytes'):
            need(row[k]==j[k],'Footprint operation identity differs')
        for k in ('vmhwm_kib','vmrss_after_cleanup_kib','vmpeak_kib'):
            need(row[k]==j['mm'][k],'Footprint result differs')
    need(len(summary['configuration_ranges'])==len({j['configuration'] for j in observations['jobs']}),'Configuration range omitted')
    return True

def recompute(path):
    path=Path(path).resolve();root=path.parent;data=read(path);validate_observations(data)
    for source in data['driver']['source_files']:
        need(sha(root/source['path'])==source['sha256'],'Sampler source changed')
    rows=[]
    for j in data['jobs']:
        f=j['raw'];p=root/f['path'];need(p.stat().st_size==f['bytes'] and sha(p)==f['sha256'],'Raw file changed')
        with p.open(encoding='utf-8-sig',newline='') as stream:
            reader=csv.DictReader(stream)
            need(reader.fieldnames==['iteration','wall_ns','cpu_ns','return_code','workspace_used'],'Changed CSV columns')
            sample=[{k:int(v) for k,v in row.items()} for row in reader]
        need(len(sample)==64 and [r['iteration'] for r in sample]==list(range(64)),'Sample rows omitted')
        need(all(r['wall_ns']>0 and r['cpu_ns']>0 and r['return_code']==0 and r['workspace_used']==j['workload']['workspace_peak'] for r in sample),'Invalid functional sample')
        row={k:j[k] for k in ('ordinal','configuration','binary_sha256','parameter','operation','workspace_bytes')}
        row.update({k:j['mm'][k] for k in ('vmhwm_kib','vmrss_after_cleanup_kib','vmpeak_kib')})
        row.update(workspace_peak_run=j['workload']['workspace_peak'],inherited_ru_maxrss_kib=j['workload']['ru_maxrss_kib'],samples=len(sample),raw_sha256=f['sha256'])
        rows.append(row)
    ranges=[]
    for config in sorted({r['configuration'] for r in rows}):
        group=[r for r in rows if r['configuration']==config]
        need({(r['parameter'],r['operation']) for r in group}=={(p,o) for p in (512,768,1024,44,65,87) for o in range(3)} and len(group)==18,'Incomplete configuration matrix')
        out={'configuration':config,'complete_operations':18,'process_repetitions_per_operation':1}
        for metric in ('vmhwm_kib','vmrss_after_cleanup_kib','vmpeak_kib','workspace_peak_run','inherited_ru_maxrss_kib'):
            values=[r[metric] for r in group]
            out.update({metric+'_minimum':min(values),metric+'_median':statistics.median(values),metric+'_maximum':max(values)})
        ranges.append(out)
    summary={'schema':'lattice.process_footprint_statistics.v1','dataset_id':data['dataset_id'],'platform':data['platform'],'observations_sha256':sha(path),'counts':{'jobs':len(rows),'recorded_samples':sum(r['samples'] for r in rows),'status_counts':dict(Counter(j['status'] for j in data['jobs']))},'method':data['method'],'operations':rows,'configuration_ranges':ranges}
    validate_summary(summary,data)
    return summary

def write_outputs(summary,out):
    out=Path(out);out.mkdir(parents=True,exist_ok=False)
    (out/'summary.xml').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    for name,rows in [('operations.csv',summary['operations']),('configuration_ranges.csv',summary['configuration_ranges'])]:
        with (out/name).open('w',encoding='utf-8-sig',newline='') as f:
            writer=csv.DictWriter(f,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('observations',type=Path);parser.add_argument('output',type=Path);a=parser.parse_args()
    summary=recompute(a.observations);write_outputs(summary,a.output);print(json.dumps(summary['counts']))
