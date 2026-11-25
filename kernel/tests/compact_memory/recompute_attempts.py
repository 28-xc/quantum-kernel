"""Audit the retained 300 complete signature-attempt sequences."""
from pathlib import Path
from collections import Counter
import argparse
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


def need(condition,message):
    if not condition:raise ValueError(message)


def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def recompute(path):
    path=Path(path).resolve();root=path.parent
    data=json.loads(path.read_text(encoding='utf-8'))
    need(data['schema']=='lattice.signature_attempt_observations.v1','Changed observation schema')
    need(data['timing_collected'] is False,'Unexpected timing claim')
    for descriptor in data['artifacts']:
        file=(root/descriptor['path']).resolve()
        need(file.is_relative_to(root) and file.is_file() and file.stat().st_size==descriptor['bytes'] and sha(file)==descriptor['sha256'],'Changed diagnostic artifact')
    records=json.loads((root/'records.xml').read_text())
    instrumentation=json.loads((root/'instrumentation.xml').read_text())
    need(records['instrumentation_sha256']==sha(root/'instrumentation.xml'),'Changed instrumented source identity')
    need(instrumentation['base_commit']=='1df22ecdfa7ff762dae87cca3d83c4f633b4a156' and
         instrumentation['signature_cases']==300,'Changed diagnostic source or size')
    need(records['status']=='PASS' and records['cases']==300 and len(records['records'])==300,'Incomplete diagnostic')
    need(set(records['libraries'])=={'compact-fixed','compact-recompute'},'Changed compared implementations')
    for value in records['libraries'].values():need(re.fullmatch('[0-9a-f]{64}',value) is not None,'Invalid binary identity')
    histograms={p:Counter() for p in (44,65,87)}
    for row,(parameter,index) in zip(records['records'],((p,i) for p in (44,65,87) for i in range(100)),strict=True):
        need((row['parameter'],row['index'])==(parameter,index),'Reordered or missing signature')
        seed=b'row-attempt-trace-v1'+bytes([parameter])+index.to_bytes(4,'little')
        need(row['input_seed_hex']==seed.hex() and row['message_bytes']==(0,32,1024,4096)[index%4] and
             row['domain_bytes']==(0,1,32,255)[(index//4)%4],'Changed deterministic transcript')
        need(row['random_requests']==[32] and row['complete_bytes_and_trace_equal'] is True,'Changed entropy or full-byte comparison')
        for name in ('signature_sha256','public_key_sha256'):
            need(re.fullmatch('[0-9a-f]{64}',row[name]) is not None,'Invalid public-output identity')
        trace=row['attempt_events'];attempts=row['attempts']
        need(type(attempts) is int and 1<=attempts<=2048 and len(trace)==2*attempts,'Incomplete attempt sequence')
        for i in range(attempts):
            need(type(trace[2*i]) is int and type(trace[2*i+1]) is int and
                 trace[2*i]==(i<<32)|0x80000000 and
                 trace[2*i+1]==(i<<32)|(0 if i==attempts-1 else 0xffffffff),
                 'Changed begin/return sequence or premature acceptance')
        histograms[parameter][attempts]+=1
    rows=[]
    for parameter,histogram in histograms.items():
        total=sum(k*v for k,v in histogram.items())
        rows.append(dict(parameter=parameter,signatures=sum(histogram.values()),attempts=total,
            rejected_attempts=total-sum(histogram.values()),maximum_attempts=max(histogram),
            attempts_histogram={str(k):v for k,v in sorted(histogram.items())}))
    return dict(schema='lattice.signature_attempt_statistics.v1',observations_sha256=sha(path),
        signatures=300,attempts=sum(r['attempts'] for r in rows),
        rejected_attempts=sum(r['rejected_attempts'] for r in rows),
        maximum_attempts=max(r['maximum_attempts'] for r in rows),rows=rows,
        measurement='exact diagnostic sequence and complete-byte equality',timing_collected=False)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('observations',type=Path);parser.add_argument('output',type=Path)
    args=parser.parse_args();need(not args.output.exists(),'Fresh output required')
    result=recompute(args.observations)
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k!='rows'}))
