"""Check registered mean-based budget queries against their actual input records."""
from pathlib import Path
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
import argparse, hashlib, http.client, record_io as json, math, sys, threading
from http.server import ThreadingHTTPServer
from urllib.parse import urlencode
ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT),str(ROOT/'demo')]
import server
from publicschemas import resources

def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();assert not a.output.exists()
    app=server.Application(a.config.resolve())
    service=ThreadingHTTPServer(('127.0.0.1',0),server.handler(app,'pending'))
    host='127.0.0.1:'+str(service.server_address[1])
    service.RequestHandlerClass=server.handler(app,host)
    thread=threading.Thread(target=service.serve_forever,daemon=True);thread.start()
    records=[]
    def get(path):
        connection=http.client.HTTPConnection(host,timeout=10)
        connection.request('GET',path,headers={'Host':host})
        response=connection.getresponse();body=response.read();connection.close()
        assert response.status==200,(path,response.status)
        records.append(dict(path=path,status=response.status,sha256=hashlib.sha256(body).hexdigest()))
        return json.loads(body)
    checked=[]
    try:
        catalog=get('/api/resources')
        for study in catalog['timing_studies']:
            statistics=app.scientific[study['dataset_id']]
            if statistics['schema']!=server.science.MEAN_TAIL:continue
            for data in app.scientific.values():
                if data['schema'] not in resources.SCHEMAS:continue
                for point in data['points']:
                    matches=[c for c in statistics['configurations'] if c['library_sha256']==point['binary_sha256'] and c['workspace_reserved']==point['reserved_components']['workspace_bytes']]
                    if point['platform']!=study['platform'] or not matches:continue
                    request=dict(resource_dataset=data['dataset_id'],timing_dataset=study['dataset_id'],platform=study['platform'],ram_bytes=point['core_reserved_bytes'],program_bytes=point['program_bytes'])
                    result=get('/api/budget?'+urlencode(request))
                    for configuration in matches:
                        rows=[r for r in statistics['cells'] if r['configuration']==configuration['id']]
                        assert len(rows)==18 and {(r['parameter'],r['operation']) for r in rows}==resources.CELLS
                        expected=math.fsum(row['statistics']['mean']['ns'] for row in rows)/18
                        candidates=[c for c in result['candidates'] if c['configuration']==configuration['id']]
                        assert len(candidates)==1
                        assert candidates[0]['equal_weight_18_operation_mean_ns']==expected
                        assert candidates[0]['binary_sha256']==point['binary_sha256']
                        assert candidates[0]['workspace_bytes']==point['reserved_components']['workspace_bytes']
                        for key,reason in [('ram_bytes','RAM_BUDGET_EXCEEDED'),('program_bytes','PROGRAM_BUDGET_EXCEEDED')]:
                            smaller=dict(request);smaller[key]-=1
                            rejected=get('/api/budget?'+urlencode(smaller))
                            assert all(c['resource_id']!=point['id'] for c in rejected['candidates'])
                            excluded=[x for x in rejected['excluded'] if x['resource_id']==point['id']]
                            assert len(excluded)==1 and reason in excluded[0]['reasons']
                        checked.append(dict(dataset=study['dataset_id'],configuration=configuration['id'],binary_sha256=point['binary_sha256'],mean_ns=expected,operation_cells=18,both_exact_boundaries=True))
        assert checked,'No registered mean/tail resource pair was exercised'
    finally:
        service.shutdown();service.server_close();thread.join(timeout=5)
    assert not thread.is_alive()
    output=dict(status='PASS',scope='Existing full-operation means and measured capacities; no new cryptographic timing.',config_sha256=sha(a.config),checks=checked,http=records,server_stopped=True,
                sources={name:sha(ROOT/name) for name in ['demo/server.py','publicschemas/resources.py','tests/demo/test_budget_mean.py']})
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(output,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(status='PASS',mean_resource_pairs=len(checked),http_queries=len(records))))
if __name__=='__main__':main()
