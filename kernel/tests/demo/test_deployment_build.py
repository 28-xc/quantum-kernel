"""Exercise the real local deployment HTTP flow with a bounded public-vector build."""
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
import argparse, hashlib, io, record_io as json, sys, threading, time, zipfile
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from demo import server
from demo.deployment_ui import DeploymentBuilds

def digest(blob):return hashlib.sha256(blob).hexdigest()
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--strategy',choices=('low-memory','performance'),default='low-memory')
    parser.add_argument('--all-operations',action='store_true')
    args=parser.parse_args();out=args.output.resolve()
    if out.exists():raise ValueError('Fresh output required')
    out.mkdir(parents=True)
    app=server.Application(args.config.resolve())
    app._deployment_builds=DeploymentBuilds(out/'builds',app.host)
    service=ThreadingHTTPServer(('127.0.0.1',0),server.handler(app,'pending'))
    host='127.0.0.1:'+str(service.server_address[1]);service.RequestHandlerClass=server.handler(app,host)
    thread=threading.Thread(target=service.serve_forever,daemon=True);thread.start();records=[]
    def http(method,path,value=None,token=None):
        headers={'Host':host}
        body=None
        if value is not None:
            body=json.dumps(value);headers.update({'Content-Type':'application/json','X-Demo-Token':app.token if token is None else token})
        connection=HTTPConnection(host,timeout=20);connection.request(method,path,body=body,headers=headers)
        response=connection.getresponse();blob=response.read();connection.close()
        records.append(dict(method=method,path=path,status=response.status,sha256=digest(blob),bytes=len(blob)))
        return response.status,blob
    try:
        code,html=http('GET','/');assert code==200 and b'/deployment_ui.js' in html
        code,js=http('GET','/deployment_ui.js');assert code==200 and b'/api/deployment-build' in js
        code,blob=http('GET','/api/deployment-builds');assert code==200
        catalog=json.loads(blob);entry=next(x for x in catalog['platforms'] if x['available'] and x['id'] in ('windows-x86_64','linux-aarch64'))
        assert [x['id'] for x in entry['strategies']]==['low-memory','performance']
        selected_strategy=next(x for x in entry['strategies'] if x['id']==args.strategy and x['available'])
        parameters=[512,768,1024,44,65,87] if args.all_operations else [768,65]
        operations={str(p):['keypair','encaps','decaps'] if p>100 else ['keypair','sign','verify'] for p in parameters} if args.all_operations else {'768':['encaps'],'65':['verify']}
        request=dict(schema='lattice.deployment_strategy_request.v1',platform=entry['id'],strategy=args.strategy,parameters=parameters,
            operations=operations,budgets=dict(program_bytes=524288,ram_bytes=262144),
            workspace_bytes=selected_strategy['workspace_bytes'])
        code,_=http('POST','/api/deployment-build',request,token='incorrect');assert code==403
        invalid=[dict(request,tools={'cc':'different-tool'}),dict(request,workspace_bytes=31),dict(request,recipes=['compact-rate']),
            dict(request,strategy='native-x86-cache40-gamma'),
            dict(request,operations={'768':['sign'],'65':['verify']}),dict(request,parameters=[768]),
            dict(request,budgets=dict(program_bytes=0,ram_bytes=262144))]
        for value in invalid:
            code,_=http('POST','/api/deployment-build',value);assert code==400
        assert not app._deployment_builds.jobs
        code,blob=http('POST','/api/deployment-build',request);assert code==202
        ident=json.loads(blob)['build_id'];deadline=time.monotonic()+620
        code,_=http('POST','/api/deployment-build',request);assert code==400
        while True:
            code,blob=http('GET','/api/deployment-build?id='+ident);assert code==200
            state=json.loads(blob)
            if state['status']!='BUILDING':break
            if time.monotonic()>deadline:raise RuntimeError('Bounded deployment did not finish')
            time.sleep(.25)
        assert state['status']=='READY',state
        assert state['strategy']==args.strategy
        code,blob=http('GET',state['result_download']);assert code==200 and json.loads(blob)==state
        code,archive=http('GET',state['download']);assert code==200 and digest(archive)==state['archive_sha256']
        (out/'download.zip').write_bytes(archive)
        with zipfile.ZipFile(io.BytesIO(archive)) as z:
            result=json.loads(z.read('result.xml'));assert result['selected']['resources']==state['resources']
            assert result['selected']['image']['sha256']==state['image_sha256']
            assert result['request']['operations']==request['operations']
            for item in result['deployment_files']:assert digest(z.read(item['path']))==item['sha256']
            build=json.loads(z.read(result['selected']['build']['path']))
            assert build['operations']==request['operations']
            assert build['parameters']==request['parameters']
        for path in ('/api/deployment-build?id=../../source','/export/deployment/../../source.xml',
                     '/export/deployment/'+ident+'.txt'):
            code,_=http('GET',path);assert code==400
        report=dict(status='PASS',scope='Existing application and HTTP handler; actual public builder, shared/static NIST checks, resource verification and archive download.',
            config_sha256=digest(args.config.read_bytes()),request=request,result=state,http=records,
            source_sha256={p:digest((ROOT/p).read_bytes()) for p in ('demo/deployment_ui.py','demo/deployment_ui.js',
                'demo/server.py','demo/index.html','demo/app.css','tools/deploy.py','tests/demo/test_deployment_build.py')})
        (out/'result.xml').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        print(json.dumps(dict(status='PASS',http_requests=len(records),artifact_count=len(state['artifacts']),build_id=ident)))
    finally:
        service.shutdown();service.server_close();thread.join(timeout=5)
        assert not thread.is_alive()
if __name__=='__main__':main()
