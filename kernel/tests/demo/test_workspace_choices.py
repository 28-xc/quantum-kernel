"""Real HTTP/ABI checks for exact-image-bound discrete workspace choices."""
from pathlib import Path
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
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
import argparse, copy, hashlib, record_io as json, subprocess, sys, threading
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from demo import server

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,required=True)
    parser.add_argument('--resource-probe',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    config_path=args.config.resolve();app=server.Application(config_path)
    catalog=app.catalog();assert {x['id'] for x in catalog['libraries']}=={'low-memory','performance'}
    performance=app.descriptors['performance'];low=app.descriptors['low-memory']
    assert performance['workspace_options']==[42944,57024]
    assert 'workspace_options' not in low
    service=ThreadingHTTPServer(('127.0.0.1',0),server.handler(app,'pending'))
    host='127.0.0.1:'+str(service.server_address[1]);service.RequestHandlerClass=server.handler(app,host)
    thread=threading.Thread(target=service.serve_forever,daemon=True);thread.start();observations=[];rejections=[]
    def run(value):
        connection=HTTPConnection(host,timeout=20)
        connection.request('POST','/api/run',body=json.dumps(value),headers={'Host':host,'Content-Type':'application/json','X-Demo-Token':app.token})
        response=connection.getresponse();blob=response.read();connection.close()
        return response.status,json.loads(blob)
    try:
        for library,capacities in (('low-memory',[low['workspace_bytes']]),('performance',performance['workspace_options'])):
            for capacity in capacities:
                for parameter in [512,768,1024,44,65,87]:
                    value=dict(library=library,parameter=parameter,message_bytes=0 if parameter>100 else 1024,
                               context_bytes=0 if parameter>100 else 255,mode='normal',workspace_bytes=capacity)
                    code,result=run(value)
                    assert code==200 and result['functional_checks_passed'] and result['canaries_ok'],result
                    assert result['workspace_bytes']==capacity and result['requested_workspace_bytes']==capacity
                    assert result['binary_sha256']==app.descriptors[library]['binary_sha256']
                    assert result['observed_arena_high_water_bytes']<=capacity
                    assert len(result['operations'])==4 and all(x['return_code']==0 for x in result['operations'][:3])
                    observations.append(result)
        high={x['workspace_bytes']:x['observed_arena_high_water_bytes'] for x in observations if x['library']=='performance' and x['parameter']==87}
        assert high[42944]<=42944 and high[57024]>42944,high
        request=dict(library='performance',parameter=87,message_bytes=32,context_bytes=0,mode='normal')
        for capacity in [0,32,42943,42976,57025,65536,True,'42944']:
            value=dict(request,workspace_bytes=capacity);code,result=run(value)
            assert code==400,(value,result);rejections.append(dict(request=value,status=code,error=result))
        code,result=run(dict(request,library='low-memory',workspace_bytes=42944))
        assert code==400;rejections.append(dict(request='low-memory capacity override',status=code,error=result))
        for capacity in [42944,57024]:
            code,result=run(dict(request,mode='insufficient',workspace_bytes=capacity))
            assert code==200 and result['workspace_bytes']==32 and result['failure_output_zero'] and result['canaries_ok']
            assert result['operations'][0]['return_code']==-5
            assert result['recovery']['workspace_bytes']==capacity and result['recovery']['functional_checks_passed']
            observations.append(result)
        probe=args.resource_probe.resolve();image=probe.parent/'latticecore.dll'
        assert sha(image)==performance['binary_sha256'],'Probe must execute the same exact library image'
        process=subprocess.run([str(probe)],cwd=probe.parent,capture_output=True)
        (out/'resource-probe.log').write_bytes(json.capture_bytes(process.stdout+process.stderr))
        assert process.returncode==0
        records=[json.loads(line) for line in process.stdout.decode().splitlines() if line.startswith('{')]
        equal=records[-1]
        assert equal['status']=='PASS' and equal['equal_signature_cases']>=24 and equal['complete_operations']==18,equal
        assert equal['common_supported_workspace']==42944 and equal['common_preferred_workspace']==57024
        config=json.loads(config_path.read_text(encoding='utf-8-sig'))
        registry_path=(config_path.parent/config['deployment_profiles']['path']).resolve()
        registry=json.loads(registry_path.read_text());registry=copy.deepcopy(registry)
        for row in registry['profiles']:
            if row['binary_sha256']==performance['binary_sha256'] and row['workspace_bytes']==42944:row['binary_sha256']='0'*64
        invalid_registry=out/'wrong-image-profiles.xml';invalid_registry.write_text(json.dumps(registry))
        def absolute(value):
            if isinstance(value,dict):
                if set(value)=={'path','sha256'}:value['path']=str((config_path.parent/value['path']).resolve())
                else:
                    for item in value.values():absolute(item)
            elif isinstance(value,list):
                for item in value:absolute(item)
        absolute(config);config['deployment_profiles']=dict(path=str(invalid_registry),sha256=sha(invalid_registry))
        invalid_config=out/'wrong-image-config.xml';invalid_config.write_text(json.dumps(config,ensure_ascii=False),encoding='utf-8')
        try:server.Application(invalid_config)
        except ValueError as error:assert 'Selectable workspace' in str(error)
        else:raise AssertionError('Capacity belonging to another image was accepted')
        report=dict(status='PASS',scope='Real HTTP calls pass selected capacities to the same registered DLL; six parameters/18 valid operations plus tamper checks per strategy/capacity. Actual deterministic resource probe confirms identical signatures. No performance measurements.',
                    config_sha256=sha(config_path),observations=observations,rejections=rejections,
                    resource_probe_sha256=sha(probe),performance_binary_sha256=sha(image),equal_outputs=equal,
                    wrong_image_registration_rejected=True,sources={p:sha(ROOT/p) for p in ['demo/server.py','demo/app.js','demo/index.html','publicschemas/demo.py','tests/demo/test_workspace_choices.py']})
        (out/'result.xml').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        print(json.dumps(dict(status='PASS',valid_flows=18,recoveries=2,rejected_requests=len(rejections),equal_signature_cases=equal['equal_signature_cases'])))
    finally:
        service.shutdown();service.server_close();thread.join(timeout=5);assert not thread.is_alive()
if __name__=='__main__':main()
