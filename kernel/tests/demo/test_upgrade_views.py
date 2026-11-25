"""Exact-image binding and byte-preserving exports of final paired evidence."""
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
import argparse, copy, hashlib, record_io as json, sys, threading
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from demo import server
from publicschemas import upgrade_views
def sha(blob):return hashlib.sha256(blob).hexdigest()
def main():
    p=argparse.ArgumentParser();p.add_argument('--config',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    a.output.mkdir(parents=True,exist_ok=False);config=a.config.resolve();app=server.Application(config);exports=[];negatives=[]
    service=ThreadingHTTPServer(('127.0.0.1',0),server.handler(app,'pending'));host='127.0.0.1:'+str(service.server_address[1]);service.RequestHandlerClass=server.handler(app,host)
    thread=threading.Thread(target=service.serve_forever,daemon=True);thread.start()
    def get(path):
        c=HTTPConnection(host,timeout=30);c.request('GET',path,headers={'Host':host});r=c.getresponse();blob=r.read();c.close();return r.status,blob
    def rejected(item,libraries):
        try:upgrade_views.load(item,config.parent,libraries)
        except ValueError:return
        raise AssertionError('Invalid measurement binding accepted')
    try:
        status,blob=get('/api/results');views=json.loads(blob)['views'];assert status==200 and len(views)==2
        for name in app.descriptors:
            status,blob=get('/api/results?library='+name);selected=json.loads(blob)['views']
            assert status==200 and len(selected)==1 and all(b['library']==name for b in selected[0]['bindings'])
        for ident,entry in app.upgrades.items():
            for name in ('summary','manifest','commands'):
                code,blob=get('/export/upgrade/'+name+'.xml?dataset='+ident);assert code==200 and sha(blob)==entry['request'][name]['sha256']
                exports.append(dict(dataset=ident,kind=name,bytes=len(blob),sha256=sha(blob)))
            for ordinal in (0,len(entry['commands'])-1):
                code,blob=get('/export/upgrade/raw.csv?dataset='+ident+'&ordinal='+str(ordinal));assert code==200 and sha(blob)==entry['commands'][ordinal]['raw_sha256']
                exports.append(dict(dataset=ident,kind='raw',ordinal=ordinal,bytes=len(blob),sha256=sha(blob)))
            for ordinal,resource in enumerate(entry['request']['resources']):
                for name in ('result','observations','commands'):
                    code,blob=get('/export/upgrade/resource-'+name+'.xml?dataset='+ident+'&ordinal='+str(ordinal))
                    assert code==200 and sha(blob)==resource[name]['sha256']
                    exports.append(dict(dataset=ident,kind='resource-'+name,ordinal=ordinal,bytes=len(blob),sha256=sha(blob)))
            item=copy.deepcopy(entry['request']);libraries=copy.deepcopy(app.descriptors);lib=item['bindings'][0]['library'];libraries[lib]['binary_sha256']='0'*64
            rejected(item,libraries);negatives.append(ident+':wrong-image')
            libraries=copy.deepcopy(app.descriptors);libraries[lib]['workspace_bytes']=32;libraries[lib].pop('workspace_options',None)
            rejected(item,libraries);negatives.append(ident+':wrong-workspace')
            altered=copy.deepcopy(entry['summary']);altered['comparisons'][0]['cells'][0]['candidate_mean_us']+=1
            altered_path=a.output/(ident+'-altered-summary.xml');altered_path.write_text(json.dumps(altered),encoding='utf-8')
            item['summary']=dict(path=str(altered_path.resolve()),sha256=sha(altered_path.read_bytes()))
            rejected(item,app.descriptors);negatives.append(ident+':inconsistent-estimate')
        for query in ('/export/upgrade/raw.csv?dataset=missing&ordinal=0','/export/upgrade/raw.csv?dataset='+next(iter(app.upgrades))+'&ordinal=-1','/export/upgrade/summary.xml?dataset='+next(iter(app.upgrades))+'&extra=1'):
            code,_=get(query);assert code==400;negatives.append(query)
        (a.output/'result.xml').write_text(json.dumps(dict(status='PASS',config_sha256=sha(config.read_bytes()),views=views,exports=exports,rejected_cases=negatives,
            scope='Original paired summaries, manifests, commands and raw CSV bytes are exported unchanged. Estimates checked against complete command blocks; intervals are hash-bound analysis results, not recomputed by the web UI.'),ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        print(json.dumps(dict(status='PASS',views=len(views),exports=len(exports),rejected_cases=len(negatives))))
    finally:service.shutdown();service.server_close();thread.join(timeout=5);assert not thread.is_alive()
if __name__=='__main__':main()
