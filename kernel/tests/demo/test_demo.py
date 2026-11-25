"""Real public-library functional/API tests plus explicitly synthetic data boundaries."""
import argparse
import copy
import hashlib
import http.client
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
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock
from http.server import ThreadingHTTPServer

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'demo')); sys.path.insert(0,str(ROOT))
import server
from publicschemas.observations import validate
from science_fixture import fixture

CONFIG=None
class DemoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app=server.Application(CONFIG)
        cls.http=ThreadingHTTPServer(('127.0.0.1',0),server.handler(cls.app,'pending'))
        cls.port=cls.http.server_address[1]; cls.host=f'127.0.0.1:{cls.port}'
        cls.http.RequestHandlerClass=server.handler(cls.app,cls.host)
        cls.thread=threading.Thread(target=cls.http.serve_forever,daemon=True); cls.thread.start()
    @classmethod
    def tearDownClass(cls):
        cls.http.shutdown();cls.http.server_close();cls.thread.join()
    def request(self,path,method='GET',data=None,headers=None):
        c=http.client.HTTPConnection('127.0.0.1',self.port,timeout=30)
        h={'Host':self.host};h.update(headers or {})
        if data is not None: data=json.dumps(data);h.setdefault('Content-Type','application/json')
        c.request(method,path,body=data,headers=h);r=c.getresponse();b=r.read();c.close();return r.status,b
    def test_01_real_six_parameters_all_lengths(self):
        for library in self.app.libs:
            for p in self.app.descriptors[library]['parameters']:
                for m,c in ((0,0),(32,1),(1024,255),(16384,0)):
                    with self.subTest(library=library,p=p,m=m,c=c):
                        r=self.app.run(dict(library=library,parameter=p,message_bytes=m,context_bytes=c,mode='normal'))
                        self.assertTrue(r['functional_checks_passed']);self.assertTrue(r['canaries_ok']);self.assertFalse(r['performance_measurement'])
                        if p<100:self.assertEqual(r['operations'][-1]['return_code'],-6)
                        else:self.assertEqual(r['operations'][-1]['return_code'],0);self.assertTrue(r['checks']['implicit_rejection'])
    def test_02_real_oom_recovery(self):
        for library in self.app.libs:
            for p in self.app.descriptors[library]['parameters']:
                with self.subTest(library=library,p=p):
                    r=self.app.run(dict(library=library,parameter=p,message_bytes=1024,context_bytes=0,mode='insufficient'))
                    self.assertEqual(r['operations'][0]['return_code'],-5);self.assertTrue(r['failure_output_zero']);self.assertTrue(r['canaries_ok']);self.assertTrue(r['recovery']['functional_checks_passed']);self.assertTrue(r['recovery']['canaries_ok'])
    def test_03_no_measurements_by_default(self):
        self.assertEqual(self.app.observations()['records'],[])
        for lib in self.app.catalog()['libraries']:self.assertEqual(lib['archived_timing_records'],0)
    def test_04_api_catalog_no_local_paths(self):
        status,body=self.request('/api/catalog');self.assertEqual(status,200)
        self.assertNotIn(str(ROOT).encode(),body);self.assertNotIn(b'artifact',body)
        self.assertNotIn(b'criteria',body);self.assertNotIn(b'gate',body)
    def test_05_static_five_pages(self):
        s,b=self.request('/');self.assertEqual(s,200)
        for p in ('overview','run','resources','measurements','data'):self.assertIn(('id="page-'+p+'"').encode(),b)
        self.assertNotIn(b'__CSRF__',b)
    def test_06_public_api_run_and_export(self):
        request=dict(library=next(iter(self.app.libs)),parameter=65,message_bytes=32,context_bytes=1,mode='normal')
        s,b=self.request('/api/run','POST',request,{'X-Demo-Token':self.app.token,'Origin':'http://'+self.host});self.assertEqual(s,200)
        result=json.loads(b);s,out=self.request('/export/run/'+result['run_id']+'.xml');self.assertEqual(s,200);self.assertEqual(json.loads(out),result)
        self.assertNotIn('secret_key',result);self.assertNotIn('shared_secret',result)
    def test_07_wrong_host(self):self.assertEqual(self.request('/api/catalog',headers={'Host':'remote.invalid'})[0],403)
    def test_08_wrong_origin(self):self.assertEqual(self.request('/api/run','POST',{}, {'X-Demo-Token':self.app.token,'Origin':'http://remote.invalid'})[0],403)
    def test_09_missing_token(self):
        with mock.patch.object(self.app,'run',side_effect=AssertionError('Unauthorized API call')) as operation:
            for _ in range(16):self.assertEqual(self.request('/api/run','POST',{})[0],403)
            operation.assert_not_called()
    def test_10_arbitrary_path_not_served(self):
        for p in ('/../server.py','/evidence/raw','/api/criteria','/release_bindings.xml','/export/run/unknown.xml'):
            self.assertEqual(self.request(p)[0],404)
    def test_11_unknown_query(self):
        for p in ('/api/observations?path=somewhere','/api/observations?scope=current&scope=historical','/api/observations?scope=bad','/api/observations?library=unknown'):
            self.assertEqual(self.request(p)[0],400)
    def test_12_unknown_run_field(self):
        r=dict(library=next(iter(self.app.libs)),parameter=65,message_bytes=0,context_bytes=0,mode='normal',command='x')
        self.assertEqual(self.request('/api/run','POST',r,{'X-Demo-Token':self.app.token})[0],400)
    def test_13_invalid_run_presets(self):
        r=dict(library=next(iter(self.app.libs)),parameter=65,message_bytes=0,context_bytes=0,mode='normal')
        for key,value in [('parameter',True),('parameter',66),('message_bytes',999999999),('context_bytes',256),('mode','arbitrary'),('library','x')]:
            with self.subTest(key=key,value=value):
                with self.assertRaises(ValueError):self.app.run(r|{key:value})
    def test_14_empty_export_valid_schema(self):
        s,b=self.request('/export/observations.xml?scope=current');self.assertEqual(s,200);self.assertEqual(validate(json.loads(b))['records'],[])
        self.assertEqual(self.request('/export/samples.csv?scope=current')[1].decode('utf-8-sig').count('\n'),1)
    def test_15_current_identity_and_history_boundaries(self):
        lib=self.app.descriptors[next(iter(self.app.libs))]
        record=dict(kind='timing_series',algorithm='ML-DSA',parameter=65,operation='sign',configuration=lib['configuration'],platform=lib['platform'],execution='native',historical=True,binary_sha256=lib['binary_sha256'],round_id='synthetic',samples_ns=[1,99999999,2],sample_semantics='individual_call',samples_per_batch=1,outcomes=['SUCCESS','FAIL','CAPACITY_INSUFFICIENT'],return_codes=[0,-7,-5])
        synthetic={'schema':1,'kind':'lattice_technical_observations','dataset_id':'synthetic_boundary_only','records':[record]}
        old=self.app.datasets
        try:
            self.app.datasets=[synthetic]
            self.assertEqual(self.app.observations()['records'],[])
            exported=self.app.observations('historical');self.assertEqual(exported['records'][0],record)
            csv=server.samples_csv(exported).decode('utf-8-sig');self.assertIn('99999999,FAIL,-7',csv);self.assertEqual(csv.count('\n'),4)
            record['historical']=False;self.assertEqual(self.app.observations()['records'],[])
            self.assertEqual(self.app.observations('all')['records'],[record])
            record['binary_sha256']='0'*64;self.assertEqual(self.app.observations()['records'],[])
        finally:self.app.datasets=old
    def test_16_inputs_only_explicit(self):
        c=server.read(CONFIG);c['private_token']='SYNTHETIC_INTERNAL_SENTINEL'
        with self.assertRaises(ValueError):server.validate_config(c)
        self.assertNotIn('SYNTHETIC_INTERNAL_SENTINEL',json.dumps(self.app.catalog()))
    def test_17_changed_library_hash_rejected(self):
        c=server.read(CONFIG);c['libraries'][0]['artifact']['sha256']='0'*64
        item=c['libraries'][0]['artifact']
        with self.assertRaises(ValueError):server.checked_file(item,Path(CONFIG).parent)
    def test_18_no_storage_or_remote_script(self):
        js=(ROOT/'demo/app.js').read_text(encoding='utf-8')
        for token in ('localStorage','sessionStorage','https://','eval('):self.assertNotIn(token,js)
    def test_19_independent_private_read_denial(self):
        script="""
import json,os,sys
from pathlib import Path
root=Path(sys.argv[1]); config=Path(sys.argv[2]).resolve()
blocked=[root.parents[1]/'project',root.parent/'internal',root.parent/'release_pipeline']
# Explicit configuration/data supplied by this test is the only allowed input
# below an otherwise denied tree. This does not permit directory enumeration.
allowed={config}
cfg=json.loads(config.read_text(encoding='utf-8'))
for d in cfg['datasets']: allowed.add((config.parent/d['path']).resolve())
def audit(event,args):
 if event in ('open','os.listdir','os.scandir') and args and isinstance(args[0],(str,bytes,os.PathLike)):
  p=Path(os.fsdecode(args[0])).resolve()
  if any(p==b or b in p.parents for b in blocked) and not (event=='open' and p in allowed):
   raise RuntimeError('Private data access denied')
sys.addaudithook(audit)
sys.path.insert(0,str(root/'demo'))
import server
app=server.Application(config)
assert app.observations()['records']==[]
r=app.run(dict(library=next(iter(app.libs)),parameter=65,message_bytes=32,context_bytes=1,mode='insufficient'))
assert r['operations'][0]['return_code']==-5 and r['recovery']['functional_checks_passed']
print('INDEPENDENT_TECHNICAL_APPLICATION_PASS')
"""
        r=subprocess.run([sys.executable,'-B','-c',script,str(ROOT),str(CONFIG)],capture_output=True,text=True,timeout=30)
        self.assertEqual(r.returncode,0,r.stderr);self.assertIn('INDEPENDENT_TECHNICAL_APPLICATION_PASS',r.stdout)
    def test_20_synthetic_canary_failure_cannot_report_pass(self):
        # Reporting-control positive case, not evidence of an actual overwrite.
        with mock.patch.object(server.C,'string_at',return_value=b'\x00'*32):
            r=self.app.execute(next(iter(self.app.libs)),65,32,0,262144)
        self.assertFalse(r['canaries_ok']);self.assertFalse(r['functional_checks_passed'])

    def test_21_scientific_default_empty(self):
        # An explicitly empty archive stays empty even when this test suite is
        # launched with the final configuration containing scientific archives.
        with mock.patch.object(self.app,'scientific',{}):
            s,b=self.request('/api/science');self.assertEqual(s,200)
            self.assertEqual(json.loads(b),dict(schema='lattice.technical_result_catalog.v1',views=[]))
        self.assertEqual(server.outcome(-8),'UNSUPPORTED')

    def test_22_registered_science_preserves_failure_slow_and_warmup(self):
        lib=self.app.descriptors[next(iter(self.app.libs))];data=fixture(lib);old=self.app.scientific
        try:
            self.app.scientific={data['dataset_id']:data}
            self.assertEqual(len(self.app.science_views()['views']),1)
            summary=self.app.science_views(lib['id'])['views'][0]
            self.assertEqual(summary['completeness']['failed_sample_rows'],1)
            self.assertFalse(summary['analysis_available'])
            s,b=self.request('/export/science.xml?dataset='+data['dataset_id']);self.assertEqual(s,200);self.assertEqual(json.loads(b),data)
            s,b=self.request('/export/science.csv?dataset='+data['dataset_id']);self.assertEqual(s,200)
            text=b.decode('utf-8-sig');self.assertEqual(text.count('\n'),73);self.assertIn('99999999,-5',text)
            s,b=self.request('/api/science?library='+lib['id']);self.assertEqual(s,200)
            self.assertEqual(json.loads(b)['views'][0]['dataset_id'],data['dataset_id'])
            for field,value in [('binary_sha256','0'*64),('platform','other'),('configuration','other'),('workspace_bytes',lib['workspace_bytes']+32)]:
                self.assertIsNone(server.science.summary(data,lib|{field:value}))
        finally:self.app.scientific=old

    def test_23_scientific_unknown_fields_and_sample_loss_rejected(self):
        data=fixture(self.app.descriptors[next(iter(self.app.libs))])
        for mutation in ('private','loss','reorder','false_summary'):
            x=copy.deepcopy(data)
            if mutation=='private':x['credentials']='SYNTHETIC_DO_NOT_PUBLISH'
            elif mutation=='loss':x['runs'][0]['samples'].pop()
            elif mutation=='reorder':x['runs'][0]['samples'].reverse()
            else:x['completeness']['failed_sample_rows']=0
            with self.assertRaises(ValueError):server.science.validate(x)

    def test_24_scientific_endpoint_whitelist(self):
        for route in ('/api/science?path=x','/api/science?role=bad','/api/science?role=development&role=confirmation',
                      '/api/science?library=unknown','/export/science.xml?dataset=../x','/export/science.csv?path=x'):
            self.assertEqual(self.request(route)[0],400)

    def test_25_current_config_explicit_only(self):
        config=server.read(CONFIG)
        self.assertEqual(server.validate_config(config),config)
        config['directory_scan']='anything'
        with self.assertRaises(ValueError):server.validate_config(config)

def main():
    global CONFIG
    p=argparse.ArgumentParser();p.add_argument('--config',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();CONFIG=a.config.resolve()
    if a.output.exists():raise ValueError('New result path required')
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(DemoTests); result=unittest.TextTestRunner(verbosity=2).run(suite)
    sources={str(f.relative_to(ROOT)):hashlib.sha256(f.read_bytes()).hexdigest() for base in ('demo','publicschemas','tests/demo') for f in (ROOT/base).glob('*') if f.is_file()}
    data={'status':'PASS' if result.wasSuccessful() else 'FAIL','tests':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'configuration_sha256':hashlib.sha256(CONFIG.read_bytes()).hexdigest(),'libraries':server.read(CONFIG)['libraries'],'sources':sources,'scope':'Real six-parameter API/modified-input/OOM checks; synthetic data boundaries labelled in tests. No performance measurement or final screenshot acceptance.'}
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');return 0 if result.wasSuccessful() else 1
if __name__=='__main__':raise SystemExit(main())
