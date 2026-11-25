"""Closed schema3 and real HTTP exports with labelled synthetic statistics."""
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
import argparse, copy, hashlib, http.client, record_io as json, sys, tempfile, threading, unittest
from http.server import ThreadingHTTPServer
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'demo'))
import server
from pooled_fixture import fixture,write
from test_resources import fixture as resource_fixture

CONFIG=None;OUTPUT=None
class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory(prefix='schema3-',dir=OUTPUT.parent);cls.base=Path(cls.tmp.name)
        config=server.read(CONFIG);config.update(schema=4,datasets=[],scientific_views=[],pooled_views=[],mean_tail_views=[],timing_views=[],resource_limit_views=[],process_footprint_views=[],application_views=[])
        if 'host_probe' in config:
            config['host_probe']['path']=str((CONFIG.parent/config['host_probe']['path']).resolve())
        config['deployment_profiles']['path']=str((CONFIG.parent/config['deployment_profiles']['path']).resolve())
        for lib in config['libraries']:
            lib['artifact']['path']=str((CONFIG.parent/lib['artifact']['path']).resolve())
        cls.paired,cls.observations,cls.stats=fixture(config['libraries'][0],cls.base/'pooled')
        resources,_,_=resource_fixture();p=resources['points'][0];lib=config['libraries'][0]
        p.update(binary_sha256=lib['artifact']['sha256'],platform=lib['platform'])
        p['source_sha256']['image']=p['binary_sha256'];p['reserved_components']['workspace_bytes']=lib['workspace_bytes']
        p['core_reserved_bytes']=sum(p['reserved_components'].values())
        cls.resources=resources;cls.resource_desc=write(cls.base/'resources.xml',resources)
        config['scientific_views']=[cls.resource_desc];config['pooled_views']=[cls.paired]
        cls.config=config;write(cls.base/'config.xml',config);cls.app=server.Application(cls.base/'config.xml')
        cls.http=ThreadingHTTPServer(('127.0.0.1',0),server.handler(cls.app,'pending'));cls.host='127.0.0.1:'+str(cls.http.server_address[1])
        cls.http.RequestHandlerClass=server.handler(cls.app,cls.host);cls.thread=threading.Thread(target=cls.http.serve_forever,daemon=True);cls.thread.start()
    @classmethod
    def tearDownClass(cls):cls.http.shutdown();cls.http.server_close();cls.thread.join();cls.tmp.cleanup()
    def get(self,path):
        c=http.client.HTTPConnection(self.host,timeout=10);c.request('GET',path,headers={'Host':self.host});r=c.getresponse();body=r.read();c.close();return r.status,body
    def test_01_loaded_identity(self):
        views=self.app.science_views(self.config['libraries'][0]['id'])['views']
        self.assertEqual({x['kind'] for x in views},{'deployment_resources','pooled_measurements'})
    def test_02_catalog_and_budget(self):
        status,b=self.get('/api/resources');self.assertEqual(status,200);self.assertEqual(len(json.loads(b)['timing_studies']),1)
        q='/api/budget?resource_dataset=resources&timing_dataset=synthetic_schema4_only&platform='+self.config['libraries'][0]['platform']+'&ram_bytes=1048576&program_bytes=131072'
        status,b=self.get(q);self.assertEqual(status,200);data=json.loads(b);self.assertEqual(data['selected']['equal_weight_18_operation_mean_ns'],100.)
        self.assertEqual(data['unmeasured_configurations'][0]['configuration'],'synthetic_reference')
    def test_03_unknown_budget_fields(self):
        self.assertEqual(self.get('/api/budget?path=internal')[0],400)
    def test_04_summary_export(self):
        status,b=self.get('/export/science.xml?dataset=synthetic_schema4_only');self.assertEqual(status,200);self.assertEqual(json.loads(b),self.stats)
    def test_05_statistics_csv(self):
        status,b=self.get('/export/science.csv?dataset=synthetic_schema4_only');self.assertEqual(status,200)
        self.assertEqual(b.decode('utf-8-sig').count('\n'),37);self.assertIn(b'pooled_mean_ns',b)
    def test_06_manifest_export(self):
        status,b=self.get('/export/observations-manifest.xml?dataset=synthetic_schema4_only');self.assertEqual(status,200);self.assertEqual(json.loads(b),self.observations)
    def test_07_raw_bytes(self):
        status,b=self.get('/export/raw.csv?dataset=synthetic_schema4_only&ordinal=0');self.assertEqual(status,200)
        self.assertEqual(hashlib.sha256(b).hexdigest(),self.observations['runs'][0]['sample_shard']['sha256'])
    def test_08_raw_whitelist(self):
        for q in ('ordinal=-1','ordinal=72','ordinal=1&ordinal=2','path=../../server.py'):
            self.assertEqual(self.get('/export/raw.csv?dataset=synthetic_schema4_only&'+q)[0],400)
    def test_09_changed_raw_refused(self):
        path=self.base/'pooled/raw/00000000.csv';old=path.read_bytes()
        try:
            path.write_bytes(old+b'x');self.assertEqual(self.get('/export/raw.csv?dataset=synthetic_schema4_only&ordinal=0')[0],400)
        finally:path.write_bytes(old)
    def test_10_mismatched_summary_manifest(self):
        config=copy.deepcopy(self.config);summary=copy.deepcopy(self.stats);summary['observations_sha256']='f'*64
        config['pooled_views'][0]['summary']=write(self.base/'changed_summary.xml',summary);write(self.base/'changed_config.xml',config)
        with self.assertRaises(ValueError):server.Application(self.base/'changed_config.xml')
    def test_11_wrong_workspace_does_not_match_live_library(self):
        descriptor=dict(self.app.descriptors[self.config['libraries'][0]['id']],workspace_bytes=32)
        self.assertIsNone(server.science.summary(self.stats,descriptor))
    def test_12_unknown_asset(self):
        self.assertEqual(self.get('/scientific_ui.js')[0],200);self.assertEqual(self.get('/pooled_provenance.xml')[0],404)
    def test_13_duplicate_json_fields(self):
        with self.assertRaises(ValueError):server.strict_json('{"schema":1,"schema":3}')
        path=self.base/'duplicate.xml'
        field='<field><name>schema</name><integer>1</integer></field>'
        path.write_text('<record format="typed-xml-v1"><object>'+field+field+'</object></record>',encoding='utf-8')
        with self.assertRaises(ValueError):server.read(path)

def main():
    global CONFIG,OUTPUT
    p=argparse.ArgumentParser();p.add_argument('--config',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    CONFIG=a.config.resolve();OUTPUT=a.output.resolve();OUTPUT.parent.mkdir(parents=True,exist_ok=True)
    if OUTPUT.exists():raise ValueError('Fresh result required')
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Tests))
    sources={p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for sub in ('demo','publicschemas','tests/demo') for p in (ROOT/sub).glob('*') if p.is_file()}
    write(OUTPUT,dict(status='PASS' if result.wasSuccessful() else 'FAIL',tests=result.testsRun,failures=len(result.failures),errors=len(result.errors),
        sources=sources,scope='Synthetic statistical/resource records exercise real schema3 loading and HTTP routes; no new cryptographic performance measurement.'))
    return 0 if result.wasSuccessful() else 1
if __name__=='__main__':raise SystemExit(main())
