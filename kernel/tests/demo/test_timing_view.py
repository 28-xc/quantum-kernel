"""Actual registered timing data: summary/manifest/raw identity and HTTP checks."""
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
sys.path.insert(0,str(ROOT/'demo'))
import server
CONFIG=None;OUTPUT=None

class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app=server.Application(CONFIG);cls.config=server.read(CONFIG)
        cls.dataset=next(d for d,v in cls.app.scientific.items() if v['schema']==server.science.TIMING)
        cls.stats=cls.app.scientific[cls.dataset];cls.entry=cls.app.pooled[cls.dataset]
        cls.raws=[r['raw'] for s in cls.entry['observations']['studies'] for r in s['records']]
        cls.http=ThreadingHTTPServer(('127.0.0.1',0),server.handler(cls.app,'pending'))
        cls.host='127.0.0.1:'+str(cls.http.server_address[1]);cls.http.RequestHandlerClass=server.handler(cls.app,cls.host)
        cls.thread=threading.Thread(target=cls.http.serve_forever,daemon=True);cls.thread.start()
    @classmethod
    def tearDownClass(cls):cls.http.shutdown();cls.http.server_close();cls.thread.join()
    def get(self,path):
        c=http.client.HTTPConnection(self.host,timeout=30);c.request('GET',path,headers={'Host':self.host})
        r=c.getresponse();data=r.read();c.close();return r.status,data
    def test_01_complete_studies(self):
        view=next(v for v in self.app.science_views()['views'] if v['kind']=='timing_distributions')
        self.assertEqual(view['studies'],self.stats['studies']);self.assertEqual(view['raw_files_checked'],len(self.raws))
        self.assertEqual([r['study_id'] for r in view['input_conditions']],[r['study_id'] for r in view['studies']])
    def test_02_library_identity_filter(self):
        for lib in self.app.descriptors.values():
            # This archival schema has no workspace identity; all observations
            # remain in the complete view and the exact exports tested below.
            self.assertIsNone(server.science.summary(self.stats,lib))
        self.assertEqual(server.science.summary(self.stats)['studies'],self.stats['studies'])
    def test_03_architecture_filter(self):
        lib=next(iter(self.app.descriptors.values()));self.assertIsNone(server.science.summary(self.stats,lib|{'platform':'unmeasured_platform'}))
    def test_04_exact_summary(self):
        status,data=self.get('/export/science.xml?dataset='+self.dataset);self.assertEqual(status,200);self.assertEqual(json.loads(data),self.stats)
    def test_05_exact_manifest(self):
        status,data=self.get('/export/observations-manifest.xml?dataset='+self.dataset);self.assertEqual(status,200)
        self.assertEqual(json.loads(data),self.entry['observations'])
    def test_06_first_and_last_raw(self):
        for ordinal in (0,len(self.raws)-1):
            status,data=self.get('/export/raw.csv?dataset='+self.dataset+'&ordinal='+str(ordinal));self.assertEqual(status,200)
            self.assertEqual(hashlib.sha256(data).hexdigest(),self.raws[ordinal]['sha256'])
    def test_07_invalid_ordinals(self):
        for q in ('ordinal=-1','ordinal='+str(len(self.raws)),'ordinal=0&path=x','ordinal=0&ordinal=1'):
            self.assertEqual(self.get('/export/raw.csv?dataset='+self.dataset+'&'+q)[0],400)
    def test_08_no_csv_summary_invention(self):self.assertEqual(self.get('/export/science.csv?dataset='+self.dataset)[0],400)
    def test_09_no_new_release_fields(self):
        view=next(v for v in self.app.science_views()['views'] if v['kind']=='timing_distributions')
        self.assertEqual(view['analysis_scope'],'finite_input_group_timing');self.assertEqual(view['deleted_rows'],0)
        self.assertNotIn('security_pass',view);self.assertNotIn('gate',view)
    def test_10_unknown_config_field(self):
        config=copy.deepcopy(self.config);config['timing_filter']='slow'
        with self.assertRaises(ValueError):server.validate_config(config)
    def test_11_changed_raw_refused(self):
        with tempfile.TemporaryDirectory(dir=OUTPUT.parent) as name:
            base=Path(name);first=self.raws[0];p=base/first['file'];p.parent.mkdir(parents=True);p.write_bytes(b'changed')
            original=self.entry['base']
            try:
                self.entry['base']=base
                self.assertEqual(self.get('/export/raw.csv?dataset='+self.dataset+'&ordinal=0')[0],400)
            finally:self.entry['base']=original

def main():
    global CONFIG,OUTPUT
    p=argparse.ArgumentParser();p.add_argument('--config',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    CONFIG=a.config.resolve();OUTPUT=a.output.resolve();OUTPUT.parent.mkdir(parents=True,exist_ok=True)
    if OUTPUT.exists():raise ValueError('Fresh result required')
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Tests))
    OUTPUT.write_text(json.dumps(dict(status='PASS' if result.wasSuccessful() else 'FAIL',tests=result.testsRun,
        failures=len(result.failures),errors=len(result.errors),config_sha256=hashlib.sha256(CONFIG.read_bytes()).hexdigest(),
        dataset=Tests.dataset,observations_sha256=Tests.entry['manifest_sha256'],source_sha256={p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in [Path(__file__),ROOT/'demo/server.py',ROOT/'publicschemas/science.py',ROOT/'publicschemas/demo.py',ROOT/'publicschemas/timing_v1.py']}),indent=2)+'\n',encoding='utf-8')
    return 0 if result.wasSuccessful() else 1
if __name__=='__main__':raise SystemExit(main())
