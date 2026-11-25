"""Actual native enablement plus controlled missing-CPU/OS-state cases."""
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
from unittest import mock
from http.server import ThreadingHTTPServer
ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT),str(ROOT/'demo')]
import server
CONFIG=None

class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.actual=server.Application(CONFIG)
        assert len(cls.actual.libs)==len(cls.actual.descriptors), 'Actual-host test requires every configured library enabled'
        cls.native=next(k for k,v in cls.actual.descriptors.items() if v['execution']['backend']=='x86_64')
        cls.portable=next(k for k,v in cls.actual.descriptors.items() if v['execution']['backend']=='portable')
        cls.portable_ids=[k for k,v in cls.actual.descriptors.items() if v['execution']['backend']=='portable']
    def disabled(self,host):
        with mock.patch.object(server.host_cpu,'query',return_value=host),mock.patch.object(server,'bind',wraps=server.bind) as loader:
            app=server.Application(CONFIG)
        self.assertEqual(list(app.libs),self.portable_ids);self.assertEqual(loader.call_count,len(self.portable_ids))
        self.assertFalse(app.descriptors[self.native]['execution_available'])
        self.assertEqual(len(app.catalog()['libraries']),len(self.actual.descriptors))
        with self.assertRaises(server.UnavailableLibraryError):app.run(dict(library=self.native,parameter=65,message_bytes=32,context_bytes=1,mode='normal'))
        return app
    def test_01_actual_all_parameters_and_recovery(self):
        for library in self.actual.libs:
            for p in self.actual.descriptors[library]['parameters']:
                for mode in ('normal','insufficient'):
                    r=self.actual.run(dict(library=library,parameter=p,message_bytes=1024,context_bytes=0,mode=mode))
                    self.assertTrue(r['canaries_ok'])
                    self.assertTrue(r['functional_checks_passed'] if mode=='normal' else r['recovery']['functional_checks_passed'])
    def test_02_missing_avx2(self):
        host=copy.deepcopy(self.actual.host);host['features'].remove('avx2');self.disabled(host)
    def test_03_os_ymm_disabled(self):
        host=copy.deepcopy(self.actual.host);host['xcr0']=3;self.disabled(host)
    def test_04_probe_unknown(self):
        host=copy.deepcopy(self.actual.host);host['query_succeeded']=False;self.disabled(host)
    def test_05_wrong_architecture(self):
        host=copy.deepcopy(self.actual.host);host['architecture']='unknown';self.disabled(host)
    def test_06_unsupported_api_and_portable_recovery(self):
        host=copy.deepcopy(self.actual.host);host['features'].remove('bmi2');app=self.disabled(host)
        listener=ThreadingHTTPServer(('127.0.0.1',0),server.handler(app,'pending'));address='127.0.0.1:'+str(listener.server_address[1]);listener.RequestHandlerClass=server.handler(app,address)
        thread=threading.Thread(target=listener.serve_forever,daemon=True);thread.start()
        try:
            connection=http.client.HTTPConnection(address)
            body=dict(library=self.native,parameter=65,message_bytes=32,context_bytes=1,mode='normal')
            connection.request('POST','/api/run',json.dumps(body),{'Content-Type':'application/json','X-Demo-Token':app.token})
            r=connection.getresponse();self.assertEqual(r.status,409);self.assertEqual(json.loads(r.read())['kind'],'UNAVAILABLE_ON_HOST');connection.close()
            result=app.run(body|{'library':self.portable});self.assertTrue(result['functional_checks_passed']);self.assertTrue(result['canaries_ok'])
        finally:listener.shutdown();listener.server_close();thread.join()
    def test_07_missing_execution_rejected_before_load(self):
        # A configuration name cannot establish the ISA of a hashed image.
        # Exercise both native and portable descriptors and the former legacy
        # name; every missing contract must fail before a library is loaded.
        for index in range(len(server.read(CONFIG)['libraries'])):
            for name in ('compact-fixed','compact-native'):
                config=copy.deepcopy(server.read(CONFIG))
                del config['libraries'][index]['execution']
                config['libraries'][index]['configuration']=name
                with mock.patch.object(server,'read',return_value=config),mock.patch.object(server,'bind') as loader:
                    with self.assertRaises(ValueError):server.Application(CONFIG)
                    loader.assert_not_called()

def main():
    global CONFIG
    p=argparse.ArgumentParser();p.add_argument('--config',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();CONFIG=a.config.resolve()
    if a.output.exists():raise ValueError('Fresh result required')
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Tests))
    record=dict(status='PASS' if result.wasSuccessful() else 'FAIL',tests=result.testsRun,failures=len(result.failures),errors=len(result.errors),configuration_sha256=hashlib.sha256(CONFIG.read_bytes()).hexdigest(),scope='Actual two-library functional checks and synthetic missing feature/OS-state query results; unsupported native is never loaded by the application.')
    a.output.write_text(json.dumps(record,indent=2)+'\n',encoding='utf-8');return 0 if result.wasSuccessful() else 1
if __name__=='__main__':raise SystemExit(main())
