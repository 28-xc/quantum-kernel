"""Offline external configuration and error contracts; no port/SSH/service opened."""
from pathlib import Path
import copy
import hashlib
import io
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
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
import test_ch32_bridge as fixtures
from demo import platform_config
from demo.platform_providers import ProviderError
from demo.platform_server import handler


class ExternalConfigTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.BridgeTests();self.fixture.setUp();self.root=self.fixture.root
        self.driver=self.root/'driver.py';self.driver.write_text("raise OSError('PRIVATE diagnostic must not enter UI')\n",encoding='utf8')
        self.dep=self.root/'dependency.py';self.dep.write_text('# locked offline dependency\n',encoding='utf8')
        self.value=dict(schema='lattice.ch32_connection.v1',driver=self.item(self.driver),dependencies=[self.item(self.dep)],
            port='COM13',timeout_seconds=120,expected_elf_sha256=fixtures.ELF,expected_hello=self.fixture.expected,
            timer_receipt=self.item(Path(self.fixture.descriptor['path'])),records_directory='private records',
            library_id='ch32_compact',title='CH32V307')
        self.config=self.root/'device.xml';self.write()
    def tearDown(self):self.fixture.tearDown()
    def item(self,p):return dict(path=p.name,sha256=hashlib.sha256(p.read_bytes()).hexdigest())
    def write(self):self.config.write_text(json.dumps(self.value),encoding='utf8')
    def test_relative_paths_and_no_driver_execution_during_load(self):
        provider=platform_config.board_provider(self.config)
        self.assertEqual(provider.state,'disconnected')
        self.assertFalse((self.root/'private records').exists())
        with self.assertRaisesRegex(ProviderError,'DEVICE_UNAVAILABLE'):provider.catalog()
        self.assertEqual(provider.state,'disconnected')
    def test_changed_dependency_rejected_before_module_exec(self):
        provider=platform_config.board_provider(self.config);self.dep.write_text('changed',encoding='utf8')
        with self.assertRaisesRegex(ValueError,'External input changed'):provider.catalog()
    def test_closed_config_and_clock_expected(self):
        for change in [lambda v:v.update(command='ignored?'),lambda v:v.update(port='COM13;bad'),
                       lambda v:v['expected_hello'].pop('rcc_config'),lambda v:v.update(dependencies=[v['driver']])]:
            old=copy.deepcopy(self.value);change(self.value);self.write()
            with self.subTest(config=self.value),self.assertRaises(ValueError):platform_config.board_provider(self.config)
            self.value=old;self.write()
    def test_relative_arm_credentials_no_transport(self):
        p=self.root/'arm.xml';p.write_text(json.dumps(dict(ssh_executable='ssh.exe',identity_file='private/key',known_hosts_file='known_hosts')),encoding='utf8')
        value=platform_config.arm_config(p)
        self.assertEqual(value['identity_file'],str((self.root/'private/key').resolve()))
    def test_unavailable_response_is_bounded_friendly_and_no_retry(self):
        class Base:
            @staticmethod
            def handler(*args):return object
        class App:
            token='test';calls=0
            def run(self,value):
                self.calls+=1;raise ProviderError('DEVICE_UNAVAILABLE')
        app=App();H=handler(Base,app,'127.0.0.1:1');h=object.__new__(H)
        data=b'{}';h.path='/api/run';h.headers={'X-Demo-Token':'test','Content-Type':'application/json','Content-Length':str(len(data))}
        h.rfile=io.BytesIO(data);h.valid_host=lambda:True;sent=[];h.send=lambda *x:sent.append(x)
        h.do_POST();self.assertEqual(app.calls,1);self.assertEqual(sent[0][0],409)
        self.assertIn('开发板暂不可用',sent[0][1]['error']);self.assertNotIn('PRIVATE',str(sent))


if __name__=='__main__':unittest.main()
