"""Fixed import-admission negative cases. Reads records; never runs a target."""
from pathlib import Path
import argparse
import copy
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
import sys
import tempfile
import unittest
from types import SimpleNamespace
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools.import_application_owner import Resolver,import_data
from publicschemas.application_v1 import read,sha

SOURCE=None


class ImportAdmission(unittest.TestCase):
    def rejected(self,change,pattern):
        d=copy.deepcopy(read(SOURCE/'result.xml'));change(d)
        with tempfile.TemporaryDirectory(prefix='application-import-check-') as temporary:
            p=Path(temporary);(p/'result.xml').write_text(json.dumps(d),encoding='utf-8')
            args=SimpleNamespace(input=p,output=p/'output',path_map=[],current_id='lattice-native',audit=None)
            with self.assertRaisesRegex(ValueError,pattern):import_data(args)
            self.assertFalse((p/'output').exists())
    def test_unknown_completion_field(self):self.rejected(lambda d:d.update(private_pass=True),'Unexpected')
    def test_incomplete_run(self):self.rejected(lambda d:d.update(processes=431),'Incomplete')
    def test_failed_run(self):self.rejected(lambda d:d.update(status='FAILED'),'Incomplete')
    def test_trimmed_run(self):self.rejected(lambda d:d.update(trimmed_processes=1),'Incomplete')
    def test_wrong_plan_hash(self):self.rejected(lambda d:d['plan'].update(sha256='0'*64),'identity mismatch')
    def test_missing_plan(self):self.rejected(lambda d:d['plan'].update(path=str(SOURCE/'absent-plan.xml')),'identity mismatch')
    def test_unknown_reference_field(self):self.rejected(lambda d:d['plan'].update(ignored=True),'Unexpected')
    def test_partial_duration(self):self.rejected(lambda d:d.update(elapsed_controller_seconds=601),'timeout')
    def test_records_outside_acquisition(self):self.rejected(lambda d:None,'Records outside')
    def test_prefix_boundary(self):
        with tempfile.TemporaryDirectory() as t:
            r=Resolver(['/home/run='+t])
            self.assertEqual(r.path('/home/run/a'),Path(t).resolve()/'a')
            self.assertNotEqual(r.path('/home/runner/a'),Path(t).resolve()/'ner/a')
            with self.assertRaisesRegex(ValueError,'escaped'):r.path('/home/run/../outside')
    def test_wrong_mapped_hash(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'a';p.write_bytes(b'bound')
            r=Resolver(['/original='+t]);self.assertEqual(r.check(dict(path='/original/a',sha256=sha(p))),p)
            with self.assertRaisesRegex(ValueError,'identity mismatch'):r.check(dict(path='/original/a',sha256='0'*64))


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--acquisition',type=Path,required=True);a,rest=p.parse_known_args();SOURCE=a.acquisition.resolve()
    unittest.main(argv=[sys.argv[0],*rest])
