"""Closed public image schema and deliberately corrupted technical observations."""
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
import argparse, copy, record_io as json, sys, unittest
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from publicschemas.program_space_v1 import validate
DATA=None
class Tests(unittest.TestCase):
    def mutate(self,fn):
        v=copy.deepcopy(DATA);fn(v)
        with self.assertRaises(ValueError):validate(v)
    def test_01_complete_observations(self):validate(DATA)
    def test_02_private_field(self):self.mutate(lambda v:v.update(private_budget=200))
    def test_03_private_path(self):self.mutate(lambda v:v['pruning'][0].update(compiler='D:/private/compiler'))
    def test_04_delta(self):self.mutate(lambda v:v['sharing'][0].update(readonly_delta_bytes=0.123))
    def test_05_section_sum(self):self.mutate(lambda v:v['images'][0]['image'].update(text_bytes=1))
    def test_06_wrong_sha(self):self.mutate(lambda v:v['images'][0]['binary'].update(sha256='0'*64))
    def test_07_file_escape(self):self.mutate(lambda v:v['images'][0]['nm'].update(path='../private/nm.log'))
    def test_08_missing_parameter_record(self):self.mutate(lambda v:v['pruning'][0]['checks']['shared']['rows'].pop())
    def test_09_duplicate_scope(self):self.mutate(lambda v:v['pruning'].append(v['pruning'][0]))
    def test_10_archive_not_image(self):self.mutate(lambda v:v['pruning'][0]['archive'].update(is_loaded_image=True))
    def test_11_cross_platform(self):self.mutate(lambda v:v['sharing'][0].update(platform='wrong'))
    def test_12_unsupported_code(self):self.mutate(lambda v:v['pruning'][0].update(unsupported_status=0))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--observations',type=Path,required=True);a=p.parse_args()
    DATA=json.loads(a.observations.read_text(encoding='utf-8'))
    r=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Tests))
    raise SystemExit(0 if r.wasSuccessful() else 1)
