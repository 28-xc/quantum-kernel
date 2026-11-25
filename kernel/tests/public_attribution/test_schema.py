"""Publication-boundary checks: reject extra fields and altered study identities."""
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
import copy, record_io as json, sys, unittest
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from publicschemas import shared_keccak_v1 as shared,timing_attribution_v1 as timing
DATA=ROOT/'data' if (ROOT/'data/shared_keccak/observations.xml').exists() else ROOT.parent/'data'
class Boundary(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.shared=json.loads((DATA/'shared_keccak/observations.xml').read_text());cls.timing=json.loads((DATA/'timing_attribution/observations.xml').read_text())
 def test_registered_records(self):self.assertTrue(shared.validate(self.shared));self.assertTrue(timing.validate(self.timing))
 def test_extra_top_level(self):
  d=copy.deepcopy(self.shared);d['execution_progress']='complete'
  with self.assertRaises(ValueError):shared.validate(d)
 def test_extra_nested(self):
  d=copy.deepcopy(self.timing);d['studies'][1]['results'][0]['management_note']='hidden'
  with self.assertRaises(ValueError):timing.validate(d)
 def test_absolute_path(self):
  d=copy.deepcopy(self.shared);d['measurements']['jobs'][0]['raw']['path']='D:/example/private.csv'
  with self.assertRaises(ValueError):shared.validate(d)
 def test_missing_samples(self):
  d=copy.deepcopy(self.timing);d['studies'][2]['retained_samples']-=100000
  with self.assertRaises(ValueError):timing.validate(d)
 def test_profile_identity(self):
  d=copy.deepcopy(self.shared);d['profile']['id']='speed'
  with self.assertRaises(ValueError):shared.validate(d)
if __name__=='__main__':unittest.main()
