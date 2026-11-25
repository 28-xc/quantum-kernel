"""Bounded rejection tests for the unfiltered sampling evidence parser."""
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
import csv, record_io as json, tempfile, unittest
import profile_windows as p

class EvidenceTests(unittest.TestCase):
 def setUp(self):
  base=Path(__file__).resolve().parent/'_tmp';base.mkdir(parents=True,exist_ok=True)
  self.tmp=tempfile.TemporaryDirectory(prefix='profile_parser_',dir=base);self.path=Path(self.tmp.name)/'raw.csv'
  self.rows=[[0,100,16],[1,101,0],[2,104,18]]
  self.summary={'samples':3,'core_samples':2,'outside_core_samples':1}
  self.mapping={'instructions':[{'rva':16,'disassembly_label':'real_label','label_rva':16,'instruction':'add','same_address_nm_aliases':['alias']} ]}
 def tearDown(self):self.tmp.cleanup()
 def call(self):
  with self.path.open('w',newline='') as f:
   w=csv.writer(f);w.writerow(['sample_id','observer_qpc','core_instruction_rva']);w.writerows(self.rows)
  return p.validate_samples(self.path,self.summary,256,self.mapping)
 def test_unknown_instruction_retained_no_nearest_symbol_guess(self):
  x=self.call();self.assertEqual(x['unknown_core_instruction_samples'],1);self.assertEqual(x['retained_samples'],3);self.assertEqual(x['labels'][0]['samples'],1)
 def test_omission_rejected(self):
  self.rows.pop(1)
  with self.assertRaises(ValueError):self.call()
 def test_reorder_rejected(self):
  self.rows.reverse()
  with self.assertRaises(ValueError):self.call()
 def test_duplicate_id_rejected(self):
  self.rows[1][0]=0
  with self.assertRaises(ValueError):self.call()
 def test_external_absolute_address_rejected(self):
  self.rows[2][2]=0x7ff800000000
  with self.assertRaises(ValueError):self.call()
 def test_decreasing_timestamp_rejected(self):
  self.rows[1][1]=99
  with self.assertRaises(ValueError):self.call()
 def test_declared_core_count_rejected(self):
  self.summary['core_samples']=3
  with self.assertRaises(ValueError):self.call()
 def test_zero_outside_does_not_disappear(self):
  self.rows=[[i,100+i,0] for i in range(3)];self.summary.update(core_samples=0,outside_core_samples=3)
  x=self.call();self.assertEqual(x['retained_samples'],3);self.assertEqual(x['outside_core_samples'],3);self.assertEqual(x['labels'],[])

if __name__=='__main__':unittest.main(verbosity=2)
