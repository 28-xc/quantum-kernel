"""Small deterministic integrity regressions for the public profile reader."""
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
import copy, record_io as json, shutil, sys, tempfile, unittest
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from publicschemas import profiling_v1 as m
class Profiles(unittest.TestCase):
 def setUp(self):
  base=ROOT/'build'/'public_profile_tests';base.mkdir(parents=True,exist_ok=True)
  self.tmp=tempfile.TemporaryDirectory(dir=base);self.root=Path(self.tmp.name)
  (self.root/'raw').mkdir();(self.root/'mapping').mkdir()
  h='1'*64
  mapping=dict(binary_sha256=h,image_bytes=4096,instructions=[dict(rva=64,instruction='ret',disassembly_label='nttpack',label_rva=64,same_address_nm_aliases=[]),dict(rva=80,instruction='ret',disassembly_label='keccak',label_rva=80,same_address_nm_aliases=[])])
  mp=self.root/'mapping'/'core.xml';mp.write_text(json.dumps(mapping),encoding='utf-8')
  self.d=dict(schema=m.SCHEMA,dataset_id='fixture',platform='windows_x86_64',driver_sha256=h,crypto_library_sha256=h,acquisition_manifest_sha256=h,source_result_sha256=h,
    measurement=dict(method='suspended_own_worker_instruction_pointer',sample_period_ms=1,quantity='instruction_sample_count',latency_estimator=False,sample_trimming=False,label_scope='exact_disassembly_labels_including_inlined_code',category_rule_version=1,message_bytes=1024,context_bytes=0,input_scope='fixed_key_and_message_fresh_operation_coins'),
    libraries=[dict(configuration='core',binary_sha256=h,mapping=dict(path='mapping/core.xml',sha256=m.sha(mp)))],cells=[])
  for p in (512,768,1024,44,65,87):
   for o in (0,1,2):
    cid=f'core_{p}_{o}';raw=self.root/'raw'/(cid+'.csv');raw.write_bytes(b'sample_id,observer_qpc,core_instruction_rva\n0,10,64\n1,11,80\n2,12,0\n')
    self.d['cells'].append(dict(id=cid,configuration='core',parameter=p,operation=o,iterations=100,seed=1,worker_cpu=0,observer_cpu=2,timer_period_ms=1,qpc_frequency=10000000,workspace_reserved=262144,samples=3,core_samples=2,outside_core_samples=1,dropped=0,context_failures=0,resume_failures=0,raw=dict(path=f'raw/{cid}.csv',sha256=m.sha(raw))))
 def tearDown(self):self.tmp.cleanup()
 def run_data(self):
  p=self.root/'observations.xml';p.write_text(json.dumps(self.d),encoding='utf-8');return m.recompute(p)
 def edit_raw(self,b):
  c=self.d['cells'][0];p=self.root/c['raw']['path'];p.write_bytes(b);c['raw']['sha256']=m.sha(p)
 def test_exact_counts_and_exclusive_classification(self):
  r=self.run_data();self.assertEqual(r['sample_count'],54);self.assertEqual(r['group_counts'],dict(encoding_and_representation=18,shake_and_keccak=18,outside_core=18))
 def test_missing_operation(self):
  self.d['cells'].pop()
  with self.assertRaises(ValueError):self.run_data()
 def test_extra_private_field(self):
  self.d['cells'][0]['private_note']='fixture'
  with self.assertRaises(ValueError):self.run_data()
 def test_hash_tamper(self):
  (self.root/self.d['cells'][0]['raw']['path']).write_bytes(b'changed')
  with self.assertRaises(ValueError):self.run_data()
 def test_reordered_raw_even_with_new_hash(self):
  self.edit_raw(b'sample_id,observer_qpc,core_instruction_rva\n1,10,64\n0,11,80\n2,12,0\n')
  with self.assertRaises(ValueError):self.run_data()
 def test_unmapped_instruction(self):
  self.edit_raw(b'sample_id,observer_qpc,core_instruction_rva\n0,10,65\n1,11,80\n2,12,0\n')
  with self.assertRaises(ValueError):self.run_data()
 def test_extra_column(self):
  self.edit_raw(b'sample_id,observer_qpc,core_instruction_rva\n0,10,64,extra\n1,11,80\n2,12,0\n')
  with self.assertRaises(ValueError):self.run_data()
 def test_outside_count_changed(self):
  self.d['cells'][0]['outside_core_samples']=0
  with self.assertRaises(ValueError):self.run_data()
 def test_unknown_artifact(self):
  (self.root/'raw'/'extra.csv').write_bytes(b'')
  with self.assertRaises(ValueError):self.run_data()
 def test_wrong_binary_mapping(self):
  self.d['libraries'][0]['binary_sha256']='2'*64
  with self.assertRaises(ValueError):self.run_data()
if __name__=='__main__':unittest.main()
