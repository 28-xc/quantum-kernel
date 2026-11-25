"""Public arithmetic evidence integrity and clock-derived statistics."""
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
import csv, record_io as json, subprocess, sys, tempfile, unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from publicschemas import primitives_v1 as model

class PrimitiveEvidence(unittest.TestCase):
 def setUp(self):
  base=Path(__file__).resolve().parent/'_tmp';base.mkdir(parents=True,exist_ok=True)
  self.tmp=tempfile.TemporaryDirectory(prefix='primitive-schema-',dir=base);self.root=Path(self.tmp.name)
  assert self.root.resolve().is_relative_to(base.resolve())
  (self.root/'raw').mkdir();self.path=self.root/'observations.xml';cases=[]
  for q,op,rank in sorted(model.expected_cases('canonical_research_component')):
   p=self.root/'raw'/f'q{q}_op{op}_rank{rank}.csv'
   with p.open('w',encoding='utf-8',newline='') as fp:
    writer=csv.writer(fp);writer.writerow(model.FIELDS)
    for i in range(-10,100):writer.writerow([i,int(i<0),100,100+i,10000000,100+i,i+10,0])
   cases.append(dict(q=q,operation=op,rank=rank,frequency=10000000,checksum=109,raw=dict(path=p.relative_to(self.root).as_posix(),sha256=model.sha(p))))
  digest='a'*64;self.data=dict(schema=model.SCHEMA,dataset_id='fixture',platform='windows_x86_64',measurement=model.METHOD,
   groups=[dict(id='canonical-round00',configuration='canonical',round=0,component='canonical_research_component',
    prepared_sha256=digest,plan_sha256=digest,result_sha256=digest,executable_sha256=digest,archive_sha256=None,
    oracle=dict(cases_per_operation=1000,cases=12000,seed=1,canaries=True,reference='schoolbook_signed_64_bit'),cpu=0,seed=1,cases=cases)])
  self.save()
 def save(self):self.path.write_text(json.dumps(self.data),encoding='utf-8')
 def tearDown(self):self.tmp.cleanup()
 def modify_raw(self,change):
  case=self.data['groups'][0]['cases'][0];p=self.root/case['raw']['path'];rows=p.read_text().splitlines();change(rows)
  p.write_text('\n'.join(rows)+'\n');case['raw']['sha256']=model.sha(p);self.save()
 def test_known_clock_statistics(self):
  r=model.recompute(self.path);self.assertEqual(r['raw_rows'],1320);self.assertEqual(r['warmup_rows'],120)
  c=r['cells'][0];self.assertEqual(c['batch_mean_median_ns'],149.5);self.assertEqual(c['batch_mean_p95_ns'],194.05)
 def test_documented_standalone_command(self):
  tool=Path(__file__).resolve().parents[1]/'tools/recompute_primitives.py';out=self.root/'summary.xml'
  result=subprocess.run([sys.executable,'-B',str(tool),str(self.path),'--output',str(out)],capture_output=True,text=True,timeout=15)
  self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(model.read(out),model.recompute(self.path))
 def test_omitted_operation(self):
  self.data['groups'][0]['cases'].pop();self.save()
  with self.assertRaises(ValueError):model.recompute(self.path)
 def test_internal_field_rejected(self):
  self.data['internal_gate']='passed';self.save()
  with self.assertRaises(ValueError):model.recompute(self.path)
 def test_changed_raw_identity(self):
  p=self.root/self.data['groups'][0]['cases'][0]['raw']['path'];p.write_text(p.read_text()+'\n')
  with self.assertRaises(ValueError):model.recompute(self.path)
 def test_ordered_batches_required(self):
  self.modify_raw(lambda rows:rows.__setitem__(slice(2,4),rows[2:4][::-1]))
  with self.assertRaises(ValueError):model.recompute(self.path)
 def test_timer_quantity_required(self):
  self.modify_raw(lambda rows:rows.__setitem__(12,rows[12].replace(',101,11,0',',777,11,0')))
  with self.assertRaises(ValueError):model.recompute(self.path)
 def test_failed_batch_retained_and_rejected(self):
  self.modify_raw(lambda rows:rows.__setitem__(12,rows[12][:-1]+'1'))
  with self.assertRaises(ValueError):model.recompute(self.path)
 def test_unknown_contract(self):
  self.data['groups'][0]['component']='individual_call_measurement';self.save()
  with self.assertRaises(ValueError):model.recompute(self.path)
 def test_unreferenced_csv(self):
  (self.root/'raw'/'extra.csv').write_text('extra')
  with self.assertRaises(ValueError):model.recompute(self.path)

if __name__=='__main__':unittest.main(verbosity=2)
