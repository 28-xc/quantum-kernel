"""Finite synthetic statistical checks; these are not benchmark observations."""
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
import numpy as np
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'analysis'))
import mean_tail_statistics as stats
from publicschemas import mean_tail_model as model
from publicschemas.pooled_conditions import SEMANTICS

def fixture(variable=False):
 h='1'*64;labels=['synthetic_reference','synthetic_candidate'];blocks=3;n=4;warm=1
 data=dict(schema='lattice.block_observations.v2',dataset_id='synthetic_mean_tail_only',platform='windows_x86_64',execution='native',target_machine='x86_64',driver_sha256=h,crypto_library_sha256=h,
  experiment=dict(blocks=blocks,samples_per_run=n,warmups_per_run=warm,seed=7,message_bytes=1024,context_bytes=0,cpu_index=0,replication_unit='randomized_complete_block',timing_boundary='fresh_serialized_key_service'),
  configurations=[dict(id=l,provider='lattice',import_pct='none',workspace_reserved=9536,library_sha256=str(i+2)*64,supplied_lattice_library_sha256=str(i+2)*64) for i,l in enumerate(labels)],schedule=[],runs=[],analysis=None)
 raw=np.array([[40,44,48,400],[120,160,200,2400],[12,16,24,4000]],dtype=float)
 for b in range(blocks):
  for ci,(p,o) in enumerate(model.CELLS):
   seed=100+b*10000+p*3+o
   for li,label in enumerate(labels):
    ordinal=len(data['runs']);data['schedule'].append(dict(ordinal=ordinal,block=b,parameter=p,operation=o,configuration=label,seed=seed))
    factor=1 if li==0 else ([.25,.5,2][b] if variable else .5)
    values=[999999]+[int(x*(ci+1)*factor) for x in raw[b]]
    samples=[dict(case_id=f'{seed:016x}-{p}-{o}-{j}',iteration=j-warm,warmup=j<warm,elapsed_ticks=x,tick_frequency=10**9,elapsed_ns=float(x),status=0,entropy_sha256=h,message_sha256=h,context_sha256=h) for j,x in enumerate(values)]
    data['runs'].append(dict(ordinal=ordinal,driver_exit_code=0,driver_status='PASS',source_csv_sha256=h,source_log_sha256=h,source_stderr_sha256=h,input_sequence_sha256=h,output_sequence_sha256=h,timer='QueryPerformanceCounter',frequency=10**9,workspace_highwater=0,entropy_mode='supplied_test_entropy',implementation_metadata=dict(SEMANTICS),samples=samples))
 data['completeness']=dict(planned_runs=len(data['runs']),recorded_runs=len(data['runs']),missing_runs=0,sample_rows=len(data['runs'])*(n+warm),failed_sample_rows=0,failed_runs=0,archive_status='COMPLETE')
 return data,[dict(id='synthetic_pair',reference=labels[0],candidate=labels[1])]

class Tests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.data,cls.pairs=fixture();cls.summary,cls.reps=stats.analyze(cls.data,cls.pairs,'1'*64,resamples=256,seed=901)
 def test_01_direction(self):
  pair=self.summary['comparisons'][0];self.assertEqual(pair['mean_time_ratio_geomean'],.5)
  for row in pair['cells']:
   for ratio in row['ratios'].values():self.assertEqual(ratio,dict(value=.5,ci95=[.5,.5]))
 def test_02_shared_block_dependence(self):
  a=self.reps['mean_tail_replicates_ns'];np.testing.assert_array_equal(a[1],a[0]*.5)
  self.assertGreater(float(np.std(a[0,0,0])),0)
  for cell in range(18):np.testing.assert_allclose(a[:,cell],a[:,0]*(cell+1),rtol=2e-15,atol=1e-9)
 def test_03_explicit_resampled_pool_oracle(self):
  data,pairs=fixture(True);summary,reps=stats.analyze(data,pairs,'2'*64,resamples=73,seed=992)
  labels,arrays=stats.shared.observations_arrays(data);counts=reps['complete_block_counts'];actual=reps['mean_tail_replicates_ns']
  for li,label in enumerate(labels):
   for cell,(p,o) in enumerate(model.CELLS):
    for draw,count in enumerate(counts):
     chosen=np.repeat(np.arange(3),count);x=arrays[label,p,o][chosen].ravel();expected=[float(np.mean(x)),*np.quantile(x,[.5,.95,.99],method='linear').tolist()]
     np.testing.assert_allclose(actual[li,cell,:,draw],expected,rtol=2e-15,atol=1e-9)
  ratio=actual[1]/actual[0]
  for i,row in enumerate(summary['comparisons'][0]['cells']):
   for s,name in enumerate(model.STATISTICS):np.testing.assert_allclose(row['ratios'][name]['ci95'],np.quantile(ratio[i,s],[.025,.975]),rtol=0,atol=1e-12)
 def test_04_extremes_and_warmups(self):
  row=self.summary['cells'][0];self.assertEqual(row['maximum_ns'],4000)
  self.assertEqual(self.summary['counts'],dict(blocks=3,samples_per_run=4,raw_rows=540,measured_rows=432,warmup_rows=108,deleted_rows=0))
  self.assertGreater(row['statistics']['p99']['ns'],row['statistics']['p95']['ns'])
 def reject(self,data):
  with self.assertRaises(ValueError):stats.analyze(data,self.pairs,'1'*64,resamples=2,seed=901)
 def test_05_missing_run(self):
  data=copy.deepcopy(self.data);data['runs'].pop();self.reject(data)
 def test_06_failed_process(self):
  data=copy.deepcopy(self.data);data['runs'][0]['driver_exit_code']=1;data['completeness']['failed_runs']=1;self.reject(data)
 def test_07_failed_sample(self):
  data=copy.deepcopy(self.data);data['runs'][0]['samples'][1]['status']=-6;data['completeness']['failed_sample_rows']=1;self.reject(data)
 def test_08_zero_not_filtered(self):
  data=copy.deepcopy(self.data);data['runs'][0]['samples'][1].update(elapsed_ticks=0,elapsed_ns=0.);self.reject(data)
 def test_09_unpaired_output(self):
  data=copy.deepcopy(self.data);data['runs'][1]['output_sequence_sha256']='9'*64;self.reject(data)
 def test_10_wrong_direction(self):
  summary=copy.deepcopy(self.summary);summary['method']['ratio_direction']='reference_over_candidate'
  with self.assertRaises(ValueError):model.validate(summary,self.data)
 def test_11_unknown_field(self):
  summary=copy.deepcopy(self.summary);summary['extra']=1
  with self.assertRaises(ValueError):model.validate(summary,self.data)
 def test_12_changed_binary(self):
  summary=copy.deepcopy(self.summary);summary['configurations'][0]['library_sha256']='7'*64
  with self.assertRaises(ValueError):model.validate(summary,self.data)
 def test_13_changed_source(self):
  summary=copy.deepcopy(self.summary);summary['source_code_hashes']['analysis/pooled_statistics.py']='8'*64
  with self.assertRaises(ValueError):stats.recompute(self.data,summary,'1'*64)
 def test_14_exact_recompute(self):
  result=stats.recompute(self.data,self.summary,'1'*64);self.assertEqual(result['status'],'EXACT_PUBLIC_MEAN_TAIL_RECOMPUTED')
 def test_15_changed_estimate(self):
  summary=copy.deepcopy(self.summary);summary['cells'][0]['statistics']['mean']['ns']+=1
  with self.assertRaises(ValueError):stats.recompute(self.data,summary,'1'*64)
 def test_16_duplicate_pair(self):
  with self.assertRaises(ValueError):stats.analyze(self.data,self.pairs*2,'1'*64,resamples=2)

def main():
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();suite=unittest.defaultTestLoader.loadTestsFromTestCase(Tests)
 result=unittest.TextTestRunner(verbosity=2).run(suite)
 stats.shared.write(a.output,dict(status='PASS' if result.wasSuccessful() else 'FAIL',scope='Finite synthetic inference checks; no performance observations or crypto execution.',tests_run=result.testsRun,failures=len(result.failures),errors=len(result.errors),explicit_pooled_oracle_values=2*18*73*4,source_hashes=stats.sources(),test_sha256=stats.shared.sha(__file__)))
 if not result.wasSuccessful():sys.exit(1)
if __name__=='__main__':main()
