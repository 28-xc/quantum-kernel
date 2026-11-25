"""Integrity regressions for actual recorded memory-component observations."""
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
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from publicschemas.resource_watermarks_v1 import derive_artifact,shard,strict_line,trial_validate,validate_method_sources
from publicschemas.profiling_v1 import read

class ResourceWatermarks(unittest.TestCase):
    def reject(self, change):
        rows=copy.deepcopy(self.rows);change(rows)
        with self.assertRaises(ValueError):derive_artifact(self.artifact,self.point,rows)
    def test_actual_valid_artifact(self):
        result=derive_artifact(self.artifact,self.point,self.rows)
        self.assertEqual(result['trials'],1348);self.assertEqual(len(result['cells']),18)
        self.assertGreater(result['classification_counts']['WORKSPACE_OOM'],0)
        self.assertTrue(all(x['full_core_simultaneous_observed_peak_bytes'] is None for x in result['cells']))
    def test_omitted_record(self):self.reject(lambda x:x.pop(7))
    def test_reordered_record(self):self.reject(lambda x:x.reverse())
    def test_private_field(self):self.reject(lambda x:x[0]['result'].update(private_plan='hidden'))
    def test_false_success(self):self.reject(lambda x:x[0].update(exit_code=1))
    def test_duplicate_confirmation_seed(self):
        def change(rows):
            seq=[r for r in rows if r['reason']=='fixed_workspace_stack_new_seed_sequence']
            seq[1]['arguments']['seed']=seq[0]['arguments']['seed']
            seq[1]['result']['seed']=seq[0]['result']['seed']
        self.reject(change)
    def test_watermark_over_reserved(self):
        def change(rows):
            r=next(x for x in rows if x['reason']=='fixed_workspace_stack_new_seed_sequence')
            r['result']['step_arena_high_water'][0]=r['arguments']['arena_bytes']+1
        self.reject(change)
    def test_result_request_disagreement(self):self.reject(lambda x:x[0]['result'].update(seed=1))
    def test_oom_recovery(self):
        def change(rows):
            r=next(x for x in rows if x['classification']=='WORKSPACE_OOM')
            r['result']['recovery_full_sequence_ok']=False
        self.reject(change)
    def test_forged_oom_from_success(self):
        def change(rows):
            r=next(x for x in rows if x['classification']=='WORKSPACE_OOM')['result']
            r.update(rc=0,worker_rc=0,step_rc=[0,0,0],allocation_failures=0)
        self.reject(change)
    def test_undercharged_stack_budget(self):
        def change(rows):
            r=next(x for x in rows if x['reason']=='explicit_total_budget')
            r['arguments']['stack_bytes']+=256;r['result']['stack_enforced_bytes']+=256
        self.reject(change)
    def test_changed_budget_operation(self):
        def change(rows):
            r=next(x for x in rows if x['reason']=='explicit_total_budget')
            r['arguments']['operation']=0;r['result']['operation']=0
        self.reject(change)
    def test_false_fault(self):
        def change(rows):
            r=next(x for x in rows if x['result'] is None)
            r['exit_code']=0
        self.reject(change)
    def test_stack_scan_omission(self):
        def change(rows):
            r=next(x for x in rows if x['reason']=='stack_grid')
            r['reason']='workspace_discovery'
        self.reject(change)
    def test_duplicate_json_keys(self):
        with self.assertRaises(ValueError):strict_line('{"a":1,"a":2}')
    def test_nonfinite_json(self):
        with self.assertRaises(ValueError):strict_line('{"a":NaN}')
    def test_sha_identity(self):
        desc=dict(self.artifact['raw']);desc['sha256']='0'*64
        with self.assertRaises(ValueError):shard(self.root,desc)
    def test_path_escape(self):
        desc=dict(self.artifact['raw']);desc['path']='../private.records.xml'
        with self.assertRaises(ValueError):shard(self.root,desc)
    def test_historical_source_set(self):
        self.assertEqual(len(validate_method_sources(self.root,self.methods)),len(self.methods))
    def test_historical_source_hash_change(self):
        desc=copy.deepcopy(self.methods);desc[0]['sha256']='0'*64
        with self.assertRaises(ValueError):validate_method_sources(self.root,desc)
    def test_historical_source_duplicate(self):
        with self.assertRaises(ValueError):validate_method_sources(self.root,self.methods+self.methods[:1])
    def test_historical_source_path_escape(self):
        desc=copy.deepcopy(self.methods);desc[0]['path']='../private.py'
        with self.assertRaises(ValueError):validate_method_sources(self.root,desc)

def main():
    p=argparse.ArgumentParser();p.add_argument('--observations',type=Path,required=True)
    p.add_argument('--resources',type=Path,required=True);a=p.parse_args()
    data=read(a.observations);resources=read(a.resources);artifact=data['artifacts'][0]
    ResourceWatermarks.root=a.observations.resolve().parent
    ResourceWatermarks.artifact=artifact
    ResourceWatermarks.point=next(x for x in resources['points'] if x['id']==artifact['resource_id'])
    ResourceWatermarks.rows=shard(ResourceWatermarks.root,artifact['raw'])
    ResourceWatermarks.methods=data['method_sources']
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ResourceWatermarks))
    if not result.wasSuccessful():raise SystemExit(1)

if __name__=='__main__':main()
