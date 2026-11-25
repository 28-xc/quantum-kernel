"""Synthetic schema/query cases; these numbers are not algorithm measurements."""
import copy
from pathlib import Path
import sys,unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from publicschemas import resources as m

def fixture():
    p=dict(id='portable',configuration='compact-fixed',platform='windows_x86_64',binary_sha256='a'*64,
        parameters=list(m.PARAMETERS),build=dict(backend='portable',compiler='test',optimization='Os',lto=True,target='x86_64'),
        program_bytes=100000,reserved_components=dict(zip(m.COMPONENTS,[10720,2048,64,32,0])),
        core_reserved_bytes=12864,common_context_validated=True,
        source_sha256={k:'a'*64 for k in ('image','build','resource','audit','common_context_result','common_context_audit')},scope=['Synthetic unit test'])
    d=dict(schema=m.SCHEMA,dataset_id='resources',core_source_commit='a'*40,verification_sha256='a'*64,points=[p],measurement_scope=['Synthetic unit test'])
    s=dict(schema=m.TIMING_SCHEMAS[0],dataset_id='timings',platform='windows_x86_64',execution='native',
        configurations=[dict(id='compact',provider='lattice',library_sha256='a'*64,workspace_reserved=10720)],
        cells=[dict(configuration='compact',parameter=p,operation=o,pooled_mean_ns=10+p+o) for p,o in sorted(m.CELLS)])
    q=dict(platform='windows_x86_64',timing_dataset='timings',ram_bytes=16384,program_bytes=131072)
    return d,s,q

class ResourceTests(unittest.TestCase):
    def test_valid_query(self):
        d,s,q=fixture();r=m.select(d,s,q);self.assertEqual(r['selected']['configuration'],'compact')
        self.assertAlmostEqual(r['selected']['equal_weight_18_operation_mean_ns'],sum(x['pooled_mean_ns'] for x in s['cells'])/18)
    def test_no_fit(self):
        d,s,q=fixture();q['ram_bytes']=1;self.assertIsNone(m.select(d,s,q)['selected'])
    def test_exact_workspace(self):
        d,s,q=fixture();s['configurations'][0]['workspace_reserved']+=32;self.assertIsNone(m.select(d,s,q)['selected'])
    def test_exact_binary(self):
        d,s,q=fixture();s['configurations'][0]['library_sha256']='b'*64;self.assertIsNone(m.select(d,s,q)['selected'])
    def test_all_operations(self):
        d,s,q=fixture();s['cells'].pop()
        with self.assertRaises(ValueError):m.select(d,s,q)
    def test_separate_study(self):
        d,s,q=fixture();q['timing_dataset']='other'
        with self.assertRaises(ValueError):m.select(d,s,q)
    def test_separate_platform(self):
        d,s,q=fixture();q['platform']='linux_aarch64'
        with self.assertRaises(ValueError):m.select(d,s,q)
    def test_emulation_not_used_for_native_timing(self):
        d,s,q=fixture();s['execution']='instruction_emulation'
        with self.assertRaises(ValueError):m.select(d,s,q)
    def test_ram_sum(self):
        d,s,q=fixture();d['points'][0]['core_reserved_bytes']-=1
        with self.assertRaises(ValueError):m.select(d,s,q)
    def test_false_context_witness(self):
        d,s,q=fixture();p=d['points'][0];p['common_context_validated']=False
        for k in ('common_context_result','common_context_audit'):p['source_sha256'][k]=None
        self.assertIsNone(m.select(d,s,q)['selected'])
    def test_missing_common_witness_hash_rejected(self):
        d,s,q=fixture();d['points'][0]['source_sha256']['common_context_result']=None
        with self.assertRaises(ValueError):m.select(d,s,q)
    def test_private_field(self):
        d,s,q=fixture();d['internal']='secret'
        with self.assertRaises(ValueError):m.validate(d)
    def test_median_not_used(self):
        d,s,q=fixture()
        for r in s['cells']:r['pooled_median_ns']=.001
        self.assertGreater(m.select(d,s,q)['selected']['equal_weight_18_operation_mean_ns'],100)
    def test_unknown_program_space_not_zero(self):
        d,s,q=fixture();d['points'][0]['program_bytes']=0
        with self.assertRaises(ValueError):m.validate(d)
    def test_scope_must_be_list(self):
        d,s,q=fixture();d['measurement_scope']='not-a-list'
        with self.assertRaises(ValueError):m.validate(d)
    def test_unmeasured_comparison_is_explicit_unknown(self):
        d,s,q=fixture();s['configurations'].append(dict(id='external',provider='openssl',library_sha256='b'*64,workspace_reserved=32))
        r=m.select(d,s,q);self.assertEqual(r['unmeasured_configurations'][0]['reason'],'RESOURCE_MEASUREMENT_UNAVAILABLE')
    def test_mean_tail_uses_mean_with_same_ranking(self):
        d,s,q=fixture();old=m.select(d,s,q)
        s['schema']=m.TIMING_SCHEMAS[1]
        for row in s['cells']:
            row['statistics']={'mean':{'ns':row.pop('pooled_mean_ns')},'median':{'ns':.001}}
        self.assertEqual(m.select(d,s,q),old)
    def test_unknown_timing_schema_rejected(self):
        d,s,q=fixture();s['schema']='unregistered'
        with self.assertRaises(ValueError):m.select(d,s,q)
    def test_mean_tail_missing_mean_rejected(self):
        d,s,q=fixture();s['schema']=m.TIMING_SCHEMAS[1]
        for row in s['cells']:row['statistics']={'median':{'ns':.001}}
        with self.assertRaises(KeyError):m.select(d,s,q)
    def test_mean_tail_exact_workspace(self):
        d,s,q=fixture();s['schema']=m.TIMING_SCHEMAS[1]
        for row in s['cells']:row['statistics']={'mean':{'ns':row['pooled_mean_ns']}}
        s['configurations'][0]['workspace_reserved']+=32
        self.assertIsNone(m.select(d,s,q)['selected'])

if __name__=='__main__':unittest.main()
