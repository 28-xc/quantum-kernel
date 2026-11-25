"""Bounded plan/mapping tests; no cryptographic library is loaded."""
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
import copy, hashlib, importlib.util, record_io as json, math, os, platform, tempfile, unittest

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
tool=load('comparison_replay',ROOT/'tools/reproduce_comparison.py')
importer=load('comparison_importer',ROOT/'tools/import_complete_operations.py')

class Plans(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=ROOT.parent);self.root=Path(self.temp.name)
        for name in ('one.bin','two.bin','crypto.bin'):(self.root/name).write_bytes(name.encode())
        headers=self.root/'openssl/include/openssl';headers.mkdir(parents=True);(headers/'evp.h').write_text('/* fixture */')
        def ref(name):return dict(path=name,sha256=tool.sha(self.root/name))
        plat='windows_x86_64' if os.name=='nt' else 'linux_aarch64'
        self.plan=dict(schema='lattice.comparison_acquisition.v1',platform=plat,dataset_id='test-comparison',compiler='gcc',
          crypto_library=ref('crypto.bin'),crypto_prefix='openssl',preparation_library='one',cpu=0,blocks=9,samples=1000,warmups=20,
          seed=1234,bootstrap_seed=1236,resamples=50000,message_bytes=1024,context_bytes=0,
          configurations=[dict(id='one',library=ref('one.bin'),workspace=262144),dict(id='two',library=ref('two.bin'),workspace=262144)],
          comparisons=[dict(id='one-over-two',candidate='one',reference='two')])
        self.file=self.root/'plan.xml'
    def tearDown(self):self.temp.cleanup()
    def run_plan(self,plan=None):
        self.file.write_text(json.dumps(self.plan if plan is None else plan));return tool.acquisition_plan(self.file)
    def test_valid(self):self.assertEqual(self.run_plan()['blocks'],9)
    def test_unknown_field(self):
        self.plan['hidden']=True
        with self.assertRaises(ValueError):self.run_plan()
    def test_platform(self):
        self.plan['platform']='invalid-platform'
        with self.assertRaises(ValueError):self.run_plan()
    def test_duplicate_arms(self):
        self.plan['configurations'][1]['id']='one'
        with self.assertRaises(ValueError):self.run_plan()
    def test_bad_hash(self):
        self.plan['configurations'][0]['library']['sha256']='0'*64
        with self.assertRaises(ValueError):self.run_plan()
    def test_missing_header(self):
        self.plan['crypto_prefix']='no-headers'
        with self.assertRaises(ValueError):self.run_plan()
    def test_boolean_samples(self):
        self.plan['samples']=True
        with self.assertRaises(ValueError):self.run_plan()
    def test_workspace(self):
        self.plan['configurations'][0]['workspace']=262145
        with self.assertRaises(ValueError):self.run_plan()
    def test_unknown_reference(self):
        self.plan['comparisons'][0]['reference']='third'
        with self.assertRaises(ValueError):self.run_plan()
    def test_absolute_path(self):
        self.plan['crypto_library']['path']='/hidden/file'
        with self.assertRaises(ValueError):self.run_plan()
    def test_check_only(self):
        self.run_plan();out=self.root/'checked';tool.collect(self.file,out,check_only=True)
        result=json.loads((out/'execution.xml').read_text());self.assertFalse(result['target_execution']);self.assertEqual(result['planned_tasks'],324)
    def test_no_overwrite(self):
        self.run_plan();out=self.root/'exists';out.mkdir()
        with self.assertRaises(ValueError):tool.collect(self.file,out,check_only=True)
    def test_mapping_hash(self):
        importer.configure_path_map(['/original='+str(self.root)])
        self.assertEqual(importer.artifact('/original/one.bin',tool.sha(self.root/'one.bin')),self.root/'one.bin')
    def test_mapping_changed_hash(self):
        importer.configure_path_map(['/original='+str(self.root)])
        with self.assertRaises(ValueError):importer.artifact('/original/one.bin','0'*64)
    def test_duplicate_mapping(self):
        with self.assertRaises(ValueError):importer.configure_path_map(['/original='+str(self.root),'/original='+str(self.root)])
    def test_longest_mapping(self):
        importer.configure_path_map(['/original='+str(self.root/'missing'),'/original/sub='+str(self.root)])
        self.assertEqual(importer.located('/original/sub/one.bin'),self.root/'one.bin')
    def test_subset_rejected(self):
        fields={k:None for k in importer.MANIFEST_FIELDS};fields.update(schema='private.latticecore.operation_subset.v1',configuration={k:None for k in importer.CONFIG_FIELDS})
        fields['configuration']['cells']=[[512,0]]
        with self.assertRaises(ValueError):importer.acquisition_cells(fields)

class NumericalReplay(unittest.TestCase):
    def setUp(self):
        self.expected = dict(method=dict(replicate_values_sha256='a'*64,
            block_draws_sha256='b'*64, bootstrap_seed=123, resamples=50000),
            observations_sha256='c'*64, source_code_hashes={'source.py':'d'*64},
            counts={'raw_rows':1000}, runtime={'python':'3.13.2','numpy':'2.2.5'},
            cells=[{'mean':1000.0,'ci95':[999.0,1001.0]}])

    def test_identical(self):
        result=tool.verify_numerical_summary(self.expected,copy.deepcopy(self.expected))
        self.assertTrue(result['replicate_bytes_equal'])
        self.assertEqual(result['unequal_float_fields'],0)

    def test_binary64_rounding_and_dual_identity(self):
        actual=copy.deepcopy(self.expected)
        actual['cells'][0]['mean']=math.nextafter(1000.0,math.inf)
        actual['method']['replicate_values_sha256']='e'*64
        actual['runtime']['python']='3.10.12'
        result=tool.verify_numerical_summary(self.expected,actual)
        self.assertEqual(result['unequal_float_fields'],1)
        self.assertFalse(result['replicate_bytes_equal'])
        self.assertEqual(result['archived_replicate_values_sha256'],'a'*64)
        self.assertEqual(result['recomputed_replicate_values_sha256'],'e'*64)

    def test_numerical_change_rejected(self):
        actual=copy.deepcopy(self.expected);actual['cells'][0]['mean']+=1e-5
        with self.assertRaises(ValueError):tool.verify_numerical_summary(self.expected,actual)

    def test_nonfinite_rejected(self):
        for value in (math.nan,math.inf,-math.inf):
            actual=copy.deepcopy(self.expected);actual['cells'][0]['mean']=value
            with self.subTest(value=value),self.assertRaises(ValueError):tool.verify_numerical_summary(self.expected,actual)

    def test_integer_and_identity_changes_rejected(self):
        for group,key,value in [('method','bootstrap_seed',124),('method','resamples',49999),
                                ('method','block_draws_sha256','f'*64),('counts','raw_rows',999),
                                ('source_code_hashes','source.py','f'*64)]:
            actual=copy.deepcopy(self.expected);actual[group][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):tool.verify_numerical_summary(self.expected,actual)
        actual=copy.deepcopy(self.expected);actual['observations_sha256']='f'*64
        with self.assertRaises(ValueError):tool.verify_numerical_summary(self.expected,actual)

    def test_shape_and_type_rejected(self):
        for value in (1000,True,'1000'):
            actual=copy.deepcopy(self.expected);actual['cells'][0]['mean']=value
            with self.subTest(value=value),self.assertRaises(ValueError):tool.verify_numerical_summary(self.expected,actual)
        actual=copy.deepcopy(self.expected);actual['cells'].append(actual['cells'][0])
        with self.assertRaises(ValueError):tool.verify_numerical_summary(self.expected,actual)
        actual=copy.deepcopy(self.expected);actual['extra']=1
        with self.assertRaises(ValueError):tool.verify_numerical_summary(self.expected,actual)

    def test_malformed_array_digest_rejected(self):
        actual=copy.deepcopy(self.expected);actual['method']['replicate_values_sha256']='not-a-digest'
        with self.assertRaises(ValueError):tool.verify_numerical_summary(self.expected,actual)

if __name__=='__main__':unittest.main()
