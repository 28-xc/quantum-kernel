"""The documented build entry ships the modules used by runtime dispatch."""
from pathlib import Path
import copy,importlib,sys,unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'tools'),str(ROOT)]
import build
import statistics_source_manifest as identities

class SourceInventory(unittest.TestCase):
    def test_manifest_has_statistics_modules_and_finite_ui_tests(self):
        records=build.source_manifest();names={x['path'] for x in records}
        self.assertEqual(len(records),len(names))
        self.assertTrue(set(identities.FILES)<=names)
        self.assertTrue({'publicschemas/pooled_provenance.xml','tests/demo/test_deployment_profiles.py',
                         'tests/test_source_inventory.py'}<=names)

    def test_dynamic_runtime_modules_are_supplied(self):
        names={x['path'] for x in build.source_manifest()}
        for name in ('publicschemas.application_latency_v1','publicschemas.primitive_samples_v1','publicschemas.application_owner_v1'):
            module=importlib.import_module(name)
            self.assertIn(Path(module.__file__).resolve().relative_to(ROOT).as_posix(),names)
            self.assertTrue(callable(module.validate_observations))

    def test_both_benchmark_boundaries_and_checkpoint_parser_are_supplied(self):
        names={x['path'] for x in build.source_manifest()}
        for boundary in ('serialized','reused'):
            self.assertIn('bench/openssl_'+boundary+'/driver.c',names)
        self.assertTrue({'bench/openssl_reused/run.py','bench/openssl_reused/blocked.py',
                         'bench/openssl_reused/method.md','bench/openssl_serialized/pooled_medians.py'}<=names)

    def test_stale_statistics_manifest_blocks_source_capture(self):
        actual=build.read
        def changed(path):
            value=actual(path)
            if Path(path).name=='pooled_provenance.xml':
                value=copy.deepcopy(value);value['files'][0]['sha256']='0'*64
            return value
        with mock.patch.object(build,'read',side_effect=changed),self.assertRaisesRegex(ValueError,'stale'):
            build.source_manifest()

if __name__=='__main__':unittest.main()
