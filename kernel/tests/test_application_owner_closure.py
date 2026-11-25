"""Finite source-closure and explicit-resource-argument checks."""
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
import copy, importlib.util, record_io as json, sys, unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('application_owner',ROOT/'tools/application_owner.py');app=importlib.util.module_from_spec(spec);spec.loader.exec_module(app)

class Closure(unittest.TestCase):
    def test_all_actual_sources_are_in_the_public_inventory(self):
        rows=app.source_records();self.assertEqual(len(rows),15)
        paths=set(json.loads((ROOT/'configs/source_files.xml').read_text())['paths'])
        for row in rows:self.assertIn('examples/enrollment_owner/'+row['path'],paths)
        self.assertTrue({'tools/application_owner.py','tests/test_application_owner_closure.py','docs/enrollment_owner.md','examples/enrollment_owner/source_identity.xml','tests/resources/image_inventory.py'}<=paths)
    def test_platform_artifacts_have_complete_five_part_binding(self):
        self.assertEqual(len(app.artifact_names()),5)
        self.assertEqual(len(set(app.artifact_names())),5)
    def test_unknown_and_duplicate_source_are_rejected(self):
        original=app.read(app.SOURCE/'source_identity.xml')
        for name in ('../application.c','/application.c','D:/application.c','unknown.c',original['files'][1]['path']):
            data=copy.deepcopy(original);data['files'][0]['path']=name
            with self.assertRaises(ValueError):app.source_records(data)
    def test_changed_source_hash_is_rejected(self):
        data=app.read(app.SOURCE/'source_identity.xml');data['files'][0]['sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'Changed'):app.source_records(data)
    def test_incomplete_and_unknown_identity_fields_are_rejected(self):
        data=app.read(app.SOURCE/'source_identity.xml');data['files'].pop()
        with self.assertRaises(ValueError):app.source_records(data)
        data=app.read(app.SOURCE/'source_identity.xml');data['extra']=1
        with self.assertRaises(ValueError):app.source_records(data)
    def test_explicit_workspace_boundaries(self):
        for value in ('32','9536','9632','1048576'):self.assertEqual(app.workspace(value),int(value))
        for value in ('','0','31','33','-1','+32',' 32','9632x','1048608','18446744073709551616'):
            with self.assertRaises(ValueError):app.workspace(value)
    def test_original_core_recipes_remain_available(self):
        data=app.read(ROOT/'configs/recipes.xml')
        required={'compact-rate','compact-recompute','compact-rate-shared','native-cache-large',
                  'native-cache-small','native-x86','native-arm','reference-full','reference-lowram','compact-fixed'}
        self.assertTrue(required <= set(data['recipes']))
    def test_public_image_view_preserves_measurements_and_removes_local_path(self):
        original=dict(path=str(ROOT/'bin/latticecore.dll'),sha256='a'*64,program_non_debug_image_bytes=121754,sections=[dict(name='.text',virtual_bytes=104240)])
        saved=copy.deepcopy(original);view=app.project_image(original)
        self.assertEqual(original,saved);self.assertEqual(view['path'],'latticecore.dll')
        for key in ('sha256','program_non_debug_image_bytes','sections'):self.assertEqual(view[key],original[key])

if __name__=='__main__':unittest.main()
