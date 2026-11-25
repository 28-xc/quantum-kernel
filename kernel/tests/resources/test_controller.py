"""Pre-execution provenance rejection tests; fixtures never load a library."""
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
import copy, record_io as json, os, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
import controller as c

class BindingTests(unittest.TestCase):
 def setUp(self):
  base=Path(__file__).resolve().parent/'_tmp';base.mkdir(parents=True,exist_ok=True)
  self.tmp=tempfile.TemporaryDirectory(prefix='resource-bind-',dir=base);self.root=Path(self.tmp.name);self.src=self.root/'product';self.src.mkdir()
  self.dll=self.src/('latticecore.dll' if os.name=='nt' else 'liblatticecore.so');self.dll.write_bytes(b'opaque provenance fixture; never loaded')
  c.dump(self.src/'commands.xml',[{'argv':['compiler','-O3'],'exit_code':0,'log':'compile.log'}])
  self.manifest={'configuration':'unit','parameters':[512,768,1024,44,65,87],'sanitizer':'none','binary':{'sha256':c.sha(self.dll),'exports':c.PUBLIC},'commands_sha256':c.sha(self.src/'commands.xml'),'backend':'portable'}
  c.dump(self.src/'build.xml',self.manifest)
  self.spec={'source_commit':'2'*40,'tasks':[{'id':'one','profile':'unit','build':str(self.src)}]};self.path=self.root/'spec.xml'
 def tearDown(self):self.tmp.cleanup()
 def prepare(self):
  c.dump(self.path,self.spec);return c.prepare(self.path,self.root/'measurement')
 def change(self,key,value):
  self.manifest[key]=value;c.dump(self.src/'build.xml',self.manifest)
 def test_copy_is_identical_and_not_new_build(self):
  p=self.prepare();v=Path(p['bindings'][0]['view']);m=c.read(v/'build.xml')
  self.assertEqual(c.sha(v/self.dll.name),c.sha(self.dll));self.assertTrue(m['measurement_view_only']);self.assertFalse(m['new_build_performed']);self.assertEqual(m['derived_from']['manifest_sha256'],c.sha(self.src/'build.xml'))
 def test_changed_binary_rejected(self):
  self.dll.write_bytes(b'changed')
  with self.assertRaisesRegex(ValueError,'does not match'):self.prepare()
 def test_changed_commands_rejected(self):
  (self.src/'commands.xml').write_text('[]')
  with self.assertRaisesRegex(ValueError,'command identity'):self.prepare()
 def test_failed_compile_rejected(self):
  c.dump(self.src/'commands.xml',[{'argv':['compiler'],'exit_code':1}]);self.change('commands_sha256',c.sha(self.src/'commands.xml'))
  with self.assertRaisesRegex(ValueError,'failed commands'):self.prepare()
 def test_sanitizer_setting_rejected(self):
  self.change('sanitizer','address')
  with self.assertRaisesRegex(ValueError,'instrumented'):self.prepare()
 def test_hidden_sanitizer_command_rejected(self):
  c.dump(self.src/'commands.xml',[{'argv':['compiler','-fsanitize=address'],'exit_code':0}]);self.change('commands_sha256',c.sha(self.src/'commands.xml'))
  with self.assertRaisesRegex(ValueError,'Sanitizer'):self.prepare()
 def test_wrong_configuration_rejected(self):
  self.change('configuration','other')
  with self.assertRaisesRegex(ValueError,'configuration'):self.prepare()
 def test_missing_parameter_rejected(self):
  self.change('parameters',[512])
  with self.assertRaisesRegex(ValueError,'deployment shape'):self.prepare()
 def test_missing_export_rejected(self):
  b=copy.deepcopy(self.manifest['binary']);b['exports']=c.PUBLIC[:-1];self.change('binary',b)
  with self.assertRaisesRegex(ValueError,'deployment shape'):self.prepare()
 def test_extra_export_rejected(self):
  b=copy.deepcopy(self.manifest['binary']);b['exports']=c.PUBLIC+['debug'];self.change('binary',b)
  with self.assertRaisesRegex(ValueError,'deployment shape'):self.prepare()
 def test_expected_flag_mismatch_rejected(self):
  self.spec['tasks'][0]['expected']={'backend':'native'}
  with self.assertRaisesRegex(ValueError,'build setting'):self.prepare()
 def test_case_insensitive_duplicate_rejected(self):
  t=copy.deepcopy(self.spec['tasks'][0]);t['id']='ONE';self.spec['tasks'].append(t)
  with self.assertRaisesRegex(ValueError,'task identities'):self.prepare()
 def test_path_id_rejected(self):
  self.spec['tasks'][0]['id']='../escape'
  with self.assertRaisesRegex(ValueError,'task identities'):self.prepare()
 def test_unknown_commit_rejected(self):
  self.spec['source_commit']='unknown'
  with self.assertRaisesRegex(ValueError,'source commit'):self.prepare()
 def test_changed_instrument_rejected_before_spawn(self):
  self.prepare();out=self.root/'measurement';(out/'instrument/tests/resources/probe.c').write_text('modified')
  with patch.object(c.subprocess,'Popen') as launch:
   with self.assertRaisesRegex(ValueError,'Snapshot instrument'):c.execute(out,1,'cc','objdump')
   launch.assert_not_called()
 def test_changed_plan_rejected_before_spawn(self):
  self.prepare();out=self.root/'measurement';m=c.read(out/'plan.xml');m['source_commit']='3'*40;c.dump(out/'plan.xml',m)
  with patch.object(c.subprocess,'Popen') as launch:
   with self.assertRaisesRegex(ValueError,'intact prepared plan'):c.execute(out,1,'cc','objdump')
   launch.assert_not_called()
 def test_unknown_build_kind_rejected(self):
  self.spec['tasks'][0]['kind']='invented'
  with self.assertRaisesRegex(ValueError,'build kind'):self.prepare()
 def test_elf_exports_inspected_when_manifest_omits_them(self):
  b=copy.deepcopy(self.manifest['binary']);del b['exports'];b['format']='ELF';self.change('binary',b)
  with patch.object(c.shutil,'which',return_value='nm'),patch.object(c.subprocess,'run',return_value=c.subprocess.CompletedProcess([],0,'\n'.join(x+' T 0 1' for x in c.PUBLIC),'')):
   p=self.prepare()
  m=c.read(Path(p['bindings'][0]['view'])/'build.xml');self.assertEqual(sorted(m['binary']['exports']),c.PUBLIC);self.assertIn('exports_derived_from',m)
 def test_elf_extra_actual_export_rejected(self):
  b=copy.deepcopy(self.manifest['binary']);del b['exports'];b['format']='ELF';self.change('binary',b)
  with patch.object(c.shutil,'which',return_value='nm'),patch.object(c.subprocess,'run',return_value=c.subprocess.CompletedProcess([],0,'\n'.join(x+' T 0 1' for x in c.PUBLIC+['debug']),'')):
   with self.assertRaisesRegex(ValueError,'deployment shape'):self.prepare()
 @unittest.skipUnless(os.name=='nt','Windows publication sharing behavior')
 def test_transient_status_sharing_does_not_rerun_work(self):
  original=Path.replace;calls=[]
  def replace(path,target):
   calls.append(str(target))
   if len(calls)==1:raise PermissionError('Temporary reader handle')
   return original(path,target)
  with patch.object(Path,'replace',replace),patch.object(c.time,'sleep'):
   c.dump(self.root/'state.xml',{'finished':17})
  self.assertEqual(len(calls),2);self.assertEqual(c.read(self.root/'state.xml'),{'finished':17})

if __name__=='__main__':unittest.main()
