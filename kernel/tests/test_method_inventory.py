"""Synthetic closed source/image links; no measurement or crypto execution."""
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
import copy, importlib.util, record_io as json, struct, sys, tempfile, unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tools'))
from publicschemas.method_inventory_v1 import validate
from recompute_method_inventory import recompute,sha


class Methods(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='methods-contract-')
        self.root=Path(self.tmp.name)
        raw=bytearray(152);raw[:2]=b'MZ';struct.pack_into('<I',raw,60,128);raw[128:132]=b'PE\0\0';struct.pack_into('<H',raw,132,0x8664)
        for name in ('driver.exe','crypto.dll','core.dll'):(self.root/name).write_bytes(raw)
        for name in ('driver.c','runner.py','validator.py','LICENSE.txt'):(self.root/name).write_text('synthetic '+name)
        image=dict(id='fixture',platform='windows_x86_64',configuration='fixture',kind='hosted_library',parameters=[512,768,1024,44,65,87],
          artifact=self.ref('core.dll'),bytes=152,format='PE',machine='x86_64',compiler=dict(family='gcc',version='synthetic'),
          code_generation=dict(optimization='O3',lto=False,backend='portable',definitions={},architecture_flags=[],translation_units=[dict(ordinal=0,source_basename='driver.c',optimization_flags=['-O3'],lto_flags=[],architecture_flags=[],integer_definitions={})]))
        self.write('images.xml',dict(schema='lattice.archived_images.v1',dataset_id='synthetic-core',core_source_commit='0'*40,images=[image]))
        self.write('observations.xml',dict(dataset_id='synthetic-observations',platform='windows_x86_64',driver_sha256=sha(self.root/'driver.exe'),crypto_library_sha256=sha(self.root/'crypto.dll')))
        binaries=[]
        for name,role in [('driver.exe','benchmark_driver'),('crypto.dll','benchmark_runtime')]:
            binaries.append(dict(id=name,category=role,platform='windows_x86_64',artifact=self.ref(name),bytes=152,format='PE',machine='x86_64',source_project='synthetic',source_version='1',source_revision='fixture',source_files=[self.ref('driver.c')],license_files=[self.ref('LICENSE.txt')]))
        self.data=dict(schema='lattice.observation_methods.v1',core_images=self.ref('images.xml'),independent_binaries=binaries,datasets=[dict(dataset_id='synthetic-observations',observations=self.ref('observations.xml'),runner=self.ref('runner.py'),validator=self.ref('validator.py'),driver=self.ref('driver.exe'),crypto_runtime=self.ref('crypto.dll'),driver_sources=[self.ref('driver.c')])])
    def tearDown(self):self.tmp.cleanup()
    def ref(self,name):return dict(path=name,sha256=sha(self.root/name))
    def write(self,name,data):
        p=self.root/name;p.write_text(json.dumps(data),encoding='utf-8');return p
    def test_complete_links(self):
        result=recompute(self.write('methods.xml',self.data))
        self.assertEqual((result['datasets'],result['independent_binaries'],result['executed_images']),(1,2,0))
    def test_changed_source(self):
        p=self.write('methods.xml',self.data);(self.root/'runner.py').write_text('changed')
        with self.assertRaises(ValueError):recompute(p)
    def test_wrong_observation_identity(self):
        obs=json.loads((self.root/'observations.xml').read_text());obs['driver_sha256']='0'*64
        self.write('observations.xml',obs);self.data['datasets'][0]['observations']=self.ref('observations.xml')
        with self.assertRaises(ValueError):recompute(self.write('methods.xml',self.data))
    def test_role_and_platform(self):
        self.data['independent_binaries'][0]['category']='independent_baseline'
        with self.assertRaises(ValueError):recompute(self.write('methods.xml',self.data))
    def test_private_unknown_traversal(self):
        for change in ('field','path','sources','conflict'):
            data=copy.deepcopy(self.data)
            if change=='field':data['cloud_token']='synthetic-negative'
            elif change=='path':data['datasets'][0]['runner']['path']='../runner.py'
            elif change=='sources':data['independent_binaries'][0]['source_files']=[]
            else:data['datasets'][0]['driver']['sha256']='0'*64
            with self.assertRaises(ValueError):validate(data)


if __name__=='__main__':unittest.main()
