"""Image-header and closed-metadata controls; synthetic bytes are not executed."""
from pathlib import Path
import copy
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
import record_io as json
import struct
import sys
import tempfile
import unittest
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(ROOT / 'tools'))
from publicschemas.archived_images_v1 import validate
from recompute_archived_images import recompute, sha


class Images(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='image-contract-')
        self.base = Path(self.temp.name)
        data = bytearray(152); data[:2] = b'MZ'; struct.pack_into('<I', data, 60, 128)
        data[128:132] = b'PE\0\0'; struct.pack_into('<H', data, 132, 0x8664)
        self.file = self.base / 'fixture.dll'; self.file.write_bytes(data)
        image = dict(id='win-fixture', platform='windows_x86_64', configuration='fixture', kind='hosted_library', parameters=[512, 768, 1024, 44, 65, 87],
            artifact=dict(path='fixture.dll', sha256=sha(self.file)), bytes=len(data), format='PE', machine='x86_64',
            compiler=dict(family='gcc', version='synthetic test'), code_generation=dict(optimization='O3', lto=False, backend='portable', definitions={},architecture_flags=[],
            translation_units=[dict(ordinal=0,source_basename='fixture.c',optimization_flags=['-O3'],lto_flags=[],architecture_flags=[],integer_definitions={})]))
        self.data = dict(schema='lattice.archived_images.v1', dataset_id='synthetic-header-test', core_source_commit='0'*40, images=[image])
    def tearDown(self): self.temp.cleanup()
    def save(self):
        p=self.base/'observations.xml'; p.write_text(json.dumps(self.data)); return p
    def test_pe_header_identity(self):
        result=recompute(self.save()); self.assertEqual((result['image_count'],result['executed_images']),(1,0))
    def test_elf_classes(self):
        for machine,cls,name,platform in ((40,1,'arm','cortex_m4'),(183,2,'aarch64','linux_aarch64'),(243,1,'riscv','riscv32')):
            raw=bytearray(64);raw[:6]=b'\x7fELF'+bytes([cls,1]);struct.pack_into('<H',raw,18,machine);self.file.write_bytes(raw)
            self.data['images'][0].update(platform=platform,kind='hosted_library' if platform=='linux_aarch64' else 'functional_target',format='ELF',machine=name,bytes=64)
            self.data['images'][0]['artifact']['sha256']=sha(self.file)
            self.assertEqual(recompute(self.save())['images'][0]['machine'],name)
    def test_changed_binary_and_wrong_target(self):
        manifest=self.save();self.file.write_bytes(b'changed')
        with self.assertRaises(ValueError):recompute(manifest)
        self.data['images'][0].update(platform='linux_aarch64')
        with self.assertRaises(ValueError):validate(self.data)
    def test_metadata_private_and_paths(self):
        for mutation in ('private_field','traversal','absolute','duplicate'):
            data=copy.deepcopy(self.data)
            if mutation=='private_field':data['images'][0]['ssh_private_key']='unregistered'
            elif mutation=='traversal':data['images'][0]['artifact']['path']='../fixture.dll'
            elif mutation=='absolute':data['images'][0]['artifact']['path']='D:/fixture.dll'
            else:data['images'].append(copy.deepcopy(data['images'][0]))
            with self.assertRaises(ValueError):validate(data)


if __name__=='__main__':unittest.main()
