"""Deterministic negative cases for measured-to-deployed image binding."""
import copy,hashlib,struct,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from publicschemas.deployment_image import verify_deployment_image,view
def digest(b):return hashlib.sha256(b).hexdigest()
def fixture():
    b=bytearray(1536);b[:2]=b'MZ';struct.pack_into('<I',b,60,128);b[128:132]=b'PE\0\0'
    struct.pack_into('<HH',b,132,0x8664,2);struct.pack_into('<HH',b,148,240,0x2022)
    o=152;struct.pack_into('<H',b,o,0x20b);struct.pack_into('<I',b,o+16,4096);struct.pack_into('<Q',b,o+24,0x180000000)
    struct.pack_into('<II',b,o+32,4096,512);struct.pack_into('<I',b,o+108,16)
    for i,(name,va,off,flags)in enumerate([(b'.text',4096,512,0x60000020),(b'.rdata',8192,1024,0x40000040)]):
        h=o+240+i*40;b[h:h+len(name)]=name;struct.pack_into('<IIII',b,h+8,512,va,512,off);struct.pack_into('<I',b,h+36,flags)
    b[512:516]=b'\x90\x90\x90\xc3';b[1024:1032]=b'constant'
    b=bytes(b);receipt=dict(schema='lattice.deployment_image_derivation.v1',label='test',status='PASS',original_sha256='0'*64,original_bytes=len(b)+100,
        derived_sha256=digest(b),derived_bytes=len(b),derived_file='test.dll',operation=['--strip-debug','--strip-unneeded'],tool_sha256='1'*64,
        execution_view=view(b),loadable_code_data_equal=True,original_unchanged=True,remaining_private_path_patterns=[])
    return b,receipt
class DeploymentImage(unittest.TestCase):
    def test_valid_image(self):
        b,r=fixture();self.assertEqual(verify_deployment_image(b,r,measured_sha256='0'*64)['status'],'PASS')
    def test_code_data_entry_and_section_permission_changes(self):
        for off in [513,1025,152+16,152+240+36]:
            with self.subTest(offset=off):
                b,r=fixture();changed=bytearray(b);changed[off]^=1;changed=bytes(changed)
                # Even a recomputed whole-image digest cannot replace the old
                # execution-view proof of unchanged measured code and data.
                r['derived_sha256']=digest(changed)
                with self.assertRaises(ValueError):verify_deployment_image(changed,r)
    def test_wrong_measured_identity(self):
        b,r=fixture()
        with self.assertRaises(ValueError):verify_deployment_image(b,r,measured_sha256='f'*64)
    def test_wrong_deployment_digest(self):
        b,r=fixture();r['derived_sha256']='e'*64
        with self.assertRaises(ValueError):verify_deployment_image(b,r)
    def test_incomplete_equivalence(self):
        b,r=fixture();r['loadable_code_data_equal']=False
        with self.assertRaises(ValueError):verify_deployment_image(b,r)
    def test_unknown_field(self):
        b,r=fixture();r['extra']='unregistered'
        with self.assertRaises(ValueError):verify_deployment_image(b,r)
    def test_elf_load_bytes_and_metadata(self):
        b=bytearray(512);b[:6]=b'\x7fELF\x02\x01'
        struct.pack_into('<H',b,18,183);struct.pack_into('<QQ',b,24,384,64)
        struct.pack_into('<HH',b,54,56,1)
        struct.pack_into('<IIQQQQQQ',b,64,1,5,0,0,0,512,512,4096)
        b[384:388]=b'\xc0\x03\x5f\xd6';b[448:456]=b'constant'
        _,r=fixture();r['derived_bytes']=len(b);r['derived_sha256']=digest(b);r['execution_view']=view(b)
        self.assertEqual(verify_deployment_image(bytes(b),r)['status'],'PASS')
        for off in[384,448,24,64+4,64+16]:
            with self.subTest(offset=off):
                c=bytearray(b);c[off]^=1;rr=copy.deepcopy(r);rr['derived_sha256']=digest(c)
                with self.assertRaises(ValueError):verify_deployment_image(bytes(c),rr)
        # Only section-table metadata is excluded from the loaded ELF header.
        c=bytearray(b);struct.pack_into('<Q',c,40,4096);struct.pack_into('<HHH',c,58,64,4,3)
        rr=copy.deepcopy(r);rr['derived_sha256']=digest(c)
        self.assertEqual(verify_deployment_image(bytes(c),rr)['status'],'PASS')
if __name__=='__main__':unittest.main()
