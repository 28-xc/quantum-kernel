"""Validate a deployment image against its measured-image derivation receipt.

The receipt hash is pinned by the trusted technical manifest. PE debug sections
and ELF section-table header metadata are excluded; executable/loadable bytes,
addresses, imports, exports, relocations, exception data and entry are checked.
"""
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
import hashlib, record_io as json, struct
from pathlib import Path

def sha(x):return hashlib.sha256(x).hexdigest()
def pe_view(b):
    p=struct.unpack_from('<I',b,60)[0];assert b[p:p+4]==b'PE\0\0'
    n=struct.unpack_from('<H',b,p+6)[0];o=p+24;z=struct.unpack_from('<H',b,p+20)[0]
    assert struct.unpack_from('<H',b,o)[0]==0x20b
    ss={};symoff,symcount=struct.unpack_from('<II',b,p+12)
    strings_at=symoff+18*symcount
    for i in range(n):
        h=o+z+i*40;name=b[h:h+8].rstrip(b'\0').decode('ascii');vs,va,rs,off=struct.unpack_from('<IIII',b,h+8);flags=struct.unpack_from('<I',b,h+36)[0]
        if name.startswith('/'):
            assert symoff and name[1:].isdigit()
            string_offset=strings_at+int(name[1:]);assert string_offset<len(b)
            name=b[string_offset:].split(b'\0',1)[0].decode('ascii')
        debug=name.startswith('.debug') and bool(flags&0x02000000) and not bool(flags&0x20000000)
        if not debug:ss[name]=dict(virtual_address=va,virtual_bytes=vs,raw_bytes=rs,flags=flags,sha256=sha(b[off:off+rs]))
    # Code/data directories remain fixed. The debug directory is metadata only.
    dirs=[struct.unpack_from('<II',b,o+112+i*8)for i in range(16)]
    return dict(format='PE32+',machine=struct.unpack_from('<H',b,p+4)[0],characteristics=struct.unpack_from('<H',b,p+22)[0]&~0x0200,
       optional_execution_fields=b[o+16:o+56].hex(),subsystem_and_dll_flags=b[o+68:o+72].hex(),stack_heap=b[o+72:o+108].hex(),
       directories={str(i):list(v) for i,v in enumerate(dirs)if i!=6},loaded_sections=ss)
def elf_view(b):
    assert b[:6]==b'\x7fELF\x02\x01';phoff=struct.unpack_from('<Q',b,32)[0];phsize,phnum=struct.unpack_from('<HH',b,54)
    normalized=bytearray(b);normalized[40:48]=b'\0'*8;normalized[58:64]=b'\0'*6
    segments=[]
    for i in range(phnum):
        t,flags,off,va,pa,fs,ms,align=struct.unpack_from('<IIQQQQQQ',b,phoff+i*phsize)
        if t==1:segments.append(dict(type=t,flags=flags,offset=off,virtual_address=va,physical_address=pa,file_bytes=fs,memory_bytes=ms,alignment=align,sha256=sha(normalized[off:off+fs])))
    return dict(format='ELF64',machine=struct.unpack_from('<H',b,18)[0],entry=struct.unpack_from('<Q',b,24)[0],program_headers_sha256=sha(b[phoff:phoff+phsize*phnum]),load_segments=segments,
        normalized_metadata_ranges=[[40,48],[58,64]])
def view(b):return pe_view(b)if b[:2]==b'MZ'else elf_view(b)

def verify_deployment_image(image,receipt,*,measured_sha256=None):
    required={'schema','label','status','original_sha256','original_bytes','derived_sha256','derived_bytes','derived_file','operation','tool_sha256','execution_view','loadable_code_data_equal','original_unchanged','remaining_private_path_patterns'}
    if set(receipt)!=required:raise ValueError('Unexpected deployment receipt fields')
    if receipt['schema']!='lattice.deployment_image_derivation.v1' or receipt['status']!='PASS':raise ValueError('Unsuccessful image derivation')
    for k in ['original_sha256','derived_sha256','tool_sha256']:
        v=receipt[k]
        if type(v)is not str or len(v)!=64 or any(c not in '0123456789abcdef' for c in v):raise ValueError('Invalid image digest')
    if receipt['loadable_code_data_equal']is not True or receipt['original_unchanged']is not True or receipt['remaining_private_path_patterns']!=[]:raise ValueError('Incomplete execution equivalence')
    supported=[['--strip-debug','--strip-unneeded'],['--input-target=elf64-little','--output-target=elf64-little','--strip-debug','--strip-unneeded','restore-original-e_machine']]
    if receipt['operation']not in supported:raise ValueError('Unexpected derivation operation')
    if len(image)!=receipt['derived_bytes'] or sha(image)!=receipt['derived_sha256']:raise ValueError('Deployment bytes differ from receipt')
    if measured_sha256 is not None and receipt['original_sha256']!=measured_sha256:raise ValueError('Measured image identity differs')
    try:actual=view(image)
    except (AssertionError,IndexError,KeyError,struct.error,UnicodeError)as e:raise ValueError('Malformed deployment image')from e
    if actual!=receipt['execution_view']:raise ValueError('Loadable execution view differs')
    return {'status':'PASS','measured_binary_sha256':receipt['original_sha256'],'binary_sha256':receipt['derived_sha256'],'execution_view':actual}

def load_deployment_image(image_path,receipt_path,receipt_sha256,*,measured_sha256=None,binary_sha256=None):
    raw=Path(receipt_path).read_bytes()
    if sha(raw)!=receipt_sha256:raise ValueError('Derivation receipt identity differs')
    receipt=json.loads(raw)
    result=verify_deployment_image(Path(image_path).read_bytes(),receipt,measured_sha256=measured_sha256)
    if binary_sha256 is not None and result['binary_sha256']!=binary_sha256:raise ValueError('Manifest deployment identity differs')
    result['derivation_sha256']=receipt_sha256
    return result
