"""Independently check finite allocation-failure and erasure observations."""
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
import argparse, hashlib, record_io as json

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def load(p):return json.loads(p.read_text(encoding='utf-8-sig'))
"""Verify same-layout archive copies differing only in non-loadable DWARF strings.

Relocations, symbols, LTO IR, archive indexes and member layout are retained.
The original non-debug byte view is pinned in the derivation receipt.
"""
import hashlib,re,struct

def digest(b):return hashlib.sha256(b).hexdigest()
_ALLOWED={'.debug_line_str','.gnu.debuglto_.debug_line_str','.debug_str'}
def members(b):
 assert b.startswith(b'!<arch>\n');at=8;long=b'';out=[]
 while at<len(b):
  assert at+60<=len(b);h=b[at:at+60];assert h[58:60]==b'`\n'
  size=int(h[48:58]);start=at+60;assert start+size<=len(b)
  name=h[:16].decode('ascii').strip();rawname=name
  if name=='//':long=b[start:start+size]
  elif name.startswith('/') and name[1:].isdigit():
   offset=int(name[1:]);assert offset<len(long);name=long[offset:].split(b'/\n',1)[0].decode('utf8')
  elif name.endswith('/') and name not in ['/','/SYM64/']:name=name[:-1]
  out.append((name,start,size,rawname));at=start+size+(size&1)
 assert at==len(b);return out

def archive_view(b):
 normalized=bytearray(b);ranges=[];records=[]
 for name,start,size,rawname in members(b):
  m=b[start:start+size]
  if rawname in ['/','//','/SYM64/']:continue
  sections=[]
  if m[:6]==b'\x7fELF\x02\x01':
   assert struct.unpack_from('<H',m,16)[0]==1
   machine=struct.unpack_from('<H',m,18)[0];assert machine in [62,183]
   off=struct.unpack_from('<Q',m,40)[0];step,count,strings_index=struct.unpack_from('<HHH',m,58);assert step==64 and strings_index<count
   assert off+step*count<=len(m);all_sections=[struct.unpack_from('<IIQQQQIIQQ',m,off+i*step) for i in range(count)]
   names=all_sections[strings_index];strings=m[names[4]:names[4]+names[5]]
   for section in all_sections:
    no,typ,flags,address,so,sz,*_=section;assert no<len(strings)
    sn=strings[no:].split(b'\0',1)[0].decode('ascii')
    if sn in _ALLOWED:
     assert typ==1 and flags&2==0 and flags&4==0 and so+sz<=len(m)
     sections.append((sn,so,sz,flags,'ELF64-REL'))
  else:
   assert len(m)>=20;machine,count=struct.unpack_from('<HH',m,0);assert machine==0x8664
   symboloff,symbolcount=struct.unpack_from('<II',m,8);assert struct.unpack_from('<H',m,16)[0]==0
   strings_at=symboloff+18*symbolcount;assert strings_at+4<=len(m);strings_size=struct.unpack_from('<I',m,strings_at)[0];assert strings_at+strings_size<=len(m)
   strings=m[strings_at:strings_at+strings_size]
   for i in range(count):
    h=20+i*40;assert h+40<=len(m);sn=m[h:h+8].rstrip(b'\0').decode('ascii')
    if sn.startswith('/'):
     no=int(sn[1:]);assert 4<=no<len(strings);sn=strings[no:].split(b'\0',1)[0].decode('ascii')
    sz,so=struct.unpack_from('<II',m,h+16);flags=struct.unpack_from('<I',m,h+36)[0]
    if sn in _ALLOWED:
     assert flags&0x02000000 and not flags&0x20000000 and so+sz<=len(m)
     sections.append((sn,so,sz,flags,'COFF-AMD64'))
  records.append(dict(name=name,data_offset=start,bytes=size,machine=machine))
  for sn,so,sz,flags,fmt in sections:
   normalized[start+so:start+so+sz]=b'\0'*sz
   ranges.append(dict(member=name,format=fmt,section=sn,flags=flags,offset=start+so,bytes=sz))
 return dict(archive_bytes=len(b),members=records,excluded_nonloadable_debug_strings=ranges,all_other_archive_bytes_sha256=digest(normalized))

def private_path_matches(b):
 # Construct the home-directory pattern from fragments so this source is portable.
 pat=re.compile(rb'(?:D:[/\\](?:pqc-r\d+|codex)|C:[/\\]Users[/\\]' + b'25338|/home/' + rb'ubuntu/[^/\x00\s]+)',re.I)
 return list(pat.finditer(b))

def verify_archive_derivation(b,receipt,*,measured_sha256=None):
 assert receipt['schema']=='lattice.archive_debug_derivation.v1' and receipt['status']=='PASS'
 assert receipt['operation']=='same-length-neutral-directory-prefix-in-nonloadable-dwarf-strings'
 assert receipt['original_unchanged'] is True and receipt['all_other_bytes_equal'] is True
 assert receipt['derived_sha256']==digest(b) and receipt['derived_bytes']==len(b)==receipt['original_bytes']
 if measured_sha256 is not None:assert receipt['original_sha256']==measured_sha256
 assert archive_view(b)==receipt['archive_view']
 assert not private_path_matches(b) and receipt['remaining_private_path_patterns']==[]
 return dict(status='PASS',original_sha256=receipt['original_sha256'],derived_sha256=receipt['derived_sha256'],members=len(receipt['archive_view']['members']),changed_debug_prefixes=receipt['changed_debug_prefixes'])


try:
 from publicschemas.deployment_image import verify_deployment_image
except ImportError:
 from deployment_image import verify_deployment_image

def derived_binding(data,profile,role,expected):
 binding=profile['derivations'][role];rp=data/binding['receipt']
 assert sha(rp)==binding['receipt_sha256']
 receipt=load(rp);actual=(data/profile[role]).read_bytes()
 assert binding['original_sha256']==expected==receipt['original_sha256']
 assert binding['derived_sha256']==receipt['derived_sha256']
 if role=='archive':return verify_archive_derivation(actual,receipt,measured_sha256=expected)
 return verify_deployment_image(actual,receipt,measured_sha256=expected)

def compute(data):
 data=Path(data);o=load(data/'observations.xml')
 for f in o['files']:
  p=(data/f['path']).resolve();assert p.is_relative_to(data.resolve())
  assert p.is_file() and p.stat().st_size==f['bytes'] and sha(p)==f['sha256'],f['path']
 rows=[]
 for p in o['profiles']:
  rec=load(data/p['record']);build=load(data/p['build']);prefix=Path(p['prefix'])
  assert rec['status']=='PASS'
  assert rec['archive_sha256']==build['binary']['static_sha256']
  assert p['production_image_sha256']==build['binary']['sha256']
  derived_binding(data,p,'archive',rec['archive_sha256'])
  derived_binding(data,p,'image',p['production_image_sha256'])
  assert sha(data/p['probe'])==rec['probe_sha256']
  assert sha(data/p['runner'])==rec['runner_sha256']
  derived_binding(data,p,'observed_executable',rec['binary_sha256'])
  derived_binding(data,p,'plain_executable',rec['plain_binary_sha256'])
  for unit in p['units']:
   assert sha(data/unit['original'])==unit['original_sha256']
   assert sha(data/unit['observed'])==unit['modified_sha256']
   assert build['source_hashes'][unit['source_path']]==unit['original_sha256']
  cells=[z for z in rec['rows'] if 'parameter' in z];plain=rec['plain_rows'];tot=rec['rows'][-1]
  expected={(x,k) for x in [512,768,1024,44,65,87] for k in range(3)}
  assert {(z['parameter'],z['operation']) for z in cells}==expected
  assert {(z['parameter'],z['operation']) for z in plain}==expected
  assert len(cells)==len(plain)==18 and tot['parameter_operation_cells']==18
  fails=0;byte_count=0
  for c in cells:
   q=next(z for z in plain if (z['parameter'],z['operation'])==(c['parameter'],c['operation']))
   assert c['status']==q['status']=='PASS'
   assert c['failed_ordinals']==c['recovery_calls']==len(c['allocation_sizes'])
   fails+=c['failed_ordinals']
   for k in ['output0','output1']:
    assert c[k]==q[k]
    byte_count+=len(bytes.fromhex(c[k]))
  assert tot['status']=='PASS' and fails==tot['failed_allocations']
  assert byte_count==rec['uninstrumented_output_comparison_bytes']==42068
  assert tot['erasure_before_free_checks']>0 and tot['detector_positive_control'] is True
  assert rec['coverage_guided'] is False and rec['formal_timing'] is False
  rows.append({'platform':p['platform'],'configuration':p['configuration'],'production_image_sha256':p['production_image_sha256'],'archive_sha256':rec['archive_sha256'],'operation_cells':18,'failed_allocations':fails,'erasure_before_free_checks':tot['erasure_before_free_checks'],'output_bytes_compared':byte_count,'positive_control':True,'observational_translation_units':len(p['units'])})
 return {'schema':'lattice.owner_boundary_summary.v2','status':'VERIFIED','observations_sha256':sha(data/'observations.xml'),'files_checked':len(o['files']),'derived_images_verified':18,'derived_archives_verified':6,'profiles':rows,'scope':'Finite allocation ordinals in the recorded deterministic operations; allocator/adapter observation binaries are distinct from deployed images. Public image copies retain the measured loadable execution view; archive copies differ only in non-loadable DWARF strings with all other bytes and member layout retained. Record validation does not replace fresh execution of the supplied runner.'}
def main():
 p=argparse.ArgumentParser();p.add_argument('--data',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();x=compute(a.data);a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(x,ensure_ascii=False,indent=2)+'\n',encoding='utf8');print(json.dumps({'status':x['status'],'profiles':len(x['profiles']),'files_checked':x['files_checked']}))
if __name__=='__main__':main()
