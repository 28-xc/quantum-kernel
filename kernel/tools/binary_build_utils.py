"""Small format helpers used by current hosted builds, without legacy records."""
import struct

def pe_exports(path):
 b=path.read_bytes();pe=struct.unpack_from('<I',b,0x3c)[0]
 if b[pe:pe+4]!=b'PE\0\0':raise ValueError('Not PE')
 machine,nsec=struct.unpack_from('<HH',b,pe+4);opt=pe+24
 magic=struct.unpack_from('<H',b,opt)[0];directory=opt+(112 if magic==0x20b else 96)
 export_rva=struct.unpack_from('<I',b,directory)[0]
 optional_size=struct.unpack_from('<H',b,pe+20)[0];sections=opt+optional_size
 def offset(rva):
  for i in range(nsec):
   virtual_size,virtual_address,raw_size,raw_address=struct.unpack_from('<IIII',b,sections+40*i+8)
   if virtual_address<=rva<virtual_address+max(virtual_size,raw_size):return raw_address+rva-virtual_address
  raise ValueError('RVA outside section')
 e=offset(export_rva);count=struct.unpack_from('<I',b,e+24)[0];table=offset(struct.unpack_from('<I',b,e+32)[0]);names=[]
 for i in range(count):
  a=offset(struct.unpack_from('<I',b,table+4*i)[0]);end=b.index(b'\0',a);names.append(b[a:end].decode('ascii'))
 return {'format':'PE','machine':machine,'bits':64 if magic==0x20b else 32,'exports':sorted(names)}

def globalize_qdata(path):
 """Change the single reviewed qdata COFF visibility byte, never section data."""
 old=path.read_bytes();data=bytearray(old)
 sympos,count=struct.unpack_from('<II',data,8);strings=sympos+18*count;i=0;found=[]
 while i<count:
  pos=sympos+18*i;raw=data[pos:pos+8]
  if raw[:4]==b'\0'*4:
   begin=strings+struct.unpack_from('<I',raw,4)[0];symbol=bytes(data[begin:data.index(0,begin)])
  else:symbol=bytes(raw).split(b'\0')[0]
  if symbol==b'lc_base_mlk_qdata':
   if data[pos+16]!=3 or data[pos+17]!=0:raise ValueError('Unexpected COFF symbol type')
   data[pos+16]=2;found.append(pos+16)
  i+=1+data[pos+17]
 if len(found)!=1 or sum(a!=b for a,b in zip(old,data))!=1:raise ValueError('COFF edit must change exactly one metadata byte')
 nsec=struct.unpack_from('<H',data,2)[0];base=20+struct.unpack_from('<H',data,16)[0]
 for i in range(nsec):
  size,start=struct.unpack_from('<II',data,base+40*i+16)
  if old[start:start+size]!=data[start:start+size]:raise ValueError('Changed COFF section')
 path.write_bytes(data)
 return {'one_metadata_byte':found[0],'all_section_bytes_identical':True}
