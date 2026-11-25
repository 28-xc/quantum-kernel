"""Read real PE/ELF image sections. No debug bytes are called core program RAM.

Writable image accounting is deliberately conservative: includes the target
library's linker/runtime metadata, not just algorithm-owned C globals.
Actual OS page mappings are separate observations from the execution probe.
"""
from pathlib import Path
import hashlib,re,struct
PUBLIC={'lc_get_sizes','lc_context_init','lc_keypair','lc_encaps','lc_decaps','lc_sign','lc_verify','lc_error_string'}
HANDLED={'malloc','calloc','realloc','free'}
ALLOC_PATTERN=re.compile(r'(alloc|heap|strdup|mmap|mremap|sbrk|brk$)',re.I)
def inventory(path):
 b=Path(path).read_bytes();sections=[];imports=[];exports=[];extra={}
 if b[:2]==b'MZ':
  pe=struct.unpack_from('<I',b,0x3c)[0]
  if b[pe:pe+4]!=b'PE\0\0':raise ValueError('Invalid PE signature')
  # COFF fields are read individually to avoid depending on optional headers.
  machine,count=struct.unpack_from('<HH',b,pe+4);symptr,nsyms=struct.unpack_from('<II',b,pe+12);optsize=struct.unpack_from('<H',b,pe+20)[0]
  opt=pe+24
  if struct.unpack_from('<H',b,opt)[0]!=0x20b:raise ValueError('Only PE32+ is supported')
  stringtable=symptr+18*nsyms;sh=opt+optsize
  for i in range(count):
   o=sh+40*i;name=b[o:o+8].split(b'\0')[0]
   if name.startswith(b'/') and name[1:].isdigit():
    q=stringtable+int(name[1:]);name=b[q:b.index(b'\0',q)]
   name=name.decode('utf-8',errors='strict');size,va,raw,ptr=struct.unpack_from('<IIII',b,o+8);flags=struct.unpack_from('<I',b,o+36)[0]
   sections.append(dict(name=name,virtual_bytes=size,initialized_image_bytes=min(size,raw) if not flags&0x80 else 0,address=va,raw_offset=ptr,raw_bytes=raw,writable=bool(flags&0x80000000),readable=bool(flags&0x40000000),executable=bool(flags&0x20000000),allocated=bool(flags&0xe0000000),tls=name=='.tls',debug=name.startswith(('.debug','.zdebug')),flags=flags))
  def at(rva):
   for s in sections:
    if s['address']<=rva<s['address']+max(s['virtual_bytes'],s['raw_bytes']):return s['raw_offset']+rva-s['address']
   raise ValueError('RVA outside image')
  def string(rva):
   q=at(rva);return b[q:b.index(b'\0',q)].decode('ascii')
  exp_rva,_,imp_rva,_=struct.unpack_from('<IIII',b,opt+112)
  if exp_rva:
   e=at(exp_rva);n=struct.unpack_from('<I',b,e+24)[0];table=at(struct.unpack_from('<I',b,e+32)[0]);exports=[string(struct.unpack_from('<I',b,table+4*i)[0]) for i in range(n)]
  if imp_rva:
   p=at(imp_rva)
   while any(b[p:p+20]):
    oft,_,_,name_rva,ft=struct.unpack_from('<IIIII',b,p);module=string(name_rva);q=at(oft or ft)
    while True:
     v=struct.unpack_from('<Q',b,q)[0];q+=8
     if not v:break
     imports.append({'module':module,'name':f'ordinal:{v&0xffff}' if v>>63 else string(v+2)})
    p+=20
  kind='PE32+';extra['windows_size_of_image_bytes']=struct.unpack_from('<I',b,opt+56)[0]
 elif b[:4]==b'\x7fELF':
  if b[4]!=2 or b[5]!=1:raise ValueError('Only little-endian ELF64 supported')
  machine=struct.unpack_from('<H',b,18)[0];phoff,shoff=struct.unpack_from('<QQ',b,32);phent,phnum,shent,shnum,shstr=struct.unpack_from('<HHHHH',b,54)
  headers=[struct.unpack_from('<IIQQQQIIQQ',b,shoff+i*shent) for i in range(shnum)];strings=headers[shstr];st=b[strings[4]:strings[4]+strings[5]]
  def sname(off,table):return table[off:table.index(b'\0',off)].decode('utf-8')
  for h in headers:
   name=sname(h[0],st);typ,flags,va,offset,size=h[1:6]
   sections.append(dict(name=name,virtual_bytes=size,initialized_image_bytes=0 if typ==8 else size,address=va,raw_offset=offset,raw_bytes=0 if typ==8 else size,writable=bool(flags&1),readable=bool(flags&2),executable=bool(flags&4),allocated=bool(flags&2),tls=bool(flags&0x400),debug=name.startswith(('.debug','.zdebug')),flags=flags))
   if typ==11:
    linked=headers[h[6]];table=b[linked[4]:linked[4]+linked[5]]
    for o in range(offset,offset+size,h[9]):
     n,info,other,index,_,_=struct.unpack_from('<IBBHQQ',b,o)
     if not n:continue
     symbol=sname(n,table)
     if index==0:imports.append({'module':'dynamic_linker','name':symbol})
     elif info>>4 in (1,2) and other&3==0:exports.append(symbol)
  extra['elf_load_segments']=[]
  for i in range(phnum):
   typ,flags,off,va,_,filesz,memsz,align=struct.unpack_from('<IIQQQQQQ',b,phoff+i*phent)
   if typ==1:extra['elf_load_segments'].append(dict(address=va,file_bytes=filesz,memory_bytes=memsz,alignment=align,writable=bool(flags&2),executable=bool(flags&1)))
  kind='ELF64'
 else:raise ValueError('Unsupported binary format')
 if set(exports)!=PUBLIC:raise ValueError('Unexpected public export set: '+repr(sorted(exports)))
 allocated=[s for s in sections if s['allocated'] and not s['debug']]
 rw=sum(s['virtual_bytes'] for s in allocated if s['writable']);ro=sum(s['virtual_bytes'] for s in allocated if not s['writable']);init_rw=sum(s['initialized_image_bytes'] for s in allocated if s['writable'])
 unhandled=[i for i in imports if (ALLOC_PATTERN.search(i['name']) and i['name'] not in HANDLED) or i['name'].startswith('ordinal:')]
 tls=sum(s['virtual_bytes'] for s in allocated if s.get('tls'))
 return {'schema':'resources.image.v1','path':str(Path(path).resolve()),'sha256':hashlib.sha256(b).hexdigest(),'format':kind,'machine':machine,'file_bytes':len(b),'sections':sections,'exports':sorted(exports),'imports':imports,'unhandled_allocator_imports':unhandled,'writable_image_conservative_bytes':rw,'tls_per_thread_conservative_bytes':tls,'writable_image_plus_single_thread_tls_bytes':rw+tls,'readonly_allocated_non_debug_bytes':ro,'initialized_writable_image_bytes':init_rw,'program_non_debug_image_bytes':ro+init_rw,'global_accounting':'All writable allocated target-library sections plus one additional thread TLS copy, including linker/runtime metadata; conservative superset of core-owned globals. Not full-process RAM.','core_owned_globals_excluding_runtime_bytes':None,'debug_excluded_bytes':sum(s['virtual_bytes'] for s in sections if s['debug']),**extra}
