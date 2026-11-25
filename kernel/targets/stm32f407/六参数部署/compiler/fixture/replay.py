"""Lossless representations for the original 21 public fixture records; case identities are fixed."""
import re,json
from pathlib import Path
SOURCE=Path(__file__).resolve().parent
PAT=r'static const uint8_t (vector_bytes_\d+)\[\]\s*=\s*\{([^}]+)\};'
PROTO="""
extern int a127_kat_key(unsigned,const unsigned char*,int,unsigned char*,const unsigned char*,const unsigned char*,unsigned char*);
extern int a127_kat_kem_key(unsigned,const unsigned char*,const unsigned char*,const unsigned char*,unsigned char*);
extern int a127_kat_sig(unsigned,const unsigned char*,const unsigned char*,const unsigned char*,unsigned,const unsigned char*,unsigned,const unsigned char*,const unsigned char*,unsigned char*);
"""
def transform(text,name):
 if name=='instances.c':
  p=int(re.search(r'unified_vectors(\d+)',text)[1]);data={int(n.split('_')[-1]):bytes(int(x,16) for x in re.findall(r'0x([a-fA-F0-9]{2})',s)) for n,s in re.findall(PAT,text)}
  for i in (1,2):text=text.replace('{vector_bytes_'+str(i)+',','{0,')
  if p>100:return text
  k,l,eta,seed_width,hints,nonce={44:(4,4,2,32,80,16),65:(6,5,4,48,55,3),87:(8,7,2,64,75,9)}[p]
  prefix=128+(k+l)*(96 if eta==2 else 128); compressed={4:data[4][:prefix],7:bytes([nonce])+data[7][:seed_width]+data[7][-(hints+k):]}
  # Use the original public NIST internal projection to represent each SigVer public
  # key by the rho/s1/s2 fields of its known test-only secret key. Retain signature,
  # message, domain, disposition, and every original coefficient of reconstructed pk.
  for start in (8,12):
   rows=json.loads((SOURCE/'nist-sigver-projection.json').read_text())
   row=next(r['t'] for r in rows if r['p']==p and bytes.fromhex(r['t']['pk'])==data[start] and bytes.fromhex(r['t']['signature'])==data[start+1])
   original_sk=bytes.fromhex(row['sk'])
   compressed[start]=original_sk[:32]+original_sk[128:prefix]
  def trim(m):
   i=int(m[1].split('_')[-1])
   return 'static const uint8_t '+m[1]+'[]={'+','.join(str(x) for x in compressed[i])+'};' if i in compressed else m[0]
  return re.sub(PAT,trim,text)
 if name!='transaction.c':return text
 kem='if(v->operation==1)rc=route->enc(' in text
 check='a127_kat_kem_key(route->p,v->coins.p,route->pk,route->sk,route->area)' if kem else 'a127_kat_key(route->p,v->coins.p,1,route->area,route->pk,route->sk,0)'
 original='exact((route->pk),(route->pk_len),v->expected0)&&exact((route->sk),(route->sk_len),v->expected1)'
 assert text.count(original)==2
 text=text.replace(original,check)
 if not kem:
  prepare='a127_kat_key(route->p,v->sk.p,0,route->area,0,0,route->sk);'
  m='unsigned slot=v->accepted?(unsigned)v->operation:3;'
  assert text.count(m)==1;text=text.replace(m,m+'\n        if(v->operation==1)'+prepare)
  m='memset(route->pk,0xa7,(route->io_size));memset((route->area),0x69,(route->cap));'
  assert text.count(m)==1;text=text.replace(m,'memset(route->pk,0xa7,(route->io_size));if(op==1)'+prepare+'memset((route->area),0x69,(route->cap));')
  text=text.replace('v->domain.n,v->sk.p,v->sk.n','v->domain.n,route->sk,v->sk.n')
  recover_pk='a127_kat_key(route->p,v->pk.p,-1,route->area,0,0,route->pk);'
  text=text.replace('if(v->operation==1)'+prepare,'if(v->operation==2)'+recover_pk+'else if(v->operation==1)'+prepare)
  text=text.replace('if(op==1)'+prepare,'if(op==2)'+recover_pk+'else if(op==1)'+prepare)
  text=text.replace('v->domain.n,v->pk.p,v->pk.n','v->domain.n,route->pk,v->pk.n')
  m='exact((route->sig),(route->sig_len),v->expected0)'
  assert text.count(m)==2;text=text.replace(m,'a127_kat_sig(route->p,v->expected0.p,route->sk,v->message.p,v->message.n,v->domain.p,v->domain.n,v->coins.p,route->sig,route->area)')
 # Read workspace canaries before reusing an idle workspace for the independent KAT checker.
 clean='int clean=zeroed(w,n)&&repeated_value((route->area),off,0x69)&&repeated_value(w+n,(route->cap)-off-n,0x69);'
 assert text.count(clean)==1;text=text.replace(clean,'').replace('int correct=err==pr;',clean+'\n    int correct=err==pr;')
 return PROTO+text

