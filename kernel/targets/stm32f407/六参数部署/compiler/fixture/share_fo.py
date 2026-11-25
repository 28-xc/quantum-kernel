"""Generate one ML-KEM outer transform from all six actual ML-KEM source bindings."""
import re
from pathlib import Path
HEADER = """
struct a127_fo {
 unsigned pk_bytes, sk_bytes, ct_bytes, cpa_sk_bytes;
 int (*cpa_key)(unsigned char*,unsigned char*,const unsigned char*,lc_arena*);
 int (*cpa_enc)(unsigned char*,const unsigned char*,const unsigned char*,const unsigned char*,lc_arena*);
 int (*cpa_dec)(unsigned char*,const unsigned char*,const unsigned char*,lc_arena*);
 int (*check_pk)(const unsigned char*,lc_arena*);
 int (*pct)(const unsigned char*,const unsigned char*,lc_arena*);
 void (*h)(unsigned char*,const unsigned char*,size_t);
 void (*g)(unsigned char*,const unsigned char*,size_t);
 void (*j)(unsigned char*,size_t,const unsigned char*,size_t);
};
"""
def body(text,name):
 m=list(re.finditer(r'\b'+re.escape(name)+r'\s*\([^{};]*?\)\s*\{',text))
 if len(m)!=1:raise ValueError((name,len(m)))
 left=m[0].end()-1
 lvl=1
 for idx in range(left+1,len(text)):
  lvl += (text[idx]=='{')-(text[idx]=='}')
  if not lvl:return left,idx+1
 raise ValueError(name)
def apply(text, p, impl):
    rank={512:2,768:3,1024:4}[p]
    prefix=f'lc_base_mlk{p}_'
    ns=f'fo_{p}_{impl}'
    operations={'check_sk':'sk,context','keypair_derand':'pk,sk,coins,context','enc_derand':'ct,ss,pk,coins,context','dec':'ss,ct,sk,context'}
    forms={'check_sk':'const uint8_t *sk,lc_arena *context','keypair_derand':'uint8_t *pk,uint8_t *sk,const uint8_t *coins,lc_arena *context','enc_derand':'uint8_t *ct,uint8_t *ss,const uint8_t *pk,const uint8_t *coins,lc_arena *context','dec':'uint8_t *ss,const uint8_t *ct,const uint8_t *sk,lc_arena *context'}
    widths={512:(320,128),768:(320,128),1024:(352,160)}
    u,v=widths[p]
    cpa=f'(({rank} * 384))';pk=f'(({rank} * 384) + 32)'
    sk=f'({cpa} + {pk} + 2 * 32)'
    ct=f'(({rank} * {u}) + {v})'
    # Longest first. Keep every allocation, error, comparison, zeroization and implicit-rejection step.
    sub={sk:'route->sk_bytes','('+ct+')':'route->ct_bytes','('+pk+')':'route->pk_bytes',cpa:'route->cpa_sk_bytes'}
    funcs={prefix+'indcpa_keypair_derand':'route->cpa_key',prefix+'indcpa_enc':'route->cpa_enc',prefix+'indcpa_dec':'route->cpa_dec',prefix+'check_pk':'route->check_pk',f'mlk_check_pct{p}':'route->pct','lc_base_mlk_sha3_256':'route->h','lc_base_mlk_sha3_512':'route->g','lc_base_mlk_shake256':'route->j'}
    first=min(body(text,prefix+n)[0] for n in operations)
    # Anchor before the function declaration with standard integer types and lc_arena in scope.
    marker=text.rfind('__attribute__((warn_unused_result))',0,text.rfind('int '+prefix+'check_sk',0,first))
    if marker<0:raise ValueError("missing declaration")
    shared=[]
    for name in operations:
      a,b=body(text,prefix+name)
      old=text[a:b]
      for oldexpr,expr in sorted(sub.items(),key=lambda x:-len(x[0])):old=old.replace(oldexpr,expr)
      for f,new in funcs.items():old=re.sub(r'\b'+f+r'(?=\s*\()',new,old)
      old=old.replace(prefix+'check_sk (sk, context)','a127_fo_check_sk(route, sk, context)')
      if prefix in old or f'* {u})' in old:raise ValueError((p,name,old))
      shared.append('__attribute__((noinline)) int a127_fo_'+name+'(const struct a127_fo *route, '+forms[name]+')\n'+old)
      text=text[:a]+'{return a127_fo_'+name+'(&'+ns+','+operations[name]+');}'+text[b:]
    # The common functions use the original constant-time primitives and arena API.
    declarations='\n'.join(e.split('\n',1)[0]+';' for e in shared)
    text=text[:marker]+HEADER+'\nstatic const struct a127_fo '+ns+';\n'+declarations+'\n'+text[marker:]
    if p==512 and impl=='combined':text+='\n'+'\n'.join(shared)+'\n'
    text+='\nstatic const struct a127_fo '+ns+'={'+','.join(map(str,[rank*384+32,rank*768+96,rank*u+v,rank*384]))+','+','.join(funcs.keys())+'};\n'
    return text,shared
