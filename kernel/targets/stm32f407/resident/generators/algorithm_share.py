"""Parameter and schedule descriptors for F407 production operations."""
import re
from compact_build import definitions,read,later,put
def kem(text,symbols):
    # The forward/inverse interfaces describe the same fixed N=256, q=3329 polynomial for all ranks.
    # ML-KEM-768 originally selected a different scheduling of the inverse, which is checked below.
    for old,new in symbols.items():
        text=re.sub(r'\b'+old+r'(?=\s*\()',new,text)
    data=re.search(r'static\s+(?:__attribute__\(\(aligned\(32\)\)\)\s+)?const\s+int16_t\s+mlk_zetas\s*\[[^\]]+\]\s*=\s*\{[^}]+\};',text)
    if not data:raise ValueError('could not find per-unit ML-KEM multiplication roots')
    canon=data[0].replace('static ','',1).replace('mlk_zetas','a127_mlkem_roots')
    text=text[:data.start()]+'extern const int16_t a127_mlkem_roots[128];'+text[data.end():]
    text=re.sub(r'\bmlk_zetas\b','a127_mlkem_roots',text)
    return text,canon

def dsa(text,p,k,small=False):
    high=k=='paired';L={44:4,65:5,87:7}[p];K={44:4,65:6,87:8}[p]
    size={44:2420,65:3309,87:4627}[p]
    rows=({44:4,65:6,87:2} if small else {44:4,65:6,87:7})[p] if high else 0
    polys=({44:9,65:1,87:0} if small else {44:13,65:6,87:0})[p] if high else 0
    if high:
        mt=re.compile(r'typedef struct \{\s*uint8_t \*pending;\s*uint32_t pending_nonce;\s*unsigned can_look_ahead;\s*\} lc_pending_product;')
        text,n=mt.subn('typedef a127_pending lc_pending_product;',text);assert n==1
    marker='struct lc_dsa_arena {'
    text=later(text,marker,'#define A127_PREPROCESSED_TYPES 1\n#include "dsa_sign_shared.h"\n'+marker)
    fs=definitions(text);fn='lcbase'+str(p)+'_signature_internal';start,at,end=fs[fn];parent=text[at:end]
    for n in ['mld_sign_hook_resume','mld_sign_hook_attempt','mld_sign_hook_finish']:
        _,b,z=fs[n]
        code=re.sub(r'\s+','',text[b:z])
        if n.endswith('finish'):
            if code!='{((void)attempt);((void)(context));}':raise ValueError('active finish hook')
        elif 'return0;' not in code:raise ValueError('active resume/attempt hook')
    if 'lc_canonical_secret = 0;' not in parent or ('pending_product' in parent)!=high or ('matrix_cache' in parent)!=(polys>0):
        raise ValueError('active schedule no longer matches the audited allocation order')
    helpers=f'''
static void shared_route_unpack(a127_sign_state *s,const uint8_t *sk){{
    uint8_t *seed=s->slot[D_SEED];
    lcbase{p}_unpack_sk(seed,seed+32,seed+96,s->slot[D_T0],s->slot[D_S1],s->slot[D_S2],sk);
}}
static void shared_route_matrix(a127_sign_state *s){{
    mld_polymat{p} *mat=s->slot[D_MATRIX];
    lcbase{p}_polyvec_matrix_expand_lazy(mat,s->slot[D_SEED]);
    {("mat->cache=s->slot[D_ACACHE];" if polys else "")}
}}
static int shared_route_attempt(a127_sign_state *s,uint8_t *sig,uint16_t kappa,struct lc_dsa_arena *a){{
    uint8_t *seed=s->slot[D_SEED];
    return mld_attempt_signature_generation{p}({("&s->look," if high else "")}sig,seed+128,seed+192,kappa,
        s->slot[D_MATRIX],s->slot[D_S1],s->slot[D_S2],s->slot[D_T0],0,a);
}}
static const a127_sign_route shared_sign_route={{
    {K},{L},{size},((65535U-{L})/{L}),
    {{256,sizeof(mld_polymat{p}),{polys}*768,{rows}*768,sizeof(mld_sk_s1hat{p}),sizeof(mld_sk_t0hat{p}),sizeof(mld_sk_s2hat{p})}},
    lc_dsa_alloc,lc_dsa_free,shared_route_unpack,mld_H{p},shared_route_matrix,shared_route_attempt
}};
'''
    repl='{ return a127_sign_message(&shared_sign_route,sig,m,mlen,pre,prelen,rnd,sk,externalmu,context); }'
    return text[:start]+'\n'+helpers+text[start:at]+repl+text[end:]

