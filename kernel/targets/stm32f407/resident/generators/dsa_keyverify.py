"""Bind six fixed-layout ML-DSA products to a common keygen/verification engine."""
import re
from compact_build import definitions,later
def transform(text,p,kind):
    fast=kind=='paired';k,l={44:(4,4),65:(6,5),87:(8,7)}[p]
    pk,sk={44:(1312,2560),65:(1952,4032),87:(2592,4896)}[p]
    eta,zbytes,challenge,wbytes,bound={44:(96,576,32,192,131072-78),65:(128,640,48,128,524288-196),87:(96,640,64,128,524288-120)}[p]
    defs=definitions(text)
    a,b,e=defs[f'mld_check_pct{p}'];pct=re.sub(r'\s+','',text[b:e])
    if pct!='{((void)pk);((void)sk);((void)(context));return0;}':raise ValueError('active pairwise key check requires binding')
    f=f'lcbase{p}_';targets={f+'keypair_internal':'{return a127_dsa_keygen(&selected_dsa_route,pk,sk,seed,context);}',
       f+'verify_segments':'{return a127_dsa_verify(&selected_dsa_route,sig,m,mlen,pre,prelen,pre1,prelen1,pk,externalmu,context);}'}
    for n in sorted(targets,key=lambda n:defs[n][1],reverse=True):
        _,b,e=defs[n];text=text[:b]+targets[n]+text[e:]
    mark='#include "dsa_sign_shared.h"'
    text=later(text,mark,mark+'\n#include "dsa_operations.h"\nstatic const a127_dsa_route selected_dsa_route;')
    prep=f'''
static void dsa_prep_s(void *s,void *t,const uint8_t *rho,unsigned i,uint8_t *sk){{
 {f}poly_uniform_eta(t,rho,(uint8_t)i);{f}polyeta_pack(sk,t);lcbase_poly_ntt(t);lc_pack_matrix_ntt24((uint8_t*)s+i*768,t);
}}
''' if fast else ''
    row='lc_packed_matrix_row(row,mat,s,i);(void)rho;(void)t;(void)sk;' if fast else 'lc_stream_s1_row(row,mat,rho,t,i,sk);(void)s;'
    vproduct='lc_packed_matrix_row(w,mat,z,i);' if fast else 'lc_stream_z_row(w,mat,sig,t,i);(void)z;'
    zprep='lcbase_poly_ntt(t);lc_pack_matrix_ntt24((uint8_t*)z+i*768,t);' if fast else '(void)z;(void)i;'
    text+=prep+f'''
static void dsa_init_mat(void *m,const uint8_t *rho){{{f}polyvec_matrix_expand_lazy(m,rho);}}
static void dsa_key_row(void *row,void *mat,void *s,const uint8_t *rho,void *t,unsigned i,uint8_t *sk){{{row}}}
static void dsa_finish_key(void *w,void *t,const uint8_t *rho,unsigned n,uint8_t*s2,uint8_t*t1,uint8_t*t0){{
 lcbase_poly_invntt_tomont(w);{f}poly_uniform_eta(t,rho,(uint8_t)n);{f}polyeta_pack(s2,t);
 lcbase_poly_add(w,t);lcbase_poly_reduce(w);lcbase_poly_caddq(w);lcbase_poly_power2round(t,w,w);
 lcbase_polyt1_pack(t1,t);lcbase_polyt0_pack(t0,w);
}}
static int dsa_z(void *t,void *z,const uint8_t *bytes,unsigned i){{
 {f}polyz_unpack(t,bytes);if(lcbase_poly_chknorm(t,{bound}))return -6;{zprep}return 0;
}}
static void dsa_verify_init(void *state,void *cp,void *mat,const uint8_t *mu,const uint8_t *pk,const uint8_t *sig){{
 lcbase_shake256_init(state);lcbase_shake256_absorb(state,mu,64);{f}polyvec_matrix_expand_lazy(mat,pk);{f}poly_challenge(cp,sig);lcbase_poly_ntt(cp);
}}
static int dsa_verify_row(void *w,void *mat,void *z,void*cp,void*t,const uint8_t *sig,const uint8_t *pk,unsigned i){{
 {vproduct}
 {f}unpack_pk_t1(t,pk,i);lcbase_poly_shiftl(t);lcbase_poly_ntt(t);lcbase_poly_pointwise_montgomery(t,cp);lcbase_poly_sub(w,t);
 lcbase_poly_reduce(w);lcbase_poly_invntt_tomont(w);lcbase_poly_caddq(w);
 if({f}sig_unpack_hints(t,sig,i))return -6;
 {f}poly_use_hint(w,t);{f}polyw1_pack((uint8_t*)t,w);return 0;
}}
static void dsa_absorb_row(void *s,const uint8_t*d,size_t n){{lcbase_shake256_absorb(s,d,n);}}
static int dsa_verify_finish(void*s,uint8_t*out,const uint8_t*challenge,size_t n){{
 lcbase_shake256_finalize(s);lcbase_shake256_squeeze(out,n,s);return mld_ct_memcmp(challenge,out,n)==0?0:-6;
}}
static void dsa_hash_done(void*s){{lcbase_shake256_release(s);}}
static const a127_dsa_route selected_dsa_route={{
 {k},{l},{pk},{sk},{eta},{zbytes},{challenge},{wbytes},
 {{128,34,64,{('sizeof(lc_packed_vecl)' if fast else '1')},sizeof(mld_polymat{p}),sizeof(mld_poly)}},
 {{sizeof(mld_shake256ctx),64,{('sizeof(lc_packed_vecl)' if fast else '1')},sizeof(mld_poly),sizeof(mld_polymat{p}),sizeof(mld_poly)}},
 __builtin_offsetof(mld_polymat{p},cur),
 lc_dsa_alloc,lc_dsa_free,lcbase_shake256,dsa_init_mat,{('dsa_prep_s' if fast else '0')},dsa_key_row,dsa_finish_key,
 dsa_z,lc_verify_mu_segments{p},dsa_verify_init,dsa_verify_row,dsa_absorb_row,dsa_verify_finish,dsa_hash_done
}};
'''
    return text

