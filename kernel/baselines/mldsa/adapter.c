#include "lc_dsa_api.h"
#include "lc_dsa_arena.h"
#include <string.h>
#include "lc_platform.h"

#define MLD_CONFIG_PARAMETER_SET 44
#include "mldsa_native.h"
#undef MLD_CONFIG_PARAMETER_SET
#undef MLD_H
#define MLD_CONFIG_PARAMETER_SET 65
#include "mldsa_native.h"
#undef MLD_CONFIG_PARAMETER_SET
#undef MLD_H
#define MLD_CONFIG_PARAMETER_SET 87
#include "mldsa_native.h"
#undef MLD_CONFIG_PARAMETER_SET

/* The cache comparison bounds cover ordinary key generation, signing and
 * verification. A key-generation pairwise consistency test invokes signing
 * under an additional live allocation scope and needs its own bound. */
#if defined(MLD_CONFIG_REDUCE_RAM) && defined(MLD_CONFIG_KEYGEN_PCT) && \
    ((defined(LC_NATIVE_MATRIX_CACHE) && LC_NATIVE_MATRIX_CACHE > 0) || \
     (defined(LC_NATIVE_S1_CACHE) && LC_NATIVE_S1_CACHE > 0) || \
     (defined(LC_NATIVE_S2_CACHE) && LC_NATIVE_S2_CACHE > 0) || \
     (defined(LC_NATIVE_T0_CACHE) && LC_NATIVE_T0_CACHE > 0))
#error Native cache comparison does not support MLD_CONFIG_KEYGEN_PCT
#endif

void *lc_dsa_alloc(struct lc_dsa_arena *a, size_t n) {
  size_t rounded;
  if (!a || n > SIZE_MAX-31) return NULL;
  rounded=(n+31)&~(size_t)31;
  a->allocations++;
  if (a->used>a->capacity || rounded>a->capacity-a->used) {
    a->failures++; return NULL;
  }
  void *p=a->base+a->used;
  a->used+=rounded;
  if(a->used>a->peak) a->peak=a->used;
  return p;
}
void lc_dsa_free(struct lc_dsa_arena *a, void *p, size_t n) {
  if (!p || !a) return;
  size_t offset=(size_t)((uint8_t*)p-a->base), rounded=(n+31)&~(size_t)31;
  if (offset>a->used || rounded!=a->used-offset) { a->lifo_errors++; return; }
  a->used=offset;
}
int lc_dsa_system_random(uint8_t *out, size_t n) {
  return lc_system_random(out,n);
}
static void init(struct lc_dsa_arena *a,void *w,size_t n) {
  uintptr_t addr=(uintptr_t)w;
  size_t pad=(32-(addr&31))&31;
  memset(a,0,sizeof(*a));
  if(!w || n<pad) return;
  a->base=(uint8_t*)w+pad; a->capacity=n-pad; a->front_pad=pad;
}
static int finish(struct lc_dsa_arena *a,lc_dsa_stats *s,int ret) {
  if(s) {
    s->arena_capacity=a->capacity+a->front_pad;
    s->arena_high_water=a->peak+a->front_pad;
    s->arena_remaining=a->used;
    s->allocations=a->allocations; s->allocation_failures=a->failures;
    s->lifo_errors=a->lifo_errors; s->context_bytes=sizeof(*a);
  }
  return a->lifo_errors || a->used ? -100 : ret;
}
size_t lc_dsa_size(int l,int k) {
  static const size_t b[3][3]={{1312,2560,2420},{1952,4032,3309},{2592,4896,4627}};
  int i=l==44?0:l==65?1:l==87?2:-1;
  return i<0||k<0||k>2?0:b[i][k];
}
size_t lc_dsa_workspace_bound(int l,int op) {
  static const size_t b[3][3]={
    {MLD_TOTAL_ALLOC_44_KEYPAIR,MLD_TOTAL_ALLOC_44_SIGN,MLD_TOTAL_ALLOC_44_VERIFY},
    {MLD_TOTAL_ALLOC_65_KEYPAIR,MLD_TOTAL_ALLOC_65_SIGN,MLD_TOTAL_ALLOC_65_VERIFY},
    {MLD_TOTAL_ALLOC_87_KEYPAIR,MLD_TOTAL_ALLOC_87_SIGN,MLD_TOTAL_ALLOC_87_VERIFY}};
  int i=l==44?0:l==65?1:l==87?2:-1;
  if(i<0||op<0||op>2)return 0;
  size_t extra=0;
#if defined(MLD_CONFIG_REDUCE_RAM) && defined(LC_NATIVE_MATRIX_CACHE) && LC_NATIVE_MATRIX_CACHE > 0
  const size_t matrix_polys=l==44?16:l==65?30:56;
  extra=(LC_NATIVE_MATRIX_CACHE<matrix_polys?LC_NATIVE_MATRIX_CACHE:matrix_polys)*1024;
#endif
#if defined(MLD_CONFIG_REDUCE_RAM)
  if(op==1) {
    const size_t rows_l=l==44?4:l==65?5:7;
    const size_t rows_k=l==44?4:l==65?6:8;
    (void)rows_l;(void)rows_k;
#if defined(LC_NATIVE_S1_CACHE) && LC_NATIVE_S1_CACHE > 0
    extra+=(LC_NATIVE_S1_CACHE<rows_l?LC_NATIVE_S1_CACHE:rows_l)*1024;
#endif
#if defined(LC_NATIVE_S2_CACHE) && LC_NATIVE_S2_CACHE > 0
    extra+=(LC_NATIVE_S2_CACHE<rows_k?LC_NATIVE_S2_CACHE:rows_k)*1024;
#endif
#if defined(LC_NATIVE_T0_CACHE) && LC_NATIVE_T0_CACHE > 0
    extra+=(LC_NATIVE_T0_CACHE<rows_k?LC_NATIVE_T0_CACHE:rows_k)*1024;
#endif
  }
#endif
#if LC_DSA_PUBLIC_A_SESSION
  /* Two pointer-sized fields enlarge the 32-byte-aligned lazy mat by32. */
  extra+=32;
#endif
  return b[i][op]+extra+31;
}
int lc_dsa_native_enabled(void) {
#ifdef MLD_CONFIG_USE_NATIVE_BACKEND_ARITH
  return 1;
#else
  return 0;
#endif
}
int lc_dsa_lowram_enabled(void) {
#ifdef MLD_CONFIG_REDUCE_RAM
  return 1;
#else
  return 0;
#endif
}
#define DISPATCH(call, ...) switch(l) { case 44: ret=lcbase44_##call(__VA_ARGS__,&a); break; case 65: ret=lcbase65_##call(__VA_ARGS__,&a); break; case 87: ret=lcbase87_##call(__VA_ARGS__,&a); break; default: ret=-9; }
int lc_dsa_keypair_seed(int l,uint8_t *pk,uint8_t *sk,const uint8_t seed[32],void *w,size_t n,lc_dsa_stats *s) {
  struct lc_dsa_arena a; int ret;
  init(&a,w,n); if(!pk||!sk||!seed||!w) return finish(&a,s,-9);
  DISPATCH(keypair_internal,pk,sk,seed);
  return finish(&a,s,ret);
}
int lc_dsa_sign_internal(int l,uint8_t *sig,const uint8_t *m,size_t ml,const uint8_t *pre,size_t pl,const uint8_t rnd[32],const uint8_t *sk,int ext,void *w,size_t n,lc_dsa_stats *s) {
  struct lc_dsa_arena a; int ret;
  init(&a,w,n);
  if(!sig||!rnd||!sk||!w||(!m&&ml)||(!pre&&pl)||(ext&&ml!=64)) return finish(&a,s,-9);
  DISPATCH(signature_internal,sig,m,ml,pre,pl,rnd,sk,ext);
  return finish(&a,s,ret);
}
int lc_dsa_verify_internal(int l,const uint8_t *sig,size_t sl,const uint8_t *m,size_t ml,const uint8_t *pre,size_t pl,const uint8_t *pk,int ext,void *w,size_t n,lc_dsa_stats *s) {
  struct lc_dsa_arena a; int ret;
  init(&a,w,n);
  if(!sig||!pk||!w||(!m&&ml)||(!pre&&pl)||(ext&&ml!=64)) return finish(&a,s,-9);
  if(!lc_dsa_size(l,2)||sl!=lc_dsa_size(l,2)) return finish(&a,s,-6);
  DISPATCH(verify_internal,sig,m,ml,pre,pl,pk,ext);
  return finish(&a,s,ret);
}
int lc_dsa_sign_seed(int l,uint8_t *sig,const uint8_t *m,size_t ml,const uint8_t *ctx,size_t cl,const uint8_t rnd[32],const uint8_t *sk,void *w,size_t n,lc_dsa_stats *s) {
  uint8_t pre[257];
  if(cl>255||(!ctx&&cl)) return -9;
  pre[0]=0; pre[1]=(uint8_t)cl; if(cl) memcpy(pre+2,ctx,cl);
  return lc_dsa_sign_internal(l,sig,m,ml,pre,cl+2,rnd,sk,0,w,n,s);
}
int lc_dsa_verify(int l,const uint8_t *sig,size_t sl,const uint8_t *m,size_t ml,const uint8_t *ctx,size_t cl,const uint8_t *pk,void *w,size_t n,lc_dsa_stats *s) {
  struct lc_dsa_arena a; int ret;
  init(&a,w,n);
  if(!sig||!pk||!w||(!m&&ml)||(!ctx&&cl)||cl>255) return finish(&a,s,-9);
  if(!lc_dsa_size(l,2)||sl!=lc_dsa_size(l,2)) return finish(&a,s,-6);
  DISPATCH(verify,sig,m,ml,ctx,cl,pk);
  return finish(&a,s,ret);
}
int lc_dsa_keypair(int l,uint8_t *pk,uint8_t *sk,void *w,size_t n,lc_dsa_stats *s) {
  struct lc_dsa_arena a; int ret;
  init(&a,w,n); if(!pk||!sk||!w) return finish(&a,s,-9);
  DISPATCH(keypair,pk,sk); return finish(&a,s,ret);
}
int lc_dsa_sign(int l,uint8_t *sig,const uint8_t *m,size_t ml,const uint8_t *ctx,size_t cl,const uint8_t *sk,void *w,size_t n,lc_dsa_stats *s) {
  struct lc_dsa_arena a; int ret;
  init(&a,w,n); if(!sig||!sk||!w||(!m&&ml)||(!ctx&&cl)||cl>255) return finish(&a,s,-9);
  DISPATCH(signature,sig,m,ml,ctx,cl,sk); return finish(&a,s,ret);
}

#if LC_DSA_PUBLIC_A_SESSION
/* Exact selected native representation, never a persistent secret cache. */
uint32_t lcbase44_public_a_format_tag(void);
uint32_t lcbase65_public_a_format_tag(void);
uint32_t lcbase87_public_a_format_tag(void);
uint32_t lc_dsa_a_format_tag(int l) {
  switch(l) {
    case 44:return lcbase44_public_a_format_tag();
    case 65:return lcbase65_public_a_format_tag();
    case 87:return lcbase87_public_a_format_tag();
    default:return 0;
  }
}
void lcbase44_public_a_prepare(uint8_t *,const uint8_t *);
void lcbase65_public_a_prepare(uint8_t *,const uint8_t *);
void lcbase87_public_a_prepare(uint8_t *,const uint8_t *);
size_t lc_dsa_a_cache_bytes(int l) {
  const size_t count=l==44?16:l==65?30:l==87?56:0;
  return count?(LC_NATIVE_A_SESSION_POLYS<count?LC_NATIVE_A_SESSION_POLYS:count)*1024:0;
}
size_t lc_dsa_a_workspace_bound(int l,int op) {
  if(!lc_dsa_a_cache_bytes(l)||op<0||op>2)return 0;
  /* Prepare uses the original sampler's residual stack; it owns no arena
   * objects. Sign/verify include the larger mat descriptor via the normal
   * query. Stack and persistent A must be charged separately. */
  return op==0?32:lc_dsa_workspace_bound(l,op);
}
static int lc_native_session_attach(struct lc_dsa_arena *a,int l,const uint8_t *cache) {
  const size_t bytes=lc_dsa_a_cache_bytes(l);
  if(!cache||!bytes||((uintptr_t)cache&31)||bytes>UINTPTR_MAX-(uintptr_t)cache)return -9;
  a->a_cache=cache;a->a_cache_bytes=bytes;return 0;
}
int lc_dsa_a_prepare(int l,uint8_t *cache,const uint8_t rho[32],void *w,size_t n,lc_dsa_stats *s) {
  struct lc_dsa_arena a;int ret=0;init(&a,w,n);
  if(!rho||!w||lc_native_session_attach(&a,l,cache))return finish(&a,s,-9);
  if(n<lc_dsa_a_workspace_bound(l,0)){a.failures++;return finish(&a,s,-9);}
  switch(l) {
    case 44:lcbase44_public_a_prepare(cache,rho);break;
    case 65:lcbase65_public_a_prepare(cache,rho);break;
    case 87:lcbase87_public_a_prepare(cache,rho);break;
    default:ret=-9;
  }
  return finish(&a,s,ret);
}
int lc_dsa_a_sign_seed(int l,const uint8_t *cache,uint8_t *sig,const uint8_t *m,size_t ml,
 const uint8_t *ctx,size_t cl,const uint8_t rnd[32],const uint8_t *sk,void *w,size_t n,lc_dsa_stats *s) {
  struct lc_dsa_arena a;int ret;uint8_t pre[257];init(&a,w,n);
  if(!sig||!rnd||!sk||!w||(!m&&ml)||(!ctx&&cl)||cl>255||lc_native_session_attach(&a,l,cache))return finish(&a,s,-9);
  pre[0]=0;pre[1]=(uint8_t)cl;if(cl)memcpy(pre+2,ctx,cl);
  DISPATCH(signature_internal,sig,m,ml,pre,cl+2,rnd,sk,0);
  /* pre contains only public mode/context bytes. Secret owners are destroyed
   * by the unchanged upstream cleanup before DISPATCH returns. */
  return finish(&a,s,ret);
}
int lc_dsa_a_verify(int l,const uint8_t *cache,const uint8_t *sig,size_t sl,
 const uint8_t *m,size_t ml,const uint8_t *ctx,size_t cl,const uint8_t *pk,
 void *w,size_t n,lc_dsa_stats *s) {
  struct lc_dsa_arena a;int ret;init(&a,w,n);
  if(!sig||!pk||!w||(!m&&ml)||(!ctx&&cl)||cl>255||lc_native_session_attach(&a,l,cache))return finish(&a,s,-9);
  if(sl!=lc_dsa_size(l,2))return finish(&a,s,-6);
  DISPATCH(verify,sig,m,ml,ctx,cl,pk);
  return finish(&a,s,ret);
}
#endif
