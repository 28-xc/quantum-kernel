#include "lc_dsa_api.h"
#include "lc_dsa_arena.h"
#include <string.h>
#include "lc_platform.h"
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE && !LC_DSA_PUBLIC_A_SESSION
#else
#if LC_DSA_SEGMENTED_MU || LC_DSA_PUBLIC_A_SESSION
#define MLD_CONFIG_PARAMETER_SET 44
#include "src/fips202/fips202.h"
#include "src/ct.h"
#undef MLD_CONFIG_PARAMETER_SET
#endif
#endif
#ifndef LC_DSA_SCALAR_SWAR32
#define LC_DSA_SCALAR_SWAR32 0
#endif
#ifndef LC_DSA_S1_CACHE_DISABLE87
#define LC_DSA_S1_CACHE_DISABLE87 0
#endif
#ifndef LC_DSA_A_CACHE_87_CAP
#define LC_DSA_A_CACHE_87_CAP 56
#endif

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
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE && !LC_DSA_PUBLIC_A_SESSION
#else

#if LC_DSA_SEGMENTED_MU || LC_DSA_PUBLIC_A_SESSION
/* This frame ends before entering the signing/verifying core. Each input is
 * absorbed separately, so no combined size_t length or temporary prefix is
 * formed. mu may temporarily contain H(pk); absorption finishes before the
 * final squeeze overwrites it. Input objects remain immutable. */
static __attribute__((noinline,noclone)) void
lc_dsa_pure_mu(uint8_t mu[64],const uint8_t *tr_or_pk,size_t pk_bytes,
               const uint8_t *ctx,size_t ctx_bytes,const uint8_t *msg,size_t msg_bytes) {
  mld_shake256ctx hash;
  const uint8_t domain[2]={0,(uint8_t)ctx_bytes};
  if(pk_bytes) {
    mld_shake256(mu,64,tr_or_pk,pk_bytes);
    tr_or_pk=mu;
  }
  mld_shake256_init(&hash);
  mld_shake256_absorb(&hash,tr_or_pk,64);
  mld_shake256_absorb(&hash,domain,2);
  mld_shake256_absorb(&hash,ctx,ctx_bytes);
  mld_shake256_absorb(&hash,msg,msg_bytes);
  mld_shake256_finalize(&hash);
  mld_shake256_squeeze(mu,64,&hash);
  mld_shake256_release(&hash);
}
#endif
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
  if(i<0||op<0||op>2) return 0;
#if LC_DSA_STACK_SMALL
  /* Aligned allocation peaks: sign owns matrix(K-independent 1056),
   * one 1024-byte scratch, and K dense output rows. Verify owns L dense
   * input rows, cp, matrix and one output row. The small automatic owners
   * are counted in the independently checked outer stack reservation.
   * Keep the original safe key-generation bound below. */
  size_t owner_extra=LC_DSA_A_CACHE_POLYS ? 32 : 0;
  if(op==1) {
    size_t public_count=l==44?16:l==65?30:56;
    if(public_count>LC_DSA_A_CACHE_POLYS)public_count=LC_DSA_A_CACHE_POLYS;
    if(l==87 && public_count>LC_DSA_A_CACHE_87_CAP)public_count=LC_DSA_A_CACHE_87_CAP;
    return (size_t)((l==44?4:l==65?6:8)+2)*1024+32+31+owner_extra
            +public_count*768+((LC_DSA_SCALAR_SWAR32 && l!=65)?0:LC_DSA_S1_CACHE_POLYS*1024)
#if LC_DSA_DIRECT_MATRIX
           -(l!=44?1024:0)
#endif
           ;
  }
  if(op==2) return (size_t)((l==44?4:l==65?5:7)+3)*1024+32+31+owner_extra;
#endif
  size_t saving=0;
  if(op==0 && LC_DSA_STREAM_KEYGEN) saving=((l==44?4:l==65?6:8)+1)*1024;
  if(op==1 && LC_DSA_ALIAS_SIGN_CP) saving=1024;
  if(op==1 && LC_DSA_PACK_W0) saving+=1024;
  if(op==2 && LC_DSA_ALIAS_VERIFY_TMP) saving=1024;
  size_t extra=0;
#if defined(MLD_CONFIG_REDUCE_RAM) && LC_DSA_A_CACHE_POLYS > 0
  /* The prefix is capped at the public matrix size. Cache bytes are a
   * multiple of 32; readiness adds one rounded allocation block. */
  size_t matrix_polys=l==44?16:l==65?30:56;
  size_t retained=LC_DSA_A_CACHE_POLYS<matrix_polys?LC_DSA_A_CACHE_POLYS:matrix_polys;
  if(l==87 && retained>LC_DSA_A_CACHE_87_CAP)retained=LC_DSA_A_CACHE_87_CAP;
  extra=retained*256*(LC_DSA_A_CACHE_BITS/8)+32;
#if LC_DSA_A_CACHE_SIGN_ONLY
  if(op!=1)extra=32;
#endif
#if LC_DSA_A_STREAM_BATCH4 && !defined(MLD_CONFIG_SERIAL_FIPS202_ONLY)
  if(op==1 && retained<matrix_polys)extra+=3*1024;
#endif
#endif
#if LC_DSA_PARTIAL_DENSE_ROWS
  if(l==87 && op==1)extra+=LC_DSA_PARTIAL_DENSE_SAVED_COUNT(7)*1024;
#endif
#if defined(MLD_CONFIG_REDUCE_RAM) && LC_DSA_S1_CACHE_POLYS > 0
  if(op==1 && !(LC_DSA_S1_CACHE_DISABLE87 && l==87) && !(LC_DSA_SCALAR_SWAR32 && l!=65))extra+=LC_DSA_S1_CACHE_POLYS*1024;
#endif
#if defined(MLD_CONFIG_REDUCE_RAM) && LC_DSA_ROW_BATCH4 && !defined(MLD_CONFIG_SERIAL_FIPS202_ONLY)
  if(op!=1)extra+=3*1024;
#if LC_DSA_A_CACHE_POLYS == 0
  extra+=32;
#endif
#endif
#if defined(MLD_CONFIG_REDUCE_RAM) && LC_DSA_RETAIN_FULL_HIGH
  if(op==1)extra+=(l==44?4*192:l==65?6*128:8*128);
#endif
#if LC_DSA_CROSSCOL6 == 2
  if(l==65 && op==1)extra+=1024;
#endif
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if !LC_DSA_BORROW_SIG_Y
#if LC_DSA_RAW_Y4_CACHE
  if(l==44 && op==1)extra+=2304;
#endif
#if LC_DSA_RAW_Y_PREFIX65
  if(l==65 && op==1)extra+=LC_DSA_RAW_Y_PREFIX65*640;
#endif
#if LC_DSA_RAW_Y_PREFIX87
  if(l==87 && op==1)extra+=LC_DSA_RAW_Y_PREFIX87*640;
#endif
#endif
#else
#if LC_DSA_RAW_Y_ALL_CACHE
#if !LC_DSA_BORROW_SIG_Y
  if(op==1 && (l==65 || l==87))extra+=(l==65?5:7)*640;
#endif
#elif LC_DSA_FIRST_GAMMA_CACHE && !LC_DSA_NATURAL_SIG_Y
  if(op==1 && (l==65 || l==87))extra+=640;
#endif
#if LC_DSA_RAW_Y4_CACHE && (!LC_DSA_BORROW_SIG_Y || LC_DSA_NATURAL_SIG_Y)
  if(l==44 && op==1)extra+=2304;
#endif
#endif
#if LC_DSA_CACHED_DOT_TILE && !LC_DSA_INPLACE_AY
  if(op==1)extra+=(l==44?4:l==65?5:7)*1024;
#endif
#if LC_DSA_DENSE_SIGN_ROWS
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
  if(op==1)extra+=(l==44?4*448:l==65?6*416:8*416);
#else
  if(op==1)extra+=(l==44?4*448:l==65?6*384:8*384);
#endif
#endif
#if LC_DSA_MASK_PIPELINE
  if(l!=44){extra+=32;if(op==1)extra+=3*640;}
#endif
#if LC_DSA_FLAT_MATRIX_NEON
  if(l!=44 && op!=1)extra+=1024;
#endif
#if LC_DSA_KEYGEN_ETA4
  if(op==0)extra+=4096;
#endif
#if LC_DSA_KEYGEN_ETA_ARENA
  if(op==0)extra+=(l==65?2336:1824);
#endif
#if LC_DSA_KEYVERIFY_DENSE
  if(op!=1)extra+=(l==44?4:l==65?5:7)*256;
#endif
#if LC_DSA_NATIVE_MATRIX_ROWS
  if(op!=1){int hash_matrix=(op==2 && LC_DSA_VERIFY_HASH_BATCH && l!=87);extra+=(hash_matrix?(l==44?16:30):2*(l==44?4:l==65?5:7))*1024+(hash_matrix?4096:0);}
#endif
#if LC_DSA_MATRIX4_ARENA
  if(op!=1)extra+=4512;
#endif
#if LC_DSA_KEYGEN_RETAIN_S2
  if(op==0)extra+=(l==44?4:l==65?6:8)*1024;
#endif
#if LC_DSA_VERIFY_HASH_BATCH && (!defined(LC_BUILD_ARM_PROFILE) || !LC_BUILD_ARM_PROFILE)
  if(op==2 && l!=65)extra+=l==44?1024+384:256;
#endif
#if LC_DSA_PARAMETER_A32 && defined(MLD_CONFIG_REDUCE_RAM)
  if(op==1 && l!=87)extra+=retained*256u;
#endif
  return b[i][op]+31-saving+extra;
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
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
  uint8_t pre[257];
  if(cl>255||(!ctx&&cl)) return -9;
  pre[0]=0; pre[1]=(uint8_t)cl; if(cl) memcpy(pre+2,ctx,cl);
  return lc_dsa_sign_internal(l,sig,m,ml,pre,cl+2,rnd,sk,0,w,n,s);
#else
#if LC_DSA_SEGMENTED_MU
  uint8_t mu[64]; int ret;
  if(cl>255||(!ctx&&cl)) return -9;
  if(!sig||!rnd||!sk||!w||(!m&&ml)||!lc_dsa_size(l,2))
    return lc_dsa_sign_internal(l,sig,m,ml,NULL,0,rnd,sk,0,w,n,s);
  /* skEncode = rho[32] || K[32] || tr[64] || encoded secret vectors. */
  lc_dsa_pure_mu(mu,sk+64,0,ctx,cl,m,ml);
  ret=lc_dsa_sign_internal(l,sig,mu,64,NULL,0,rnd,sk,1,w,n,s);
  mld_zeroize(mu,sizeof(mu));
  return ret;
#else
  uint8_t pre[257];
  if(cl>255||(!ctx&&cl)) return -9;
  pre[0]=0; pre[1]=(uint8_t)cl; if(cl) memcpy(pre+2,ctx,cl);
  return lc_dsa_sign_internal(l,sig,m,ml,pre,cl+2,rnd,sk,0,w,n,s);
#endif
#endif
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

#include "lc_a_session_adapter.h"
