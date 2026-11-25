typedef int ptrdiff_t;
typedef unsigned int size_t;
typedef unsigned int wchar_t;
typedef struct {
  long long __clang_max_align_nonce1
      __attribute__((__aligned__(__alignof__(long long))));
  long double __clang_max_align_nonce2
      __attribute__((__aligned__(__alignof__(long double))));
} max_align_t;
typedef long long int int64_t;
typedef long long unsigned int uint64_t;
typedef int64_t int_least64_t;
typedef uint64_t uint_least64_t;
typedef int64_t int_fast64_t;
typedef uint64_t uint_fast64_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef int32_t int_least32_t;
typedef uint32_t uint_least32_t;
typedef int32_t int_fast32_t;
typedef uint32_t uint_fast32_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int16_t int_least16_t;
typedef uint16_t uint_least16_t;
typedef int16_t int_fast16_t;
typedef uint16_t uint_fast16_t;
typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef int8_t int_least8_t;
typedef uint8_t uint_least8_t;
typedef int8_t int_fast8_t;
typedef uint8_t uint_fast8_t;
typedef int intptr_t;
typedef unsigned int uintptr_t;
typedef long long int intmax_t;
typedef long long unsigned int uintmax_t;

typedef struct lc_dsa_stats {
  size_t arena_capacity, arena_high_water, arena_remaining;
  size_t allocations, allocation_failures, lifo_errors, context_bytes;
} lc_dsa_stats;
size_t lc_dsa_workspace_bound(int level, int op);
size_t lc_dsa_size(int level, int kind);
int lc_dsa_native_enabled(void);
int lc_dsa_lowram_enabled(void);
int lc_dsa_keypair_seed(int level, uint8_t *pk, uint8_t *sk,
  const uint8_t seed[32], void *workspace, size_t workspace_bytes, lc_dsa_stats *stats);
int lc_dsa_sign_internal(int level, uint8_t *sig, const uint8_t *msg, size_t msg_bytes,
  const uint8_t *prefix, size_t prefix_bytes, const uint8_t rnd[32], const uint8_t *sk,
  int externalmu, void *workspace, size_t workspace_bytes, lc_dsa_stats *stats);
int lc_dsa_verify_internal(int level, const uint8_t *sig, size_t sig_bytes,
  const uint8_t *msg, size_t msg_bytes, const uint8_t *prefix, size_t prefix_bytes,
  const uint8_t *pk, int externalmu, void *workspace, size_t workspace_bytes,
  lc_dsa_stats *stats);
int lc_dsa_sign_seed(int level, uint8_t *sig, const uint8_t *msg, size_t msg_bytes,
  const uint8_t *ctx, size_t ctx_bytes, const uint8_t rnd[32], const uint8_t *sk,
  void *workspace, size_t workspace_bytes, lc_dsa_stats *stats);
int lc_dsa_verify(int level, const uint8_t *sig, size_t sig_bytes,
  const uint8_t *msg, size_t msg_bytes, const uint8_t *ctx, size_t ctx_bytes,
  const uint8_t *pk, void *workspace, size_t workspace_bytes, lc_dsa_stats *stats);
int lc_dsa_keypair(int level, uint8_t *pk, uint8_t *sk, void *workspace,
  size_t workspace_bytes, lc_dsa_stats *stats);
int lc_dsa_sign(int level, uint8_t *sig, const uint8_t *msg, size_t msg_bytes,
  const uint8_t *ctx, size_t ctx_bytes, const uint8_t *sk, void *workspace,
  size_t workspace_bytes, lc_dsa_stats *stats);

struct lc_dsa_arena {
  uint8_t *base;
  size_t capacity, used, peak, front_pad, allocations, failures, lifo_errors;
};
void *lc_dsa_alloc(struct lc_dsa_arena *a, size_t bytes);
void lc_dsa_free(struct lc_dsa_arena *a, void *ptr, size_t bytes);
int lc_dsa_system_random(uint8_t *out, size_t bytes);
void *memcpy(void *restrict dst, const void *restrict src, size_t n);
void *memmove(void *dst, const void *src, size_t n);
void *memset(void *dst, int value, size_t n);
int memcmp(const void *a, const void *b, size_t n);
size_t strlen(const char *s);
int lc_system_random(uint8_t *out, size_t bytes);
__attribute__((warn_unused_result))
int lcbase44_keypair_internal(
    uint8_t pk[1312],
    uint8_t sk[2560],
    const uint8_t seed[32]
    ,
    struct lc_dsa_arena * context
);
__attribute__((warn_unused_result))
int lcbase44_keypair(
    uint8_t pk[1312],
    uint8_t sk[2560]
    ,
    struct lc_dsa_arena * context
);
__attribute__((warn_unused_result))
int lcbase44_signature_internal(
    uint8_t sig[2420], const uint8_t *m,
    size_t mlen, const uint8_t *pre, size_t prelen,
    const uint8_t rnd[32],
    const uint8_t sk[2560],
    int externalmu
    ,
    struct lc_dsa_arena * context
);
__attribute__((warn_unused_result))
int lcbase44_signature(
    uint8_t sig[2420], const uint8_t *m,
    size_t mlen, const uint8_t *ctx, size_t ctxlen,
    const uint8_t sk[2560]
    ,
    struct lc_dsa_arena * context
);
__attribute__((warn_unused_result))
int lcbase44_signature_extmu(
    uint8_t sig[2420],
    const uint8_t mu[64],
    const uint8_t sk[2560]
    ,
    struct lc_dsa_arena * context
);
__attribute__((warn_unused_result))
int lcbase44_verify_internal(
    const uint8_t sig[2420], const uint8_t *m,
    size_t mlen, const uint8_t *pre, size_t prelen,
    const uint8_t pk[1312],
    int externalmu
    ,
    struct lc_dsa_arena * context
);
__attribute__((warn_unused_result))
int lcbase44_verify(
    const uint8_t sig[2420], const uint8_t *m,
    size_t mlen, const uint8_t *ctx, size_t ctxlen,
    const uint8_t pk[1312]
    ,
    struct lc_dsa_arena * context
);
__attribute__((warn_unused_result))
int lcbase44_verify_extmu(
    const uint8_t sig[2420],
    const uint8_t mu[64],
    const uint8_t pk[1312]
    ,
    struct lc_dsa_arena * context
);
__attribute__((warn_unused_result))
int lcbase44_signature_pre_hash_internal(
    uint8_t sig[2420], const uint8_t *ph,
    size_t phlen, const uint8_t *ctx, size_t ctxlen,
    const uint8_t rnd[32],
    const uint8_t sk[2560],
    int hashalg
    ,
    struct lc_dsa_arena * context
);
__attribute__((warn_unused_result))
int lcbase44_verify_pre_hash_internal(
    const uint8_t sig[2420], const uint8_t *ph,
    size_t phlen, const uint8_t *ctx, size_t ctxlen,
    const uint8_t pk[1312],
    int hashalg
    ,
    struct lc_dsa_arena * context
);
__attribute__((warn_unused_result))
int lcbase44_signature_pre_hash_shake256(
    uint8_t sig[2420], const uint8_t *m,
    size_t mlen, const uint8_t *ctx, size_t ctxlen,
    const uint8_t rnd[32],
    const uint8_t sk[2560]
    ,
    struct lc_dsa_arena * context
);
__attribute__((warn_unused_result))
int lcbase44_verify_pre_hash_shake256(
    const uint8_t sig[2420], const uint8_t *m,
    size_t mlen, const uint8_t *ctx, size_t ctxlen,
    const uint8_t pk[1312]
    ,
    struct lc_dsa_arena * context
);
__attribute__((warn_unused_result))
size_t lcbase44_prepare_domain_separation_prefix(
    uint8_t prefix[(2 + 255 + 11 + 64)], const uint8_t *ph,
    size_t phlen, const uint8_t *ctx, size_t ctxlen, int hashalg);
__attribute__((warn_unused_result))
int lcbase44_pk_from_sk(
    uint8_t pk[1312],
    const uint8_t sk[2560]
    ,
    struct lc_dsa_arena * context
);
__attribute__((warn_unused_result))
int lcbase65_keypair_internal(
    uint8_t pk[1952],
    uint8_t sk[4032],
    const uint8_t seed[32]
    ,
    struct lc_dsa_arena * context
);
__attribute__((warn_unused_result))
int lcbase65_keypair(
    uint8_t pk[1952],
    uint8_t sk[4032]
    ,
    struct lc_dsa_arena * context
);
__attribute__((warn_unused_result))
int lcbase65_signature_internal(
    uint8_t sig[3309], const uint8_t *m,
    size_t mlen, const uint8_t *pre, size_t prelen,
    const uint8_t rnd[32],
    const uint8_t sk[4032],
    int externalmu
    ,
    struct lc_dsa_arena * context
);
__attribute__((warn_unused_result))
int lcbase65_signature(
    uint8_t sig[3309], const uint8_t *m,
    size_t mlen, const uint8_t *ctx, size_t ctxlen,
    const uint8_t sk[4032]
    ,
    struct lc_dsa_arena * context
);
__attribute__((warn_unused_result))
int lcbase65_signature_extmu(
    uint8_t sig[3309],
    const uint8_t mu[64],
    const uint8_t sk[4032]
    ,
    struct lc_dsa_arena * context
);
__attribute__((warn_unused_result))
int lcbase65_verify_internal(
    const uint8_t sig[3309], const uint8_t *m,
    size_t mlen, const uint8_t *pre, size_t prelen,
    const uint8_t pk[1952],
    int externalmu
    ,
    struct lc_dsa_arena * context
);
__attribute__((warn_unused_result))
int lcbase65_verify(
    const uint8_t sig[3309], const uint8_t *m,
    size_t mlen, const uint8_t *ctx, size_t ctxlen,
    const uint8_t pk[1952]
    ,
    struct lc_dsa_arena * context
);
__attribute__((warn_unused_result))
int lcbase65_verify_extmu(
    const uint8_t sig[3309],
    const uint8_t mu[64],
    const uint8_t pk[1952]
    ,
    struct lc_dsa_arena * context
);
__attribute__((warn_unused_result))
int lcbase65_signature_pre_hash_internal(
    uint8_t sig[3309], const uint8_t *ph,
    size_t phlen, const uint8_t *ctx, size_t ctxlen,
    const uint8_t rnd[32],
    const uint8_t sk[4032],
    int hashalg
    ,
    struct lc_dsa_arena * context
);
__attribute__((warn_unused_result))
int lcbase65_verify_pre_hash_internal(
    const uint8_t sig[3309], const uint8_t *ph,
    size_t phlen, const uint8_t *ctx, size_t ctxlen,
    const uint8_t pk[1952],
    int hashalg
    ,
    struct lc_dsa_arena * context
);
__attribute__((warn_unused_result))
int lcbase65_signature_pre_hash_shake256(
    uint8_t sig[3309], const uint8_t *m,
    size_t mlen, const uint8_t *ctx, size_t ctxlen,
    const uint8_t rnd[32],
    const uint8_t sk[4032]
    ,
    struct lc_dsa_arena * context
);
__attribute__((warn_unused_result))
int lcbase65_verify_pre_hash_shake256(
    const uint8_t sig[3309], const uint8_t *m,
    size_t mlen, const uint8_t *ctx, size_t ctxlen,
    const uint8_t pk[1952]
    ,
    struct lc_dsa_arena * context
);
__attribute__((warn_unused_result))
size_t lcbase65_prepare_domain_separation_prefix(
    uint8_t prefix[(2 + 255 + 11 + 64)], const uint8_t *ph,
    size_t phlen, const uint8_t *ctx, size_t ctxlen, int hashalg);
__attribute__((warn_unused_result))
int lcbase65_pk_from_sk(
    uint8_t pk[1952],
    const uint8_t sk[4032]
    ,
    struct lc_dsa_arena * context
);
__attribute__((warn_unused_result))
int lcbase87_keypair_internal(
    uint8_t pk[2592],
    uint8_t sk[4896],
    const uint8_t seed[32]
    ,
    struct lc_dsa_arena * context
);
__attribute__((warn_unused_result))
int lcbase87_keypair(
    uint8_t pk[2592],
    uint8_t sk[4896]
    ,
    struct lc_dsa_arena * context
);
__attribute__((warn_unused_result))
int lcbase87_signature_internal(
    uint8_t sig[4627], const uint8_t *m,
    size_t mlen, const uint8_t *pre, size_t prelen,
    const uint8_t rnd[32],
    const uint8_t sk[4896],
    int externalmu
    ,
    struct lc_dsa_arena * context
);
__attribute__((warn_unused_result))
int lcbase87_signature(
    uint8_t sig[4627], const uint8_t *m,
    size_t mlen, const uint8_t *ctx, size_t ctxlen,
    const uint8_t sk[4896]
    ,
    struct lc_dsa_arena * context
);
__attribute__((warn_unused_result))
int lcbase87_signature_extmu(
    uint8_t sig[4627],
    const uint8_t mu[64],
    const uint8_t sk[4896]
    ,
    struct lc_dsa_arena * context
);
__attribute__((warn_unused_result))
int lcbase87_verify_internal(
    const uint8_t sig[4627], const uint8_t *m,
    size_t mlen, const uint8_t *pre, size_t prelen,
    const uint8_t pk[2592],
    int externalmu
    ,
    struct lc_dsa_arena * context
);
__attribute__((warn_unused_result))
int lcbase87_verify(
    const uint8_t sig[4627], const uint8_t *m,
    size_t mlen, const uint8_t *ctx, size_t ctxlen,
    const uint8_t pk[2592]
    ,
    struct lc_dsa_arena * context
);
__attribute__((warn_unused_result))
int lcbase87_verify_extmu(
    const uint8_t sig[4627],
    const uint8_t mu[64],
    const uint8_t pk[2592]
    ,
    struct lc_dsa_arena * context
);
__attribute__((warn_unused_result))
int lcbase87_signature_pre_hash_internal(
    uint8_t sig[4627], const uint8_t *ph,
    size_t phlen, const uint8_t *ctx, size_t ctxlen,
    const uint8_t rnd[32],
    const uint8_t sk[4896],
    int hashalg
    ,
    struct lc_dsa_arena * context
);
__attribute__((warn_unused_result))
int lcbase87_verify_pre_hash_internal(
    const uint8_t sig[4627], const uint8_t *ph,
    size_t phlen, const uint8_t *ctx, size_t ctxlen,
    const uint8_t pk[2592],
    int hashalg
    ,
    struct lc_dsa_arena * context
);
__attribute__((warn_unused_result))
int lcbase87_signature_pre_hash_shake256(
    uint8_t sig[4627], const uint8_t *m,
    size_t mlen, const uint8_t *ctx, size_t ctxlen,
    const uint8_t rnd[32],
    const uint8_t sk[4896]
    ,
    struct lc_dsa_arena * context
);
__attribute__((warn_unused_result))
int lcbase87_verify_pre_hash_shake256(
    const uint8_t sig[4627], const uint8_t *m,
    size_t mlen, const uint8_t *ctx, size_t ctxlen,
    const uint8_t pk[2592]
    ,
    struct lc_dsa_arena * context
);
__attribute__((warn_unused_result))
size_t lcbase87_prepare_domain_separation_prefix(
    uint8_t prefix[(2 + 255 + 11 + 64)], const uint8_t *ph,
    size_t phlen, const uint8_t *ctx, size_t ctxlen, int hashalg);
__attribute__((warn_unused_result))
int lcbase87_pk_from_sk(
    uint8_t pk[2592],
    const uint8_t sk[4896]
    ,
    struct lc_dsa_arena * context
);
void *lc_dsa_alloc(struct lc_dsa_arena *a, size_t n) {
  size_t rounded;
  if (!a || n > 4294967295U -31) return ((void*)0);
  rounded=(n+31)&~(size_t)31;
  a->allocations++;
  if (a->used>a->capacity || rounded>a->capacity-a->used) {
    a->failures++; return ((void*)0);
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
    {11584,9792,9120},
    {14656,11872,10208},
    {18752,14176,12512}};
  int i=l==44?0:l==65?1:l==87?2:-1;
  if(i<0||op<0||op>2) return 0;
  size_t saving=0;
  if(op==0 && 1) saving=((l==44?4:l==65?6:8)+1)*1024;
  if(op==1 && 1) saving=1024;
  if(op==1 && 1) saving+=1024;
  if(op==2 && 1) saving=1024;
  size_t extra=0;
  return b[i][op]+31-saving+extra;
}
int lc_dsa_native_enabled(void) {
  return 0;
}
int lc_dsa_lowram_enabled(void) {
  return 1;
}
int lc_dsa_keypair_seed(int l,uint8_t *pk,uint8_t *sk,const uint8_t seed[32],void *w,size_t n,lc_dsa_stats *s) {
  struct lc_dsa_arena a; int ret;
  init(&a,w,n); if(!pk||!sk||!seed||!w) return finish(&a,s,-9);
  switch(l) { case 65: ret=lcbase65_keypair_internal(pk,sk,seed,&a); break; default: ret=-9; };
  return finish(&a,s,ret);
}
int lc_dsa_sign_internal(int l,uint8_t *sig,const uint8_t *m,size_t ml,const uint8_t *pre,size_t pl,const uint8_t rnd[32],const uint8_t *sk,int ext,void *w,size_t n,lc_dsa_stats *s) {
  struct lc_dsa_arena a; int ret;
  init(&a,w,n);
  if(!sig||!rnd||!sk||!w||(!m&&ml)||(!pre&&pl)||(ext&&ml!=64)) return finish(&a,s,-9);
  switch(l) { case 65: ret=lcbase65_signature_internal(sig,m,ml,pre,pl,rnd,sk,ext,&a); break; default: ret=-9; };
  return finish(&a,s,ret);
}
int lc_dsa_verify_internal(int l,const uint8_t *sig,size_t sl,const uint8_t *m,size_t ml,const uint8_t *pre,size_t pl,const uint8_t *pk,int ext,void *w,size_t n,lc_dsa_stats *s) {
  struct lc_dsa_arena a; int ret;
  init(&a,w,n);
  if(!sig||!pk||!w||(!m&&ml)||(!pre&&pl)||(ext&&ml!=64)) return finish(&a,s,-9);
  if(!lc_dsa_size(l,2)||sl!=lc_dsa_size(l,2)) return finish(&a,s,-6);
  switch(l) { case 65: ret=lcbase65_verify_internal(sig,m,ml,pre,pl,pk,ext,&a); break; default: ret=-9; };
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
  switch(l) { case 65: ret=lcbase65_verify(sig,m,ml,ctx,cl,pk,&a); break; default: ret=-9; };
  return finish(&a,s,ret);
}
int lc_dsa_keypair(int l,uint8_t *pk,uint8_t *sk,void *w,size_t n,lc_dsa_stats *s) {
  struct lc_dsa_arena a; int ret;
  init(&a,w,n); if(!pk||!sk||!w) return finish(&a,s,-9);
  switch(l) { case 65: ret=lcbase65_keypair(pk,sk,&a); break; default: ret=-9; }; return finish(&a,s,ret);
}
int lc_dsa_sign(int l,uint8_t *sig,const uint8_t *m,size_t ml,const uint8_t *ctx,size_t cl,const uint8_t *sk,void *w,size_t n,lc_dsa_stats *s) {
  struct lc_dsa_arena a; int ret;
  init(&a,w,n); if(!sig||!sk||!w||(!m&&ml)||(!ctx&&cl)||cl>255) return finish(&a,s,-9);
  switch(l) { case 65: ret=lcbase65_signature(sig,m,ml,ctx,cl,sk,&a); break; default: ret=-9; }; return finish(&a,s,ret);
}

