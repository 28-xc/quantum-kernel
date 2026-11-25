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
enum { LC_OK=0, LC_E_ARGUMENT=-1, LC_E_LENGTH=-2, LC_E_ALIAS=-3,
       LC_E_RANDOM=-4, LC_E_WORKSPACE=-5, LC_E_REJECT=-6, LC_E_INTERNAL=-7 };
typedef int (*lc_random_fn)(void *user,uint8_t *out,size_t bytes);
typedef struct {
  void *workspace;
  size_t workspace_bytes;
  lc_random_fn random;
  void *random_user;
  size_t arena_high_water, allocations, allocation_failures;
  int last_error;
} lc_context;
typedef struct { size_t public_key,secret_key,ciphertext,shared_secret,signature; } lc_sizes;
__attribute__((externally_visible)) int lc_get_sizes(int parameter,lc_sizes *sizes);
__attribute__((externally_visible)) int lc_context_init(lc_context *ctx,void *workspace,size_t bytes,
                    lc_random_fn random,void *random_user);
__attribute__((externally_visible)) int lc_keypair(lc_context *ctx,int parameter,uint8_t *pk,size_t pk_capacity,
               uint8_t *sk,size_t sk_capacity);
__attribute__((externally_visible)) int lc_encaps(lc_context *ctx,int parameter,uint8_t *ct,size_t ct_capacity,
              uint8_t *ss,size_t ss_capacity,const uint8_t *pk,size_t pk_bytes);
__attribute__((externally_visible)) int lc_decaps(lc_context *ctx,int parameter,uint8_t *ss,size_t ss_capacity,
              const uint8_t *ct,size_t ct_bytes,const uint8_t *sk,size_t sk_bytes);
__attribute__((externally_visible)) int lc_sign(lc_context *ctx,int parameter,uint8_t *sig,size_t sig_capacity,
            const uint8_t *message,size_t message_bytes,const uint8_t *domain,
            size_t domain_bytes,const uint8_t *sk,size_t sk_bytes);
__attribute__((externally_visible)) int lc_verify(lc_context *ctx,int parameter,const uint8_t *sig,size_t sig_bytes,
              const uint8_t *message,size_t message_bytes,const uint8_t *domain,
              size_t domain_bytes,const uint8_t *pk,size_t pk_bytes);
__attribute__((externally_visible)) const char *lc_error_string(int status);
enum { LC_E_UNSUPPORTED = -8 };
static int lc_standard_parameter(int p){return p==512||p==768||p==1024||p==44||p==65||p==87;}
static int lc_pruned_supports(int p){return p==87;}

typedef struct lc_arena {
    uint8_t *base;
    size_t capacity, used, high_water, failed_size, allocations;
    int error;
} lc_arena;
void lc_arena_init(lc_arena *a, void *base, size_t capacity);
void *lc_arena_alloc(lc_arena *a, size_t bytes);
void lc_arena_free(lc_arena *a, void *ptr, size_t bytes);
void lc_zero(void *p, size_t bytes);
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
int lc_system_random(uint8_t *out, size_t bytes);
static int lc_dsa_secret_encoding_valid(int parameter,const uint8_t *sk)
{
    const uint8_t *v=sk+128;
    uint32_t bad=0;
    if(parameter==65){
        for(unsigned i=0;i<11u*128u;i++){
            uint32_t x=v[i];
            bad|=(8u-(x&15u))>>31;
            bad|=(8u-(x>>4))>>31;
        }
    }else{
        const unsigned n=parameter==44?8u*96u:15u*96u;
        for(unsigned i=0;i<n;i+=3){
            uint32_t x=(uint32_t)v[i]|((uint32_t)v[i+1]<<8)|((uint32_t)v[i+2]<<16);
            for(unsigned j=0;j<8;j++)bad|=(4u-((x>>(3*j))&7u))>>31;
        }
    }
    return bad==0;
}
void *memcpy(void *restrict dst, const void *restrict src, size_t n);
void *memmove(void *dst, const void *src, size_t n);
void *memset(void *dst, int value, size_t n);
int memcmp(const void *a, const void *b, size_t n);
size_t strlen(const char *s);

extern int lc_mlk_call(int,int,unsigned char*,unsigned char*,const unsigned char*,const unsigned char*,lc_arena*);
typedef struct { const void *p; size_t n; } region;
static int kem(int p){return 0;}
static int dsa(int p){return p==87;}
int lc_get_sizes(int p,lc_sizes*s){
 if(!s)return LC_E_ARGUMENT;
 memset(s,0,sizeof(*s));
 switch(p){
 case 87:s->public_key=2592;s->secret_key=4896;s->signature=4627;break;
 default:return lc_standard_parameter(p)?LC_E_UNSUPPORTED:LC_E_ARGUMENT;
 }
 if(kem(p))s->shared_secret=32;
 return LC_OK;
}
static int overlaps(region a,region b){
 uintptr_t x=(uintptr_t)a.p,y=(uintptr_t)b.p;
 if(!a.n||!b.n)return 0;
 return x<=y?y-x<a.n:x-y<b.n;
}
static int validate(lc_context*c,region*r,size_t n){
 size_t i,j;
 if(!c||!c->workspace||!c->workspace_bytes)return LC_E_ARGUMENT;
 r[n++]=(region){c->workspace,c->workspace_bytes};
 r[n++]=(region){c,sizeof(*c)};
 for(i=0;i<n;i++){
  if((!r[i].p&&r[i].n)||r[i].n>4294967295U -(uintptr_t)r[i].p)return LC_E_ARGUMENT;
  for(j=0;j<i;j++)if(overlaps(r[i],r[j]))return LC_E_ALIAS;
 }
 c->arena_high_water=c->allocations=c->allocation_failures=0;c->last_error=0;
 return LC_OK;
}
int lc_context_init(lc_context*c,void*w,size_t n,lc_random_fn f,void*u){
 if(!c||!w||!n||n>4294967295U -(uintptr_t)w)return LC_E_ARGUMENT;
 if(overlaps((region){c,sizeof(*c)},(region){w,n}))return LC_E_ALIAS;
 memset(c,0,sizeof(*c));c->workspace=w;c->workspace_bytes=n;c->random=f;c->random_user=u;
 return 0;
}
static int random_bytes(lc_context*c,uint8_t*p,size_t n){
 int r=c->random?c->random(c->random_user,p,n):lc_system_random(p,n);
 return r?LC_E_RANDOM:LC_OK;
}
extern int lc_f407_fits(int,int,const void *,size_t);
static int lc_target_workspace(lc_context *ctx,int p,int op) {
  if (lc_f407_fits(p,op,ctx->workspace,ctx->workspace_bytes)) return LC_OK;
  ctx->allocation_failures=1;
  return ctx->last_error=LC_E_WORKSPACE;
}
static int result(lc_context*c,int raw,lc_arena*a,lc_dsa_stats*s){
 int r;
 if(a){c->arena_high_water=a->high_water;c->allocations=a->allocations;
  c->allocation_failures=a->failed_size?1:0;
  r=a->error||a->used?LC_E_INTERNAL:a->failed_size?LC_E_WORKSPACE:raw?LC_E_REJECT:0;
 }else{c->arena_high_water=s->arena_high_water;c->allocations=s->allocations;
  c->allocation_failures=s->allocation_failures;
  r=s->lifo_errors||s->arena_remaining?LC_E_INTERNAL:s->allocation_failures?LC_E_WORKSPACE:raw?LC_E_REJECT:0;
 }
 c->last_error=r;return r;
}

typedef struct {
  unsigned short p,pk,sk,ct,sig;
  __typeof__(lc_target_workspace) *workspace;
  __typeof__(lc_mlk_call) *kem;
  __typeof__(lc_dsa_keypair_seed) *key;
  __typeof__(lc_dsa_sign_seed) *sign;
  __typeof__(lc_dsa_verify) *verify;
} cap_public_dispatch;
static const __attribute__((used)) cap_public_dispatch cap_public_cell={87,2592,4896,0,4627,lc_target_workspace,0,lc_dsa_keypair_seed,lc_dsa_sign_seed,lc_dsa_verify};
static int lc_dsa_secret_encoding_valid(int parameter,const uint8_t *sk);
__attribute__((weak,noinline)) int cap_pub_lc_keypair(lc_context*c,const cap_public_dispatch *v,uint8_t*pk,size_t pn,uint8_t*sk,size_t sn);
__attribute__((weak,noinline)) int cap_pub_lc_encaps(lc_context*c,const cap_public_dispatch *v,uint8_t*ct,size_t cn,uint8_t*ss,size_t sn,const uint8_t*pk,size_t pn);
__attribute__((weak,noinline)) int cap_pub_lc_decaps(lc_context*c,const cap_public_dispatch *v,uint8_t*ss,size_t sn,const uint8_t*ct,size_t cn,const uint8_t*sk,size_t kn);
__attribute__((weak,noinline)) int cap_pub_lc_sign(lc_context*c,const cap_public_dispatch *v,uint8_t*sig,size_t sn,const uint8_t*m,size_t mn,const uint8_t*d,size_t dn,const uint8_t*sk,size_t kn);
__attribute__((weak,noinline)) int cap_pub_lc_verify(lc_context*c,const cap_public_dispatch *v,const uint8_t*sig,size_t sn,const uint8_t*m,size_t mn,const uint8_t*d,size_t dn,const uint8_t*pk,size_t pn);
__attribute__((naked)) int lc_keypair(lc_context*c,int p,uint8_t*pk,size_t pn,uint8_t*sk,size_t sn){__asm__ volatile("ldr r12,=cap_public_cell\n b k24_gate_keypair");}
__attribute__((naked)) int lc_encaps(lc_context*c,int p,uint8_t*ct,size_t cn,uint8_t*ss,size_t sn,const uint8_t*pk,size_t pn){__asm__ volatile("ldr r12,=cap_public_cell\n b k24_gate_wrong");}
__attribute__((naked)) int lc_decaps(lc_context*c,int p,uint8_t*ss,size_t sn,const uint8_t*ct,size_t cn,const uint8_t*sk,size_t kn){__asm__ volatile("ldr r12,=cap_public_cell\n b k24_gate_wrong");}
__attribute__((naked)) int lc_sign(lc_context*c,int p,uint8_t*sig,size_t sn,const uint8_t*m,size_t mn,const uint8_t*d,size_t dn,const uint8_t*sk,size_t kn){__asm__ volatile("ldr r12,=cap_public_cell\n b k24_gate_sign");}
__attribute__((naked)) int lc_verify(lc_context*c,int p,const uint8_t*sig,size_t sn,const uint8_t*m,size_t mn,const uint8_t*d,size_t dn,const uint8_t*pk,size_t pn){__asm__ volatile("ldr r12,=cap_public_cell\n b k24_gate_verify");}
const char*lc_error_string(int e){switch(e){case LC_E_UNSUPPORTED:return "unsupported parameter or operation in this build";case LC_OK:return "success";case LC_E_ARGUMENT:return "invalid argument";
 case LC_E_LENGTH:return "invalid length";case LC_E_ALIAS:return "overlapping objects";case LC_E_RANDOM:return "random source failed";
 case LC_E_WORKSPACE:return "insufficient workspace";case LC_E_REJECT:return "operation rejected";default:return "internal invariant failure";}}

