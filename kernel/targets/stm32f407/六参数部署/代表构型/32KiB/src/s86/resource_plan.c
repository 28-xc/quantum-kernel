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
extern size_t lc_f407_aligned_workspace(int,int);
extern size_t lc_f407_usable_requirement(int,int,size_t);
enum { LC_RESOURCE_FIXED=0, LC_RESOURCE_FULL_MATRIX=1,
       LC_RESOURCE_FIVE_ROWS=2 };
enum { LC_RESOURCE_E_UNSUPPORTED=-8 };
typedef struct {
  size_t minimum_workspace_bytes, preferred_workspace_bytes;
  size_t alignment, public_context_bytes, caller_plan_bytes;
  unsigned adaptive, exact_workspace_bound;
} lc_resource_requirements;
typedef struct {
  size_t workspace_bytes, alignment_padding, usable_workspace_bytes;
  size_t required_workspace_bytes, matrix_cache_bytes, saved_input_bytes;
  unsigned mode, cached_rows, cached_polynomials;
} lc_resource_plan;
__attribute__((externally_visible)) int lc_resource_query(int parameter,int operation,
    lc_resource_requirements *requirements);
__attribute__((externally_visible)) int lc_resource_make_plan(int parameter,int operation,
    const void *workspace,size_t bytes,lc_resource_plan *plan);
__attribute__((externally_visible)) int lc_resource_algorithm_bytes(size_t workspace_bytes,
    size_t stack_bytes,size_t other_bytes,size_t *total_bytes);
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
void *memcpy(void *restrict dst, const void *restrict src, size_t n);
void *memmove(void *dst, const void *src, size_t n);
void *memset(void *dst, int value, size_t n);
int memcmp(const void *a, const void *b, size_t n);
size_t strlen(const char *s);
typedef size_t (*cap_aligned_fn)(int,int);typedef size_t (*cap_usable_fn)(int,int,size_t);
__attribute__((noinline,weak)) int cap_query(cap_aligned_fn bound,int p,int op,lc_resource_requirements *r){
  unsigned index;
  if(!r)return LC_E_ARGUMENT;
  memset(r,0,sizeof(*r));
  if(op<0||op>2)return LC_E_ARGUMENT;
  switch(p) {
  case 512:index=0;break;case 768:index=1;break;case 1024:index=2;break;
  case 44:index=3;break;case 65:index=4;break;case 87:index=5;break;
  default:return LC_E_ARGUMENT;
  }
  if(!(262143u & (1u << (index*3+(unsigned)op))))
    return LC_RESOURCE_E_UNSUPPORTED;
  r->alignment=32;r->public_context_bytes=sizeof(lc_context);
  r->caller_plan_bytes=sizeof(lc_resource_plan);
  size_t fixed = bound(p,op);
  if (!fixed) { memset(r,0,sizeof(*r)); return LC_RESOURCE_E_UNSUPPORTED; }
  r->minimum_workspace_bytes = r->preferred_workspace_bytes = fixed;
  return 0;
}
int lc_resource_query(int p,int op,lc_resource_requirements *r) {return cap_query(lc_f407_aligned_workspace,p,op,r);}
__attribute__((noinline,weak)) int cap_plan(cap_aligned_fn bound,cap_usable_fn usable,int p,int op,const void *w,size_t bytes,lc_resource_plan *out){
  lc_resource_requirements r;size_t pad,need;unsigned rows=0;int rc;
  if(!out)return LC_E_ARGUMENT;
  memset(out,0,sizeof(*out));
  if((rc=cap_query(bound,p,op,&r)))return rc;
  if(!w||bytes>4294967295U -(uintptr_t)w)return LC_E_ARGUMENT;
  pad=(32-((uintptr_t)w&31))&31;
  out->workspace_bytes=bytes;out->alignment_padding=pad;
  out->usable_workspace_bytes=bytes>=pad?bytes-pad:0;
  need=usable(p,op,pad);
  if(out->usable_workspace_bytes<need)return LC_E_WORKSPACE;
  out->required_workspace_bytes=need;
  return 0;
}
int lc_resource_make_plan(int p,int op,const void *w,size_t bytes,lc_resource_plan *out) {return cap_plan(lc_f407_aligned_workspace,lc_f407_usable_requirement,p,op,w,bytes,out);}
int lc_resource_algorithm_bytes(size_t w,size_t stack,size_t other,size_t *total) {
  size_t n=w;
  if(!total)return LC_E_ARGUMENT;
  *total=0;
  if(stack>4294967295U -n)return LC_E_ARGUMENT;
  n+=stack;
  if(sizeof(lc_context)>4294967295U -n)return LC_E_ARGUMENT;
  n+=sizeof(lc_context);
  if(other>4294967295U -n)return LC_E_ARGUMENT;
  n+=other;
  *total=n;return 0;
}
