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
int lc_dsa_keypair_seed(int l,uint8_t*p,uint8_t*s,const uint8_t*r,void*w,size_t n,lc_dsa_stats*t){return -8;}
int lc_dsa_sign_seed(int l,uint8_t*s,const uint8_t*m,size_t n,const uint8_t*c,size_t k,const uint8_t*r,const uint8_t*d,void*w,size_t z,lc_dsa_stats*t){return -8;}
int lc_dsa_verify(int l,const uint8_t*s,size_t z,const uint8_t*m,size_t n,const uint8_t*c,size_t k,const uint8_t*p,void*w,size_t b,lc_dsa_stats*t){return -8;}
size_t lc_dsa_workspace_bound(int l,int op){(void)l;(void)op;return 0;}
