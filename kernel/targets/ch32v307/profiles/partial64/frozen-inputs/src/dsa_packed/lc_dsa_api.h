#ifndef LC_DSA_API_H
#define LC_DSA_API_H
#include <stddef.h>
#include <stdint.h>

typedef struct lc_dsa_stats {
  size_t arena_capacity, arena_high_water, arena_remaining;
  size_t allocations, allocation_failures, lifo_errors, context_bytes;
} lc_dsa_stats;

/* op: 0=keygen, 1=sign, 2=verify. Bounds exclude residual stack and I/O. */
size_t lc_dsa_workspace_bound(int level, int op);
size_t lc_dsa_size(int level, int kind); /* 0=pk,1=sk,2=sig */
int lc_dsa_native_enabled(void);
int lc_dsa_lowram_enabled(void);
int lc_dsa_keypair_seed(int level, uint8_t *pk, uint8_t *sk,
  const uint8_t seed[32], void *workspace, size_t workspace_bytes, lc_dsa_stats *stats);
/* Raw internal API for ACVP. Prefix is formatted message prefix; externalmu=1 expects 64-byte mu. */
int lc_dsa_sign_internal(int level, uint8_t *sig, const uint8_t *msg, size_t msg_bytes,
  const uint8_t *prefix, size_t prefix_bytes, const uint8_t rnd[32], const uint8_t *sk,
  int externalmu, void *workspace, size_t workspace_bytes, lc_dsa_stats *stats);
int lc_dsa_verify_internal(int level, const uint8_t *sig, size_t sig_bytes,
  const uint8_t *msg, size_t msg_bytes, const uint8_t *prefix, size_t prefix_bytes,
  const uint8_t *pk, int externalmu, void *workspace, size_t workspace_bytes,
  lc_dsa_stats *stats);
/* FIPS 204 pure-ML-DSA message formatting, caller-supplied random input for controlled tests. */
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

#if LC_DSA_PUBLIC_A_SESSION
/* Cache points to dedicated public-only storage, never to workspace. The raw
 * adapter is trusted by the validated explicit public session API. */
size_t lc_dsa_a_cache_bytes(int level);
uint32_t lc_dsa_a_format_tag(int level);
size_t lc_dsa_a_workspace_bound(int level,int op);
int lc_dsa_a_prepare(int level,uint8_t *cache,const uint8_t rho[32],
 void *workspace,size_t workspace_bytes,lc_dsa_stats *stats);
int lc_dsa_a_sign_seed(int level,const uint8_t *cache,uint8_t *sig,
 const uint8_t *msg,size_t msg_bytes,const uint8_t *domain,size_t domain_bytes,
 const uint8_t rnd[32],const uint8_t *sk,void *workspace,size_t workspace_bytes,lc_dsa_stats *stats);
int lc_dsa_a_verify(int level,const uint8_t *cache,const uint8_t *sig,size_t sig_bytes,
 const uint8_t *msg,size_t msg_bytes,const uint8_t *domain,size_t domain_bytes,
 const uint8_t *pk,void *workspace,size_t workspace_bytes,lc_dsa_stats *stats);
#endif
#endif
