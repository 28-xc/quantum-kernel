#ifndef LATTICE_SESSION_H
#define LATTICE_SESSION_H
#include "latticecore.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Experimental explicit public-A reuse API. Cache format is specific to the
 * exact library build. Caller owns all storage and must not alter cache or
 * metadata while initialized. All objects, including scratch, are disjoint.
 * Initialize only a new or closed descriptor; close before reinitialization.
 * A session and its context are single-threaded and non-reentrant. Binding
 * covers parameter+rho, not key identity; equal rho legitimately shares A. */
typedef struct {
  uint8_t *cache;
  size_t capacity, cache_bytes;
  uint8_t rho[32];
  uint32_t magic, ready;
  int parameter;
  uint32_t format_tag;
} lc_a_session;
__attribute__((externally_visible)) size_t lc_a_session_cache_bytes(int parameter);
/* op=0 prepare,1 sign,2 verify. Excludes persistent cache, descriptor, stack,
 * globals and application buffers; include all of them in deployment budgets. */
__attribute__((externally_visible)) size_t lc_a_session_workspace_bound(int parameter,int op);
__attribute__((externally_visible)) int lc_a_session_init(lc_a_session*,int parameter,void *cache,size_t capacity);
__attribute__((externally_visible)) int lc_a_session_prepare(lc_context*,lc_a_session*,const uint8_t *pk,size_t pk_bytes);
__attribute__((externally_visible)) int lc_a_session_sign(lc_context*,lc_a_session*,int parameter,
 uint8_t *sig,size_t sig_capacity,const uint8_t *message,size_t message_bytes,
 const uint8_t *domain,size_t domain_bytes,const uint8_t *sk,size_t sk_bytes);
__attribute__((externally_visible)) int lc_a_session_verify(lc_context*,lc_a_session*,int parameter,
 const uint8_t *sig,size_t sig_bytes,const uint8_t *message,size_t message_bytes,
 const uint8_t *domain,size_t domain_bytes,const uint8_t *pk,size_t pk_bytes);
__attribute__((externally_visible)) int lc_a_session_close(lc_a_session*);
#ifdef __cplusplus
}
#endif
#endif
