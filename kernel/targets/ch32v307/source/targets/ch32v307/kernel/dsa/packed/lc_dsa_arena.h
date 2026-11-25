#ifndef LC_DSA_ARENA_H
#define LC_DSA_ARENA_H
#include <stddef.h>
#include <stdint.h>
struct lc_dsa_arena {
  uint8_t *base;
#if LC_DSA_PUBLIC_A_SESSION
  const uint8_t *a_cache;
  size_t a_cache_bytes;
#endif
  size_t capacity, used, peak, front_pad, allocations, failures, lifo_errors;
};
void *lc_dsa_alloc(struct lc_dsa_arena *a, size_t bytes);
void lc_dsa_free(struct lc_dsa_arena *a, void *ptr, size_t bytes);
#if LC_DSA_SHARED_SENSITIVE_FREE
__attribute__((noipa,visibility("hidden")))
void lc_dsa_sensitive_free(struct lc_dsa_arena *a,void *ptr,size_t bytes);
#endif
int lc_dsa_system_random(uint8_t *out, size_t bytes);
#endif
