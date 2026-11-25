#ifndef LC_SHARED_KECCAK_COMPACT_H
#define LC_SHARED_KECCAK_COMPACT_H
#include <stdint.h>
/* One 25-lane Keccak-f[1600] permutation. Family SHAKE rates, domain bytes,
 * absorb/squeeze buffers and standard interfaces remain in their frontends. */
#if defined(__GNUC__) && !defined(_WIN32)
__attribute__((visibility("hidden")))
#endif
#if defined(__GNUC__)
__attribute__((noinline))
#endif
void lc_shared_keccakf1600(uint64_t state[25]);
#endif
