#ifndef LC_SHARED_KECCAK_H
#define LC_SHARED_KECCAK_H
#include <stdint.h>
/* Exactly 25 canonical uint64_t lanes; no SHAKE context, rate or domain is
 * transferred across algorithm families. No CPU-dependent ABI is used here. */
void lc_shared_keccakf1600(uint64_t state[25]);
#endif
