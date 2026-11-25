/*
 * Thin sharing adapter. The permutation implementation below is included
 * unchanged from mlkem-native, copyright The mlkem-native project authors,
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT.
 * Its original references/attributions and licence files remain in the tree.
 * This adapter makes no claim to invent the permutation or its C schedule.
 */
#include "shared.h"
#include "../../third_party/mlkem-native/mlkem/src/fips202/keccakf1600.c"
#if defined(__GNUC__) && !defined(__clang__)
__attribute__((noinline,noclone))
#elif defined(__clang__)
__attribute__((noinline))
#endif
void lc_shared_keccakf1600(uint64_t state[25]) {
  mlk_keccakf1600_permute_c(state);
}
