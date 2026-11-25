/* SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT */
#ifndef LC_KECCAK_X4_INTERLEAVED_H
#define LC_KECCAK_X4_INTERLEAVED_H
#include <stdint.h>
static const unsigned lc_keccak_slot_to_word[25]={0,1,2,3,4,5,6,9,10,13,14,16,17,19,20,23,7,8,11,12,15,18,21,22,24};
void __attribute__((sysv_abi)) lc_keccak_x4_interleaved(
 uint64_t state[100],const uint64_t rc[24],
 const uint64_t rho8[4],const uint64_t rho56[4]);
#endif
