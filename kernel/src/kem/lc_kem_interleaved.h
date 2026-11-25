/* SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 * Reuse the shared four-lane permutation and its existing constant owner.
 * State is exactly 800 bytes, in the same slot order as the DSA stream. */
#ifndef LC_KEM_INTERLEAVED_H
#define LC_KEM_INTERLEAVED_H
#include <stdint.h>
#include <stddef.h>
#include "../dsa_packed/keccak_x4_interleaved.h"
extern const uint64_t lc_base_mlk_keccakf1600_round_constants[24];
extern const uint64_t lc_base_mlk_keccak_rho8[4];
extern const uint64_t lc_base_mlk_keccak_rho56[4];
static const uint8_t lc_kem_word_to_slot[25]={0,1,2,3,4,5,6,16,17,7,8,18,19,9,10,20,11,12,21,13,14,22,23,15,24};
static void lc_kem_interleaved_init(uint64_t state[100],const uint8_t *input,size_t stride) {
 mlk_memset(state,0,800);
 for(unsigned lane=0;lane<4;lane++) {
  const uint8_t *p=input+lane*stride;
  for(unsigned word=0;word<4;word++) {uint64_t x;mlk_memcpy(&x,p+8*word,8);state[4*word+lane]=x;}
  state[16+lane]=(uint64_t)p[32]|((uint64_t)p[33]<<8)|((uint64_t)0x1f<<16);
  state[56+lane]=(uint64_t)0x80<<56;
 }
}
static void lc_kem_interleaved_permute(uint64_t state[100]) {
 lc_keccak_x4_interleaved(state,lc_base_mlk_keccakf1600_round_constants,lc_base_mlk_keccak_rho8,lc_base_mlk_keccak_rho56);
}
static void lc_kem_interleaved_extract(uint8_t *output,size_t stride,const uint64_t state[100]) {
 for(unsigned lane=0;lane<4;lane++)
  for(unsigned word=0;word<21;word++)
   mlk_memcpy(output+lane*stride+8*word,state+4*lc_kem_word_to_slot[word]+lane,8);
}
/* SHAKE256 PRF(seed || nonce), with its exact 136-byte rate. The same owner
 * holds the 800-byte state used by matrix sampling at a disjoint lifetime. */
static void lc_kem_noise_interleaved_init(uint64_t state[100],const uint8_t seed[32],uint8_t first) {
 mlk_memset(state,0,800);
 for(unsigned word=0;word<4;word++) {
  uint64_t x;mlk_memcpy(&x,seed+8*word,8);
  for(unsigned lane=0;lane<4;lane++)state[4*word+lane]=x;
 }
 for(unsigned lane=0;lane<4;lane++) {
  state[16+lane]=(uint64_t)(uint8_t)(first+lane)|((uint64_t)0x1f<<8);
  state[44+lane]=(uint64_t)0x80<<56;
 }
}
static void lc_kem_noise_interleaved_extract(uint8_t *a,uint8_t *b,uint8_t *c,uint8_t *d,const uint64_t state[100]) {
 for(unsigned word=0;word<17;word++) {
  const uint64_t *x=state+4*lc_kem_word_to_slot[word];
  mlk_memcpy(a+8*word,x,8);mlk_memcpy(b+8*word,x+1,8);
  mlk_memcpy(c+8*word,x+2,8);mlk_memcpy(d+8*word,x+3,8);
 }
}

#endif
