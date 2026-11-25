/* Copyright (c) 2026 A1-27 project authors
 * SPDX-License-Identifier: Apache-2.0
 * Public encapsulation precomputation: SHA3-256(pk) and four SHAKE128 A streams.
 * prefix holds four complete custom-order polynomials until G/noise finishes.
 */
#ifndef LC_KEM_ENC_HYBRID_H
#define LC_KEM_ENC_HYBRID_H
#include <stdint.h>
#include <string.h>
#include "lc_kem_interleaved.h"
void __attribute__((sysv_abi)) lc_keccak5_hybrid(uint64_t state[125],uint64_t temporary[25],const uint64_t constants[24]);
/* Disjoint views into three existing arena union members. The s union
 * has no live secret until this helper returns; tile remains disjoint/live. */
typedef struct {
 uint64_t *states;       /* 125 words in the unused s owner. */
 uint64_t *temporary;    /* 25 words in the cache owner. */
 int16_t *decoded;      /* 256 coefficients, then a 168-byte rate, in work. */
} lc_kem_enc_hybrid_scratch;
#ifndef LC_EH_RATE_HOOK
#define LC_EH_RATE_HOOK(rate,lane,round) ((void)0)
#endif
#ifndef LC_EH_COUNT_HOOK
#define LC_EH_COUNT_HOOK(kind) ((void)0)
#endif
#ifndef LC_EH_PERMUTE_POLY
#define LC_EH_PERMUTE_POLY(p) mlk_poly_permute_bitrev_to_custom(p)
#endif
static void lc_eh_absorb(uint64_t state[25],const uint8_t *pk,unsigned rank,unsigned round) {
 unsigned n=384*rank+32-136*round;
 if(n>136)n=136;
 for(unsigned i=0;i<n/8;i++) {
  uint64_t a;mlk_memcpy(&a,pk+136*round+8*i,8);state[i]^=a;
 }
 if(round+1==3*rank) {state[n/8]^=6;state[16]^=(uint64_t)128<<56;}
}
__attribute__((noinline,noclone))
static void lc_kem_enc_hybrid(uint8_t hash[32],int16_t prefix[4][256],
 const uint8_t *pk,unsigned rank,lc_kem_enc_hybrid_scratch *scratch) {
 uint64_t *state=scratch->states;
 unsigned count[4]={0,0,0,0},pending=0,round;
 mlk_memset(state,0,1000);
 for(unsigned lane=0;lane<4;lane++) {
  for(unsigned word=0;word<4;word++) {
   uint64_t a;mlk_memcpy(&a,pk+384*rank+8*word,8);state[4*word+lane]=a;
  }
  state[16+lane]=(uint64_t)(lane/rank)|((uint64_t)(lane%rank)<<8)|((uint64_t)31<<16);
  state[56+lane]=(uint64_t)128<<56;
 }
 /* Preserve the parent's three-block batch and exact 504-byte decoding. */
 for(round=0;round<3;round++) {
  lc_eh_absorb(state+100,pk,rank,round);
  lc_keccak5_hybrid(state,scratch->temporary,lc_base_mlk_keccakf1600_round_constants);
  LC_EH_COUNT_HOOK(0);
#if LC_KEM_DIRECT_STATE
  lc_kem_direct_state_rate4(prefix,count,state);
#else
  for(unsigned lane=0;lane<4;lane++) {
   uint8_t *out=(uint8_t *)(void*)prefix[lane]+168*round;
   for(unsigned word=0;word<21;word++)
    mlk_memcpy(out+8*word,state+4*lc_kem_word_to_slot[word]+lane,8);
   LC_EH_RATE_HOOK(out,lane,round);
  }
#endif
 }
 for(unsigned lane=0;lane<4;lane++) {
#if !LC_KEM_DIRECT_STATE
  count[lane]=lc_kem_reject8(scratch->decoded,0,(const uint8_t *)(const void*)prefix[lane],504);
  mlk_memcpy(prefix[lane],scratch->decoded,2*count[lane]);
#endif
  pending|=count[lane]<256;
 }
 /* An unfinished public matrix lane continues without discarding bytes.
  * The completed hash lane is detached before any subsequent XOF-only calls. */
 for(;pending || round<3*rank;round++) {
  if(round<3*rank) {
   lc_eh_absorb(state+100,pk,rank,round);
   if(pending) {
    lc_keccak5_hybrid(state,scratch->temporary,lc_base_mlk_keccakf1600_round_constants);
    LC_EH_COUNT_HOOK(0);
   } else {mlk_keccakf1600_permute(state+100);LC_EH_COUNT_HOOK(1);}
   if(round+1==3*rank)mlk_memcpy(hash,state+100,32);
  } else {lc_kem_interleaved_permute(state);LC_EH_COUNT_HOOK(2);}
  if(pending) {
   pending=0;
#if LC_KEM_DIRECT_STATE
   lc_kem_direct_state_rate4(prefix,count,state);
   for(unsigned lane=0;lane<4;lane++)pending|=count[lane]<256;
#else
   for(unsigned lane=0;lane<4;lane++)if(count[lane]<256) {
    for(unsigned word=0;word<21;word++)
     mlk_memcpy(((uint8_t *)(void*)scratch->decoded)+8*word,state+4*lc_kem_word_to_slot[word]+lane,8);
    LC_EH_RATE_HOOK(((uint8_t *)(void*)scratch->decoded),lane,round);
    count[lane]=lc_kem_reject8(prefix[lane],count[lane],((uint8_t *)(void*)scratch->decoded),168);
    pending|=count[lane]<256;
   }
#endif
  }
 }
 for(unsigned lane=0;lane<4;lane++)LC_EH_PERMUTE_POLY(prefix[lane]);
 mlk_zeroize(scratch->states,1000);
 mlk_zeroize(scratch->temporary,200);
 mlk_zeroize(scratch->decoded,512);
}
#endif
