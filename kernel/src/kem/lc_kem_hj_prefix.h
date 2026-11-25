/* Copyright (c) 2026 A1-27 project authors
 * SPDX-License-Identifier: Apache-2.0
 * Two long hash lanes and two public matrix lanes.
 * Public lengths are the three standard ML-KEM parameter sets. */
#ifndef LC_KEM_HJ_PREFIX_PROTOTYPE_H
#define LC_KEM_HJ_PREFIX_PROTOTYPE_H
#include <stdint.h>
#include <string.h>
#include "lc_kem_interleaved.h"
#ifndef LC_HJ_APPEND
#define LC_HJ_APPEND(index,out,count,rate,length) lc_kem_reject8(out,count,rate,length)
#endif
typedef struct __attribute__((aligned(32))) {
 uint64_t state[100];
 int16_t polynomial[2][256];
 uint8_t rate[168];
} lc_kem_hj_scratch;

static void lc_hj_xor(uint64_t *state,unsigned lane,const uint8_t *src,
                      unsigned word,unsigned words) {
 for(unsigned i=0;i<words;i++) {
  uint64_t x;memcpy(&x,src+8*i,8);
  state[4*lc_kem_word_to_slot[word+i]+lane]^=x;
 }
}
static void lc_hj_matrix_init(uint64_t *state,unsigned lane,const uint8_t rho[32],unsigned index,unsigned rank) {
 for(unsigned word=0;word<25;word++)state[4*word+lane]=0;
 lc_hj_xor(state,lane,rho,0,4);
 state[16+lane]=(uint64_t)(index/rank)|((uint64_t)(index%rank)<<8)|((uint64_t)0x1f<<16);
 state[56+lane]=(uint64_t)0x80<<56;
}
__attribute__((noinline,noclone))
static void lc_kem_hj_prefix(uint8_t h[32],uint8_t j[32],uint8_t prefix[1536],
 const uint8_t *pk,const uint8_t *ct,const uint8_t z[32],unsigned rank,unsigned ctbytes,
 lc_kem_hj_scratch *scratch) {
 uint64_t *state=scratch->state;
 unsigned count[2]={0,0},index[2]={0,1};
 const unsigned pkbytes=384*rank+32,hash_blocks=3*rank;
 memset(state,0,800);
 for(unsigned lane=0;lane<2;lane++)lc_hj_matrix_init(state,2+lane,pk+pkbytes-32,lane,rank);
 for(unsigned round=0;round<hash_blocks || index[0]<4 || index[1]<4;round++) {
  if(round<hash_blocks) {
   unsigned pos=136*round,hn=pkbytes-pos,jn=ctbytes+32-pos;
   if(hn>136)hn=136;if(jn>136)jn=136;
   lc_hj_xor(state,0,pk+pos,0,hn/8);
   if(round==0) {lc_hj_xor(state,1,z,0,4);lc_hj_xor(state,1,ct,4,13);}
   else lc_hj_xor(state,1,ct+pos-32,0,jn/8);
   if(round+1==hash_blocks) {
    state[4*lc_kem_word_to_slot[hn/8]]^=6;
    state[4*lc_kem_word_to_slot[jn/8]+1]^=31;
    state[4*lc_kem_word_to_slot[16]]^=(uint64_t)0x80<<56;
    state[4*lc_kem_word_to_slot[16]+1]^=(uint64_t)0x80<<56;
   }
  }
  lc_kem_interleaved_permute(state);
  if(round+1==hash_blocks)for(unsigned word=0;word<4;word++) {
   memcpy(h+8*word,state+4*word,8);memcpy(j+8*word,state+4*word+1,8);
  }
  for(unsigned lane=0;lane<2;lane++)if(index[lane]<4) {
   for(unsigned word=0;word<21;word++)
    memcpy(scratch->rate+8*word,state+4*lc_kem_word_to_slot[word]+2+lane,8);
   count[lane]=LC_HJ_APPEND(index[lane],scratch->polynomial[lane],count[lane],scratch->rate,168);
   if(count[lane]==256) {
    uint8_t *out=prefix+384*index[lane];
    for(unsigned i=0;i<128;i++) {
     unsigned a=(uint16_t)scratch->polynomial[lane][2*i],b=(uint16_t)scratch->polynomial[lane][2*i+1];
     out[3*i]=(uint8_t)a;out[3*i+1]=(uint8_t)((a>>8)|(b<<4));out[3*i+2]=(uint8_t)(b>>4);
    }
    index[lane]+=2;count[lane]=0;
    if(index[lane]<4)lc_hj_matrix_init(state,2+lane,pk+pkbytes-32,index[lane],rank);
   }
  }
 }
 mlk_zeroize(scratch,sizeof(*scratch));
}
#endif
