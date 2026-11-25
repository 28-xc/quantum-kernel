/* Copyright (c) 2026 A1-27 project authors
 * SPDX-License-Identifier: Apache-2.0
 * Consecutive public ExpandA streams cross at most one row boundary.
 * Both row accumulators remain independent of the SHAKE storage. */
#ifndef LC_FLAT_VERIFY_H
#define LC_FLAT_VERIFY_H
#if !LC_DSA_MATRIX_STREAM_DIRECT4 || !LC_DSA_MATRIX_STREAM_VECTOR || !LC_DSA_MATRIX_INTERLEAVED || !defined(__AVX2__)
#error "This candidate requires the qualified AVX2 interleaved matrix backend"
#endif
#include "lc_verify_hash_state.h"
void lc_dsa_flat_matrix_hash(int32_t *out, int32_t *carry, mld_polymat *mat,
                         const uint8_t *v, unsigned flat, unsigned columns,
                         unsigned lanes,lc_verify_hash3_state *hash);
#if defined(MLD_CONFIG_MULTILEVEL_WITH_SHARED)
__attribute__((noinline,noclone,optimize("O3")))
void lc_dsa_flat_matrix_hash(int32_t *out, int32_t *carry, mld_polymat *mat,
                         const uint8_t *v, unsigned flat, unsigned columns,
                         unsigned lanes,lc_verify_hash3_state *hash) {
  unsigned ctr[4]={0,0,0,0}, pending, round=0;
  const unsigned matrix_lanes=hash?3:4;
  unsigned col0=flat%columns, row0=flat/columns;
  const uint8_t *rhs[4];
  int32_t *dst[4];
  if(hash){for(unsigned word=0;word<25;word++)for(unsigned lane=0;lane<3;lane++)mat->stream4.state[4*word+lane]=0;}
  else mld_memset(&mat->stream4,0,sizeof(mat->stream4));
  if(col0+lanes>columns) mld_memset(carry,0,256*sizeof(int32_t));
  for(unsigned lane=0;lane<matrix_lanes;lane++) {
    unsigned at=flat+(lane<lanes?lane:0);
    unsigned col=at%columns, row=at/columns;
    rhs[lane]=v+col*768;
    dst[lane]=row==row0?out:carry;
    for(unsigned word=0;word<4;word++) {
      uint64_t x; mld_memcpy(&x,mat->rho+8*word,8);
      mat->stream4.state[4*word+lane]=x;
    }
    mat->stream4.state[16+lane]=(uint64_t)col|((uint64_t)row<<8)|((uint64_t)0x1f<<16);
    mat->stream4.state[56+lane]=(uint64_t)0x80<<56;
  }
  do {
    pending=0;
    if(hash && !hash->done) {
      lc_vh_block(hash,mat->stream4.rate);
      for(unsigned word=0;word<17;word++){uint64_t x;mld_memcpy(&x,mat->stream4.rate+8*word,8);mat->stream4.state[4*lc_matrix_word_to_slot[word]+3]^=x;}
    }
    lc_matrix_x4_permute(mat,4);
    if(hash && !hash->done)lc_vh_after(hash,mat->stream4.state,1);
    for(unsigned lane=0;lane<lanes;lane++) {
      lc_matrix_x4_extract(mat,lane,4);
      LC_VERIFY_HASH3_RATE_HOOK(mat->stream4.rate,flat+lane,round);
      for(unsigned j=0;ctr[lane]<256 && j+3<=SHAKE128_RATE;) {
        const uint8_t *b=mat->stream4.rate+j;
        if(j+24<=SHAKE128_RATE && ctr[lane]+8<=256 &&
           lc_stream4_v_block(dst[lane]+ctr[lane],b,rhs[lane]+3*ctr[lane])) {
          ctr[lane]+=8; j+=24; continue;
        }
        j+=3;
        uint32_t a=((uint32_t)b[0]|((uint32_t)b[1]<<8)|((uint32_t)b[2]<<16))&0x7fffffu;
        if(a<8380417u) {
          unsigned at=ctr[lane]++;
          dst[lane][at]+=mld_montgomery_reduce((int64_t)a*lc_load_signed24(rhs[lane]+3*at));
        }
      }
      pending|=(unsigned)(ctr[lane]<256);
    }
    round++;
  } while(pending);
  if(!hash)mld_zeroize(&mat->stream4,sizeof(mat->stream4));
}
#endif
static __attribute__((always_inline)) inline void
lc_dsa_flat_matrix4(int32_t *out,int32_t *carry,mld_polymat *mat,const uint8_t *v,
 unsigned flat,unsigned columns,unsigned lanes) {
 lc_dsa_flat_matrix_hash(out,carry,mat,v,flat,columns,lanes,NULL);
}
#if MLDSA_K > 4 || LC_DSA_VERIFY_HASH_BATCH
static void lc_flat_verify_row(mld_poly *out, mld_poly *carry, mld_polymat *mat,
                              const lc_packed_vecl *v, unsigned row,
                              unsigned *cursor) {
  if(*cursor==row*MLDSA_L) mld_memset(out,0,sizeof(*out));
  while(*cursor<(row+1)*MLDSA_L) {
    unsigned remain=MLDSA_K*MLDSA_L-*cursor;
    unsigned lanes=remain<4?remain:4;
    lc_dsa_flat_matrix4(out->coeffs,carry->coeffs,mat,(const uint8_t *)v,
                       *cursor,MLDSA_L,lanes);
    *cursor+=lanes;
  }
  mld_poly_reduce(out);
  lc_stream_transform_order(out);
}
#endif
#endif
