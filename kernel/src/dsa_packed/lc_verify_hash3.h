/* Copyright (c) 2026 A1-27 project authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef LC_VERIFY_HASH3_H
#define LC_VERIFY_HASH3_H
#if (!LC_DSA_VERIFY_HASH_BATCH && (MLDSA_K != 6 || MLDSA_L != 5)) || !LC_DSA_FLAT_VERIFY || !LC_DSA_MATRIX_INTERLEAVED
#error "The three-matrix/hash schedule requires the qualified ML-DSA-65 backend"
#endif
#include "lc_verify_hash_state.h"
static void lc_vh_row(mld_poly *out,mld_poly *carry,mld_polymat *mat,
 const lc_packed_vecl *v,unsigned row,unsigned *cursor,lc_verify_hash3_state *hash,mld_shake256ctx *saved) {
 if(*cursor==row*MLDSA_L)mld_memset(out,0,1024);
 for(unsigned word=0;word<25;word++)mat->stream4.state[4*lc_matrix_word_to_slot[word]+3]=saved->s[word];
 while(*cursor<(row+1)*MLDSA_L) {
  unsigned remaining=MLDSA_K*MLDSA_L-*cursor;
  if(!hash->done){unsigned lanes=remaining<3?remaining:3;lc_dsa_flat_matrix_hash(out->coeffs,carry->coeffs,mat,(const uint8_t *)v,*cursor,MLDSA_L,lanes,hash);*cursor+=lanes;}
  else {unsigned lanes=remaining<4?remaining:4;lc_dsa_flat_matrix4(out->coeffs,carry->coeffs,mat,(const uint8_t *)v,*cursor,MLDSA_L,lanes);*cursor+=lanes;}
 }
 if(!hash->done)for(unsigned word=0;word<25;word++)saved->s[word]=mat->stream4.state[4*lc_matrix_word_to_slot[word]+3];
 mld_zeroize(&mat->stream4,sizeof(mat->stream4));
 mld_poly_reduce(out);lc_stream_transform_order(out);
}
#endif
