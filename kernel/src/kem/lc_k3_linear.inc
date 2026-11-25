/* SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 * Public rank-three row-major matrix groups 4+4+1. */
#if LC_KEM_LINEAR_K3 && MLKEM_K==3
#if !LC_KEM_MATRIX_INTERLEAVED || !LC_KEM_MATRIX_INITIAL3 || !LC_KEM_RATE_NATIVE_STAGE || !LC_KEM_TILE_BORROW || !LC_KEM_NOISE_RAW
#error "Linear K3 requires the validated interleaved staged/raw-noise parent"
#endif
#include "lc_k3_product.h"
_Static_assert(sizeof(((lc_kem_work_union*)0)->linear)<=sizeof(lc_kem_work_union),"Linear work fits original union");
_Static_assert(offsetof(lc_kem_work_union,linear.rate)==512,"Live partial row is protected");
_Static_assert(offsetof(lc_kem_work_union,linear.decoded)==704,"Native decoded scratch alignment");
_Static_assert(sizeof(mlk_xof_ctx)<=sizeof(lc_kem_cache_union),"Scalar tail fits shared state owner");
static void lc_k3_append(mlk_poly *out,unsigned *count,lc_kem_work_union *work,const uint8_t *bytes,unsigned length) {
#if LC_KEM_REJECT_DIRECT
 /* First 504 bytes occupy out itself: preserve disjoint decoding before the
  * expanding 12-to-16-bit representation is copied back. Continuations are
  * in the separate rate buffer and append directly to the complete object. */
 if(bytes==(const uint8_t*)out) {
  unsigned n=lc_kem_reject8(work->linear.decoded,0,bytes,length);
  mlk_memcpy(out->coeffs,work->linear.decoded,2*n);*count=n;
 } else *count=lc_kem_reject8(out->coeffs,*count,bytes,length);
#else
 int produced=mlk_rej_uniform_native(work->linear.decoded,MLKEM_N,bytes,length);
 if(produced==MLK_NATIVE_FUNC_FALLBACK)
  produced=(int)lc_kem_reject_rate(work->linear.decoded,0,bytes,length);
 unsigned take=(unsigned)produced;
 if(take>MLKEM_N-*count)take=MLKEM_N-*count;
 mlk_memcpy(out->coeffs+*count,work->linear.decoded,take*sizeof(int16_t));
 *count+=take;
#endif
}
static void lc_k3_tile(mlk_poly *tile,const uint8_t seed[32],unsigned first,int transpose,lc_kem_cache_union *owner,lc_kem_work_union *work) {
 MLK_ALIGN uint8_t ext[4][MLK_ALIGN_UP(34)];
 unsigned count[4]={0,0,0,0},n=first==8?1:4;
 for(unsigned lane=0;lane<n;lane++) {
  unsigned row=(first+lane)/3,col=(first+lane)%3;
  mlk_memcpy(ext[lane],seed,32);
  ext[lane][32]=(uint8_t)(transpose?row:col);
  ext[lane][33]=(uint8_t)(transpose?col:row);
 }
 if(n==4) {
  lc_kem_interleaved_init(owner->xof.ctx,&ext[0][0],sizeof ext[0]);
#if LC_KEM_DIRECT_STATE
  do {
   lc_kem_interleaved_permute(owner->xof.ctx);
   lc_kem_direct_state_rate4((int16_t (*)[256])(void*)tile,count,owner->xof.ctx);
  } while(count[0]<MLKEM_N||count[1]<MLKEM_N||count[2]<MLKEM_N||count[3]<MLKEM_N);
#else
  for(unsigned block=0;block<3;block++) {
   lc_kem_interleaved_permute(owner->xof.ctx);
   lc_kem_interleaved_extract((uint8_t*)tile+block*MLK_XOF_RATE,sizeof(mlk_poly),owner->xof.ctx);
  }
  for(unsigned lane=0;lane<4;lane++)lc_k3_append(tile+lane,count+lane,work,(uint8_t*)(tile+lane),3*MLK_XOF_RATE);
  while(count[0]<MLKEM_N||count[1]<MLKEM_N||count[2]<MLKEM_N||count[3]<MLKEM_N) {
   lc_kem_interleaved_permute(owner->xof.ctx);
   for(unsigned lane=0;lane<4;lane++) {
    for(unsigned word=0;word<21;word++)
     mlk_memcpy(work->linear.rate+8*word,owner->xof.ctx+4*lc_kem_word_to_slot[word]+lane,8);
    lc_k3_append(tile+lane,count+lane,work,work->linear.rate,MLK_XOF_RATE);
   }
  }
#endif
  mlk_xof_x4_release(&owner->xof);
 } else {
  mlk_xof_init(&owner->single);mlk_xof_absorb(&owner->single,ext[0],34);
  mlk_xof_squeezeblocks((uint8_t*)tile,3,&owner->single);
  lc_k3_append(tile,count,work,(uint8_t*)tile,3*MLK_XOF_RATE);
  while(count[0]<MLKEM_N) {
   mlk_xof_squeezeblocks(work->linear.rate,1,&owner->single);
   lc_k3_append(tile,count,work,work->linear.rate,MLK_XOF_RATE);
  }
  mlk_xof_release(&owner->single);
 }
 mlk_zeroize(owner,sizeof(*owner));
 mlk_zeroize(work->linear.rate,sizeof work->linear.rate);
 mlk_zeroize(work->linear.decoded,sizeof work->linear.decoded);
 for(unsigned lane=0;lane<n;lane++)mlk_poly_permute_bitrev_to_custom(tile[lane].coeffs);
 mlk_zeroize(ext,sizeof ext);
}
#endif
