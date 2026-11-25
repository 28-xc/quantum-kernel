/* Copyright (c) 2026 A1-27 project authors
 * SPDX-License-Identifier: Apache-2.0
 * ML-DSA-65: four public matrix streams overlap the next masking stream.
 * Original eight matrix groups and five y transforms are retained.
 */
#ifndef LC_NEXTY5_H
#define LC_NEXTY5_H
#if MLDSA_K != 6 || MLDSA_L != 5 || !LC_DSA_FIRST_GAMMA_CACHE || !LC_DSA_GAMMA_REVERSE_AVX2
#error "next-y schedule requires the qualified ML-DSA-65 owners"
#endif
void __attribute__((sysv_abi)) lc_keccak5_hybrid(uint64_t state[125],uint64_t temporary[25],const uint64_t constants[24]);
_Static_assert(sizeof(((mld_polymat *)0)->stream5)<=sizeof(mld_poly),"five states fit matrix owner");
_Static_assert(sizeof(lc_sign_w0_storage)>=6*768+200,"auxiliary follows all live matrix rows");
#ifndef LC_NEXTY5_RATE_HOOK
#define LC_NEXTY5_RATE_HOOK(rate,position,round) ((void)0)
#define LC_NEXTY5_RATE_HOOK_DEFAULT 1
#else
#define LC_NEXTY5_RATE_HOOK_DEFAULT 0
#endif
static __attribute__((optimize("O3"))) void
lc_nexty5_group(uint8_t *w,mld_polymat *mat,const mld_poly *current,mld_poly *future,
               const mld_yvec *y,unsigned next_col,unsigned start) {
  unsigned ctr[4]={0,0,0,0},round=0,pending;
  uint8_t *aux=w+6*768;
  uint64_t *states=mat->stream5;
  mld_memset(states,0,1000);
  for(unsigned lane=0;lane<4;lane++) {
    unsigned pos=start+lane;
    for(unsigned word=0;word<4;word++)mld_memcpy(states+4*word+lane,mat->rho+8*word,8);
    states[16+lane]=(uint64_t)(pos/6)|((uint64_t)(pos%6)<<8)|((uint64_t)0x1f<<16);
    states[56+lane]=(uint64_t)0x80<<56;
  }
  mld_memcpy(states+100,y->rhoprime,64);
  states[108]=(uint64_t)((uint16_t)(y->kappa+next_col))|((uint64_t)0x1f<<16);
  states[116]=(uint64_t)0x80<<56;
  do {
    pending=0;
    if(round<5) {
      lc_keccak5_hybrid(states,(uint64_t *)(void*)aux,lc_base_mlk_keccakf1600_round_constants);
      /* Keep the parent's complete five rate blocks, including the40 bytes
       * past the encoded polynomial. Reverse decoding reads at most646. */
      mld_memcpy((uint8_t *)(void*)future+136*round,states+100,136);
    } else {
      lc_keccak_x4_interleaved(states,lc_base_mlk_keccakf1600_round_constants,
                               lc_base_mlk_keccak_rho8,lc_base_mlk_keccak_rho56);
    }
    unsigned lc_prefix_bytes=0;
#if LC_DSA_LOWMEM_MATRIX_FAST && LC_DSA_MATRIX_INTERLEAVED && defined(__AVX2__) && !LC_DSA_STREAM_CACHE24
    /* Each hybrid group stays within one column and four contiguous rows.
     * Its first 100 words have the same public-state layout as stream4;
     * the fifth, secret masking stream and its output remain untouched. */
    lc_prefix_bytes=lc_lowmem_matrix_prefix(w+(start%6)*768,mat,current,ctr,4,start==0);
#endif
    for(unsigned lane=0;lane<4;lane++) {
#if LC_NEXTY5_RATE_HOOK_DEFAULT
      if(lc_prefix_bytes) {
        if(ctr[lane]>=256)continue;
        if(lc_prefix_bytes==168){pending=1;continue;}
      }
#endif
      for(unsigned word=0;word<21;word++)mld_memcpy(aux+8*word,states+4*lc_matrix_word_to_slot[word]+lane,8);
      LC_NEXTY5_RATE_HOOK(aux,start+lane,round);
      uint8_t *out=w+(start+lane)%6*768;
      for(unsigned j=lc_prefix_bytes;ctr[lane]<256 && j+3<=168;) {
        const uint8_t *b=aux+j;
        if(j+24<=168 && ctr[lane]+8<=256 &&
           lc_stream4_y_block(out+3*ctr[lane],b,current->coeffs+ctr[lane],start==0)) {
          ctr[lane]+=8;j+=24;continue;
        }
        j+=3;
        uint32_t a=((uint32_t)b[0]|((uint32_t)b[1]<<8)|((uint32_t)b[2]<<16))&0x7fffffu;
        if(a<8380417u) {
          unsigned i=lc_matrix_native_index(ctr[lane]++);
          uint8_t *v=out+3*i;int32_t x=mld_montgomery_reduce((int64_t)a*current->coeffs[i]);
          x+=start==0?0:lc_load_signed24(v);lc_store_signed24(v,mld_reduce32(x));
        }
      }
      pending|=(unsigned)(ctr[lane]<256);
    }
    round++;
  } while(pending);
  mld_zeroize(states,1000);mld_zeroize(aux,200);
#if LC_DSA_NATURAL_SIG_Y_ACTIVE
  /* The hybrid permutation already produced all five standard rate blocks.
   * Retain the useful640 bytes before reverse expansion destroys them. */
  mld_memcpy(y->encoded+next_col*MLDSA_POLYZ_PACKEDBYTES,
             future,MLDSA_POLYZ_PACKEDBYTES);
#endif
  lc_expand_gamma(future->coeffs,20,1<<19);
  mld_poly_ntt(future);lc_stream_transform_order(future);
}
static void lc_nexty5_ay(uint8_t *w,mld_polymat *mat,const mld_yvec *y,
                         mld_poly *first,uint8_t saved[1024]) {
  mld_poly *second=(mld_poly *)(void*)saved;
  mld_yvec_get_poly(first,y,0);mld_poly_ntt(first);lc_stream_transform_order(first);
  lc_nexty5_group(w,mat,first,second,y,1,0);
  lc_cross_matrix4(w,mat,second,(const uint8_t *)(const void*)first,1,4,4);
  lc_nexty5_group(w,mat,second,first,y,2,8);
  lc_nexty5_group(w,mat,first,second,y,3,12);
  lc_cross_matrix4(w,mat,second,(const uint8_t *)(const void*)first,3,16,4);
  lc_nexty5_group(w,mat,second,first,y,4,20);
  lc_cross_matrix4(w,mat,first,(const uint8_t *)(const void*)second,4,24,4);
  lc_cross_matrix4(w,mat,first,(const uint8_t *)(const void*)second,4,28,2);
  mld_zeroize(saved,1024);
}
#endif
