/* SPDX-License-Identifier: Apache-2.0
 * Four consecutive public matrix entries share one Keccak batch. Entries
 * crossing a row boundary accumulate in a second independent polynomial. */
#ifndef LC_FLAT_MATRIX_NEON_H
#define LC_FLAT_MATRIX_NEON_H
static __attribute__((optimize("O3"))) void lc_arm_flat_matrix4(
    int32_t *out,int32_t *carry,mld_polymat *mat,const uint8_t *v,
    unsigned flat,unsigned columns,unsigned lanes) {
  unsigned ctr[4]={0,0,0,0};const uint8_t *rhs[4];int32_t *dst[4];
  unsigned row0=flat/columns;
  mld_memset(&mat->stream4,0,sizeof(mat->stream4));
  if(flat%columns+lanes>columns)mld_memset(carry,0,256*sizeof(int32_t));
  for(unsigned lane=0;lane<4;lane++) {
    unsigned at=flat+(lane<lanes?lane:0),col=at%columns,row=at/columns;
    rhs[lane]=v+col*LC_DSA_VECTOR_ROW_BYTES;dst[lane]=row==row0?out:carry;
    uint64_t *state=mat->stream4.state+25*lane;
    mld_memcpy(state,mat->rho,32);
    state[4]=(uint64_t)col|((uint64_t)row<<8)|((uint64_t)0x1f<<16);
    state[20]=(uint64_t)0x80<<56;
  }
  for(;;) {
    unsigned pending=0;
    if(lanes<=2)for(unsigned lane=0;lane<lanes;lane++)mld_keccakf1600_permute(mat->stream4.state+25*lane);
    else mld_keccakf1600x4_permute(mat->stream4.state);
    for(unsigned lane=0;lane<lanes;lane++) {
      const uint8_t *rate=(const uint8_t *)(const void *)(mat->stream4.state+25*lane);
      for(unsigned j=0;ctr[lane]<256 && j+3<=SHAKE128_RATE;) {
        const uint8_t *b=rate+j;
        if(j+24<=SHAKE128_RATE && ctr[lane]+8<=256) {
          uint32x4_t a0,a1;
          if(lc_stream_public8(b,&a0,&a1)) {
#if LC_DSA_KEYVERIFY_DENSE
            const int32_t *input=(const int32_t *)(const void *)rhs[lane]+ctr[lane];
            int32x4_t r0=lc_stream_montgomery(vreinterpretq_s32_u32(a0),vld1q_s32(input));
            int32x4_t r1=lc_stream_montgomery(vreinterpretq_s32_u32(a1),vld1q_s32(input+4));
            vst1q_s32(dst[lane]+ctr[lane],vaddq_s32(vld1q_s32(dst[lane]+ctr[lane]),r0));
            vst1q_s32(dst[lane]+ctr[lane]+4,vaddq_s32(vld1q_s32(dst[lane]+ctr[lane]+4),r1));
#else
            lc_stream_v8(dst[lane]+ctr[lane],rhs[lane]+3*ctr[lane],a0,a1);
#endif
            ctr[lane]+=8;j+=24;continue;
          }
        }
        j+=3;
        uint32_t a=((uint32_t)b[0]|((uint32_t)b[1]<<8)|((uint32_t)b[2]<<16))&0x7fffffu;
        if(a<8380417u) {
          unsigned at=ctr[lane]++;
#if LC_DSA_KEYVERIFY_DENSE
          int32_t input;mld_memcpy(&input,rhs[lane]+4*at,sizeof(input));
#else
          int32_t input=lc_load_signed24(rhs[lane]+3*at);
#endif
          dst[lane][at]+=mld_montgomery_reduce((int64_t)a*input);
        }
      }
      pending|=ctr[lane]<256;
    }
    if(!pending)break;
  }
  mld_zeroize(&mat->stream4,sizeof(mat->stream4));
}
#if MLDSA_K > 4
static void lc_flat_verify_row(mld_poly *out,mld_poly *carry,mld_polymat *mat,
                              const lc_packed_vecl *v,unsigned row,unsigned *cursor) {
  if(*cursor==row*MLDSA_L)mld_memset(out,0,sizeof(*out));
  while(*cursor<(row+1)*MLDSA_L) {
    unsigned remaining=MLDSA_K*MLDSA_L-*cursor,lanes=remaining<4?remaining:4;
    lc_arm_flat_matrix4(out->coeffs,carry->coeffs,mat,(const uint8_t *)v,*cursor,MLDSA_L,lanes);
    *cursor+=lanes;
  }
  mld_poly_reduce(out);lc_stream_transform_order(out);
}
#endif
#endif
