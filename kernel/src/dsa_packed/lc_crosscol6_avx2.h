/* Copyright (c) 2026 A1-27 project authors
 * SPDX-License-Identifier: Apache-2.0
 * Consecutive groups of four entries of the public 6-by-5 matrix.
 * Two live masking transforms fit the existing common workspace reserve.
 */
#ifndef LC_CROSSCOL6_AVX2_H
#define LC_CROSSCOL6_AVX2_H
#if MLDSA_K != 6 || MLDSA_L != 5 || !defined(__AVX2__) || !LC_DSA_MATRIX_INTERLEAVED
#error "This schedule requires the AVX2 persistent four-state backend and ML-DSA-65"
#endif
static __attribute__((optimize("O3"))) void lc_cross_matrix4(uint8_t *w,mld_polymat *mat,
    const mld_poly *current,const uint8_t saved[1024],unsigned current_col,
    unsigned start,unsigned lanes) {
  unsigned ctr[4]={0,0,0,0},pending;
  mld_memset(&mat->stream4,0,sizeof(mat->stream4));
  for(unsigned lane=0;lane<4;lane++) {
    unsigned position=start+(lane<lanes?lane:0);
    for(unsigned word=0;word<4;word++) {
      uint64_t x;mld_memcpy(&x,mat->rho+8*word,8);
      mat->stream4.state[4*word+lane]=x;
    }
    mat->stream4.state[16+lane]=(uint64_t)(position/6)
       |((uint64_t)(position%6)<<8)|((uint64_t)0x1f<<16);
    mat->stream4.state[56+lane]=(uint64_t)0x80<<56;
  }
  do {
    pending=0;lc_matrix_x4_permute(mat,lanes);
    for(unsigned lane=0;lane<lanes;lane++) {
      unsigned position=start+lane,col=position/6,row=position%6;
      const uint8_t *rhs=col==current_col?(const uint8_t *)(const void *)current:saved;
      uint8_t *out=w+row*LC_PACKED_ROW_BYTES;
      lc_matrix_x4_extract(mat,lane,lanes);
      for(unsigned j=0;ctr[lane]<MLDSA_N && j+3<=SHAKE128_RATE;) {
        const uint8_t *b=mat->stream4.rate+j;
        if(j+24<=SHAKE128_RATE && ctr[lane]+8<=MLDSA_N &&
           lc_stream4_y_block(out+3*ctr[lane],b,
              (const int32_t *)(const void *)(rhs+4*ctr[lane]),col==0)) {
          ctr[lane]+=8;j+=24;continue;
        }
        j+=3;
        uint32_t a=((uint32_t)b[0]|((uint32_t)b[1]<<8)|((uint32_t)b[2]<<16))&0x7fffffu;
        if(a<MLDSA_Q) {
          unsigned i=lc_matrix_native_index(ctr[lane]++);
          int32_t yvalue;mld_memcpy(&yvalue,rhs+4*i,4);
          uint8_t *v=out+3*i;int32_t x=mld_montgomery_reduce((int64_t)a*yvalue);
          x+=col==0?0:lc_load_signed24(v);lc_store_signed24(v,mld_reduce32(x));
        }
      }
      pending|=(unsigned)(ctr[lane]<MLDSA_N);
    }
  } while(pending);
  mld_zeroize(&mat->stream4,sizeof(mat->stream4));
}
static void lc_crosscol6_ay(uint8_t *w,mld_polymat *mat,const mld_yvec *y,
                           mld_poly *scratch,uint8_t saved[1024]) {
  unsigned current_col=0;
  mld_yvec_get_poly(scratch,y,0);mld_poly_ntt(scratch);lc_stream_transform_order(scratch);
  for(unsigned position=0;position<30;position+=4) {
    unsigned lanes=30-position<4?30-position:4;
    unsigned first_col=position/6,last_col=(position+lanes-1)/6;
    if(last_col!=current_col) {
      if(first_col!=last_col)mld_memcpy(saved,scratch,1024);
      mld_yvec_get_poly(scratch,y,last_col);mld_poly_ntt(scratch);lc_stream_transform_order(scratch);
      current_col=last_col;
    }
    lc_cross_matrix4(w,mat,scratch,saved,current_col,position,lanes);
  }
  mld_zeroize(saved,1024);
}
#endif
