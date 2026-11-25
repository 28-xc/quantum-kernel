/* SPDX-License-Identifier: Apache-2.0
 * Whole-row public A cache with destructive dense A*y scheduling.
 * For ML-DSA-87, rows r..7 are generated first. Their overwritten y columns
 * r..6 are saved; row7 has no original y. Cached rows0..r-1 then use the
 * original eight-frequency capture-before-store dot product. The separate-Y
 * ablation retains all seven transformed columns in an independent owner;
 * sampling, arithmetic and output row order stay the same. All saved y owners
 * are call-local, included in the arena bound and wiped by MLD_FREE.
 */
#ifndef LC_PARTIAL_DENSE_H
#define LC_PARTIAL_DENSE_H
#if LC_DSA_RUNTIME_CACHE_ACTIVE
/* Runtime admission selects only the qualified five-row or full layout.
 * This helper is entered only by the five-row branch, so preserve the static
 * arithmetic schedule and its loop bounds instead of generalizing them. */
#define LC_PARTIAL_ROWS(mat) 5u
#define LC_PARTIAL_COUNT(mat) (5u*MLDSA_L)
#else
#define LC_PARTIAL_ROWS(mat) LC_DSA_PARTIAL_DENSE_ROWS
#define LC_PARTIAL_COUNT(mat) LC_DSA_A_CACHE_COUNT
#endif
_Static_assert(MLDSA_K==8 && MLDSA_L==7,"qualified partial-row dimensions");
static void lc_partial_permute(mld_polymat *mat) {
#if defined(__aarch64__)
  mld_keccakf1600x4_permute(mat->stream4.state);
#else
  lc_matrix_x4_permute(mat,4);
#endif
}
static const uint8_t *lc_partial_rate(mld_polymat *mat,unsigned lane) {
#if defined(__aarch64__)
  return (const uint8_t *)(const void *)(mat->stream4.state+25*lane);
#else
  lc_matrix_x4_extract(mat,lane,4);return mat->stream4.rate;
#endif
}
static void lc_partial_fill(mld_polymat *mat) {
  for(unsigned base=0;base<LC_PARTIAL_COUNT(mat);base+=4) {
    unsigned lanes=LC_PARTIAL_COUNT(mat)-base<4?LC_PARTIAL_COUNT(mat)-base:4;
    unsigned ctr[4]={0,0,0,0};mld_memset(&mat->stream4,0,sizeof(mat->stream4));
    for(unsigned lane=0;lane<4;lane++) {
      unsigned at=base+(lane<lanes?lane:0),col=at%MLDSA_L,row=at/MLDSA_L;
#if defined(__aarch64__)
      uint64_t *state=mat->stream4.state+25*lane;mld_memcpy(state,mat->rho,32);
      state[4]=(uint64_t)col|((uint64_t)row<<8)|((uint64_t)0x1f<<16);state[20]=(uint64_t)0x80<<56;
#else
      for(unsigned word=0;word<4;word++){uint64_t x;mld_memcpy(&x,mat->rho+8*word,8);mat->stream4.state[4*word+lane]=x;}
      mat->stream4.state[16+lane]=(uint64_t)col|((uint64_t)row<<8)|((uint64_t)0x1f<<16);mat->stream4.state[56+lane]=(uint64_t)0x80<<56;
#endif
    }
    for(;;) {
      unsigned pending=0;lc_partial_permute(mat);
      for(unsigned lane=0;lane<lanes;lane++) {
        const uint8_t *rate=lc_partial_rate(mat,lane);
        for(unsigned j=0;ctr[lane]<256 && j+3<=SHAKE128_RATE;) {
          const uint8_t *b=rate+j;
          if(j+24<=SHAKE128_RATE && ctr[lane]+8<=256) {
#if defined(__aarch64__)
            uint32x4_t a,c;
            if(lc_stream_public8(b,&a,&c)) {lc_stream_cache_store8(mat,base+lane,ctr[lane],a,c);ctr[lane]+=8;j+=24;continue;}
#else
            __m256i a=_mm256_and_si256(lc_s4_load24(b),_mm256_set1_epi32(0x7fffff));
            if(!_mm256_movemask_epi8(_mm256_cmpgt_epi32(a,_mm256_set1_epi32(8380416)))) {lc_stream_cache_store8(mat,base+lane,ctr[lane],b);ctr[lane]+=8;j+=24;continue;}
#endif
          }
          uint32_t a=((uint32_t)b[0]|((uint32_t)b[1]<<8)|((uint32_t)b[2]<<16))&0x7fffffu;j+=3;
          if(a<MLDSA_Q)lc_stream_cache_store1(mat,base+lane,ctr[lane]++,a);
        }
        if(ctr[lane]<256)pending=1;
      }
      if(!pending)break;
    }
  }
  mat->cache_ready=1;
}
static const int32_t *lc_partial_y(const mld_polymat *mat,const uint8_t *w,const mld_poly *saved,unsigned l) {
  (void)mat;
#if LC_DSA_PARTIAL_DENSE_SEPARATE_Y
  (void)w;(void)mat;return saved[l].coeffs;
#else
  return l<LC_PARTIAL_ROWS(mat)?(const int32_t *)(const void *)(w+l*LC_SIGN_AY_ROW_BYTES):saved[l-LC_PARTIAL_ROWS(mat)].coeffs;
#endif
}
static void lc_partial_stream_row(int32_t *out,mld_polymat *mat,const uint8_t *w,const mld_poly *saved,unsigned row) {
  mld_memset(out,0,1024);
  for(unsigned base=0;base<MLDSA_L;base+=4) {
    unsigned lanes=MLDSA_L-base<4?MLDSA_L-base:4;unsigned ctr[4]={0,0,0,0};
    lc_matrix_x4_start(mat,base,row,0,lanes);
    for(;;) {
      unsigned pending=0;lc_partial_permute(mat);
      for(unsigned lane=0;lane<lanes;lane++) {
        const uint8_t *rate=lc_partial_rate(mat,lane);const int32_t *rhs=lc_partial_y(mat,w,saved,base+lane);
        for(unsigned j=0;ctr[lane]<256 && j+3<=SHAKE128_RATE;) {
          const uint8_t *b=rate+j;unsigned pos=ctr[lane];
          if(j+24<=SHAKE128_RATE && pos+8<=256) {
#if defined(__aarch64__)
            uint32x4_t a,c;
            if(lc_stream_public8(b,&a,&c)) {
              int32x4_t lo=lc_stream_montgomery(vreinterpretq_s32_u32(a),vld1q_s32(rhs+pos)),hi=lc_stream_montgomery(vreinterpretq_s32_u32(c),vld1q_s32(rhs+pos+4));
              vst1q_s32(out+pos,lc_stream_reduce32(vaddq_s32(vld1q_s32(out+pos),lo)));vst1q_s32(out+pos+4,lc_stream_reduce32(vaddq_s32(vld1q_s32(out+pos+4),hi)));
              ctr[lane]+=8;j+=24;continue;
            }
#else
            __m256i a=_mm256_and_si256(lc_s4_load24(b),_mm256_set1_epi32(0x7fffff));
            if(!_mm256_movemask_epi8(_mm256_cmpgt_epi32(a,_mm256_set1_epi32(8380416)))) {
              __m256i v=lc_s4_product(a,_mm256_loadu_si256((const __m256i *)(const void *)(rhs+pos)));
              v=lc_s4_reduce(_mm256_add_epi32(v,_mm256_loadu_si256((const __m256i *)(const void *)(out+pos))));_mm256_storeu_si256((__m256i *)(void *)(out+pos),v);
              ctr[lane]+=8;j+=24;continue;
            }
#endif
          }
          uint32_t a=((uint32_t)b[0]|((uint32_t)b[1]<<8)|((uint32_t)b[2]<<16))&0x7fffffu;j+=3;
          if(a<MLDSA_Q){unsigned i=ctr[lane]++;out[i]=mld_reduce32(out[i]+mld_montgomery_reduce((int64_t)a*rhs[i]));}
        }
        if(ctr[lane]<256)pending=1;
      }
      if(!pending)break;
    }
  }
}

#if defined(__aarch64__)
static void lc_partial_dense_ay(uint8_t *w,mld_polymat *mat,const mld_yvec *y,mld_poly *saved) {
  if(!mat->cache_ready)lc_partial_fill(mat);
  for(unsigned l=0;l<MLDSA_L;l++) {
#if LC_DSA_PARTIAL_DENSE_SEPARATE_Y
    mld_poly *yp=&saved[l];
#else
    mld_poly *yp=(mld_poly *)(void *)(w+l*LC_SIGN_AY_ROW_BYTES);
#endif
    mld_yvec_get_poly(yp,y,l);mld_poly_ntt(yp);lc_stream_transform_order(yp);
  }
#if !LC_DSA_PARTIAL_DENSE_SEPARATE_Y
  for(unsigned l=LC_PARTIAL_ROWS(mat);l<MLDSA_L;l++)
    mld_memcpy(saved[l-LC_PARTIAL_ROWS(mat)].coeffs,w+l*LC_SIGN_AY_ROW_BYTES,1024);
#endif
  for(unsigned k=MLDSA_K;k-->LC_PARTIAL_ROWS(mat);)
    lc_partial_stream_row((int32_t *)(void *)(w+k*LC_SIGN_AY_ROW_BYTES),mat,w,saved,k);
  const int32x4_t q=vdupq_n_s32(8380417);
  for(unsigned i=0;i<MLDSA_N;i+=8) {
    int32x4_t y0a,y0b;
    mld_memcpy(&y0a,((const uint8_t *)(const void *)lc_partial_y(mat,w,saved,0))+4*i,16);
    mld_memcpy(&y0b,((const uint8_t *)(const void *)lc_partial_y(mat,w,saved,0))+4*i+16,16);
    int32x4_t y1a,y1b;
    mld_memcpy(&y1a,((const uint8_t *)(const void *)lc_partial_y(mat,w,saved,1))+4*i,16);
    mld_memcpy(&y1b,((const uint8_t *)(const void *)lc_partial_y(mat,w,saved,1))+4*i+16,16);
    int32x4_t y2a,y2b;
    mld_memcpy(&y2a,((const uint8_t *)(const void *)lc_partial_y(mat,w,saved,2))+4*i,16);
    mld_memcpy(&y2b,((const uint8_t *)(const void *)lc_partial_y(mat,w,saved,2))+4*i+16,16);
    int32x4_t y3a,y3b;
    mld_memcpy(&y3a,((const uint8_t *)(const void *)lc_partial_y(mat,w,saved,3))+4*i,16);
    mld_memcpy(&y3b,((const uint8_t *)(const void *)lc_partial_y(mat,w,saved,3))+4*i+16,16);
#if MLDSA_L > 4
    int32x4_t y4a,y4b;
    mld_memcpy(&y4a,((const uint8_t *)(const void *)lc_partial_y(mat,w,saved,4))+4*i,16);
    mld_memcpy(&y4b,((const uint8_t *)(const void *)lc_partial_y(mat,w,saved,4))+4*i+16,16);
#endif
#if MLDSA_L > 5
    int32x4_t y5a,y5b;
    mld_memcpy(&y5a,((const uint8_t *)(const void *)lc_partial_y(mat,w,saved,5))+4*i,16);
    mld_memcpy(&y5b,((const uint8_t *)(const void *)lc_partial_y(mat,w,saved,5))+4*i+16,16);
#endif
#if MLDSA_L > 6
    int32x4_t y6a,y6b;
    mld_memcpy(&y6a,((const uint8_t *)(const void *)lc_partial_y(mat,w,saved,6))+4*i,16);
    mld_memcpy(&y6b,((const uint8_t *)(const void *)lc_partial_y(mat,w,saved,6))+4*i+16,16);
#endif
    for(unsigned k=0;k<LC_PARTIAL_ROWS(mat);k++) {
      int64x2_t s0=vdupq_n_s64(0),s1=s0,s2=s0,s3=s0;
      {
        uint32x4_t u0,u1;
#if LC_DSA_A_PLANES24
        lc_a_planes_load_neon(mat->cache[k*MLDSA_L+0],i,&u0,&u1);
#else
        mld_memcpy(&u0,mat->cache[k*MLDSA_L+0]+4*i,16);
        mld_memcpy(&u1,mat->cache[k*MLDSA_L+0]+4*i+16,16);
#endif
        const int32x4_t a0=vreinterpretq_s32_u32(u0),a1=vreinterpretq_s32_u32(u1);
        s0=vmlal_s32(s0,vget_low_s32(a0),vget_low_s32(y0a));
        s1=vmlal_high_s32(s1,a0,y0a);
        s2=vmlal_s32(s2,vget_low_s32(a1),vget_low_s32(y0b));
        s3=vmlal_high_s32(s3,a1,y0b);
      }
      {
        uint32x4_t u0,u1;
#if LC_DSA_A_PLANES24
        lc_a_planes_load_neon(mat->cache[k*MLDSA_L+1],i,&u0,&u1);
#else
        mld_memcpy(&u0,mat->cache[k*MLDSA_L+1]+4*i,16);
        mld_memcpy(&u1,mat->cache[k*MLDSA_L+1]+4*i+16,16);
#endif
        const int32x4_t a0=vreinterpretq_s32_u32(u0),a1=vreinterpretq_s32_u32(u1);
        s0=vmlal_s32(s0,vget_low_s32(a0),vget_low_s32(y1a));
        s1=vmlal_high_s32(s1,a0,y1a);
        s2=vmlal_s32(s2,vget_low_s32(a1),vget_low_s32(y1b));
        s3=vmlal_high_s32(s3,a1,y1b);
      }
      {
        uint32x4_t u0,u1;
#if LC_DSA_A_PLANES24
        lc_a_planes_load_neon(mat->cache[k*MLDSA_L+2],i,&u0,&u1);
#else
        mld_memcpy(&u0,mat->cache[k*MLDSA_L+2]+4*i,16);
        mld_memcpy(&u1,mat->cache[k*MLDSA_L+2]+4*i+16,16);
#endif
        const int32x4_t a0=vreinterpretq_s32_u32(u0),a1=vreinterpretq_s32_u32(u1);
        s0=vmlal_s32(s0,vget_low_s32(a0),vget_low_s32(y2a));
        s1=vmlal_high_s32(s1,a0,y2a);
        s2=vmlal_s32(s2,vget_low_s32(a1),vget_low_s32(y2b));
        s3=vmlal_high_s32(s3,a1,y2b);
      }
      {
        uint32x4_t u0,u1;
#if LC_DSA_A_PLANES24
        lc_a_planes_load_neon(mat->cache[k*MLDSA_L+3],i,&u0,&u1);
#else
        mld_memcpy(&u0,mat->cache[k*MLDSA_L+3]+4*i,16);
        mld_memcpy(&u1,mat->cache[k*MLDSA_L+3]+4*i+16,16);
#endif
        const int32x4_t a0=vreinterpretq_s32_u32(u0),a1=vreinterpretq_s32_u32(u1);
        s0=vmlal_s32(s0,vget_low_s32(a0),vget_low_s32(y3a));
        s1=vmlal_high_s32(s1,a0,y3a);
        s2=vmlal_s32(s2,vget_low_s32(a1),vget_low_s32(y3b));
        s3=vmlal_high_s32(s3,a1,y3b);
      }
#if MLDSA_L > 4
      {
        uint32x4_t u0,u1;
#if LC_DSA_A_PLANES24
        lc_a_planes_load_neon(mat->cache[k*MLDSA_L+4],i,&u0,&u1);
#else
        mld_memcpy(&u0,mat->cache[k*MLDSA_L+4]+4*i,16);
        mld_memcpy(&u1,mat->cache[k*MLDSA_L+4]+4*i+16,16);
#endif
        const int32x4_t a0=vreinterpretq_s32_u32(u0),a1=vreinterpretq_s32_u32(u1);
        s0=vmlal_s32(s0,vget_low_s32(a0),vget_low_s32(y4a));
        s1=vmlal_high_s32(s1,a0,y4a);
        s2=vmlal_s32(s2,vget_low_s32(a1),vget_low_s32(y4b));
        s3=vmlal_high_s32(s3,a1,y4b);
      }
#endif
#if MLDSA_L > 5
      {
        uint32x4_t u0,u1;
#if LC_DSA_A_PLANES24
        lc_a_planes_load_neon(mat->cache[k*MLDSA_L+5],i,&u0,&u1);
#else
        mld_memcpy(&u0,mat->cache[k*MLDSA_L+5]+4*i,16);
        mld_memcpy(&u1,mat->cache[k*MLDSA_L+5]+4*i+16,16);
#endif
        const int32x4_t a0=vreinterpretq_s32_u32(u0),a1=vreinterpretq_s32_u32(u1);
        s0=vmlal_s32(s0,vget_low_s32(a0),vget_low_s32(y5a));
        s1=vmlal_high_s32(s1,a0,y5a);
        s2=vmlal_s32(s2,vget_low_s32(a1),vget_low_s32(y5b));
        s3=vmlal_high_s32(s3,a1,y5b);
      }
#endif
#if MLDSA_L > 6
      {
        uint32x4_t u0,u1;
#if LC_DSA_A_PLANES24
        lc_a_planes_load_neon(mat->cache[k*MLDSA_L+6],i,&u0,&u1);
#else
        mld_memcpy(&u0,mat->cache[k*MLDSA_L+6]+4*i,16);
        mld_memcpy(&u1,mat->cache[k*MLDSA_L+6]+4*i+16,16);
#endif
        const int32x4_t a0=vreinterpretq_s32_u32(u0),a1=vreinterpretq_s32_u32(u1);
        s0=vmlal_s32(s0,vget_low_s32(a0),vget_low_s32(y6a));
        s1=vmlal_high_s32(s1,a0,y6a);
        s2=vmlal_s32(s2,vget_low_s32(a1),vget_low_s32(y6b));
        s3=vmlal_high_s32(s3,a1,y6b);
      }
#endif
        int32x4_t t0=vuzp1q_s32(vreinterpretq_s32_s64(s0),vreinterpretq_s32_s64(s1));
        int32x4_t t1=vuzp1q_s32(vreinterpretq_s32_s64(s2),vreinterpretq_s32_s64(s3));
        t0=vreinterpretq_s32_u32(vmulq_u32(vreinterpretq_u32_s32(t0),vdupq_n_u32(58728449)));
        t1=vreinterpretq_s32_u32(vmulq_u32(vreinterpretq_u32_s32(t1),vdupq_n_u32(58728449)));
        s0=vmlsl_s32(s0,vget_low_s32(t0),vget_low_s32(q));s1=vmlsl_high_s32(s1,t0,q);
        s2=vmlsl_s32(s2,vget_low_s32(t1),vget_low_s32(q));s3=vmlsl_high_s32(s3,t1,q);
        int32x4_t lo=vuzp2q_s32(vreinterpretq_s32_s64(s0),vreinterpretq_s32_s64(s1));
        int32x4_t hi=vuzp2q_s32(vreinterpretq_s32_s64(s2),vreinterpretq_s32_s64(s3));
      lo=lc_stream_reduce32(lo);hi=lc_stream_reduce32(hi);
      mld_memcpy(w+k*LC_SIGN_AY_ROW_BYTES+4*i,&lo,16);
      mld_memcpy(w+k*LC_SIGN_AY_ROW_BYTES+4*i+16,&hi,16);
    }
  }
}
#else
static void lc_partial_dense_ay(uint8_t *w,mld_polymat *mat,const mld_yvec *y,mld_poly *saved) {
  if(!mat->cache_ready)lc_partial_fill(mat);
  for(unsigned l=0;l<MLDSA_L;l++) {
#if LC_DSA_PARTIAL_DENSE_SEPARATE_Y
    mld_poly *yp=&saved[l];
#else
    mld_poly *yp=(mld_poly *)(void *)(w+l*LC_SIGN_AY_ROW_BYTES);
#endif
    mld_yvec_get_poly(yp,y,l);mld_poly_ntt(yp);lc_stream_transform_order(yp);
  }
#if !LC_DSA_PARTIAL_DENSE_SEPARATE_Y
  for(unsigned l=LC_PARTIAL_ROWS(mat);l<MLDSA_L;l++)
    mld_memcpy(saved[l-LC_PARTIAL_ROWS(mat)].coeffs,w+l*LC_SIGN_AY_ROW_BYTES,1024);
#endif
  for(unsigned k=MLDSA_K;k-->LC_PARTIAL_ROWS(mat);)
    lc_partial_stream_row((int32_t *)(void *)(w+k*LC_SIGN_AY_ROW_BYTES),mat,w,saved,k);
  for(unsigned i=0;i<MLDSA_N;i+=8) {
#if MLDSA_L > 0
    const __m256i y0=_mm256_load_si256((const __m256i *)(const void *)(((const uint8_t *)(const void *)lc_partial_y(mat,w,saved,0))+4*i));
#endif
#if MLDSA_L > 1
    const __m256i y1=_mm256_load_si256((const __m256i *)(const void *)(((const uint8_t *)(const void *)lc_partial_y(mat,w,saved,1))+4*i));
#endif
#if MLDSA_L > 2
    const __m256i y2=_mm256_load_si256((const __m256i *)(const void *)(((const uint8_t *)(const void *)lc_partial_y(mat,w,saved,2))+4*i));
#endif
#if MLDSA_L > 3
    const __m256i y3=_mm256_load_si256((const __m256i *)(const void *)(((const uint8_t *)(const void *)lc_partial_y(mat,w,saved,3))+4*i));
#endif
#if MLDSA_L > 4
    const __m256i y4=_mm256_load_si256((const __m256i *)(const void *)(((const uint8_t *)(const void *)lc_partial_y(mat,w,saved,4))+4*i));
#endif
#if MLDSA_L > 5
    const __m256i y5=_mm256_load_si256((const __m256i *)(const void *)(((const uint8_t *)(const void *)lc_partial_y(mat,w,saved,5))+4*i));
#endif
#if MLDSA_L > 6
    const __m256i y6=_mm256_load_si256((const __m256i *)(const void *)(((const uint8_t *)(const void *)lc_partial_y(mat,w,saved,6))+4*i));
#endif
    for(unsigned k=0;k<LC_PARTIAL_ROWS(mat);k++) {
      __m256i even=_mm256_setzero_si256(),odd=_mm256_setzero_si256();
#if MLDSA_L > 0
      {
#if LC_DSA_A_PLANES24
        const __m256i av=lc_a_planes_load(mat->cache[k*MLDSA_L+0],i);
#else
        const __m256i av=_mm256_loadu_si256((const __m256i *)(const void *)(mat->cache[k*MLDSA_L+0]+4*i));
#endif
        even=_mm256_add_epi64(even,_mm256_mul_epi32(av,y0));
        odd=_mm256_add_epi64(odd,_mm256_mul_epi32(_mm256_srli_epi64(av,32),_mm256_srli_epi64(y0,32))); }
#endif
#if MLDSA_L > 1
      {
#if LC_DSA_A_PLANES24
        const __m256i av=lc_a_planes_load(mat->cache[k*MLDSA_L+1],i);
#else
        const __m256i av=_mm256_loadu_si256((const __m256i *)(const void *)(mat->cache[k*MLDSA_L+1]+4*i));
#endif
        even=_mm256_add_epi64(even,_mm256_mul_epi32(av,y1));
        odd=_mm256_add_epi64(odd,_mm256_mul_epi32(_mm256_srli_epi64(av,32),_mm256_srli_epi64(y1,32))); }
#endif
#if MLDSA_L > 2
      {
#if LC_DSA_A_PLANES24
        const __m256i av=lc_a_planes_load(mat->cache[k*MLDSA_L+2],i);
#else
        const __m256i av=_mm256_loadu_si256((const __m256i *)(const void *)(mat->cache[k*MLDSA_L+2]+4*i));
#endif
        even=_mm256_add_epi64(even,_mm256_mul_epi32(av,y2));
        odd=_mm256_add_epi64(odd,_mm256_mul_epi32(_mm256_srli_epi64(av,32),_mm256_srli_epi64(y2,32))); }
#endif
#if MLDSA_L > 3
      {
#if LC_DSA_A_PLANES24
        const __m256i av=lc_a_planes_load(mat->cache[k*MLDSA_L+3],i);
#else
        const __m256i av=_mm256_loadu_si256((const __m256i *)(const void *)(mat->cache[k*MLDSA_L+3]+4*i));
#endif
        even=_mm256_add_epi64(even,_mm256_mul_epi32(av,y3));
        odd=_mm256_add_epi64(odd,_mm256_mul_epi32(_mm256_srli_epi64(av,32),_mm256_srli_epi64(y3,32))); }
#endif
#if MLDSA_L > 4
      {
#if LC_DSA_A_PLANES24
        const __m256i av=lc_a_planes_load(mat->cache[k*MLDSA_L+4],i);
#else
        const __m256i av=_mm256_loadu_si256((const __m256i *)(const void *)(mat->cache[k*MLDSA_L+4]+4*i));
#endif
        even=_mm256_add_epi64(even,_mm256_mul_epi32(av,y4));
        odd=_mm256_add_epi64(odd,_mm256_mul_epi32(_mm256_srli_epi64(av,32),_mm256_srli_epi64(y4,32))); }
#endif
#if MLDSA_L > 5
      {
#if LC_DSA_A_PLANES24
        const __m256i av=lc_a_planes_load(mat->cache[k*MLDSA_L+5],i);
#else
        const __m256i av=_mm256_loadu_si256((const __m256i *)(const void *)(mat->cache[k*MLDSA_L+5]+4*i));
#endif
        even=_mm256_add_epi64(even,_mm256_mul_epi32(av,y5));
        odd=_mm256_add_epi64(odd,_mm256_mul_epi32(_mm256_srli_epi64(av,32),_mm256_srli_epi64(y5,32))); }
#endif
#if MLDSA_L > 6
      {
#if LC_DSA_A_PLANES24
        const __m256i av=lc_a_planes_load(mat->cache[k*MLDSA_L+6],i);
#else
        const __m256i av=_mm256_loadu_si256((const __m256i *)(const void *)(mat->cache[k*MLDSA_L+6]+4*i));
#endif
        even=_mm256_add_epi64(even,_mm256_mul_epi32(av,y6));
        odd=_mm256_add_epi64(odd,_mm256_mul_epi32(_mm256_srli_epi64(av,32),_mm256_srli_epi64(y6,32))); }
#endif
      const __m256i qi=_mm256_set1_epi32(58728449),q=_mm256_set1_epi32(8380417);
      const __m256i te=_mm256_mul_epi32(even,qi),to=_mm256_mul_epi32(odd,qi);
      const __m256i re=_mm256_sub_epi64(even,_mm256_mul_epi32(te,q));
      const __m256i ro=_mm256_sub_epi64(odd,_mm256_mul_epi32(to,q));
      const __m256i sum=_mm256_blend_epi32(_mm256_srli_epi64(re,32),ro,0xaa);
      _mm256_store_si256((__m256i *)(void *)(w+k*LC_SIGN_AY_ROW_BYTES+4*i),lc_s4_reduce(sum));
    }
  }
}
#endif
#endif
