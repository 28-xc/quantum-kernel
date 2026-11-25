/* SPDX-License-Identifier: Apache-2.0
 * Call-owned complete public matrix, natural-order NTT(y), and one Montgomery
 * reduction after each 64-bit row dot product. For a<q and |NTT(y)|<94279698,
 * |sum|<=7*(q-1)*(94279698-1)=5530721568497664<q*2^31; correction is int64-safe.
 * All loops and addresses depend on public dimensions or public A rejection.
 */
#ifndef LC_SPEED32_NEON_H
#define LC_SPEED32_NEON_H
#if !defined(__aarch64__) || !LC_DSA_CACHED_DOT_TILE || !LC_DSA_STREAM_CACHE24 || (LC_DSA_A_CACHE_BITS != 32 && !LC_DSA_A_PLANES24) || LC_DSA_A_CACHE_COUNT < MLDSA_K*MLDSA_L
#error "ARM wide dot requires complete A and call-owned NTT(y)"
#endif
static __attribute__((optimize("O3"))) void lc_arm_speed32_fill(mld_polymat *mat) {
  for(unsigned base=0;base<MLDSA_K*MLDSA_L;base+=4) {
    unsigned lanes=MLDSA_K*MLDSA_L-base<4?MLDSA_K*MLDSA_L-base:4;
    unsigned ctr[4]={0,0,0,0};
    mld_memset(&mat->stream4,0,sizeof(mat->stream4));
    for(unsigned lane=0;lane<4;lane++) {
      unsigned index=base+(lane<lanes?lane:0);
      uint64_t *state=mat->stream4.state+25*lane;
      mld_memcpy(state,mat->rho,MLDSA_SEEDBYTES);
      state[4]=(uint64_t)(index/MLDSA_K)|((uint64_t)(index%MLDSA_K)<<8)|((uint64_t)0x1f<<16);
      state[20]=(uint64_t)0x80<<56;
    }
    for(;;) {
      unsigned pending=0;
      mld_keccakf1600x4_permute(mat->stream4.state);
      for(unsigned lane=0;lane<lanes;lane++) {
        if(ctr[lane]==MLDSA_N)continue;
        const uint8_t *rate=(const uint8_t *)(const void *)(mat->stream4.state+25*lane);
        for(unsigned j=0;ctr[lane]<MLDSA_N && j+3<=SHAKE128_RATE;) {
          const uint8_t *bytes=rate+j;
#if defined(LC_DSA_NEON_SAMPLE16) && LC_DSA_NEON_SAMPLE16 && LC_DSA_A_PLANES24
          /* q=0x7fe001: decide rejection directly on public byte planes.
           * Accepted coefficients are already the desired split-plane cache
           * representation, so no intermediate int32 expansion is needed. */
          if(j+48<=SHAKE128_RATE && ctr[lane]+16<=MLDSA_N) {
            uint8x16x3_t b=vld3q_u8(bytes);
            uint8x16_t h=vandq_u8(b.val[2],vdupq_n_u8(127));
            uint8x16_t at_top=vceqq_u8(h,vdupq_n_u8(127));
            uint8x16_t above_mid=vcgtq_u8(b.val[1],vdupq_n_u8(224));
            uint8x16_t at_mid=vceqq_u8(b.val[1],vdupq_n_u8(224));
            uint8x16_t low_nonzero=vcgtq_u8(b.val[0],vdupq_n_u8(0));
            uint8x16_t invalid=vandq_u8(at_top,vorrq_u8(above_mid,vandq_u8(at_mid,low_nonzero)));
            if(vmaxvq_u8(invalid)==0) {
              uint8x16x2_t low={{b.val[0],b.val[1]}};
              vst2q_u8(mat->cache[base+lane]+2*ctr[lane],low);
              vst1q_u8(mat->cache[base+lane]+512+ctr[lane],h);
              ctr[lane]+=16;j+=48;continue;
            }
          }
#endif
          if(j+24<=SHAKE128_RATE && ctr[lane]+8<=MLDSA_N) {
            uint32x4_t a,c;
            if(lc_stream_public8(bytes,&a,&c)) {
              lc_stream_cache_store8(mat,base+lane,ctr[lane],a,c);
              ctr[lane]+=8;j+=24;continue;
            }
          }
          uint32_t a=((uint32_t)bytes[0]|((uint32_t)bytes[1]<<8)|((uint32_t)bytes[2]<<16))&0x7fffffu;
          j+=3;
          if(a<MLDSA_Q) {lc_stream_cache_store1(mat,base+lane,ctr[lane],a);ctr[lane]++;}
        }
        if(ctr[lane]<MLDSA_N)pending=1;
      }
      if(!pending)break;
    }
  }
  mat->cache_ready=1;
}
#if LC_DSA_INPLACE_AY
/* Each eight-index input slab is captured for all L columns before any
 * output row is stored. Later slabs occupy disjoint bytes. K>=L, and the
 * original w owner clears all temporary frequency-domain secret values. */
_Static_assert(MLDSA_K>=MLDSA_L,"in-place A*y needs enough output rows");
_Static_assert(LC_SIGN_AY_ROW_BYTES>=sizeof(mld_poly),"row must hold an NTT polynomial");
static void lc_arm_speed32_ay(uint8_t *w,mld_polymat *mat,const mld_yvec *y,mld_poly *tile) {
  (void)tile;
  if(!mat->cache_ready)lc_arm_speed32_fill(mat);
  for(unsigned l=0;l<MLDSA_L;l++) {
    mld_poly *yp=(mld_poly *)(void *)(w+l*LC_SIGN_AY_ROW_BYTES);
    mld_yvec_get_poly(yp,y,l);mld_poly_ntt(yp);lc_stream_transform_order(yp);
  }
  const int32x4_t q=vdupq_n_s32(8380417);
  for(unsigned i=0;i<MLDSA_N;i+=8) {
    int32x4_t y0a,y0b;
    mld_memcpy(&y0a,w+0*LC_SIGN_AY_ROW_BYTES+4*i,16);
    mld_memcpy(&y0b,w+0*LC_SIGN_AY_ROW_BYTES+4*i+16,16);
    int32x4_t y1a,y1b;
    mld_memcpy(&y1a,w+1*LC_SIGN_AY_ROW_BYTES+4*i,16);
    mld_memcpy(&y1b,w+1*LC_SIGN_AY_ROW_BYTES+4*i+16,16);
    int32x4_t y2a,y2b;
    mld_memcpy(&y2a,w+2*LC_SIGN_AY_ROW_BYTES+4*i,16);
    mld_memcpy(&y2b,w+2*LC_SIGN_AY_ROW_BYTES+4*i+16,16);
    int32x4_t y3a,y3b;
    mld_memcpy(&y3a,w+3*LC_SIGN_AY_ROW_BYTES+4*i,16);
    mld_memcpy(&y3b,w+3*LC_SIGN_AY_ROW_BYTES+4*i+16,16);
#if MLDSA_L > 4
    int32x4_t y4a,y4b;
    mld_memcpy(&y4a,w+4*LC_SIGN_AY_ROW_BYTES+4*i,16);
    mld_memcpy(&y4b,w+4*LC_SIGN_AY_ROW_BYTES+4*i+16,16);
#endif
#if MLDSA_L > 5
    int32x4_t y5a,y5b;
    mld_memcpy(&y5a,w+5*LC_SIGN_AY_ROW_BYTES+4*i,16);
    mld_memcpy(&y5b,w+5*LC_SIGN_AY_ROW_BYTES+4*i+16,16);
#endif
#if MLDSA_L > 6
    int32x4_t y6a,y6b;
    mld_memcpy(&y6a,w+6*LC_SIGN_AY_ROW_BYTES+4*i,16);
    mld_memcpy(&y6b,w+6*LC_SIGN_AY_ROW_BYTES+4*i+16,16);
#endif
    for(unsigned k=0;k<MLDSA_K;k++) {
      int64x2_t s0=vdupq_n_s64(0),s1=s0,s2=s0,s3=s0;
      {
        uint32x4_t u0,u1;
#if LC_DSA_A_PLANES24
        lc_a_planes_load_neon(mat->cache[0*MLDSA_K+k],i,&u0,&u1);
#else
        mld_memcpy(&u0,mat->cache[0*MLDSA_K+k]+4*i,16);
        mld_memcpy(&u1,mat->cache[0*MLDSA_K+k]+4*i+16,16);
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
        lc_a_planes_load_neon(mat->cache[1*MLDSA_K+k],i,&u0,&u1);
#else
        mld_memcpy(&u0,mat->cache[1*MLDSA_K+k]+4*i,16);
        mld_memcpy(&u1,mat->cache[1*MLDSA_K+k]+4*i+16,16);
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
        lc_a_planes_load_neon(mat->cache[2*MLDSA_K+k],i,&u0,&u1);
#else
        mld_memcpy(&u0,mat->cache[2*MLDSA_K+k]+4*i,16);
        mld_memcpy(&u1,mat->cache[2*MLDSA_K+k]+4*i+16,16);
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
        lc_a_planes_load_neon(mat->cache[3*MLDSA_K+k],i,&u0,&u1);
#else
        mld_memcpy(&u0,mat->cache[3*MLDSA_K+k]+4*i,16);
        mld_memcpy(&u1,mat->cache[3*MLDSA_K+k]+4*i+16,16);
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
        lc_a_planes_load_neon(mat->cache[4*MLDSA_K+k],i,&u0,&u1);
#else
        mld_memcpy(&u0,mat->cache[4*MLDSA_K+k]+4*i,16);
        mld_memcpy(&u1,mat->cache[4*MLDSA_K+k]+4*i+16,16);
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
        lc_a_planes_load_neon(mat->cache[5*MLDSA_K+k],i,&u0,&u1);
#else
        mld_memcpy(&u0,mat->cache[5*MLDSA_K+k]+4*i,16);
        mld_memcpy(&u1,mat->cache[5*MLDSA_K+k]+4*i+16,16);
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
        lc_a_planes_load_neon(mat->cache[6*MLDSA_K+k],i,&u0,&u1);
#else
        mld_memcpy(&u0,mat->cache[6*MLDSA_K+k]+4*i,16);
        mld_memcpy(&u1,mat->cache[6*MLDSA_K+k]+4*i+16,16);
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
static void lc_arm_speed32_ay(uint8_t *w,mld_polymat *mat,const mld_yvec *y,mld_poly *tile) {
  if(!mat->cache_ready)lc_arm_speed32_fill(mat);
    for(unsigned l=0;l<MLDSA_L;l++) {
      mld_yvec_get_poly(&tile[l],y,l);mld_poly_ntt(&tile[l]);
      lc_stream_transform_order(&tile[l]);
    }
    const int32x4_t q=vdupq_n_s32(8380417);
    for(unsigned k=0;k<MLDSA_K;k++) {
      for(unsigned i=0;i<MLDSA_N;i+=8) {
        int64x2_t s0=vdupq_n_s64(0),s1=s0,s2=s0,s3=s0;
        for(unsigned l=0;l<MLDSA_L;l++) {
          uint32x4_t u0,u1;
#if LC_DSA_A_PLANES24
          lc_a_planes_load_neon(mat->cache[l*MLDSA_K+k],i,&u0,&u1);
#elif LC_DSA_A_CACHE_BITS == 32
          mld_memcpy(&u0,mat->cache[l*MLDSA_K+k]+4*i,16);
          mld_memcpy(&u1,mat->cache[l*MLDSA_K+k]+4*i+16,16);
#else
          lc_stream_unpack8(mat->cache[l*MLDSA_K+k]+3*i,&u0,&u1);
#endif
          int32x4_t a0=vreinterpretq_s32_u32(u0),a1=vreinterpretq_s32_u32(u1);
          int32x4_t y0=vld1q_s32(tile[l].coeffs+i),y1=vld1q_s32(tile[l].coeffs+i+4);
          s0=vmlal_s32(s0,vget_low_s32(a0),vget_low_s32(y0));
          s1=vmlal_high_s32(s1,a0,y0);
          s2=vmlal_s32(s2,vget_low_s32(a1),vget_low_s32(y1));
          s3=vmlal_high_s32(s3,a1,y1);
        }
        int32x4_t t0=vuzp1q_s32(vreinterpretq_s32_s64(s0),vreinterpretq_s32_s64(s1));
        int32x4_t t1=vuzp1q_s32(vreinterpretq_s32_s64(s2),vreinterpretq_s32_s64(s3));
        t0=vreinterpretq_s32_u32(vmulq_u32(vreinterpretq_u32_s32(t0),vdupq_n_u32(58728449)));
        t1=vreinterpretq_s32_u32(vmulq_u32(vreinterpretq_u32_s32(t1),vdupq_n_u32(58728449)));
        s0=vmlsl_s32(s0,vget_low_s32(t0),vget_low_s32(q));s1=vmlsl_high_s32(s1,t0,q);
        s2=vmlsl_s32(s2,vget_low_s32(t1),vget_low_s32(q));s3=vmlsl_high_s32(s3,t1,q);
        int32x4_t lo=vuzp2q_s32(vreinterpretq_s32_s64(s0),vreinterpretq_s32_s64(s1));
        int32x4_t hi=vuzp2q_s32(vreinterpretq_s32_s64(s2),vreinterpretq_s32_s64(s3));
#if LC_DSA_DENSE_SIGN_ROWS
        lo=lc_stream_reduce32(lo);hi=lc_stream_reduce32(hi);
        mld_memcpy(w+k*LC_SIGN_AY_ROW_BYTES+4*i,&lo,16);
        mld_memcpy(w+k*LC_SIGN_AY_ROW_BYTES+4*i+16,&hi,16);
#else
        lc_stream_pack8(w+k*LC_PACKED_ROW_BYTES+3*i,lc_stream_reduce32(lo),lc_stream_reduce32(hi));
#endif
      }
    }
}
#endif
#endif
