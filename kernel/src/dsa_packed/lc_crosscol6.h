/* SPDX-License-Identifier: Apache-2.0
 * ML-DSA-65: groups of four public matrix entries cross column boundaries.
 * The second y transform uses exactly1024 bytes supplied by the caller of
 * this internal helper, either an owned arena object or signature scratch.
 * Its storage and clearing are part of the complete call cost.
 * Character copies support arbitrary caller output alignment. */
#ifndef LC_CROSSCOL6_H
#define LC_CROSSCOL6_H
#if MLDSA_K != 6 || MLDSA_L != 5 || !defined(__aarch64__) || \
    !LC_DSA_MATRIX_STREAM_DIRECT4 || !LC_DSA_STREAM_DIRECT_STATE
#error "Cross-column schedule is defined for the AArch64 6-by-5 matrix"
#endif
_Static_assert(sizeof(mld_poly)==1024 && MLDSA_CRYPTO_BYTES>=1024,"Borrowed signature extent");
static inline void lc_cross_y8(uint8_t *out,const uint8_t *rhs,
                               uint32x4_t a,uint32x4_t b,unsigned first) {
  int32x4_t y0,y1;mld_memcpy(&y0,rhs,16);mld_memcpy(&y1,rhs+16,16);
  int32x4_t lo=lc_stream_montgomery(vreinterpretq_s32_u32(a),y0);
  int32x4_t hi=lc_stream_montgomery(vreinterpretq_s32_u32(b),y1);
  if(!first) {
    uint32x4_t old0,old1;lc_stream_unpack8(out,&old0,&old1);
    lo=vaddq_s32(lo,lc_stream_signed24(old0));hi=vaddq_s32(hi,lc_stream_signed24(old1));
  }
  lc_stream_pack8(out,lc_stream_reduce32(lo),lc_stream_reduce32(hi));
}
#if LC_DSA_STREAM_CACHE24
static void lc_cross_cache_product(uint8_t *w,const uint8_t *a,const uint8_t *rhs,unsigned first) {
  for(unsigned i=0;i<256;i+=8) {
    uint32x4_t a0,a1;lc_stream_unpack8(a+3*i,&a0,&a1);
    lc_cross_y8(w+3*i,rhs+4*i,a0,a1,first);
  }
}
#endif
static void lc_cross_matrix4(uint8_t *w,mld_polymat *mat,
                            const mld_poly *current,const uint8_t saved[1024],
                            unsigned current_col,unsigned start,unsigned lanes) {
  uint8_t seed[34];const uint8_t suffix=0x1f,final=0x80;
  unsigned ctr[4]={0,0,0,0},pending;
#if LC_DSA_STREAM_CACHE24
  unsigned cache_pending=0;
  for(unsigned lane=0;lane<lanes;lane++) {
    unsigned position=start+lane,col=position/6,row=position%6;
    if(lc_stream_cache_hit(mat,position)) {
      const uint8_t *rhs=col==current_col?(const uint8_t *)(const void *)current:saved;
      lc_cross_cache_product(w+row*LC_PACKED_ROW_BYTES,mat->cache[position],rhs,col==0);
      ctr[lane]=MLDSA_N;
    } else cache_pending++;
  }
  if(cache_pending==0)return;
#endif
  mld_memcpy(seed,mat->rho,32);mld_memset(&mat->stream4,0,sizeof(mat->stream4));
  for(unsigned lane=0;lane<4;lane++) {
    unsigned position=start+(lane<lanes?lane:0);
    seed[32]=(uint8_t)(position/6);seed[33]=(uint8_t)(position%6);
    uint64_t *s=mat->stream4.state+25*lane;
    mld_keccakf1600_xor_bytes(s,seed,0,34);
    mld_keccakf1600_xor_bytes(s,&suffix,34,1);
    mld_keccakf1600_xor_bytes(s,&final,SHAKE128_RATE-1,1);
  }
  mld_zeroize(seed,sizeof(seed));
  do {
    pending=0;
#if LC_DSA_STREAM_CACHE24
    if(cache_pending<=2) {
      for(unsigned lane=0;lane<lanes;lane++)if(ctr[lane]<MLDSA_N)
        mld_keccakf1600_permute(mat->stream4.state+25*lane);
    } else mld_keccakf1600x4_permute(mat->stream4.state);
#else
    if(lanes<=2)for(unsigned lane=0;lane<lanes;lane++)mld_keccakf1600_permute(mat->stream4.state+25*lane);
    else mld_keccakf1600x4_permute(mat->stream4.state);
#endif
    for(unsigned lane=0;lane<lanes;lane++) {
      unsigned position=start+lane,col=position/6,row=position%6;
      const uint8_t *rhs=col==current_col?(const uint8_t *)(const void *)current:saved;
      const uint8_t *rate=(const uint8_t *)(mat->stream4.state+25*lane);
      uint8_t *out=w+row*LC_PACKED_ROW_BYTES;
      for(unsigned j=0;ctr[lane]<MLDSA_N && j+3<=SHAKE128_RATE;) {
        const uint8_t *b=rate+j;
        if(j+24<=SHAKE128_RATE && ctr[lane]+8<=MLDSA_N) {
          uint32x4_t a0,a1;
          if(lc_stream_public8(b,&a0,&a1)) {
#if LC_DSA_STREAM_CACHE24
            lc_stream_cache_store8(mat,position,ctr[lane],a0,a1);
#endif
            lc_cross_y8(out+3*ctr[lane],rhs+4*ctr[lane],a0,a1,col==0);
            ctr[lane]+=8;j+=24;continue;
          }
        }
        j+=3;
        uint32_t a=((uint32_t)b[0]|((uint32_t)b[1]<<8)|((uint32_t)b[2]<<16))&0x7fffffu;
        if(a<MLDSA_Q) {
          unsigned i=ctr[lane]++;
#if LC_DSA_STREAM_CACHE24
          lc_stream_cache_store1(mat,position,i,a);
#endif
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
#if LC_DSA_MIXED_HEAD65
#include "lc_mixed_head65.h"
_Static_assert(LC_DSA_CROSSCOL6==2 && LC_DSA_Y_CACHE_COUNT==0,
               "Mixed head uses its own explicit arena cache");
_Static_assert(sizeof(mld_yvec)<=32 && MLDSA_POLYZ_PACKEDBYTES==640,
               "Mixed head pointer stays in the existing y allocation");
#if LC_DSA_STREAM_CACHE24
static void lc_cached_head_gamma(mld_polymat *mat,const uint8_t seed[64],
                                uint16_t kappa,uint8_t gamma0[640],uint8_t gamma1[640]) {
  for(unsigned lane=0;lane<2;lane++) {
    const uint16_t nonce=(uint16_t)(kappa+lane);
    uint8_t b[2]={(uint8_t)nonce,(uint8_t)(nonce>>8)};
    mld_shake256ctx *ctx=&mat->stream_cache_gamma;
    mld_shake256_init(ctx);mld_shake256_absorb(ctx,seed,64);
    mld_shake256_absorb(ctx,b,2);mld_shake256_finalize(ctx);
    mld_shake256_squeeze(lane?gamma1:gamma0,640,ctx);
    mld_shake256_release(ctx);mld_zeroize(ctx,sizeof(*ctx));
  }
}
_Static_assert(sizeof(mld_shake256ctx)<=800,"Gamma context fits original matrix union");
#endif
static void lc_crosscol6_ay_head(uint8_t *w,mld_polymat *mat,mld_yvec *y,
    mld_poly *scratch,uint8_t saved[1024],uint8_t first_gamma[640]) {
#if LC_DSA_STREAM_CACHE24
  if(mat->cache_ready && LC_DSA_A_CACHE_COUNT>=2) {
    lc_cached_head_gamma(mat,y->rhoprime,y->kappa,
                         first_gamma,(uint8_t *)(void *)scratch);
    mld_memcpy(w,mat->cache[0],2*LC_PACKED_ROW_BYTES);
  } else
  {
#endif
    lc_mixed_head65_fill(mat->stream4.state,mat->rho,y->rhoprime,y->kappa,
                        w,first_gamma,(uint8_t *)(void *)scratch);
#if LC_DSA_STREAM_CACHE24
    for(unsigned i=0;i<2 && i<LC_DSA_A_CACHE_COUNT;i++)
      mld_memcpy(mat->cache[i],w+i*LC_PACKED_ROW_BYTES,LC_PACKED_ROW_BYTES);
  }
#endif
  y->head_gamma=first_gamma;
  mld_poly *first=(mld_poly *)(void *)saved;
  mld_yvec_get_poly(first,y,0);mld_poly_ntt(first);lc_stream_transform_order(first);
  for(unsigned lane=0;lane<2;lane++)for(unsigned i=0;i<256;i+=8) {
    uint32x4_t a,b;uint8_t *out=w+lane*768+3*i;
    lc_stream_unpack8(out,&a,&b);lc_stream_y8(out,first->coeffs+i,a,b,1);
  }
  /* Complete column0 using first; scratch still holds raw gamma1. */
  lc_cross_matrix4(w,mat,first,saved,0,2,4);
  lc_expand_gamma_neon(scratch->coeffs,20,MLDSA_GAMMA1);
  mld_poly_ntt(scratch);lc_stream_transform_order(scratch);
  unsigned current_col=1;
  for(unsigned position=6;position<30;position+=4) {
    unsigned first_col=position/6,last_col=(position+3)/6;
    if(last_col!=current_col) {
      if(first_col!=last_col)mld_memcpy(saved,scratch,1024);
      mld_yvec_get_poly(scratch,y,last_col);mld_poly_ntt(scratch);lc_stream_transform_order(scratch);
      current_col=last_col;
    }
    lc_cross_matrix4(w,mat,scratch,saved,current_col,position,4);
  }
  mld_zeroize(saved,1024);
}
#endif
static void lc_crosscol6_ay(uint8_t *w,mld_polymat *mat,const mld_yvec *y,
                            mld_poly *scratch,uint8_t sig[1024]) {
  unsigned current_col=0;
  mld_yvec_get_poly(scratch,y,0);mld_poly_ntt(scratch);lc_stream_transform_order(scratch);
  for(unsigned position=0;position<30;position+=4) {
    unsigned lanes=30-position<4?30-position:4;
    unsigned first_col=position/6,last_col=(position+lanes-1)/6;
    if(last_col!=current_col) {
      if(first_col!=last_col)mld_memcpy(sig,scratch,1024);
      mld_yvec_get_poly(scratch,y,last_col);mld_poly_ntt(scratch);lc_stream_transform_order(scratch);
      current_col=last_col;
    }
    lc_cross_matrix4(w,mat,scratch,sig,current_col,position,lanes);
  }
  mld_zeroize(sig,1024);
}
#endif
