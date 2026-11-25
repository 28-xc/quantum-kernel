/* SPDX-License-Identifier: Apache-2.0
 * ML-KEM seven-layer NTT: natural coefficients to standard bit-reversed pairs.
 * Public loops; exact256 int16 coefficients. Forward |x|<q, output |x|<8q.
 * Inverse accepts all int16 inputs, applies R/128 first and returns |x|<q.
 */
#ifndef LC_KEM_NTT_COMPACT_NEON_H
#define LC_KEM_NTT_COMPACT_NEON_H
#include <arm_neon.h>
#include "lc_ntt_ordinary_zetas.h"
#define LC_KNTT_INLINE static inline __attribute__((always_inline))
LC_KNTT_INLINE int16x8_t lc_kntt_product(int16x8_t a,int16x8_t root,int16x8_t quotient)
{
  /* Low-word arithmetic is modulo2^16; unsigned intrinsics express the
   * wraparound also in GCC's C-vector intrinsic expansion under UBSan. */
  uint16x8_t low=vmulq_u16(vreinterpretq_u16_s16(a),vreinterpretq_u16_s16(root));
  uint16x8_t estimate=vreinterpretq_u16_s16(vqrdmulhq_s16(a,quotient));
  return vreinterpretq_s16_u16(vmlsq_n_u16(low,estimate,3329));
}
LC_KNTT_INLINE int16x8_t lc_kntt_reduce_sum(int16x8_t a)
{
  /* |a|<2q. Approximate(2^15/q)=10 gives a remainder of absolute value<q. */
  return vmlsq_n_s16(a,vqrdmulhq_n_s16(a,10),3329);
}
LC_KNTT_INLINE int16x8_t lc_kntt_pair_twiddles(const int16_t *p)
{
  int16x8_t z=vcombine_s16(vld1_s16(p),vld1_s16(p));return vzip1q_s16(z,z);
}
__attribute__((visibility("hidden"),noipa))
void lc_kem_compact_ntt(int16_t a[256])
{
  unsigned k=1;
  for(unsigned len=128;len>=8;len>>=1)
    for(unsigned start=0;start<256;start+=2*len){
      int16x8_t z=vdupq_n_s16(lc_kntt_roots[k]),h=vdupq_n_s16(lc_kntt_quotients[k]);k++;
      for(unsigned j=start;j<start+len;j+=8){
        int16x8_t u=vld1q_s16(a+j),v=lc_kntt_product(vld1q_s16(a+j+len),z,h);
        vst1q_s16(a+j,vaddq_s16(u,v));vst1q_s16(a+j+len,vsubq_s16(u,v));
      }
    }
  /* Keep the len=4 result in registers for the following len=2 layer.
   * TRN on 32-bit pairs is exactly the old store/reload/UZP permutation. */
  for(unsigned j=0;j<256;j+=16){
    unsigned k4=32+j/8,k2=64+j/4;
    int16x8_t x=vld1q_s16(a+j),y=vld1q_s16(a+j+8);
    int16x8_t u=vcombine_s16(vget_low_s16(x),vget_low_s16(y));
    int16x8_t v=vcombine_s16(vget_high_s16(x),vget_high_s16(y));
    int16x8_t z=vcombine_s16(vdup_n_s16(lc_kntt_roots[k4]),vdup_n_s16(lc_kntt_roots[k4+1]));
    int16x8_t h=vcombine_s16(vdup_n_s16(lc_kntt_quotients[k4]),vdup_n_s16(lc_kntt_quotients[k4+1]));
    int16x8_t t=lc_kntt_product(v,z,h),p=vaddq_s16(u,t),q=vsubq_s16(u,t);
    int32x4_t pp=vreinterpretq_s32_s16(p),qq=vreinterpretq_s32_s16(q);
    u=vreinterpretq_s16_s32(vtrn1q_s32(pp,qq));
    v=vreinterpretq_s16_s32(vtrn2q_s32(pp,qq));
    t=lc_kntt_product(v,lc_kntt_pair_twiddles(lc_kntt_roots+k2),lc_kntt_pair_twiddles(lc_kntt_quotients+k2));
    pp=vreinterpretq_s32_s16(vaddq_s16(u,t));
    qq=vreinterpretq_s32_s16(vsubq_s16(u,t));
    vst1q_s16(a+j,vreinterpretq_s16_s32(vzip1q_s32(pp,qq)));
    vst1q_s16(a+j+8,vreinterpretq_s16_s32(vzip2q_s32(pp,qq)));
  }
}
__attribute__((visibility("hidden"),noipa))
void lc_kem_compact_intt(int16_t a[256])
{
  for(unsigned j=0;j<256;j+=8)vst1q_s16(a+j,lc_kntt_product(vld1q_s16(a+j),vdupq_n_s16(LC_KNTT_SCALE),vdupq_n_s16(LC_KNTT_SCALE_QUOTIENT)));
  unsigned k=127;
  for(unsigned j=0;j<256;j+=16,k-=4){
    int32x4_t x=vreinterpretq_s32_s16(vld1q_s16(a+j)),y=vreinterpretq_s32_s16(vld1q_s16(a+j+8));
    int16x8_t u=vreinterpretq_s16_s32(vuzp1q_s32(x,y)),v=vreinterpretq_s16_s32(vuzp2q_s32(x,y));
    int16x8_t z=vrev64q_s16(lc_kntt_pair_twiddles(lc_kntt_roots+k-3));z=vextq_s16(z,z,4);
    int16x8_t h=vrev64q_s16(lc_kntt_pair_twiddles(lc_kntt_quotients+k-3));h=vextq_s16(h,h,4);
    int32x4_t p=vreinterpretq_s32_s16(lc_kntt_reduce_sum(vaddq_s16(u,v)));
    int32x4_t q=vreinterpretq_s32_s16(lc_kntt_product(vsubq_s16(v,u),z,h));
    vst1q_s16(a+j,vreinterpretq_s16_s32(vzip1q_s32(p,q)));
    vst1q_s16(a+j+8,vreinterpretq_s16_s32(vzip2q_s32(p,q)));
  }
  for(unsigned j=0;j<256;j+=16,k-=2){
    int16x8_t x=vld1q_s16(a+j),y=vld1q_s16(a+j+8);
    int16x8_t u=vcombine_s16(vget_low_s16(x),vget_low_s16(y));
    int16x8_t v=vcombine_s16(vget_high_s16(x),vget_high_s16(y));
    int16x8_t z=vcombine_s16(vdup_n_s16(lc_kntt_roots[k]),vdup_n_s16(lc_kntt_roots[k-1]));
    int16x8_t h=vcombine_s16(vdup_n_s16(lc_kntt_quotients[k]),vdup_n_s16(lc_kntt_quotients[k-1]));
    int16x8_t p=lc_kntt_reduce_sum(vaddq_s16(u,v)),q=lc_kntt_product(vsubq_s16(v,u),z,h);
    vst1q_s16(a+j,vcombine_s16(vget_low_s16(p),vget_low_s16(q)));
    vst1q_s16(a+j+8,vcombine_s16(vget_high_s16(p),vget_high_s16(q)));
  }
  for(unsigned len=8;len<=128;len<<=1)
    for(unsigned start=0;start<256;start+=2*len){
      int16x8_t z=vdupq_n_s16(lc_kntt_roots[k]),h=vdupq_n_s16(lc_kntt_quotients[k]);k--;
      for(unsigned j=start;j<start+len;j+=8){
        int16x8_t u=vld1q_s16(a+j),v=vld1q_s16(a+j+len);
        vst1q_s16(a+j,lc_kntt_reduce_sum(vaddq_s16(u,v)));
        vst1q_s16(a+j+len,lc_kntt_product(vsubq_s16(v,u),z,h));
      }
    }
}
#undef LC_KNTT_INLINE
#endif
