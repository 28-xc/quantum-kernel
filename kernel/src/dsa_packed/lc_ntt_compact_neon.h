/* SPDX-License-Identifier: Apache-2.0
 * Standard-order ML-DSA transforms (natural coefficients, bit-reversed NTT slots) with public butterfly loops. Included once
 * after the attributed standard mld_zetas table. Exact256 coefficients, q8380417.
 * Forward input |a|<q; inverse input |a|<q. Forward output |a|<9q, inverse <q.
 * The inverse returns Montgomery-scaled coefficients as the native API requires.
 */
#ifndef LC_NTT_COMPACT_NEON_H
#define LC_NTT_COMPACT_NEON_H
#include <arm_neon.h>
#include <stdint.h>
#if LC_DSA_COMPACT_NTT_BARRETT
#include "lc_ntt_ordinary_zetas.h"
#else
#define lc_ntt_roots mld_zetas
#define lc_ntt_quotients mld_zetas
#define LC_NTT_SCALE 41978
#define LC_NTT_SCALE_QUOTIENT 0
#endif
#define LC_NTT_INLINE static inline __attribute__((always_inline))
LC_NTT_INLINE int32x4_t lc_ntt_mul4(int32x4_t a,int32x4_t b,int32x4_t quotient)
{
#if LC_DSA_COMPACT_NTT_BARRETT
  int32x4_t estimate=vqrdmulhq_s32(a,quotient);
  /* The low32 multiply/subtract deliberately uses modular word arithmetic. */
  uint32x4_t low=vmulq_u32(vreinterpretq_u32_s32(a),vreinterpretq_u32_s32(b));
  return vreinterpretq_s32_u32(vmlsq_n_u32(low,vreinterpretq_u32_s32(estimate),8380417));
#else
  (void)quotient;
  int64x2_t lo=vmull_s32(vget_low_s32(a),vget_low_s32(b));
  int64x2_t hi=vmull_high_s32(a,b);
  uint32x4_t low=vreinterpretq_u32_s32(vuzp1q_s32(vreinterpretq_s32_s64(lo),vreinterpretq_s32_s64(hi)));
  int32x4_t t=vreinterpretq_s32_u32(vmulq_n_u32(low,58728449u));
  lo=vmlsl_n_s32(lo,vget_low_s32(t),8380417);
  hi=vmlsl_high_n_s32(hi,t,8380417);
  return vuzp2q_s32(vreinterpretq_s32_s64(lo),vreinterpretq_s32_s64(hi));
#endif
}
LC_NTT_INLINE int32x4_t lc_ntt_reverse4(int32x4_t a)
{
  a=vrev64q_s32(a);return vextq_s32(a,a,2);
}
#if LC_DSA_COMPACT_NTT_FUSED3
#include "lc_ntt_fused3_neon.h"
#else
__attribute__((visibility("hidden"),noipa))
void lc_dsa_compact_ntt(int32_t a[256])
{
  unsigned k=1;
  for(unsigned len=128;len>=4;len>>=1)
    for(unsigned start=0;start<256;start+=2*len) {
      int32x4_t z=vdupq_n_s32(lc_ntt_roots[k]),h=vdupq_n_s32(lc_ntt_quotients[k]);k++;
      for(unsigned j=start;j<start+len;j+=4) {
        int32x4_t u=vld1q_s32(a+j),t=lc_ntt_mul4(vld1q_s32(a+j+len),z,h);
        vst1q_s32(a+j,vaddq_s32(u,t));vst1q_s32(a+j+len,vsubq_s32(u,t));
      }
    }
  for(unsigned j=0;j<256;j+=8,k+=2) {
    int32x4_t x=vld1q_s32(a+j),y=vld1q_s32(a+j+4);
    int32x4_t u=vcombine_s32(vget_low_s32(x),vget_low_s32(y));
    int32x4_t v=vcombine_s32(vget_high_s32(x),vget_high_s32(y));
    int32x4_t z=vcombine_s32(vdup_n_s32(lc_ntt_roots[k]),vdup_n_s32(lc_ntt_roots[k+1]));
    int32x4_t h=vcombine_s32(vdup_n_s32(lc_ntt_quotients[k]),vdup_n_s32(lc_ntt_quotients[k+1]));
    int32x4_t t=lc_ntt_mul4(v,z,h),p=vaddq_s32(u,t),q=vsubq_s32(u,t);
    vst1q_s32(a+j,vcombine_s32(vget_low_s32(p),vget_low_s32(q)));
    vst1q_s32(a+j+4,vcombine_s32(vget_high_s32(p),vget_high_s32(q)));
  }
  for(unsigned j=0;j<256;j+=8,k+=4) {
    int32x4x2_t x=vld2q_s32(a+j);int32x4_t t=lc_ntt_mul4(x.val[1],vld1q_s32(lc_ntt_roots+k),vld1q_s32(lc_ntt_quotients+k));
    int32x4x2_t r={{vaddq_s32(x.val[0],t),vsubq_s32(x.val[0],t)}};
    vst2q_s32(a+j,r);
  }
}
__attribute__((visibility("hidden"),noipa))
void lc_dsa_compact_intt(int32_t a[256])
{
  unsigned k=255;
  for(unsigned j=0;j<256;j+=8,k-=4) {
    int32x4x2_t x=vld2q_s32(a+j);
    int32x4_t z=vnegq_s32(lc_ntt_reverse4(vld1q_s32(lc_ntt_roots+k-3)));
    int32x4_t h=vnegq_s32(lc_ntt_reverse4(vld1q_s32(lc_ntt_quotients+k-3)));
    int32x4x2_t r={{vaddq_s32(x.val[0],x.val[1]),lc_ntt_mul4(vsubq_s32(x.val[0],x.val[1]),z,h)}};
    vst2q_s32(a+j,r);
  }
  for(unsigned j=0;j<256;j+=8,k-=2) {
    int32x4_t x=vld1q_s32(a+j),y=vld1q_s32(a+j+4);
    int32x4_t u=vcombine_s32(vget_low_s32(x),vget_low_s32(y));
    int32x4_t v=vcombine_s32(vget_high_s32(x),vget_high_s32(y));
    int32x4_t z=vcombine_s32(vdup_n_s32(-lc_ntt_roots[k]),vdup_n_s32(-lc_ntt_roots[k-1]));
    int32x4_t h=vcombine_s32(vdup_n_s32(-lc_ntt_quotients[k]),vdup_n_s32(-lc_ntt_quotients[k-1]));
    int32x4_t p=vaddq_s32(u,v),q=lc_ntt_mul4(vsubq_s32(u,v),z,h);
    vst1q_s32(a+j,vcombine_s32(vget_low_s32(p),vget_low_s32(q)));
    vst1q_s32(a+j+4,vcombine_s32(vget_high_s32(p),vget_high_s32(q)));
  }
#if LC_DSA_COMPACT_NTT_BARRETT
  for(unsigned len=4;len<=64;len<<=1)
#else
  for(unsigned len=4;len<=128;len<<=1)
#endif
    for(unsigned start=0;start<256;start+=2*len) {
      int32x4_t z=vdupq_n_s32(-lc_ntt_roots[k]),h=vdupq_n_s32(-lc_ntt_quotients[k]);k--;
      for(unsigned j=start;j<start+len;j+=4) {
        int32x4_t u=vld1q_s32(a+j),v=vld1q_s32(a+j+len);
        vst1q_s32(a+j,vaddq_s32(u,v));
        vst1q_s32(a+j+len,lc_ntt_mul4(vsubq_s32(u,v),z,h));
      }
    }
#if LC_DSA_COMPACT_NTT_BARRETT
  /* The final root and the output scale are combined modulo q. These
   * constants match mldsa-native's AArch64 inverse table. For |input|<q,
   * the last sum/difference is <=256*(q-1)<2^31; both outputs retain |x|<q
   * and the original Montgomery scale. Redundant representatives may differ
   * by q before the caller's canonicalization. No extra owner is used. */
  for(unsigned j=0;j<128;j+=4) {
    int32x4_t u=vld1q_s32(a+j),v=vld1q_s32(a+j+128);
    vst1q_s32(a+j,lc_ntt_mul4(vaddq_s32(u,v),vdupq_n_s32(LC_NTT_SCALE),vdupq_n_s32(LC_NTT_SCALE_QUOTIENT)));
    vst1q_s32(a+j+128,lc_ntt_mul4(vsubq_s32(u,v),vdupq_n_s32(-294725),vdupq_n_s32(-75523344)));
  }
#else
  for(unsigned j=0;j<256;j+=4)
    vst1q_s32(a+j,lc_ntt_mul4(vld1q_s32(a+j),vdupq_n_s32(LC_NTT_SCALE),vdupq_n_s32(LC_NTT_SCALE_QUOTIENT)));
#endif
}
#endif
#undef LC_NTT_INLINE
#endif
