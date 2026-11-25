/* SPDX-License-Identifier: Apache-2.0
 * Eight-coefficient consumer for a public SHAKE rejection block.
 * Caller bounds both buffers and confirms every public candidate is < q.
 * Packed signed intermediates have their low 24 bits stored in byte order.
 */
#ifndef LC_STREAM_NEON_H
#define LC_STREAM_NEON_H
#include <arm_neon.h>
#if defined(LC_DSA_STREAM_INLINE_LEAVES) && LC_DSA_STREAM_INLINE_LEAVES
#define LC_STREAM_INLINE_LEAF static __attribute__((always_inline)) inline
#else
#define LC_STREAM_INLINE_LEAF static inline
#endif

LC_STREAM_INLINE_LEAF void lc_stream_unpack8(const uint8_t *p, uint32x4_t *lo,
                                     uint32x4_t *hi) {
  const uint8x8x3_t b=vld3_u8(p);
  const uint16x8_t low=vorrq_u16(vmovl_u8(b.val[0]),vshll_n_u8(b.val[1],8));
  const uint16x8_t high=vmovl_u8(b.val[2]);
  *lo=vorrq_u32(vmovl_u16(vget_low_u16(low)),vshll_n_u16(vget_low_u16(high),16));
  *hi=vorrq_u32(vmovl_high_u16(low),vshll_high_n_u16(high,16));
}
static inline int32x4_t lc_stream_signed24(uint32x4_t x) {
  return vshrq_n_s32(vreinterpretq_s32_u32(vshlq_n_u32(x,8)),8);
}
LC_STREAM_INLINE_LEAF int32x4_t lc_stream_montgomery(int32x4_t a,int32x4_t b) {
  const int32x4_t q=vdupq_n_s32(8380417);
  int64x2_t lo=vmull_s32(vget_low_s32(a),vget_low_s32(b));
  int64x2_t hi=vmull_high_s32(a,b);
  const uint32x4_t product=vreinterpretq_u32_s32(vuzp1q_s32(vreinterpretq_s32_s64(lo),vreinterpretq_s32_s64(hi)));
  const int32x4_t correction=vreinterpretq_s32_u32(vmulq_u32(product,vdupq_n_u32(58728449)));
  lo=vmlsl_s32(lo,vget_low_s32(correction),vget_low_s32(q));
  hi=vmlsl_high_s32(hi,correction,q);
  return vuzp2q_s32(vreinterpretq_s32_s64(lo),vreinterpretq_s32_s64(hi));
}
static inline int32x4_t lc_stream_reduce32(int32x4_t x) {
  const int32x4_t quotient=vshrq_n_s32(vaddq_s32(x,vdupq_n_s32(4194304)),23);
  return vsubq_s32(x,vmulq_n_s32(quotient,8380417));
}
static inline void lc_stream_pack8(uint8_t *p,int32x4_t lo,int32x4_t hi) {
  uint8x8x3_t b;
  const uint32x4_t a=vreinterpretq_u32_s32(lo),c=vreinterpretq_u32_s32(hi);
  const uint16x8_t low=vcombine_u16(vmovn_u32(a),vmovn_u32(c));
  const uint16x8_t high=vcombine_u16(vshrn_n_u32(a,16),vshrn_n_u32(c,16));
  b.val[0]=vmovn_u16(low);b.val[1]=vshrn_n_u16(low,8);b.val[2]=vmovn_u16(high);
  vst3_u8(p,b);
}
static inline int lc_stream_public8(const uint8_t *p,uint32x4_t *a,uint32x4_t *b) {
  lc_stream_unpack8(p,a,b);
  *a=vandq_u32(*a,vdupq_n_u32(8388607));*b=vandq_u32(*b,vdupq_n_u32(8388607));
  return vmaxvq_u32(vmaxq_u32(*a,*b))<8380417u;
}
static inline void lc_stream_y8(uint8_t *out,const int32_t *y,
                                uint32x4_t a,uint32x4_t b,unsigned first) {
  int32x4_t lo=lc_stream_montgomery(vreinterpretq_s32_u32(a),vld1q_s32(y));
  int32x4_t hi=lc_stream_montgomery(vreinterpretq_s32_u32(b),vld1q_s32(y+4));
  if(!first) {
    uint32x4_t old0,old1;lc_stream_unpack8(out,&old0,&old1);
    lo=vaddq_s32(lo,lc_stream_signed24(old0));hi=vaddq_s32(hi,lc_stream_signed24(old1));
  }
  lc_stream_pack8(out,lc_stream_reduce32(lo),lc_stream_reduce32(hi));
}
static inline void lc_stream_v8(int32_t *out,const uint8_t *v,
                                uint32x4_t a,uint32x4_t b) {
  uint32x4_t v0,v1;lc_stream_unpack8(v,&v0,&v1);
  int32x4_t lo=lc_stream_montgomery(vreinterpretq_s32_u32(a),lc_stream_signed24(v0));
  int32x4_t hi=lc_stream_montgomery(vreinterpretq_s32_u32(b),lc_stream_signed24(v1));
  vst1q_s32(out,vaddq_s32(vld1q_s32(out),lo));
  vst1q_s32(out+4,vaddq_s32(vld1q_s32(out+4),hi));
}
#undef LC_STREAM_INLINE_LEAF
#endif
