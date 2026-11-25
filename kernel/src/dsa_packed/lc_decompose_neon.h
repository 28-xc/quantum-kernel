/* Copyright (c) 2026 A1-27 project authors
 * SPDX-License-Identifier: Apache-2.0
 * FIPS 204 decomposition, high-part encoding and nonzero bits in one pass.
 * Inputs are 256 standard representatives; all loop bounds are public. */
#ifndef LC_DECOMPOSE_NEON_H
#define LC_DECOMPOSE_NEON_H
#if !defined(__aarch64__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "This packed NEON backend requires little-endian AArch64"
#endif
#include <arm_neon.h>
#include <stdint.h>
#include <string.h>
#if LC_DSA_DECOMPOSE_INLINE
#define LC_DECOMPOSE_INLINE_ATTR __attribute__((always_inline))
#define LC_DECOMPOSE_OUTER_ATTR __attribute__((optimize("O3")))
#else
#define LC_DECOMPOSE_INLINE_ATTR
#define LC_DECOMPOSE_OUTER_ATTR inline
#endif
static inline LC_DECOMPOSE_INLINE_ATTR uint32x4_t lc_decompose_neon4(int32_t *coeffs,int gamma2) {
  int32x4_t a=vld1q_s32(coeffs);
  uint32x4_t h=vshrq_n_u32(vreinterpretq_u32_s32(vaddq_s32(a,vdupq_n_s32(127))),7);
  if(gamma2==95232) {
    h=vshrq_n_u32(vaddq_u32(vmulq_n_u32(h,11275),vdupq_n_u32(1u<<23)),24);
    h=vbicq_u32(h,vcgtq_u32(h,vdupq_n_u32(43)));
  } else {
    h=vandq_u32(vshrq_n_u32(vaddq_u32(vmulq_n_u32(h,1025),vdupq_n_u32(1u<<21)),22),vdupq_n_u32(15));
  }
  int32x4_t low=vsubq_s32(a,vmulq_n_s32(vreinterpretq_s32_u32(h),2*gamma2));
  low=vsubq_s32(low,vreinterpretq_s32_u32(vandq_u32(vcgtq_s32(low,vdupq_n_s32(4190208)),vdupq_n_u32(8380417))));
  vst1q_s32(coeffs,low);
  return h;
}
static LC_DECOMPOSE_OUTER_ATTR void lc_decompose_encode_neon(int32_t *coeffs,uint8_t *encoded,
                                           uint8_t *flags,int gamma2) {
  const uint32_t weights[4]={1,2,4,8};
  const int32_t shifts6[4]={0,6,12,18},shifts4[4]={0,4,8,12};
  const int32x4_t shift=vld1q_s32(gamma2==95232?shifts6:shifts4);
  const uint32x4_t bits=vld1q_u32(weights),zero=vdupq_n_u32(0);
  for(unsigned i=0;i<256;i+=8) {
    uint32x4_t a=lc_decompose_neon4(coeffs+i,gamma2);
    uint32x4_t b=lc_decompose_neon4(coeffs+i+4,gamma2);
    flags[i/8]=(uint8_t)(vaddvq_u32(vandq_u32(vcgtq_u32(a,zero),bits)) |
               (vaddvq_u32(vandq_u32(vcgtq_u32(b,zero),bits))<<4));
    uint32_t ea=vaddvq_u32(vshlq_u32(a,shift)),eb=vaddvq_u32(vshlq_u32(b,shift));
    if(gamma2==95232) {
      uint64_t word=(uint64_t)ea|((uint64_t)eb<<24);
      memcpy(encoded+3*i/4,&word,6);
    } else {
      uint32_t word=ea|(eb<<16);
      memcpy(encoded+i/2,&word,4);
    }
  }
}
#endif
