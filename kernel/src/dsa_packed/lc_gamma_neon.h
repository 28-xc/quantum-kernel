/* SPDX-License-Identifier: Apache-2.0
 * Reverse expansion of four 18/20-bit gamma coefficients at a time.
 * The whole 1024-byte object contains packed input at its beginning. */
#ifndef LC_GAMMA_NEON_H
#define LC_GAMMA_NEON_H
#include <arm_neon.h>
#include <stdint.h>
#include <string.h>
#if !defined(__aarch64__)
#error "This gamma decoder requires AArch64 NEON"
#endif
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "This exact-load gamma decoder uses little-endian coefficient bytes"
#endif
static __attribute__((always_inline)) inline uint32x4_t
lc_gamma4_neon(const uint8_t *p,unsigned bits) {
  static const uint8_t selectors18[16]={0,1,2,255,2,3,4,255,4,5,6,255,6,7,8,255};
  static const uint8_t selectors20[16]={0,1,2,255,2,3,4,255,5,6,7,255,7,8,9,255};
  static const int32_t shifts18[4]={0,-2,-4,-6},shifts20[4]={0,-4,0,-4};
  uint64_t first;memcpy(&first,p,8);
  uint64_t last=(uint64_t)p[8];
  if(bits==20)last|=(uint64_t)p[9]<<8;
  uint8x16_t packed=vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(first),vcreate_u64(last)));
  uint8x16_t selector=vld1q_u8(bits==18?selectors18:selectors20);
  uint32x4_t words=vreinterpretq_u32_u8(vqtbl1q_u8(packed,selector));
  int32x4_t shifts=vld1q_s32(bits==18?shifts18:shifts20);
  return vandq_u32(vshlq_u32(words,shifts),vdupq_n_u32((1u<<bits)-1));
}
static void lc_expand_gamma_neon(int32_t *out,unsigned bits,int32_t gamma) {
  uint8_t *packed=(uint8_t *)(void *)out;
  for(unsigned group=64;group-- >0;) {
    uint32x4_t x=lc_gamma4_neon(packed+group*(bits/2),bits);
    vst1q_s32(out+4*group,vsubq_s32(vdupq_n_s32(gamma),vreinterpretq_s32_u32(x)));
  }
}
#endif
