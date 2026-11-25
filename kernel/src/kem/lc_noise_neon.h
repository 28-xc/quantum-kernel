/* Copyright (c) 2026 A1-27 project authors
 * SPDX-License-Identifier: Apache-2.0
 * FIPS 203 CBD with reverse block traversal. The input is either disjoint
 * from the output or starts at exactly the same address. eta is public. */
#ifndef LC_NOISE_NEON_H
#define LC_NOISE_NEON_H
#include <arm_neon.h>
#include <stdint.h>
#ifndef LC_KEM_SHARED_CBD_NEON
#define LC_KEM_SHARED_CBD_NEON 0
#endif
#if LC_KEM_SHARED_CBD_NEON < 0 || LC_KEM_SHARED_CBD_NEON > 1
#error "Shared CBD selector must be zero or one"
#endif
#if LC_KEM_SHARED_CBD_NEON
#if defined(__GNUC__) && !defined(__clang__)
#define LC_CBD_SHARED __attribute__((noinline,noclone))
#else
#define LC_CBD_SHARED __attribute__((noinline))
#endif
/* Public eta selects one fixed kernel. Reverse traversal preserves the
 * original equal-base expansion contract. No new owner or secret copy. */
static LC_CBD_SHARED void lc_cbd2_neon_shared(int16_t out[256],const uint8_t *bytes) {
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC unroll 1
#endif
for(unsigned g=8;g-- >0;) {
  uint8x16_t v=vld1q_u8(bytes+16*g),m=vdupq_n_u8(0x55);
  uint8x16_t d=vaddq_u8(vandq_u8(v,m),vandq_u8(vshrq_n_u8(v,1),m));
  uint8x16_t three=vdupq_n_u8(3);
  int8x16_t a=vreinterpretq_s8_u8(vsubq_u8(vandq_u8(d,three),vandq_u8(vshrq_n_u8(d,2),three)));
  int8x16_t b=vreinterpretq_s8_u8(vsubq_u8(vandq_u8(vshrq_n_u8(d,4),three),vshrq_n_u8(d,6)));
  int8x16x2_t z=vzipq_s8(a,b);
  vst1q_s16(out+32*g,vmovl_s8(vget_low_s8(z.val[0])));
  vst1q_s16(out+32*g+8,vmovl_s8(vget_high_s8(z.val[0])));
  vst1q_s16(out+32*g+16,vmovl_s8(vget_low_s8(z.val[1])));
  vst1q_s16(out+32*g+24,vmovl_s8(vget_high_s8(z.val[1])));
 }
}
static LC_CBD_SHARED void lc_cbd3_neon_shared(int16_t out[256],const uint8_t *bytes) {
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC unroll 1
#endif
for(unsigned g=8;g-- >0;) {
  uint8x8x3_t v=vld3_u8(bytes+24*g);
  uint16x8_t a=vmovl_u8(v.val[0]),b=vmovl_u8(v.val[1]),c=vmovl_u8(v.val[2]);
  uint32x4_t lo=vorrq_u32(vmovl_u16(vget_low_u16(a)),vorrq_u32(vshlq_n_u32(vmovl_u16(vget_low_u16(b)),8),vshlq_n_u32(vmovl_u16(vget_low_u16(c)),16)));
  uint32x4_t hi=vorrq_u32(vmovl_u16(vget_high_u16(a)),vorrq_u32(vshlq_n_u32(vmovl_u16(vget_high_u16(b)),8),vshlq_n_u32(vmovl_u16(vget_high_u16(c)),16)));
  uint32x4_t mask=vdupq_n_u32(0x249249),seven=vdupq_n_u32(7);
  lo=vaddq_u32(vandq_u32(lo,mask),vaddq_u32(vandq_u32(vshrq_n_u32(lo,1),mask),vandq_u32(vshrq_n_u32(lo,2),mask)));
  hi=vaddq_u32(vandq_u32(hi,mask),vaddq_u32(vandq_u32(vshrq_n_u32(hi,1),mask),vandq_u32(vshrq_n_u32(hi,2),mask)));
  int16x8x4_t result;
#define LC_CBD_NEON_PART(J) do { \
  uint32x4_t x=vshlq_u32(lo,vdupq_n_s32(-6*(J))),y=vshlq_u32(hi,vdupq_n_s32(-6*(J))); \
  int32x4_t p=vreinterpretq_s32_u32(vsubq_u32(vandq_u32(x,seven),vandq_u32(vshrq_n_u32(x,3),seven))); \
  int32x4_t q=vreinterpretq_s32_u32(vsubq_u32(vandq_u32(y,seven),vandq_u32(vshrq_n_u32(y,3),seven))); \
  result.val[J]=vcombine_s16(vmovn_s32(p),vmovn_s32(q)); \
 } while(0)
  LC_CBD_NEON_PART(0);LC_CBD_NEON_PART(1);LC_CBD_NEON_PART(2);LC_CBD_NEON_PART(3);
#undef LC_CBD_NEON_PART
  vst4q_s16(out+32*g,result);
 }
}
static inline void lc_cbd_neon(int16_t out[256],const uint8_t *bytes,unsigned eta) {
 if(eta==2)lc_cbd2_neon_shared(out,bytes);else lc_cbd3_neon_shared(out,bytes);
}
#undef LC_CBD_SHARED
#else
static inline void lc_cbd_neon(int16_t out[256],const uint8_t *bytes,unsigned eta) {
 if(eta==2)for(unsigned g=8;g-- >0;) {
  uint8x16_t v=vld1q_u8(bytes+16*g),m=vdupq_n_u8(0x55);
  uint8x16_t d=vaddq_u8(vandq_u8(v,m),vandq_u8(vshrq_n_u8(v,1),m));
  uint8x16_t three=vdupq_n_u8(3);
  int8x16_t a=vreinterpretq_s8_u8(vsubq_u8(vandq_u8(d,three),vandq_u8(vshrq_n_u8(d,2),three)));
  int8x16_t b=vreinterpretq_s8_u8(vsubq_u8(vandq_u8(vshrq_n_u8(d,4),three),vshrq_n_u8(d,6)));
  int8x16x2_t z=vzipq_s8(a,b);
  vst1q_s16(out+32*g,vmovl_s8(vget_low_s8(z.val[0])));
  vst1q_s16(out+32*g+8,vmovl_s8(vget_high_s8(z.val[0])));
  vst1q_s16(out+32*g+16,vmovl_s8(vget_low_s8(z.val[1])));
  vst1q_s16(out+32*g+24,vmovl_s8(vget_high_s8(z.val[1])));
 } else for(unsigned g=8;g-- >0;) {
  uint8x8x3_t v=vld3_u8(bytes+24*g);
  uint16x8_t a=vmovl_u8(v.val[0]),b=vmovl_u8(v.val[1]),c=vmovl_u8(v.val[2]);
  uint32x4_t lo=vorrq_u32(vmovl_u16(vget_low_u16(a)),vorrq_u32(vshlq_n_u32(vmovl_u16(vget_low_u16(b)),8),vshlq_n_u32(vmovl_u16(vget_low_u16(c)),16)));
  uint32x4_t hi=vorrq_u32(vmovl_u16(vget_high_u16(a)),vorrq_u32(vshlq_n_u32(vmovl_u16(vget_high_u16(b)),8),vshlq_n_u32(vmovl_u16(vget_high_u16(c)),16)));
  uint32x4_t mask=vdupq_n_u32(0x249249),seven=vdupq_n_u32(7);
  lo=vaddq_u32(vandq_u32(lo,mask),vaddq_u32(vandq_u32(vshrq_n_u32(lo,1),mask),vandq_u32(vshrq_n_u32(lo,2),mask)));
  hi=vaddq_u32(vandq_u32(hi,mask),vaddq_u32(vandq_u32(vshrq_n_u32(hi,1),mask),vandq_u32(vshrq_n_u32(hi,2),mask)));
  int16x8x4_t result;
#define LC_CBD_NEON_PART(J) do { \
  uint32x4_t x=vshlq_u32(lo,vdupq_n_s32(-6*(J))),y=vshlq_u32(hi,vdupq_n_s32(-6*(J))); \
  int32x4_t p=vreinterpretq_s32_u32(vsubq_u32(vandq_u32(x,seven),vandq_u32(vshrq_n_u32(x,3),seven))); \
  int32x4_t q=vreinterpretq_s32_u32(vsubq_u32(vandq_u32(y,seven),vandq_u32(vshrq_n_u32(y,3),seven))); \
  result.val[J]=vcombine_s16(vmovn_s32(p),vmovn_s32(q)); \
 } while(0)
  LC_CBD_NEON_PART(0);LC_CBD_NEON_PART(1);LC_CBD_NEON_PART(2);LC_CBD_NEON_PART(3);
#undef LC_CBD_NEON_PART
  vst4q_s16(out+32*g,result);
 }
}
#endif /* LC_KEM_SHARED_CBD_NEON */
#endif /* LC_NOISE_NEON_H */
