/* SPDX-License-Identifier: Apache-2.0
 * Exact canonical ByteEncode_12 check. Input consists of 24-byte groups;
 * each group encodes sixteen coefficients. The public seed is outside it. */
#ifndef LC_CANONICAL12_NEON_H
#define LC_CANONICAL12_NEON_H
#include <arm_neon.h>
#include <stddef.h>
#include <stdint.h>
#ifndef LC_PK12_BARRIER
#error "Provide the implementation's constant-time value barrier"
#endif
static unsigned lc_canonical12_neon_invalid(const uint8_t *in,size_t bytes) {
  uint16x8_t any=vdupq_n_u16(0),parity=vdupq_n_u16(0);
  const uint16x8_t lowmask=vdupq_n_u16(15),limit=vdupq_n_u16(3328);
  for(size_t i=0;i<bytes;i+=24) {
    uint8x8x3_t x=vld3_u8(in+i);
    uint16x8_t mid=vmovl_u8(x.val[1]);
    uint16x8_t a=vorrq_u16(vmovl_u8(x.val[0]),vshlq_n_u16(vandq_u16(mid,lowmask),8));
    uint16x8_t b=vorrq_u16(vshrq_n_u16(mid,4),vshlq_n_u16(vmovl_u8(x.val[2]),4));
    uint16x8_t invalid_a=vcgtq_u16(a,limit),invalid_b=vcgtq_u16(b,limit);
    any=vorrq_u16(any,vorrq_u16(invalid_a,invalid_b));
    parity=veorq_u16(parity,veorq_u16(invalid_a,invalid_b));
  }
  uint64x2_t pairs=vreinterpretq_u64_u16(parity);
  uint64_t t=vgetq_lane_u64(pairs,0)^vgetq_lane_u64(pairs,1);
  uint32_t s=(uint32_t)t^(uint32_t)(t>>32);
  uint32_t r=(uint32_t)vmaxvq_u16(any);
  /* The parity dependency keeps the whole scan live at the value barrier. */
  return (unsigned)((LC_PK12_BARRIER((0u-(uint32_t)(r!=0))^s)^s)&1u);
}
#endif
