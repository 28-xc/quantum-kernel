/* SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 * Reverse in-place SWAR CBD expansion, using the upstream bit-count rule. */
#ifndef LC_NOISE_COMPACT_H
#define LC_NOISE_COMPACT_H
#include <stdint.h>
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if defined(LC_KEM_NOISE_NEON) && LC_KEM_NOISE_NEON
#include "lc_noise_neon.h"
#endif
#else
#endif
static void lc_cbd_reverse(int16_t out[256],unsigned eta) {
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if defined(LC_KEM_NOISE_NEON) && LC_KEM_NOISE_NEON
  lc_cbd_neon(out,(const uint8_t*)out,eta);
#else
  const uint8_t *bytes=(const uint8_t*)out;
  if(eta==2)for(unsigned g=32;g-- >0;) {
    const uint8_t *p=bytes+4*g;
    uint32_t x=(uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);
    uint32_t d=(x&UINT32_C(0x55555555))+((x>>1)&UINT32_C(0x55555555));
    for(unsigned j=0;j<8;j++)out[8*g+j]=(int16_t)((int32_t)((d>>(4*j))&3u)-(int32_t)((d>>(4*j+2))&3u));
  } else for(unsigned g=64;g-- >0;) {
    const uint8_t *p=bytes+3*g;
    uint32_t x=(uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16);
    uint32_t d=(x&UINT32_C(0x249249))+((x>>1)&UINT32_C(0x249249))+((x>>2)&UINT32_C(0x249249));
    for(unsigned j=0;j<4;j++)out[4*g+j]=(int16_t)((int32_t)((d>>(6*j))&7u)-(int32_t)((d>>(6*j+3))&7u));
  }
#endif
#else
  const uint8_t *bytes=(const uint8_t*)out;
  if(eta==2)for(unsigned g=32;g-- >0;) {
    const uint8_t *p=bytes+4*g;
    uint32_t x=(uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);
    uint32_t d=(x&UINT32_C(0x55555555))+((x>>1)&UINT32_C(0x55555555));
    for(unsigned j=0;j<8;j++)out[8*g+j]=(int16_t)((int32_t)((d>>(4*j))&3u)-(int32_t)((d>>(4*j+2))&3u));
  } else for(unsigned g=64;g-- >0;) {
    const uint8_t *p=bytes+3*g;
    uint32_t x=(uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16);
    uint32_t d=(x&UINT32_C(0x249249))+((x>>1)&UINT32_C(0x249249))+((x>>2)&UINT32_C(0x249249));
    for(unsigned j=0;j<4;j++)out[4*g+j]=(int16_t)((int32_t)((d>>(6*j))&7u)-(int32_t)((d>>(6*j+3))&7u));
  }
#endif
}
static void lc_noise_pack3(uint8_t out[96],const int16_t coefficients[256]) {
  for(unsigned g=0;g<32;g++) {
    uint32_t word=0;
    for(unsigned j=0;j<8;j++)word|=(uint32_t)(coefficients[g*8+j]+3)<<(3*j);
    out[g*3]=(uint8_t)word;out[g*3+1]=(uint8_t)(word>>8);out[g*3+2]=(uint8_t)(word>>16);
  }
}
static void lc_noise_unpack3(int16_t coefficients[256],const uint8_t in[96]) {
  for(unsigned g=0;g<32;g++) {
    uint32_t word=(uint32_t)in[g*3]|((uint32_t)in[g*3+1]<<8)|((uint32_t)in[g*3+2]<<16);
    for(unsigned j=0;j<8;j++)coefficients[g*8+j]=(int16_t)((int32_t)((word>>(3*j))&7u)-3);
  }
}
#endif
