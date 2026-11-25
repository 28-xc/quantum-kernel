/* SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 * Packed temporary representation for the portable low-memory path. */
#ifndef LC_INPLACE_SAMPLING_H
#define LC_INPLACE_SAMPLING_H
#ifndef LC_DSA_INPLACE_SAMPLE
#define LC_DSA_INPLACE_SAMPLE 0
#endif
#ifndef LC_DSA_STREAM_RECOMPUTE
#define LC_DSA_STREAM_RECOMPUTE 0
#endif
#ifndef LC_DSA_PACKED_ACCUM
#define LC_DSA_PACKED_ACCUM 0
#endif
#ifndef LC_DSA_GAMMA_REVERSE_AVX2
#define LC_DSA_GAMMA_REVERSE_AVX2 0
#endif
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if LC_DSA_GAMMA_REVERSE_AVX2 && defined(__AVX2__)
#include <immintrin.h>
#endif
#if defined(LC_DSA_GAMMA_REVERSE_NEON) && LC_DSA_GAMMA_REVERSE_NEON
#include "lc_gamma_neon.h"
#endif
#else
#if LC_DSA_GAMMA_REVERSE_AVX2 && defined(__AVX2__)
#include <immintrin.h>
#endif
#endif
/* Input starts after the accepted prefix. Each accepted triple replaces an
 * already consumed triple; the write cursor never passes the read cursor. */
static unsigned lc_reject_compact24(uint8_t *p,unsigned count,unsigned source,unsigned bytes) {
  unsigned pos=source,end=source+bytes;
  while(count<256 && pos+3<=end) {
    uint32_t x=(uint32_t)p[pos]|((uint32_t)p[pos+1]<<8)|((uint32_t)p[pos+2]<<16);
    pos+=3;x&=0x7fffffu;
    if(x<8380417u) {p[3*count]=(uint8_t)x;p[3*count+1]=(uint8_t)(x>>8);p[3*count+2]=(uint8_t)(x>>16);count++;}
  }
  return count;
}
static void lc_expand_unsigned24(int32_t *out) {
  uint8_t *p=(uint8_t*)out;
  for(unsigned i=256;i-- >0;) {
    uint32_t x=(uint32_t)p[3*i]|((uint32_t)p[3*i+1]<<8)|((uint32_t)p[3*i+2]<<16);
    out[i]=(int32_t)x;
  }
}
static void lc_expand_gamma(int32_t *out,unsigned bits,int32_t gamma) {
  uint8_t *p=(uint8_t*)out;
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if defined(LC_DSA_GAMMA_REVERSE_NEON) && LC_DSA_GAMMA_REVERSE_NEON
  if(bits==18 || bits==20) {lc_expand_gamma_neon(out,bits,gamma);return;}
#endif
#else
#endif
#if LC_DSA_GAMMA_REVERSE_AVX2 && defined(__AVX2__)
  if(bits==18 || bits==20) {
    /* Two four-coefficient groups occupy 9+9 or 10+10 packed bytes.
     * Both groups are read before the 32-byte output is stored. Traversing
     * blocks backwards keeps every still-needed packed byte below the write. */
    const __m128i gather18=_mm_setr_epi8(0,1,2,3,2,3,4,5,4,5,6,7,6,7,8,9);
    const __m128i gather20=_mm_setr_epi8(0,1,2,3,2,3,4,5,5,6,7,8,7,8,9,10);
    const __m256i gather=_mm256_broadcastsi128_si256(bits==18?gather18:gather20);
    const __m256i shifts=bits==18?_mm256_setr_epi32(0,2,4,6,0,2,4,6):_mm256_setr_epi32(0,4,0,4,0,4,0,4);
    const __m256i mask=_mm256_set1_epi32((int32_t)((1u<<bits)-1u));
    const __m256i center=_mm256_set1_epi32(gamma);
    for(unsigned block=32;block-- >0;) {
      const uint8_t *source=p+block*bits;
      __m128i lower=_mm_loadu_si128((const __m128i*)source);
      __m128i upper=_mm_loadu_si128((const __m128i*)(source+bits/2));
      __m256i packed=_mm256_inserti128_si256(_mm256_castsi128_si256(lower),upper,1);
      __m256i values=_mm256_and_si256(_mm256_srlv_epi32(_mm256_shuffle_epi8(packed,gather),shifts),mask);
      _mm256_storeu_si256((__m256i*)(out+8*block),_mm256_sub_epi32(center,values));
    }
    return;
  }
#endif
  for(unsigned i=256;i-- >0;) {
    unsigned bit=i*bits,pos=bit/8;
    uint32_t x=(uint32_t)p[pos]|((uint32_t)p[pos+1]<<8)|((uint32_t)p[pos+2]<<16);
    out[i]=gamma-(int32_t)((x>>(bit%8))&((1u<<bits)-1));
  }
}
static int32_t lc_load_signed24(const uint8_t *p) {
  uint32_t x=(uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16);
  return (int32_t)(x&0x7fffffu)-(int32_t)(x&0x800000u);
}
static void lc_store_signed24(uint8_t *p,int32_t v) {
  uint32_t x=(uint32_t)v;p[0]=(uint8_t)x;p[1]=(uint8_t)(x>>8);p[2]=(uint8_t)(x>>16);
}
#endif
