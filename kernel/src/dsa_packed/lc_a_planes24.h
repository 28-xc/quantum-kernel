/* SPDX-License-Identifier: Apache-2.0
 * Exact positive public coefficients: 256 low uint16 values followed by
 * 256 high uint8 values. The modulus is below 2^23. SIMD loads reconstruct
 * eight coefficients with two zero-extension loads, one shift and one OR.
 */
#ifndef LC_A_PLANES24_H
#define LC_A_PLANES24_H
#if LC_DSA_A_CACHE_BITS != 24
#error "split matrix planes require 24-bit storage"
#endif
#if defined(__AVX2__)
#include <immintrin.h>
static inline __m256i lc_a_planes_load(const uint8_t *a,unsigned i) {
  const __m256i lo=_mm256_cvtepu16_epi32(_mm_loadu_si128((const __m128i *)(const void *)(a+2*i)));
  const __m256i hi=_mm256_cvtepu8_epi32(_mm_loadl_epi64((const __m128i *)(const void *)(a+512+i)));
  return _mm256_or_si256(lo,_mm256_slli_epi32(hi,16));
}
static inline void lc_a_planes_store8(uint8_t *a,unsigned i,__m256i v) {
  const __m256i lo=_mm256_and_si256(v,_mm256_set1_epi32(65535));
  const __m128i packed=_mm_packus_epi32(_mm256_castsi256_si128(lo),_mm256_extracti128_si256(lo,1));
  _mm_storeu_si128((__m128i *)(void *)(a+2*i),packed);
  const __m256i hi=_mm256_srli_epi32(v,16);
  const __m128i h16=_mm_packus_epi32(_mm256_castsi256_si128(hi),_mm256_extracti128_si256(hi,1));
  _mm_storel_epi64((__m128i *)(void *)(a+512+i),_mm_packus_epi16(h16,_mm_setzero_si128()));
}
#elif defined(__aarch64__)
#include <arm_neon.h>
static inline void lc_a_planes_load_neon(const uint8_t *a,unsigned i,
                                         uint32x4_t *v0,uint32x4_t *v1) {
  uint16x8_t low;
  uint8x8_t high;
  mld_memcpy(&low,a+2*i,16);
  mld_memcpy(&high,a+512+i,8);
  const uint16x8_t h16=vmovl_u8(high);
  *v0=vorrq_u32(vmovl_u16(vget_low_u16(low)),vshlq_n_u32(vmovl_u16(vget_low_u16(h16)),16));
  *v1=vorrq_u32(vmovl_high_u16(low),vshlq_n_u32(vmovl_high_u16(h16),16));
}
static inline void lc_a_planes_store8_neon(uint8_t *a,unsigned i,
                                          uint32x4_t v0,uint32x4_t v1) {
  const uint16x8_t low=vcombine_u16(vmovn_u32(v0),vmovn_u32(v1));
  const uint16x8_t h16=vcombine_u16(vmovn_u32(vshrq_n_u32(v0,16)),vmovn_u32(vshrq_n_u32(v1,16)));
  const uint8x8_t high=vmovn_u16(h16);
  mld_memcpy(a+2*i,&low,16);
  mld_memcpy(a+512+i,&high,8);
}
#else
#error "split matrix planes require AVX2 or AArch64 NEON"
#endif
static inline void lc_a_planes_store1(uint8_t *a,unsigned i,uint32_t v) {
  const uint16_t lo=(uint16_t)v;mld_memcpy(a+2*i,&lo,2);a[512+i]=(uint8_t)(v>>16);
}
#endif
