/* Copyright (c) 2026 A1-27 project authors
 * SPDX-License-Identifier: Apache-2.0
 *
 * Signed reduced coefficients are stored in their native NTT order, in three
 * little-endian bytes. Decode and Montgomery multiplication share one pass.
 * Each input block reads exactly 24 bytes, including the final block.
 * Arithmetic uses q = 8380417, R = 2^32, q^-1 mod R = 58728449.
 */
#ifndef LC_SIGNED24_POINTWISE_H
#define LC_SIGNED24_POINTWISE_H
#include <stdint.h>
#include <string.h>
#if defined(__AVX2__)
#include <immintrin.h>
#endif

static inline void lc_signed24_pointwise_acc(int32_t out[256],
    const uint8_t packed[768], const int32_t rhs[256], int add, int use_avx2)
{
#if defined(__AVX2__)
  if (use_avx2) {
    const __m128i sh0 = _mm_setr_epi8(0,1,2,-1,3,4,5,-1,
                                    6,7,8,-1,9,10,11,-1);
    const __m128i sh1 = _mm_setr_epi8(4,5,6,-1,7,8,9,-1,
                                    10,11,12,-1,13,14,15,-1);
    const __m256i q = _mm256_set1_epi32(8380417);
    const __m256i qi = _mm256_set1_epi32(58728449);
    for (unsigned j=0; j<256; j+=8) {
      const uint8_t *p = packed+3*j;
      const __m128i lo = _mm_shuffle_epi8(
          _mm_loadu_si128((const __m128i *)(const void *)p), sh0);
      const __m128i hi = _mm_shuffle_epi8(
          _mm_loadu_si128((const __m128i *)(const void *)(p+8)), sh1);
      const __m256i u = _mm256_inserti128_si256(_mm256_castsi128_si256(lo),hi,1);
      const __m256i a = _mm256_srai_epi32(_mm256_slli_epi32(u,8),8);
      const __m256i b = _mm256_loadu_si256((const __m256i *)(const void *)(rhs+j));
      const __m256i pe = _mm256_mul_epi32(a,b);
      const __m256i po = _mm256_mul_epi32(_mm256_srli_epi64(a,32),
                                        _mm256_srli_epi64(b,32));
      const __m256i te = _mm256_mul_epi32(pe,qi);
      const __m256i to = _mm256_mul_epi32(po,qi);
      const __m256i re = _mm256_sub_epi64(pe,_mm256_mul_epi32(te,q));
      const __m256i ro = _mm256_sub_epi64(po,_mm256_mul_epi32(to,q));
      __m256i v = _mm256_blend_epi32(_mm256_srli_epi64(re,32),ro,0xaa);
      if (add) v = _mm256_add_epi32(v,
          _mm256_loadu_si256((const __m256i *)(const void *)(out+j)));
      _mm256_storeu_si256((__m256i *)(void *)(out+j),v);
    }
    return;
  }
#else
  (void)use_avx2;
#endif
  for (unsigned j=0; j<256; j++) {
    const uint32_t u = (uint32_t)packed[3*j] |
        ((uint32_t)packed[3*j+1]<<8) | ((uint32_t)packed[3*j+2]<<16);
    const int32_t a = (int32_t)(u & 0x7fffffu) - (int32_t)(u & 0x800000u);
    const int64_t product = (int64_t)a * rhs[j];
    const uint32_t tu = (uint32_t)product * UINT32_C(58728449);
    int32_t t;
    memcpy(&t,&tu,sizeof(t));
    const int32_t v = (int32_t)((product-(int64_t)t*8380417)/INT64_C(4294967296));
    out[j] = add ? out[j]+v : v;
  }
}
#endif
