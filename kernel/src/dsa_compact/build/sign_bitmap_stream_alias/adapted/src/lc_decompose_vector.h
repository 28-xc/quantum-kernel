/* Copyright (c) 2026 A1-27 project authors
 * SPDX-License-Identifier: Apache-2.0
 * FIPS 204 Decompose plus high-bit encoding and nonzero predicates.
 * Input: 256 standard representatives in [0,8380417).
 * Output: low parts in place, 192/128 encoded high bytes and 32 flag bytes.
 * Every load, store and branch depends only on public loop/parameter values.
 */
#ifndef LC_DECOMPOSE_VECTOR_H
#define LC_DECOMPOSE_VECTOR_H
#include <immintrin.h>
#include <stdint.h>
#include <string.h>
static inline void lc_decompose_encode_vector(int32_t *coeffs,uint8_t *encoded,
                                              uint8_t *flags,int gamma2) {
  const __m256i zero=_mm256_setzero_si256();
  const __m256i q=_mm256_set1_epi32(8380417);
  for(unsigned i=0;i<256;i+=8) {
    __m256i a=_mm256_loadu_si256((const __m256i*)(const void*)(coeffs+i));
    __m256i h=_mm256_srli_epi32(_mm256_add_epi32(a,_mm256_set1_epi32(127)),7);
    if(gamma2==95232) {
      h=_mm256_srli_epi32(_mm256_add_epi32(_mm256_mullo_epi32(h,_mm256_set1_epi32(11275)),_mm256_set1_epi32(1<<23)),24);
      h=_mm256_andnot_si256(_mm256_cmpgt_epi32(h,_mm256_set1_epi32(43)),h);
    } else {
      h=_mm256_srli_epi32(_mm256_add_epi32(_mm256_mullo_epi32(h,_mm256_set1_epi32(1025)),_mm256_set1_epi32(1<<21)),22);
      h=_mm256_and_si256(h,_mm256_set1_epi32(15));
    }
    __m256i low=_mm256_sub_epi32(a,_mm256_mullo_epi32(h,_mm256_set1_epi32(2*gamma2)));
    low=_mm256_sub_epi32(low,_mm256_and_si256(q,_mm256_cmpgt_epi32(low,_mm256_set1_epi32(4190208))));
    _mm256_storeu_si256((__m256i*)(void*)(coeffs+i),low);
    flags[i/8]=(uint8_t)_mm256_movemask_ps(_mm256_castsi256_ps(_mm256_cmpgt_epi32(h,zero)));
    __m128i h16=_mm_packus_epi32(_mm256_castsi256_si128(h),_mm256_extracti128_si256(h,1));
    __m128i h8=_mm_packus_epi16(h16,_mm_setzero_si128());
    __m128i packed;
    unsigned offset;
    if(gamma2==95232) {
      __m128i pairs=_mm_maddubs_epi16(h8,_mm_set1_epi16(0x4001));
      packed=_mm_madd_epi16(pairs,_mm_set1_epi32(0x10000001));
      packed=_mm_shuffle_epi8(packed,_mm_setr_epi8(0,1,2,4,5,6,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1));
      offset=3*i/4;
      uint16_t tail=(uint16_t)_mm_extract_epi16(packed,2);
      memcpy(encoded+offset+4,&tail,2);
    } else {
      packed=_mm_maddubs_epi16(h8,_mm_set1_epi16(0x1001));
      packed=_mm_packus_epi16(packed,_mm_setzero_si128());offset=i/2;
    }
    uint32_t head=(uint32_t)_mm_cvtsi128_si32(packed);
    memcpy(encoded+offset,&head,4);
  }
}
#endif
