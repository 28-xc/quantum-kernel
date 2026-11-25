/* Copyright (c) 2026 A1-27 project authors
 * SPDX-License-Identifier: Apache-2.0
 * Eight public matrix candidates are consumed together when all are valid.
 * Signed24 unpack and Montgomery arithmetic follow signed24_pointwise.h. */
#ifndef LC_STREAM4_VECTOR_H
#define LC_STREAM4_VECTOR_H
#if LC_DSA_MATRIX_STREAM_VECTOR && defined(__AVX2__)
#include <immintrin.h>
#define LC_S4_INLINE static inline __attribute__((always_inline))
LC_S4_INLINE __m256i lc_s4_load24(const uint8_t *p) {
  const __m128i sh0=_mm_setr_epi8(0,1,2,-1,3,4,5,-1,6,7,8,-1,9,10,11,-1);
  const __m128i sh1=_mm_setr_epi8(4,5,6,-1,7,8,9,-1,10,11,12,-1,13,14,15,-1);
  __m128i lo=_mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(const void*)p),sh0);
  __m128i hi=_mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(const void*)(p+8)),sh1);
  __m256i x=_mm256_inserti128_si256(_mm256_castsi128_si256(lo),hi,1);
  return _mm256_srai_epi32(_mm256_slli_epi32(x,8),8);
}
LC_S4_INLINE void lc_s4_store24(uint8_t *p,__m256i x) {
  const __m128i sh=_mm_setr_epi8(0,1,2,4,5,6,8,9,10,12,13,14,-1,-1,-1,-1);
  __m128i lo=_mm_shuffle_epi8(_mm256_castsi256_si128(x),sh);
  __m128i hi=_mm_shuffle_epi8(_mm256_extracti128_si256(x,1),sh);
  _mm_storeu_si128((__m128i*)(void*)p,_mm_or_si128(lo,_mm_slli_si128(hi,12)));
  _mm_storel_epi64((__m128i*)(void*)(p+16),_mm_srli_si128(hi,4));
}
LC_S4_INLINE __m256i lc_s4_product(__m256i a,__m256i b) {
  const __m256i q=_mm256_set1_epi32(8380417),qi=_mm256_set1_epi32(58728449);
  __m256i pe=_mm256_mul_epi32(a,b);
  __m256i po=_mm256_mul_epi32(_mm256_srli_epi64(a,32),_mm256_srli_epi64(b,32));
  __m256i te=_mm256_mul_epi32(pe,qi),to=_mm256_mul_epi32(po,qi);
  __m256i re=_mm256_sub_epi64(pe,_mm256_mul_epi32(te,q));
  __m256i ro=_mm256_sub_epi64(po,_mm256_mul_epi32(to,q));
  return _mm256_blend_epi32(_mm256_srli_epi64(re,32),ro,0xaa);
}
LC_S4_INLINE __m256i lc_s4_reduce(__m256i x) {
  __m256i t=_mm256_srai_epi32(_mm256_add_epi32(x,_mm256_set1_epi32(1<<22)),23);
  return _mm256_sub_epi32(x,_mm256_mullo_epi32(t,_mm256_set1_epi32(8380417)));
}
LC_S4_INLINE int lc_stream4_y_block(uint8_t *out,const uint8_t *sample,
                                   const int32_t *rhs,unsigned first) {
  __m256i a=_mm256_and_si256(lc_s4_load24(sample),_mm256_set1_epi32(0x7fffff));
  /* This predicate uses only the public ExpandA byte stream. */
  if(_mm256_movemask_epi8(_mm256_cmpgt_epi32(a,_mm256_set1_epi32(8380416))))return 0;
  __m256i x=lc_s4_product(a,_mm256_loadu_si256((const __m256i*)(const void*)rhs));
  if(!first)x=_mm256_add_epi32(x,lc_s4_load24(out));
  lc_s4_store24(out,lc_s4_reduce(x));
  return 1;
}
LC_S4_INLINE int lc_stream4_v_block(int32_t *out,const uint8_t *sample,
                                   const uint8_t *rhs) {
  __m256i a=_mm256_and_si256(lc_s4_load24(sample),_mm256_set1_epi32(0x7fffff));
  if(_mm256_movemask_epi8(_mm256_cmpgt_epi32(a,_mm256_set1_epi32(8380416))))return 0;
  __m256i x=lc_s4_product(a,lc_s4_load24(rhs));
  x=_mm256_add_epi32(x,_mm256_loadu_si256((const __m256i*)(const void*)out));
  _mm256_storeu_si256((__m256i*)(void*)out,x);
  return 1;
}
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#else
/* Dense-to-compact conversion consumes each complete eight-coefficient
 * group before its 24 output bytes are stored; same-base packing is safe.
 * Unpacking uses a distinct dense destination. */
static void lc_s4_pack_row(uint8_t *out,const int32_t *p) {
  for(unsigned i=0;i<256;i+=8) {
    __m256i x=_mm256_loadu_si256((const __m256i*)(const void*)(p+i));
    lc_s4_store24(out+3*i,lc_s4_reduce(x));
  }
}
static void lc_s4_unpack_row(int32_t *out,const uint8_t *p) {
  for(unsigned i=0;i<256;i+=8)
    _mm256_storeu_si256((__m256i*)(void*)(out+i),lc_s4_load24(p+3*i));
}
#endif
#undef LC_S4_INLINE
#endif
#endif
