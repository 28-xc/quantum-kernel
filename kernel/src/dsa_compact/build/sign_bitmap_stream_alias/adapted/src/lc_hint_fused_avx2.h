/* SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 * Compute eight FIPS204 MakeHint predicates directly into each bitmap byte.
 * The caller has checked |low[i]| < gamma2-beta and |ct0[i]| < gamma2.
 * flags holds the prior high-part-nonzero predicate. Only flags is modified.
 * low, ct0 and the32-byte flags owner are disjoint. gamma2 is public.
 */
#ifndef LC_HINT_FUSED_AVX2_H
#define LC_HINT_FUSED_AVX2_H
#include <immintrin.h>
#include <stdint.h>
static void lc_hint_fused_avx2(uint8_t flags[32],const int32_t low[256],
                             const int32_t ct0[256],int32_t gamma2) {
    const __m256i gamma=_mm256_set1_epi32(gamma2);
    const __m256i negative_gamma=_mm256_set1_epi32(-gamma2);
    const __m256i shifts=_mm256_setr_epi32(31,30,29,28,27,26,25,24);
    for(unsigned group=0;group<32;group++) {
        __m256i a=_mm256_add_epi32(
            _mm256_loadu_si256((const __m256i*)(const void*)(low+8*group)),
            _mm256_loadu_si256((const __m256i*)(const void*)(ct0+8*group)));
        __m256i outside=_mm256_cmpgt_epi32(_mm256_abs_epi32(a),gamma);
        __m256i boundary=_mm256_cmpeq_epi32(a,negative_gamma);
        __m256i high=_mm256_sllv_epi32(_mm256_set1_epi32(flags[group]),shifts);
        __m256i mask=_mm256_or_si256(outside,_mm256_and_si256(boundary,high));
        flags[group]=(uint8_t)_mm256_movemask_ps(_mm256_castsi256_ps(mask));
    }
}
#endif
