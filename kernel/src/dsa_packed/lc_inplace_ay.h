/* SPDX-License-Identifier: Apache-2.0
 * Fixed-order in-place dense matrix-vector product. The first L output rows
 * initially hold NTT(y); K >= L. For each eight independent frequency positions
 * all L source vectors are loaded before any output row is overwritten.
 * Therefore no later tile reads an overwritten input. The row stride remains
 * 32-byte aligned and final row owners retain the original zeroization scope.
 * The 64-bit dot-product and Montgomery domains match lc_packed_ay exactly.
 */
#ifndef LC_INPLACE_AY_H
#define LC_INPLACE_AY_H
#if !defined(__AVX2__) || !LC_DSA_DENSE_SIGN_ROWS || !LC_DSA_CACHED_DOT_TILE || (LC_DSA_A_CACHE_BITS != 32 && !LC_DSA_A_PLANES24) || LC_DSA_A_CACHE_COUNT < MLDSA_K*MLDSA_L
#error "in-place A*y requires full AVX2 A32 and dense output rows"
#endif
static void lc_inplace_ay(uint8_t *w,mld_polymat *mat,const mld_yvec *y) {
  for(unsigned l=0;l<MLDSA_L;l++) {
    mld_poly *yp=(mld_poly *)(void *)(w+l*LC_SIGN_AY_ROW_BYTES);
    mld_yvec_get_poly(yp,y,l);mld_poly_ntt(yp);lc_stream_transform_order(yp);
  }
  for(unsigned i=0;i<MLDSA_N;i+=8) {
#if MLDSA_L > 0
    const __m256i y0=_mm256_load_si256((const __m256i *)(const void *)(w+0*LC_SIGN_AY_ROW_BYTES+4*i));
#endif
#if MLDSA_L > 1
    const __m256i y1=_mm256_load_si256((const __m256i *)(const void *)(w+1*LC_SIGN_AY_ROW_BYTES+4*i));
#endif
#if MLDSA_L > 2
    const __m256i y2=_mm256_load_si256((const __m256i *)(const void *)(w+2*LC_SIGN_AY_ROW_BYTES+4*i));
#endif
#if MLDSA_L > 3
    const __m256i y3=_mm256_load_si256((const __m256i *)(const void *)(w+3*LC_SIGN_AY_ROW_BYTES+4*i));
#endif
#if MLDSA_L > 4
    const __m256i y4=_mm256_load_si256((const __m256i *)(const void *)(w+4*LC_SIGN_AY_ROW_BYTES+4*i));
#endif
#if MLDSA_L > 5
    const __m256i y5=_mm256_load_si256((const __m256i *)(const void *)(w+5*LC_SIGN_AY_ROW_BYTES+4*i));
#endif
#if MLDSA_L > 6
    const __m256i y6=_mm256_load_si256((const __m256i *)(const void *)(w+6*LC_SIGN_AY_ROW_BYTES+4*i));
#endif
    for(unsigned k=0;k<MLDSA_K;k++) {
      __m256i even=_mm256_setzero_si256(),odd=_mm256_setzero_si256();
#if MLDSA_L > 0
      {
#if LC_DSA_A_PLANES24
        const __m256i av=lc_a_planes_load(mat->cache[0*MLDSA_K+k],i);
#else
        const __m256i av=_mm256_loadu_si256((const __m256i *)(const void *)(mat->cache[0*MLDSA_K+k]+4*i));
#endif
        even=_mm256_add_epi64(even,_mm256_mul_epi32(av,y0));
        odd=_mm256_add_epi64(odd,_mm256_mul_epi32(_mm256_srli_epi64(av,32),_mm256_srli_epi64(y0,32))); }
#endif
#if MLDSA_L > 1
      {
#if LC_DSA_A_PLANES24
        const __m256i av=lc_a_planes_load(mat->cache[1*MLDSA_K+k],i);
#else
        const __m256i av=_mm256_loadu_si256((const __m256i *)(const void *)(mat->cache[1*MLDSA_K+k]+4*i));
#endif
        even=_mm256_add_epi64(even,_mm256_mul_epi32(av,y1));
        odd=_mm256_add_epi64(odd,_mm256_mul_epi32(_mm256_srli_epi64(av,32),_mm256_srli_epi64(y1,32))); }
#endif
#if MLDSA_L > 2
      {
#if LC_DSA_A_PLANES24
        const __m256i av=lc_a_planes_load(mat->cache[2*MLDSA_K+k],i);
#else
        const __m256i av=_mm256_loadu_si256((const __m256i *)(const void *)(mat->cache[2*MLDSA_K+k]+4*i));
#endif
        even=_mm256_add_epi64(even,_mm256_mul_epi32(av,y2));
        odd=_mm256_add_epi64(odd,_mm256_mul_epi32(_mm256_srli_epi64(av,32),_mm256_srli_epi64(y2,32))); }
#endif
#if MLDSA_L > 3
      {
#if LC_DSA_A_PLANES24
        const __m256i av=lc_a_planes_load(mat->cache[3*MLDSA_K+k],i);
#else
        const __m256i av=_mm256_loadu_si256((const __m256i *)(const void *)(mat->cache[3*MLDSA_K+k]+4*i));
#endif
        even=_mm256_add_epi64(even,_mm256_mul_epi32(av,y3));
        odd=_mm256_add_epi64(odd,_mm256_mul_epi32(_mm256_srli_epi64(av,32),_mm256_srli_epi64(y3,32))); }
#endif
#if MLDSA_L > 4
      {
#if LC_DSA_A_PLANES24
        const __m256i av=lc_a_planes_load(mat->cache[4*MLDSA_K+k],i);
#else
        const __m256i av=_mm256_loadu_si256((const __m256i *)(const void *)(mat->cache[4*MLDSA_K+k]+4*i));
#endif
        even=_mm256_add_epi64(even,_mm256_mul_epi32(av,y4));
        odd=_mm256_add_epi64(odd,_mm256_mul_epi32(_mm256_srli_epi64(av,32),_mm256_srli_epi64(y4,32))); }
#endif
#if MLDSA_L > 5
      {
#if LC_DSA_A_PLANES24
        const __m256i av=lc_a_planes_load(mat->cache[5*MLDSA_K+k],i);
#else
        const __m256i av=_mm256_loadu_si256((const __m256i *)(const void *)(mat->cache[5*MLDSA_K+k]+4*i));
#endif
        even=_mm256_add_epi64(even,_mm256_mul_epi32(av,y5));
        odd=_mm256_add_epi64(odd,_mm256_mul_epi32(_mm256_srli_epi64(av,32),_mm256_srli_epi64(y5,32))); }
#endif
#if MLDSA_L > 6
      {
#if LC_DSA_A_PLANES24
        const __m256i av=lc_a_planes_load(mat->cache[6*MLDSA_K+k],i);
#else
        const __m256i av=_mm256_loadu_si256((const __m256i *)(const void *)(mat->cache[6*MLDSA_K+k]+4*i));
#endif
        even=_mm256_add_epi64(even,_mm256_mul_epi32(av,y6));
        odd=_mm256_add_epi64(odd,_mm256_mul_epi32(_mm256_srli_epi64(av,32),_mm256_srli_epi64(y6,32))); }
#endif
      const __m256i qi=_mm256_set1_epi32(58728449),q=_mm256_set1_epi32(8380417);
      const __m256i te=_mm256_mul_epi32(even,qi),to=_mm256_mul_epi32(odd,qi);
      const __m256i re=_mm256_sub_epi64(even,_mm256_mul_epi32(te,q));
      const __m256i ro=_mm256_sub_epi64(odd,_mm256_mul_epi32(to,q));
      const __m256i sum=_mm256_blend_epi32(_mm256_srli_epi64(re,32),ro,0xaa);
      _mm256_store_si256((__m256i *)(void *)(w+k*LC_SIGN_AY_ROW_BYTES+4*i),lc_s4_reduce(sum));
    }
  }
}
#endif
