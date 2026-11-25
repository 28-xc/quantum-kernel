/* SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 * One polynomial of the existing mlkem-native custom-order dot product.
 * Its sign pattern and Montgomery factors match the attributed native kernel.
 * Public column order controls overwrite versus accumulation. */
#ifndef LC_K3_PRODUCT_H
#define LC_K3_PRODUCT_H
#include <stdint.h>
#include <immintrin.h>
static __attribute__((always_inline)) inline __m256i lc_k3_mont(__m256i a,__m256i b) {
 __m256i u=_mm256_mullo_epi16(_mm256_mullo_epi16(a,b),_mm256_set1_epi16(-3327));
 return _mm256_sub_epi16(_mm256_mulhi_epi16(a,b),_mm256_mulhi_epi16(u,_mm256_set1_epi16(3329)));
}
#if defined(__GNUC__) && !defined(__clang__)
__attribute__((optimize("O3")))
#endif
static void lc_k3_product(int16_t out[256],const int16_t a[256],const int16_t b[256],const int16_t cache[128],int accumulate) {
 for(unsigned block=0;block<8;block++) {
  unsigned j=32*block;
  __m256i a0=_mm256_load_si256((const __m256i*)(a+j)),a1=_mm256_load_si256((const __m256i*)(a+j+16));
  __m256i b0=_mm256_load_si256((const __m256i*)(b+j)),b1=_mm256_load_si256((const __m256i*)(b+j+16));
  __m256i bc=_mm256_load_si256((const __m256i*)(cache+16*block));
  __m256i z0=lc_k3_mont(a0,b0),z1=lc_k3_mont(a1,bc);
  z0=(block&1)?_mm256_sub_epi16(z0,z1):_mm256_add_epi16(z0,z1);
  __m256i z2=_mm256_add_epi16(lc_k3_mont(a0,b1),lc_k3_mont(a1,b0));
  if(accumulate) {
   z0=_mm256_add_epi16(z0,_mm256_load_si256((const __m256i*)(out+j)));
   z2=_mm256_add_epi16(z2,_mm256_load_si256((const __m256i*)(out+j+16)));
  }
  _mm256_store_si256((__m256i*)(out+j),z0);
  _mm256_store_si256((__m256i*)(out+j+16),z2);
 }
}
#endif
