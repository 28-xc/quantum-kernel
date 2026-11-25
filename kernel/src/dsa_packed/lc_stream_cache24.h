/* SPDX-License-Identifier: Apache-2.0
 * Per-signature fixed public matrix prefix. Coefficients remain in [0,q).
 * The existing call-owned cache allocation is cleared by the existing owner.
 * Ready is published only after the first complete A*y pass. No secret
 * coefficient, rejection predicate or access history selects retained rows.
 */
#ifndef LC_STREAM_CACHE24_H
#define LC_STREAM_CACHE24_H
#if !LC_DSA_A_CACHE_SIGN_ONLY || (LC_DSA_A_CACHE_BITS != 24 && LC_DSA_A_CACHE_BITS != 32) || LC_DSA_A_CACHE_POLYS == 0 || LC_DSA_A_CACHE_BATCH4
#error "Stream cache requires a 24/32-bit call-owned lazy prefix"
#endif
static inline unsigned lc_stream_cache_hit(const mld_polymat *mat,unsigned index) {
  return mat->cache_ready && index<LC_DSA_A_CACHE_COUNT;
}
#if defined(__aarch64__)
static inline void lc_stream_cache_store8(mld_polymat *mat,unsigned index,
    unsigned offset,uint32x4_t a,uint32x4_t b) {
  if(!mat->cache_ready && index<LC_DSA_A_CACHE_COUNT) {
#if LC_DSA_A_PLANES24
    lc_a_planes_store8_neon(mat->cache[index],offset,a,b);
#elif LC_DSA_A_CACHE_BITS == 32
    mld_memcpy(mat->cache[index]+4*offset,&a,16);
    mld_memcpy(mat->cache[index]+4*offset+16,&b,16);
#else
    lc_stream_pack8(mat->cache[index]+3*offset,vreinterpretq_s32_u32(a),vreinterpretq_s32_u32(b));
#endif
  }
}
#else
#if LC_DSA_A_CACHE_BITS == 32
static inline void lc_stream_cache_store8(mld_polymat *mat,unsigned index,
    unsigned offset,const uint8_t *bytes) {
  if(!mat->cache_ready && index<LC_DSA_A_CACHE_COUNT) {
    __m256i a=_mm256_and_si256(lc_s4_load24(bytes),_mm256_set1_epi32(0x7fffff));
#if LC_DSA_A_CACHE_BITS == 32
    _mm256_storeu_si256((__m256i*)(void*)(mat->cache[index]+4*offset),a);
#else
    lc_s4_store24(mat->cache[index]+3*offset,a);
#endif
  }
}
#else
static inline void lc_stream_cache_store8(mld_polymat *mat,unsigned index,
    unsigned offset,const uint8_t *bytes) {
  if(!mat->cache_ready && index<LC_DSA_A_CACHE_COUNT) {
#if LC_DSA_A_PLANES24
    lc_a_planes_store8(mat->cache[index],offset,_mm256_and_si256(lc_s4_load24(bytes),_mm256_set1_epi32(0x7fffff)));
#else
    lc_s4_store24(mat->cache[index]+3*offset,_mm256_and_si256(lc_s4_load24(bytes),_mm256_set1_epi32(0x7fffff)));
#endif
  }
}
#endif
#endif
static inline void lc_stream_cache_store1(mld_polymat *mat,unsigned index,
    unsigned offset,uint32_t a) {
  if(!mat->cache_ready && index<LC_DSA_A_CACHE_COUNT) {
#if LC_DSA_A_PLANES24
    lc_a_planes_store1(mat->cache[index],offset,a);
#elif LC_DSA_A_CACHE_BITS == 32
    mld_memcpy(mat->cache[index]+4*offset,&a,sizeof(a));
#else
    uint8_t *p=mat->cache[index]+3*offset;
    p[0]=(uint8_t)a;p[1]=(uint8_t)(a>>8);p[2]=(uint8_t)(a>>16);
#endif
  }
}
static void lc_stream_cache_product(uint8_t *out,const uint8_t *a,
                                    const int32_t y[256],unsigned first) {
  for(unsigned i=0;i<256;i+=8) {
#if defined(__aarch64__)
    uint32x4_t a0,a1;
#if LC_DSA_A_PLANES24
    lc_a_planes_load_neon(a,i,&a0,&a1);
#elif LC_DSA_A_CACHE_BITS == 32
    a0=vld1q_u32((const uint32_t*)(const void*)(a+4*i));
    a1=vld1q_u32((const uint32_t*)(const void*)(a+4*i+16));
#else
    lc_stream_unpack8(a+3*i,&a0,&a1);
#endif
    lc_stream_y8(out+3*i,y+i,a0,a1,first);
#else
#if LC_DSA_A_PLANES24
    __m256i av=lc_a_planes_load(a,i);
#elif LC_DSA_A_CACHE_BITS == 32
    __m256i av=_mm256_loadu_si256((const __m256i*)(const void*)(a+4*i));
#else
    __m256i av=lc_s4_load24(a+3*i);
#endif
    __m256i x=lc_s4_product(av,_mm256_loadu_si256((const __m256i*)(const void*)(y+i)));
    if(!first)x=_mm256_add_epi32(x,lc_s4_load24(out+3*i));
    lc_s4_store24(out+3*i,lc_s4_reduce(x));
#endif
  }
}
#endif
