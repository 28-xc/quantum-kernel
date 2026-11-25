#ifndef LC_KEM_POLY_ADDSUB_LOOP16_V1_H
#define LC_KEM_POLY_ADDSUB_LOOP16_V1_H
#include <immintrin.h>
#include <stdint.h>
#include <stddef.h>

/* Accumulator r and immutable b are disjoint 512-byte objects. Every
 * mathematical result is in INT16_MIN..INT16_MAX, as in the production
 * mlk_poly_add/sub contract. Exactly sixteen public, fixed-width steps. */
#ifndef LC_POLY_LOOP_NOINLINE
#if defined(__GNUC__) || defined(__clang__)
#define LC_POLY_LOOP_NOINLINE __attribute__((noinline))
#else
#define LC_POLY_LOOP_NOINLINE __declspec(noinline)
#endif
#endif

LC_POLY_LOOP_NOINLINE void lc_kem_poly_add_loop16(int16_t *r, const int16_t *b)
{
#if defined(__clang__)
#pragma clang loop unroll(disable)
#elif defined(__GNUC__)
#pragma GCC unroll 1
#endif
    for (size_t i = 0; i < 256; i += 16) {
        const __m256i a = _mm256_loadu_si256((const __m256i *)(const void *)(r + i));
        const __m256i c = _mm256_loadu_si256((const __m256i *)(const void *)(b + i));
        _mm256_storeu_si256((__m256i *)(void *)(r + i), _mm256_add_epi16(a, c));
    }
}

LC_POLY_LOOP_NOINLINE void lc_kem_poly_sub_loop16(int16_t *r, const int16_t *b)
{
#if defined(__clang__)
#pragma clang loop unroll(disable)
#elif defined(__GNUC__)
#pragma GCC unroll 1
#endif
    for (size_t i = 0; i < 256; i += 16) {
        const __m256i a = _mm256_loadu_si256((const __m256i *)(const void *)(r + i));
        const __m256i c = _mm256_loadu_si256((const __m256i *)(const void *)(b + i));
        _mm256_storeu_si256((__m256i *)(void *)(r + i), _mm256_sub_epi16(a, c));
    }
}
#endif
