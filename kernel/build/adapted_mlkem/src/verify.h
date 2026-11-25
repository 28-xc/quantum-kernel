/*
 * Copyright (c) The mlkem-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* References
 * ==========
 *
 * - [FIPS203]
 *   FIPS 203 Module-Lattice-Based Key-Encapsulation Mechanism Standard
 *   National Institute of Standards and Technology
 *   https://csrc.nist.gov/pubs/fips/203/final
 *
 * - [REF]
 *   CRYSTALS-Kyber C reference implementation
 *   Bos, Ducas, Kiltz, Lepoint, Lyubashevsky, Schanck, Schwabe, Seiler, Stehlé
 *   https://github.com/pq-crystals/kyber/tree/main/ref
 *
 * - [libmceliece]
 *   libmceliece implementation of Classic McEliece
 *   Bernstein, Chou
 *   https://lib.mceliece.org/
 *
 * - [optblocker]
 *   PQC forum post on opt-blockers using volatile globals
 *   Daniel J. Bernstein
 *   https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/hqbtIGFKIpU/m/H14H0wOlBgAJ
 */

#ifndef MLK_VERIFY_H
#define MLK_VERIFY_H


#include "cbmc.h"
#include "common.h"
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if defined(LC_KEM_CT_MEMCMP_NEON) && LC_KEM_CT_MEMCMP_NEON && defined(__aarch64__) && defined(__ARM_NEON)
#include <arm_neon.h>
#endif
#else
#if defined(LC_KEM_CT_MEMCMP_AVX2) && LC_KEM_CT_MEMCMP_AVX2 && defined(__AVX2__)
#include <immintrin.h>
#endif
#endif

/* Constant-time comparisons and conditional operations

   We reduce the risk for compilation into variable-time code
   through the use of 'value barriers'.

   Functionally, a value barrier is a no-op. To the compiler, however,
   it constitutes an arbitrary modification of its input, and therefore
   harden's value propagation and range analysis.

   We consider two approaches to implement a value barrier:
   - An empty inline asm block which marks the target value as clobbered.
   - XOR'ing with the value of a volatile global that's set to 0;
     see @[optblocker] for a discussion of this idea, and
     @[libmceliece, inttypes/crypto_intN.h] for an implementation.

   The first approach is cheap because it only prevents the compiler
   from reasoning about the value of the variable past the barrier,
   but does not directly generate additional instructions.

   The second approach generates redundant loads and XOR operations
   and therefore comes at a higher runtime cost. However, it appears
   more robust towards optimization, as compilers should never drop
   a volatile load.

   We use the empty-ASM value barrier for GCC and clang, and fall
   back to the global volatile barrier otherwise.

   The global value barrier can be forced by setting
   MLK_CONFIG_NO_ASM_VALUE_BARRIER.

*/

#if defined(MLK_HAVE_INLINE_ASM) && !defined(MLK_CONFIG_NO_ASM_VALUE_BARRIER)
#define MLK_USE_ASM_VALUE_BARRIER
#endif

#if !defined(MLK_USE_ASM_VALUE_BARRIER)

/*
 * Declaration of global volatile that the global value barrier
 * is loading from and masking with.
 */
#define mlk_ct_opt_blocker_u64 MLK_NAMESPACE(ct_opt_blocker_u64)
extern volatile uint64_t mlk_ct_opt_blocker_u64;

/* Helper functions for obtaining global masks of various sizes */

/* This contract is not proved but treated as an axiom.
 *
 * Its validity relies on the assumption that the global opt-blocker
 * constant mlk_ct_opt_blocker_u64 is not modified.
 */
static MLK_INLINE uint64_t mlk_ct_get_optblocker_u64(void)
__contract__(ensures(return_value == 0)) { return mlk_ct_opt_blocker_u64; }

static MLK_INLINE uint8_t mlk_ct_get_optblocker_u8(void)
__contract__(ensures(return_value == 0)) { return (uint8_t)mlk_ct_get_optblocker_u64(); }

static MLK_INLINE uint32_t mlk_ct_get_optblocker_u32(void)
__contract__(ensures(return_value == 0)) { return (uint32_t)mlk_ct_get_optblocker_u64(); }

static MLK_INLINE int32_t mlk_ct_get_optblocker_i32(void)
__contract__(ensures(return_value == 0)) { return (int32_t)mlk_ct_get_optblocker_u64(); }

/* Opt-blocker based implementation of value barriers */
static MLK_INLINE uint32_t mlk_value_barrier_u32(uint32_t b)
__contract__(ensures(return_value == b)) { return (b ^ mlk_ct_get_optblocker_u32()); }

static MLK_INLINE int32_t mlk_value_barrier_i32(int32_t b)
__contract__(ensures(return_value == b)) { return (b ^ mlk_ct_get_optblocker_i32()); }

static MLK_INLINE uint8_t mlk_value_barrier_u8(uint8_t b)
__contract__(ensures(return_value == b)) { return (b ^ mlk_ct_get_optblocker_u8()); }

#else /* !MLK_USE_ASM_VALUE_BARRIER */

static MLK_INLINE uint32_t mlk_value_barrier_u32(uint32_t b)
__contract__(ensures(return_value == b))
{
  __asm__ volatile("" : "+r"(b));
  return b;
}

static MLK_INLINE int32_t mlk_value_barrier_i32(int32_t b)
__contract__(ensures(return_value == b))
{
  __asm__ volatile("" : "+r"(b));
  return b;
}

static MLK_INLINE uint8_t mlk_value_barrier_u8(uint8_t b)
__contract__(ensures(return_value == b))
{
  __asm__ volatile("" : "+r"(b));
  return b;
}

#endif /* MLK_USE_ASM_VALUE_BARRIER */

#ifdef CBMC
#pragma CPROVER check push
#pragma CPROVER check disable "conversion"
#endif
/**
 * Cast uint16 value to int16.
 *
 * @param x Input value.
 *
 * @return For uint16_t x, the unique y in int16_t so that x == y mod 2^16.
 *         Concretely:
 *         - x <  32768: returns x
 *         - x >= 32768: returns x - 65536
 */
static MLK_ALWAYS_INLINE int16_t mlk_cast_uint16_to_int16(uint16_t x)
{
  /*
   * PORTABILITY: This relies on uint16_t -> int16_t
   * being implemented as the inverse of int16_t -> uint16_t,
   * which is implementation-defined (C99 6.3.1.3 (3))
   * CBMC (correctly) fails to prove this conversion is OK,
   * so we have to suppress that check here
   */
  return (int16_t)x;
}
#ifdef CBMC
#pragma CPROVER check pop
#endif

/**
 * Cast int32 value to uint16 as per C standard.
 *
 * @param x Input value.
 *
 * @return For int32_t x, the unique y in uint16_t so that x == y mod 2^16.
 */
static MLK_ALWAYS_INLINE uint16_t mlk_cast_int32_to_uint16(int32_t x)
{
  return (uint16_t)(x & (int32_t)UINT16_MAX);
}

/**
 * Cast int16 value to uint16 as per C standard.
 *
 * @param x Input value.
 *
 * @return For int16_t x, the unique y in uint16_t so that x == y mod 2^16.
 */
static MLK_ALWAYS_INLINE uint16_t mlk_cast_int16_to_uint16(int32_t x)
{
  return mlk_cast_int32_to_uint16(x);
}

/**
 * Return 0 if input is non-negative, and -1 otherwise.
 *
 * @reference{Embedded in the polynomial compression function in the
 * reference implementation @[REF]. Used as part of signed->unsigned
 * conversion for modular representatives to detect whether the input is
 * negative. This happens in `mlk_poly_reduce()` here, and as part of
 * polynomial compression functions in the reference implementation. See
 * `mlk_poly_reduce()`. We use value barriers to reduce the risk of
 * compiler-introduced branches.}
 *
 * @param x Value to be converted into a mask.
 *
 * @return Mask value (0 or 0xFFFF).
 */
static MLK_INLINE uint16_t mlk_ct_cmask_neg_i16(int16_t x)
__contract__(ensures(return_value == ((x < 0) ? 0xFFFF : 0)))
{
  int32_t tmp = mlk_value_barrier_i32((int32_t)x);
  /*
   * PORTABILITY: Right-shift on a signed integer is
   * implementation-defined for negative left argument.
   * Here, we assume it's sign-preserving "arithmetic" shift right.
   * See (C99 6.5.7 (5))
   */
  tmp >>= 16;
  return mlk_cast_int32_to_uint16(tmp);
}

/**
 * Return 0 if input is zero, and -1 otherwise.
 *
 * @reference{Embedded in `cmov_int16()` in the reference implementation
 * @[REF]. Uses a value barrier and shift instead of `b = -b` to convert
 * condition into mask.}
 *
 * @param x Value to be converted into a mask.
 *
 * @return Mask value (0 or 0xFFFF).
 */
static MLK_INLINE uint16_t mlk_ct_cmask_nonzero_u16(uint16_t x)
__contract__(ensures(return_value == ((x == 0) ? 0 : 0xFFFF)))
{
  int32_t tmp = mlk_value_barrier_i32(-((int32_t)x));
  /*
   * PORTABILITY: Right-shift on a signed integer is
   * implementation-defined for negative left argument.
   * Here, we assume it's sign-preserving "arithmetic" shift right.
   * See (C99 6.5.7 (5))
   */
  tmp >>= 16;
  return mlk_cast_int32_to_uint16(tmp);
}

/**
 * Return 0 if input is zero, and -1 otherwise.
 *
 * @reference{Embedded in `verify()` and `cmov()` in the reference
 * implementation @[REF]. We include a value barrier not present in the
 * reference implementation, to prevent the compiler from realizing that
 * this function returns a mask.}
 *
 * @param x Value to be converted into a mask.
 *
 * @return Mask value (0 or 0xFF).
 */
static MLK_INLINE uint8_t mlk_ct_cmask_nonzero_u8(uint8_t x)
__contract__(ensures(return_value == ((x == 0) ? 0 : 0xFF)))
{
  uint16_t mask = mlk_ct_cmask_nonzero_u16((uint16_t)x);
  return (uint8_t)(mask & 0xFF);
}

/**
 * Functionally equivalent to cond ? a : b, but implemented with guards
 * against compiler-introduced branches.
 *
 * @spec{With `a = MLKEM_Q_HALF` and `b=0`, this essentially implements
 * `Decompress_1` @[FIPS203, Eq (4.8)] in `mlk_poly_frommsg()`. With
 * `a = x + MLKEM_Q`, `b = x`, and `cond` indicating whether `x` is negative,
 * implements signed->unsigned conversion of modular representatives.
 * Questions of representation are not considered in the specification
 * @[FIPS203, Section 2.4.1, "The pseudocode is agnostic regarding how an
 * integer modulo 𝑚 is represented in actual implementations"].}
 *
 * @reference{Embedded in the polynomial compression function in the
 * reference implementation @[REF]. Used as part of signed->unsigned
 * conversion for modular representatives. This happens in `mlk_poly_reduce()`
 * here, and as part of polynomial compression functions in @[REF]. See
 * `mlk_poly_reduce()`. Barrier to reduce the risk of compiler-introduced
 * branches. For `a = MLKEM_Q_HALF` and `b=0`, also embedded in
 * `poly_frommsg()` from the reference implementation, which uses
 * `cmov_int16()` instead.}
 *
 * @param a    First alternative.
 * @param b    Second alternative.
 * @param cond Condition variable.
 *
 * @return @p a if @p cond != 0, else @p b.
 */
static MLK_INLINE int16_t mlk_ct_sel_int16(int16_t a, int16_t b, uint16_t cond)
__contract__(ensures(return_value == (cond ? a : b)))
{
  uint16_t au = mlk_cast_int16_to_uint16(a);
  uint16_t bu = mlk_cast_int16_to_uint16(b);
  uint16_t res = bu ^ (mlk_ct_cmask_nonzero_u16(cond) & (au ^ bu));
  return mlk_cast_uint16_to_int16(res);
}

/**
 * Functionally equivalent to cond ? a : b, but implemented with guards
 * against compiler-introduced branches.
 *
 * @reference{Embedded into `cmov()` in the reference implementation @[REF].
 * Uses a value barrier to get mask from condition value.}
 *
 * @param a    First alternative.
 * @param b    Second alternative.
 * @param cond Condition variable.
 *
 * @return @p a if @p cond != 0, else @p b.
 */
static MLK_INLINE uint8_t mlk_ct_sel_uint8(uint8_t a, uint8_t b, uint8_t cond)
__contract__(ensures(return_value == (cond ? a : b)))
{
  return b ^ (mlk_ct_cmask_nonzero_u8(cond) & (a ^ b));
}

/**
 * Compare two arrays for equality in constant time.
 *
 * @spec{Used to securely compute conditional move in @[FIPS203, Algorithm
 * 18 (ML-KEM.Decaps_Internal, L9-11].}
 *
 * @reference{`cmov()` in the reference implementation @[REF]. We return
 * `uint8_t`, not `int`. We use an additional XOR-accumulator in the
 * comparison loop which prevents early abort if the OR-accumulator is 0xFF.
 * We use a value barrier to convert the OR-accumulator into a mask; the
 * reference implementation uses a shift which the compiler can argue to
 * result in either 0 or 0xFF..FF.}
 *
 * @param[in] a   First byte array.
 * @param[in] b   Second byte array.
 * @param     len Length of the byte arrays, upper-bounded to UINT16_MAX to
 *                control proof complexity only.
 *
 * @retval 0    The byte arrays are equal.
 * @retval 0xFF The byte arrays are not equal.
 */
static MLK_INLINE uint8_t mlk_ct_memcmp(const uint8_t *a, const uint8_t *b,
                                        const size_t len)
__contract__(
  requires(len <= UINT16_MAX)
  requires(memory_no_alias(a, len))
  requires(memory_no_alias(b, len))
  ensures((return_value == 0) || (return_value == 0xFF))
  ensures((return_value == 0) == forall(i, 0, len, (a[i] == b[i]))))
{
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if defined(LC_KEM_CT_MEMCMP_NEON) && LC_KEM_CT_MEMCMP_NEON && defined(__aarch64__) && defined(__ARM_NEON)

 uint8x16_t rv=vdupq_n_u8(0),sv=vdupq_n_u8(0);size_t i=0;
 for(;len-i>=16;i+=16){uint8x16_t d=veorq_u8(vld1q_u8(a+i),vld1q_u8(b+i));rv=vorrq_u8(rv,d);sv=veorq_u8(sv,d);}
 uint64x2_t r2=vreinterpretq_u64_u8(rv),s2=vreinterpretq_u64_u8(sv);
 uint64_t r=vgetq_lane_u64(r2,0)|vgetq_lane_u64(r2,1),s=vgetq_lane_u64(s2,0)^vgetq_lane_u64(s2,1);
 r|=r>>32;s^=s>>32;r|=r>>16;s^=s>>16;r|=r>>8;s^=s>>8;
 uint8_t rr=(uint8_t)r,ss=(uint8_t)s;
 for(;i<len;i++){uint8_t d=a[i]^b[i];rr|=d;ss^=d;}
 return mlk_value_barrier_u8(mlk_ct_cmask_nonzero_u8(rr)^ss)^ss;

#else

  uint8_t r = 0, s = 0;
  unsigned i;

  for (i = 0; i < len; i++)
  __loop__(
    invariant(i <= len)
    invariant((r == 0) == (forall(k, 0, i, (a[k] == b[k]))))
    decreases(len - i))
  {
    r |= a[i] ^ b[i];
    /* s is useless, but prevents the loop from being aborted once r=0xff. */
    s ^= a[i] ^ b[i];
  }

  /*
   * - Convert r into a mask; this may not be necessary, but is an additional
   *   safeguard
   *   towards leaking information about a and b.
   * - XOR twice with s, separated by a value barrier, to prevent the compile
   *   from dropping the s computation in the loop.
   */
  return (mlk_value_barrier_u8(mlk_ct_cmask_nonzero_u8(r) ^ s) ^ s);

#endif
#else
#if defined(LC_KEM_CT_MEMCMP_AVX2) && LC_KEM_CT_MEMCMP_AVX2 && defined(__AVX2__)

 __m256i rv=_mm256_setzero_si256(),sv=_mm256_setzero_si256();size_t i=0;
 for(;len-i>=32;i+=32){
  __m256i d=_mm256_xor_si256(_mm256_loadu_si256((const __m256i*)(const void*)(a+i)),_mm256_loadu_si256((const __m256i*)(const void*)(b+i)));
  rv=_mm256_or_si256(rv,d);sv=_mm256_xor_si256(sv,d);
 }
 __m128i r=_mm_or_si128(_mm256_castsi256_si128(rv),_mm256_extracti128_si256(rv,1));
 __m128i s=_mm_xor_si128(_mm256_castsi256_si128(sv),_mm256_extracti128_si256(sv,1));
 r=_mm_or_si128(r,_mm_srli_si128(r,8));s=_mm_xor_si128(s,_mm_srli_si128(s,8));
 r=_mm_or_si128(r,_mm_srli_si128(r,4));s=_mm_xor_si128(s,_mm_srli_si128(s,4));
 r=_mm_or_si128(r,_mm_srli_si128(r,2));s=_mm_xor_si128(s,_mm_srli_si128(s,2));
 r=_mm_or_si128(r,_mm_srli_si128(r,1));s=_mm_xor_si128(s,_mm_srli_si128(s,1));
 uint8_t rr=(uint8_t)_mm_cvtsi128_si32(r),ss=(uint8_t)_mm_cvtsi128_si32(s);
 for(;i<len;i++){uint8_t d=a[i]^b[i];rr|=d;ss^=d;}
 return mlk_value_barrier_u8(mlk_ct_cmask_nonzero_u8(rr)^ss)^ss;

#else

  uint8_t r = 0, s = 0;
  unsigned i;

  for (i = 0; i < len; i++)
  __loop__(
    invariant(i <= len)
    invariant((r == 0) == (forall(k, 0, i, (a[k] == b[k]))))
    decreases(len - i))
  {
    r |= a[i] ^ b[i];
    /* s is useless, but prevents the loop from being aborted once r=0xff. */
    s ^= a[i] ^ b[i];
  }

  /*
   * - Convert r into a mask; this may not be necessary, but is an additional
   *   safeguard
   *   towards leaking information about a and b.
   * - XOR twice with s, separated by a value barrier, to prevent the compile
   *   from dropping the s computation in the loop.
   */
  return (mlk_value_barrier_u8(mlk_ct_cmask_nonzero_u8(r) ^ s) ^ s);

#endif
#endif
}

/**
 * Copy len bytes from x to r if b is zero; don't modify x if b is non-zero.
 * Assumes two's complement representation of negative integers. Runs in
 * constant time.
 *
 * @spec{Used to securely compute conditional move in @[FIPS203, Algorithm
 * 18 (ML-KEM.Decaps_Internal, L9-11].}
 *
 * @reference{`cmov()` in the reference implementation @[REF]. We move if
 * condition value is `0`, not `1`. We use `mlk_ct_sel_uint8` for
 * constant-time selection.}
 *
 * @param[out] r   Output byte array.
 * @param[in]  x   Input byte array.
 * @param      len Number of bytes to be copied.
 * @param      b   Condition value.
 */
static MLK_INLINE void mlk_ct_cmov_zero(uint8_t *r, const uint8_t *x,
                                        size_t len, uint8_t b)
__contract__(
  requires(len <= UINT32_MAX)
  requires(memory_no_alias(r, len))
  requires(memory_no_alias(x, len))
  assigns(memory_slice(r, len))
  ensures(forall(i, 0, len, (r[i] == (b == 0 ? x[i] : old(r)[i])))))
{
  size_t i;
  for (i = 0; i < len; i++)
  __loop__(
    invariant(i <= len)
    invariant(forall(k, 0, i, r[k] == (b == 0 ? x[k] : loop_entry(r)[k])))
    decreases(len - i))
  {
    r[i] = mlk_ct_sel_uint8(r[i], x[i], b);
  }
}

/**
 * Force-zeroize a buffer.
 *
 * @spec{Used to implement @[FIPS203, Section 3.3, Destruction of
 * intermediate values].}
 *
 * @reference{Not present in the reference implementation @[REF].}
 *
 * @param[out] ptr Buffer to be zeroed.
 * @param      len Number of bytes to be zeroed.
 */
#if !defined(MLK_CONFIG_CUSTOM_ZEROIZE)
#if defined(MLK_SYS_WINDOWS)
#include <windows.h>
#elif !defined(MLK_HAVE_INLINE_ASM)
#error No plausibly-secure implementation of mlk_zeroize available. Please provide your own using MLK_CONFIG_CUSTOM_ZEROIZE.
#endif

static MLK_INLINE void mlk_zeroize(void *ptr, size_t len)
__contract__(
  requires(len <= UINT32_MAX)
  requires(memory_no_alias(ptr, len))
  assigns(memory_slice(ptr, len))
  ensures(array_zeroized_u8((uint8_t *)ptr, len)))
{
#if defined(MLK_SYS_WINDOWS)
  SecureZeroMemory(ptr, len);
#else
  mlk_memset(ptr, 0, len);
  /* This follows OpenSSL and seems sufficient to prevent the compiler
   * from optimizing away the memset.
   *
   * If there was a reliable way to detect availability of memset_s(),
   * that would be preferred. */
  __asm__ volatile("" : : "r"(ptr) : "memory");
#endif /* !MLK_SYS_WINDOWS */
}
#endif /* !MLK_CONFIG_CUSTOM_ZEROIZE */

#endif /* !MLK_VERIFY_H */
