#include "lc_poly.h"
/*
 * Copyright (c) The mlkem-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* References
 * ==========
 *
 * - [NeonNTT]
 *   Neon NTT: Faster Dilithium, Kyber, and Saber on Cortex-A72 and Apple M1
 *   Becker, Hwang, Kannwischer, Yang, Yang
 *   https://eprint.iacr.org/2021/986
 *
 * - [REF]
 *   CRYSTALS-Kyber C reference implementation
 *   Bos, Ducas, Kiltz, Lepoint, Lyubashevsky, Schanck, Schwabe, Seiler, Stehlé
 *   https://github.com/pq-crystals/kyber/tree/main/ref
 */

#include "common.h"
#if !defined(MLK_CONFIG_MULTILEVEL_NO_SHARED)


#include "cbmc.h"
#include "debug.h"
#include "poly.h"
#include "sampling.h"
#include "symmetric.h"
#include "verify.h"
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#else
#if LC_KEM_COMPACT_ADDSUB && defined(LC_NATIVE) && defined(__AVX2__)
#define LC_POLY_LOOP_NOINLINE static inline __attribute__((always_inline))
#include "lc_kem_poly_addsub_loop16.h"
#undef LC_POLY_LOOP_NOINLINE
#endif
#endif

/**
 * Montgomery multiplication modulo MLKEM_Q.
 *
 * @reference{`fqmul()` in the reference implementation @[REF].}
 *
 * @param a First factor. Can be any int16_t.
 * @param b Second factor. Must be signed canonical
 *          (abs value < (MLKEM_Q+1)/2).
 *
 * @return 16-bit integer congruent to a*b*R^{-1} mod MLKEM_Q, and
 *         smaller than MLKEM_Q in absolute value.
 */
static MLK_INLINE int16_t mlk_fqmul(int16_t a, int16_t b)
__contract__(
  requires(b > -MLKEM_Q_HALF && b < MLKEM_Q_HALF)
  ensures(return_value > -MLKEM_Q && return_value < MLKEM_Q)
)
{
  int16_t res;
  mlk_assert_abs_bound(&b, 1, MLKEM_Q_HALF);

  res = mlk_montgomery_reduce((int32_t)a * (int32_t)b);
  /* Bounds:
   * |res| <= ceil(|a| * |b| / 2^16) + (MLKEM_Q + 1) / 2
   *       <= ceil(2^15 * ((MLKEM_Q - 1)/2) / 2^16) + (MLKEM_Q + 1) / 2
   *       <= ceil((MLKEM_Q - 1) / 4) + (MLKEM_Q + 1) / 2
   *        < MLKEM_Q
   */

  mlk_assert_abs_bound(&res, 1, MLKEM_Q);
  return res;
}

/**
 * Barrett reduction; given a 16-bit integer a, computes the centered
 * representative congruent to a mod MLKEM_Q in [-(MLKEM_Q-1)/2, (MLKEM_Q-1)/2].
 *
 * @reference{`barrett_reduce()` in the reference implementation @[REF].}
 *
 * @param a Input integer to be reduced.
 *
 * @return Integer in [-(MLKEM_Q-1)/2, (MLKEM_Q-1)/2] congruent to @p a modulo
 *         MLKEM_Q.
 */
static MLK_INLINE int16_t mlk_barrett_reduce(int16_t a)
__contract__(
  ensures(return_value > -MLKEM_Q_HALF && return_value < MLKEM_Q_HALF)
)
{
  /* Barrett reduction approximates
   * ```
   *     round(a/MLKEM_Q)
   *   = round(a*(2^N/MLKEM_Q))/2^N)
   *  ~= round(a*round(2^N/MLKEM_Q)/2^N)
   * ```
   * Here, we pick N=26.
   */
  const int32_t magic = 20159; /* check-magic: 20159 == round(2^26 / MLKEM_Q) */

  /*
   * PORTABILITY: Right-shift on a signed integer is
   * implementation-defined for negative left argument.
   * Here, we assume it's sign-preserving "arithmetic" shift right.
   * See (C99 6.5.7 (5))
   */
  const int32_t t = (magic * a + ((int32_t)1 << 25)) >> 26;

  /*
   * t is in -10 .. +10, so we need 32-bit math to
   * evaluate t * MLKEM_Q and the subsequent subtraction
   */
  int16_t res = (int16_t)(a - t * MLKEM_Q);

  mlk_assert_abs_bound(&res, 1, MLKEM_Q_HALF);
  return res;
}

#if !defined(MLK_CONFIG_NO_KEYPAIR_API)
/* Reference: `poly_tomont()` in the reference implementation @[REF]. */
MLK_STATIC_TESTABLE void mlk_poly_tomont_c(mlk_poly *r)
__contract__(
  requires(memory_no_alias(r, sizeof(mlk_poly)))
  assigns(memory_slice(r, sizeof(mlk_poly)))
  ensures(array_abs_bound(r->coeffs, 0, MLKEM_N, MLKEM_Q))
)
{
  unsigned i;
  const int16_t f = 1353; /* check-magic: 1353 == signed_mod(2^32, MLKEM_Q) */
  for (i = 0; i < MLKEM_N; i++)
  __loop__(
    invariant(i <= MLKEM_N)
    invariant(array_abs_bound(r->coeffs, 0, i, MLKEM_Q))
    decreases(MLKEM_N - i))
  {
    r->coeffs[i] = mlk_fqmul(r->coeffs[i], f);
  }

  mlk_assert_abs_bound(r, MLKEM_N, MLKEM_Q);
}

MLK_INTERNAL_API
void mlk_poly_tomont(mlk_poly *r)
{
#if defined(MLK_USE_NATIVE_POLY_TOMONT)
  int ret;
  ret = mlk_poly_tomont_native(r->coeffs);
  if (ret == MLK_NATIVE_FUNC_SUCCESS)
  {
    mlk_assert_abs_bound(r, MLKEM_N, MLKEM_Q);
    return;
  }
#endif /* MLK_USE_NATIVE_POLY_TOMONT */

  mlk_poly_tomont_c(r);
}
#endif /* !MLK_CONFIG_NO_KEYPAIR_API */

/**
 * Constant-time conversion of signed representatives modulo MLKEM_Q within
 * range [-(MLKEM_Q-1), MLKEM_Q-1] into unsigned representatives within
 * range [0, MLKEM_Q-1].
 *
 * @reference{Not present in the reference implementation @[REF]. Used here
 * to implement different semantics of `poly_reduce()`; see below. In the
 * reference implementation @[REF] this logic is part of all compression
 * functions (see `compress.c`).}
 *
 * @param c Signed coefficient to be converted.
 *
 * @return Unsigned representative in [0, MLKEM_Q).
 */
static MLK_INLINE int16_t mlk_scalar_signed_to_unsigned_q(int16_t c)
__contract__(
  requires(c > -MLKEM_Q && c < MLKEM_Q)
  ensures(return_value >= 0 && return_value < MLKEM_Q)
  ensures(return_value == (int32_t)c + (((int32_t)c < 0) * MLKEM_Q)))
{
  mlk_assert_abs_bound(&c, 1, MLKEM_Q);

  /* Add MLKEM_Q if c is negative, but in constant time.
   *
   * Note that c + MLKEM_Q does not overflow in int16_t,
   * so the cast to uint16_t is safe. */
  c = mlk_ct_sel_int16((int16_t)(c + MLKEM_Q), c, mlk_ct_cmask_neg_i16(c));

  mlk_assert_bound(&c, 1, 0, MLKEM_Q);
  return c;
}

/* Reference: `poly_reduce()` in the reference implementation @[REF]
 *            - We use _unsigned_ canonical outputs, while the reference
 *              implementation uses _signed_ canonical outputs.
 *              Accordingly, we need a conditional addition of MLKEM_Q
 *              here to go from signed to unsigned representatives.
 *              This conditional addition is then dropped from all
 *              polynomial compression functions instead (see `compress.c`). */
MLK_STATIC_TESTABLE void mlk_poly_reduce_c(mlk_poly *r)
__contract__(
  requires(memory_no_alias(r, sizeof(mlk_poly)))
  assigns(memory_slice(r, sizeof(mlk_poly)))
  ensures(array_bound(r->coeffs, 0, MLKEM_N, 0, MLKEM_Q))
)
{
  unsigned i;

  for (i = 0; i < MLKEM_N; i++)
  __loop__(
    invariant(i <= MLKEM_N)
    invariant(array_bound(r->coeffs, 0, i, 0, MLKEM_Q))
    decreases(MLKEM_N - i))
  {
    /* Barrett reduction, giving signed canonical representative */
    int16_t t = mlk_barrett_reduce(r->coeffs[i]);
    /* Conditional addition to get unsigned canonical representative */
    r->coeffs[i] = mlk_scalar_signed_to_unsigned_q(t);
  }

  mlk_assert_bound(r, MLKEM_N, 0, MLKEM_Q);
}

MLK_INTERNAL_API
void mlk_poly_reduce(mlk_poly *r)
{
#if defined(MLK_USE_NATIVE_POLY_REDUCE)
  int ret;
  ret = mlk_poly_reduce_native(r->coeffs);
  if (ret == MLK_NATIVE_FUNC_SUCCESS)
  {
    mlk_assert_bound(r, MLKEM_N, 0, MLKEM_Q);
    return;
  }
#endif /* MLK_USE_NATIVE_POLY_REDUCE */

  mlk_poly_reduce_c(r);
}

/* Reference: `poly_add()` in the reference implementation @[REF].
 *            - We use destructive version (output=first input) to avoid
 *              reasoning about aliasing in the CBMC specification */
MLK_INTERNAL_API
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#else
#if defined(__GNUC__) && !defined(__clang__)
__attribute__((optimize("O3")))
#endif
#endif
void mlk_poly_add(mlk_poly *r, const mlk_poly *b)
{
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
  unsigned i;
  for (i = 0; i < MLKEM_N; i++)
  __loop__(
    invariant(i <= MLKEM_N)
    invariant(forall(k0, i, MLKEM_N, r->coeffs[k0] == loop_entry(*r).coeffs[k0]))
    invariant(forall(k1, 0, i, r->coeffs[k1] == loop_entry(*r).coeffs[k1] + b->coeffs[k1]))
    decreases(MLKEM_N - i))
  {
    /* The preconditions imply that the addition stays within int16_t. */
    r->coeffs[i] = (int16_t)(r->coeffs[i] + b->coeffs[i]);
  }
#else
#if LC_KEM_COMPACT_ADDSUB && defined(LC_NATIVE) && defined(__AVX2__)
  lc_kem_poly_add_loop16(r->coeffs,b->coeffs);
#else
  unsigned i;
  for (i = 0; i < MLKEM_N; i++)
  __loop__(
    invariant(i <= MLKEM_N)
    invariant(forall(k0, i, MLKEM_N, r->coeffs[k0] == loop_entry(*r).coeffs[k0]))
    invariant(forall(k1, 0, i, r->coeffs[k1] == loop_entry(*r).coeffs[k1] + b->coeffs[k1]))
    decreases(MLKEM_N - i))
  {
    /* The preconditions imply that the addition stays within int16_t. */
    r->coeffs[i] = (int16_t)(r->coeffs[i] + b->coeffs[i]);
  }
#endif
#endif
}

#if !defined(MLK_CONFIG_NO_DECAPS_API)
/* Reference: `poly_sub()` in the reference implementation @[REF].
 *            - We use destructive version (output=first input) to avoid
 *              reasoning about aliasing in the CBMC specification */
MLK_INTERNAL_API
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#else
#if defined(__GNUC__) && !defined(__clang__)
__attribute__((optimize("O3")))
#endif
#endif
void mlk_poly_sub(mlk_poly *r, const mlk_poly *b)
{
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
  unsigned i;
  for (i = 0; i < MLKEM_N; i++)
  __loop__(
    invariant(i <= MLKEM_N)
    invariant(forall(k0, i, MLKEM_N, r->coeffs[k0] == loop_entry(*r).coeffs[k0]))
    invariant(forall(k1, 0, i, r->coeffs[k1] == loop_entry(*r).coeffs[k1] - b->coeffs[k1]))
    decreases(MLKEM_N - i))
  {
    /* The preconditions imply that the subtraction stays within int16_t. */
    r->coeffs[i] = (int16_t)(r->coeffs[i] - b->coeffs[i]);
  }
#else
#if LC_KEM_COMPACT_ADDSUB && defined(LC_NATIVE) && defined(__AVX2__)
  lc_kem_poly_sub_loop16(r->coeffs,b->coeffs);
#else
  unsigned i;
  for (i = 0; i < MLKEM_N; i++)
  __loop__(
    invariant(i <= MLKEM_N)
    invariant(forall(k0, i, MLKEM_N, r->coeffs[k0] == loop_entry(*r).coeffs[k0]))
    invariant(forall(k1, 0, i, r->coeffs[k1] == loop_entry(*r).coeffs[k1] - b->coeffs[k1]))
    decreases(MLKEM_N - i))
  {
    /* The preconditions imply that the subtraction stays within int16_t. */
    r->coeffs[i] = (int16_t)(r->coeffs[i] - b->coeffs[i]);
  }
#endif
#endif
}
#endif /* !MLK_CONFIG_NO_DECAPS_API */


/* Positive public lift B=z*2^16 mod q, T=B/q mod 2^32.
 * For every signed16 a, |a*B|<2^31 and u=signed32(a*T).
 * (a*B-u*q)/2^32 = (a>>31)-high32(u*q), in [-1664,1664].
 * The output is congruent to the existing Montgomery product a*z/2^16.
 * Related signed Plantard arithmetic is prior work; this range restriction
 * and integration must be assessed separately from mathematical novelty. */
static __attribute__((always_inline)) inline int32_t lc_positive_lift(int32_t a,uint32_t T) {
#if defined(__riscv) && (__riscv_xlen == 32)
  int32_t u,sg;
  __asm__("mul %0,%2,%3\n"
          "mulh %0,%0,%4\n"
          "srai %1,%2,31\n"
          "sub %0,%1,%0\n"
          : "=&r"(u),"=&r"(sg):"r"((int32_t)a),"r"(T),"r"(3329));
  return u;
#else
  uint32_t ub=(uint32_t)(int32_t)a*T;
  int64_t u=ub<2147483648u?(int64_t)ub:(int64_t)ub-4294967296LL;
  return ((a<0?-1:0)-(int32_t)((u*3329)>>32));
#endif
}
static __attribute__((always_inline)) inline int32_t lc_positive_neg(int32_t a,uint32_t T);
static const uint16_t lc_zetas_positive[128] = {
  1353,2379,1948,2473,2609,166,3311,2168,
  2087,3116,1467,3074,1030,3184,858,2077,
  1008,1765,691,2957,3265,2530,1330,2560,
  1887,203,1462,1087,1941,357,964,2256,
  1524,1757,371,2291,1647,1368,1456,700,
  594,1694,1180,2872,1389,1372,1616,1033,
  1689,748,3288,2349,1478,2119,1535,802,
  2716,2074,3064,1217,1677,3303,2289,2829,
  3027,495,3155,2093,1076,2822,3023,237,
  2189,3037,1636,2323,865,864,1270,2019,
  491,44,1760,334,2241,3062,2636,243,
  2118,122,1551,1834,3036,2740,3072,1733,
  2605,3237,2978,2328,1367,3282,1449,1913,
  111,2166,86,2218,310,21,840,916,
  2081,2729,2632,3314,1823,2733,2792,318,
  2895,1968,2153,715,1877,2887,2294,1487
};
#include "zetas.inc"
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if LC_KEM_COMPACT_NTT_NEON
#include "lc_ntt_compact_neon.h"
#endif
#else
#endif

/* Exact high-word cancellation: B=2^16 mod q, T=B/q mod 2^32.
 * Low32(t*B)==low32(signed32(t*T)*q), so their signed high-word
 * difference is the exact quotient and congruent to t/2^16 modulo q.
 * Internal dot bound: |t|<=4*2*4095*32768. 64-bit proof products fit;
 * the output fits int16. This is a Montgomery-domain implementation
 * arrangement using existing arithmetic identities, not a new modulus. */
static __attribute__((always_inline)) inline int32_t lc_dot_montgomery_wide(int32_t t) {
#if defined(__riscv) && (__riscv_xlen == 32)
  int32_t u,h;
  __asm__("mul %0,%2,%3\n"
          "mulh %1,%2,%4\n"
          "mulh %0,%0,%5\n"
          "sub %0,%1,%0\n"
          : "=&r"(u),"=&r"(h):"r"(t),"r"(4076929005u),"r"(2285),"r"(3329));
  return u;
#else
  uint32_t v=(uint32_t)t*4076929005u;
  int64_t u=v<2147483648u?(int64_t)v:(int64_t)v-4294967296LL;
  return (int32_t)(((int64_t)t*2285)>>32)-(int32_t)((u*3329)>>32);
#endif
}

/* Public column count is separated from the shared coefficient kernel.
 * Internal contract: columns in {2,3,4}; a coefficients in [0,4095];
 * b and cache coefficients are int16. The actual generated cache is the
 * exact negative of the upstream centered cache and is subtracted below.
 * All arrays have columns elements and cannot alias the output.
 * Every partial sum has magnitude <=4*2*4095*32768. */
__attribute__((noinline,noclone,aligned(4))) void lc_kem_cached_dot_shared(
    mlk_poly *r,const mlk_poly *a,const mlk_poly *b,
    const mlk_poly_mulcache *cache,unsigned columns) {
  for(unsigned i=0;i<128;++i) {
    int32_t t0=0,t1=0;
    {
      int32_t a0=a[0].coeffs[2*i],a1=a[0].coeffs[2*i+1];
      int32_t b0=b[0].coeffs[2*i],b1=b[0].coeffs[2*i+1];
      t0-=a1*cache[0].coeffs[i];t0+=a0*b0;
      t1+=a0*b1;t1+=a1*b0;
    }
    {
      int32_t a0=a[1].coeffs[2*i],a1=a[1].coeffs[2*i+1];
      int32_t b0=b[1].coeffs[2*i],b1=b[1].coeffs[2*i+1];
      t0-=a1*cache[1].coeffs[i];t0+=a0*b0;
      t1+=a0*b1;t1+=a1*b0;
    }
    if(columns>2) {
      int32_t a0=a[2].coeffs[2*i],a1=a[2].coeffs[2*i+1];
      int32_t b0=b[2].coeffs[2*i],b1=b[2].coeffs[2*i+1];
      t0-=a1*cache[2].coeffs[i];t0+=a0*b0;
      t1+=a0*b1;t1+=a1*b0;
    }
    if(columns>3) {
      int32_t a0=a[3].coeffs[2*i],a1=a[3].coeffs[2*i+1];
      int32_t b0=b[3].coeffs[2*i],b1=b[3].coeffs[2*i+1];
      t0-=a1*cache[3].coeffs[i];t0+=a0*b0;
      t1+=a0*b1;t1+=a1*b0;
    }
    r->coeffs[2*i]=lc_dot_montgomery_wide(t0);
    r->coeffs[2*i+1]=lc_dot_montgomery_wide(t1);
  }
}

/* Reference: Does not exist in the reference implementation @[REF].
 *            - The reference implementation does not use a
 *              multiplication cache ('mulcache'). This idea originates
 *              from @[NeonNTT] and is used at the C level here. */
MLK_STATIC_TESTABLE __attribute__((aligned(4))) void mlk_poly_mulcache_compute_c(mlk_poly_mulcache *x,
                                                     const mlk_poly *a)
__contract__(
  requires(memory_no_alias(x, sizeof(mlk_poly_mulcache)))
  requires(memory_no_alias(a, sizeof(mlk_poly)))
  assigns(memory_slice(x, sizeof(mlk_poly_mulcache)))
)
{
  unsigned i;
  for (i = 0; i < MLKEM_N / 4; i++)
  __loop__(
    invariant(i <= MLKEM_N / 4)
    invariant(array_abs_bound(x->coeffs, 0, 2 * i, MLKEM_Q))
    decreases(MLKEM_N / 4 - i))
  {
    x->coeffs[2 * i + 0] = lc_positive_neg((int32_t)a->coeffs[4 * i + 1]+33290, ((uint32_t)lc_zetas_positive[64 + i]*1806234369u));
    /* The values in zeta table are <= MLKEM_Q in absolute value,
     * so the negation in int16_t is safe. */
    x->coeffs[2 * i + 1] =
        (int16_t)-lc_positive_neg((int32_t)a->coeffs[4 * i + 3]+33290, ((uint32_t)lc_zetas_positive[64 + i]*1806234369u));
  }

  /*
   * This bound is true for the C implementation, but not needed
   * in the higher level bounds reasoning. It is thus omitted
   * from the spec to not unnecessarily constrain native
   * implementations, but checked here nonetheless.
   */
  mlk_assert_abs_bound(x, MLKEM_N / 2, MLKEM_Q);
}

MLK_INTERNAL_API
void mlk_poly_mulcache_compute(mlk_poly_mulcache *x, const mlk_poly *a)
{
#if defined(MLK_USE_NATIVE_POLY_MULCACHE_COMPUTE)
  int ret;
  ret = mlk_poly_mulcache_compute_native(x->coeffs, a->coeffs);
  if (ret == MLK_NATIVE_FUNC_SUCCESS)
  {
    return;
  }
#endif /* MLK_USE_NATIVE_POLY_MULCACHE_COMPUTE */

  mlk_poly_mulcache_compute_c(x, a);
}

/*
 * Computes a block CT butterflies with a fixed twiddle factor,
 * using Montgomery multiplication.
 * Parameters:
 * - r: Pointer to base of polynomial (_not_ the base of butterfly block)
 * - root: Twiddle factor to use for the butterfly. This must be in
 *         Montgomery form and signed canonical.
 * - start: Offset to the beginning of the butterfly block
 * - len: Index difference between coefficients subject to a butterfly
 * - bound: Ghost variable describing coefficient bound: Prior to `start`,
 *          coefficients must be bound by `bound + MLKEM_Q`. Post `start`,
 *          they must be bound by `bound`.
 * When this function returns, output coefficients in the index range
 * [start, start+2*len) have bound bumped to `bound + MLKEM_Q`.
 * Example:
 * - start=8, len=4
 *   This would compute the following four butterflies
 *          8     --    12
 *             9    --     13
 *                10   --     14
 *                   11   --     15
 * - start=4, len=2
 *   This would compute the following two butterflies
 *          4 -- 6
 *             5 -- 7
 */

/* Reference: Embedded in `ntt()` in the reference implementation @[REF]. */
static void mlk_ntt_butterfly_block(int16_t r[MLKEM_N], int16_t zeta,
                                    unsigned start, unsigned len,
                                    unsigned bound)
__contract__(
  requires(start < MLKEM_N)
  requires(1 <= len && len <= MLKEM_N / 2 && start + 2 * len <= MLKEM_N)
  requires(0 <= bound && bound < INT16_MAX - MLKEM_Q)
  requires(-MLKEM_Q_HALF < zeta && zeta < MLKEM_Q_HALF)
  requires(memory_no_alias(r, sizeof(int16_t) * MLKEM_N))
  requires(array_abs_bound(r, 0, start, bound + MLKEM_Q))
  requires(array_abs_bound(r, start, MLKEM_N, bound))
  assigns(memory_slice(r, sizeof(int16_t) * MLKEM_N))
  ensures(array_abs_bound(r, 0, start + 2*len, bound + MLKEM_Q))
  ensures(array_abs_bound(r, start + 2 * len, MLKEM_N, bound)))
{
  /* `bound` is a ghost variable only needed in the CBMC specification */
  unsigned j;
  ((void)bound);
  for (j = start; j < start + len; j++)
  __loop__(
    invariant(start <= j && j <= start + len)
    /*
     * Coefficients are updated in strided pairs, so the bounds for the
     * intermediate states alternate twice between the old and new bound
     */
    invariant(array_abs_bound(r, 0,           j,           bound + MLKEM_Q))
    invariant(array_abs_bound(r, j,           start + len, bound))
    invariant(array_abs_bound(r, start + len, j + len,     bound + MLKEM_Q))
    invariant(array_abs_bound(r, j + len,     MLKEM_N,     bound))
    decreases(start + len - j))
  {
    int16_t t;
    t = mlk_fqmul(r[j + len], zeta);
    /* The precondition implies that the arithmetic does not overflow. */
    r[j + len] = (int16_t)(r[j] - t);
    r[j] = (int16_t)(r[j] + t);
  }
}


/* For P=a*z and t=signed16(P*qinv), P and t*q have identical low
 * 16 bits. Hence (P-t*q)/2^16=floor(P/2^16)-floor(t*q/2^16).
 * Each floor is a signed 32-bit high product after lifting its operand.
 * Twiddle factors are public and invariant within a butterfly block. */
static __attribute__((always_inline)) inline int16_t lc_mont16_high(
    int16_t a,int32_t zhi,int32_t zq) {
#if defined(__riscv) && (__riscv_xlen == 32)
  int32_t hi,lo;
  __asm__("mulh %0,%2,%3\n"
          "mul %1,%2,%4\n"
          "slli %1,%1,16\n"
          "mulh %1,%1,%5\n"
          "sub %0,%0,%1\n"
          : "=&r"(hi),"=&r"(lo)
          : "r"((int32_t)a),"r"(zhi),"r"(zq),"r"(3329));
  return (int16_t)hi;
#else
  (void)zq;return mlk_fqmul(a,(int16_t)(zhi/65536));
#endif
}

/* Negative centered fixed-factor product for a>=0. The CT schedule below
 * proves nonnegativity, so neither per-product sign correction nor explicit
 * negation is necessary. The butterfly consumes the negated result directly. */
static __attribute__((always_inline)) inline int32_t lc_positive_neg(int32_t a,uint32_t T) {
#if defined(__riscv) && (__riscv_xlen == 32)
  int32_t u;
  __asm__("mul %0,%1,%2\n"
          "mulh %0,%0,%3\n"
          : "=&r"(u):"r"(a),"r"(T),"r"(3329));
  return u;
#else
  uint32_t ub=(uint32_t)a*T;
  int64_t u=ub<2147483648u?(int64_t)ub:(int64_t)ub-4294967296LL;
  return (int32_t)((u*3329)>>32);
#endif
}
/*
 * Compute one layer of forward NTT
 * Parameters:
 * - r: Pointer to base of polynomial
 * - layer: Variable indicating which layer is being applied.
 */

/* Reference: Embedded in `ntt()` in the reference implementation @[REF]. */
static void mlk_ntt_layer(int16_t r[MLKEM_N], unsigned layer)
__contract__(
  requires(memory_no_alias(r, sizeof(int16_t) * MLKEM_N))
  requires(1 <= layer && layer <= 7)
  requires(array_abs_bound(r, 0, MLKEM_N, layer * MLKEM_Q))
  assigns(memory_slice(r, sizeof(int16_t) * MLKEM_N))
  ensures(array_abs_bound(r, 0, MLKEM_N, (layer + 1) * MLKEM_Q)))
{
  unsigned start, k, len;
  /* Twiddle factors for layer n are at indices 2^(n-1)..2^n-1. */
  k = 1u << (layer - 1);
  len = (unsigned)MLKEM_N >> layer;
  for (start = 0; start < MLKEM_N; start += 2 * len)
  __loop__(
    invariant(start < MLKEM_N + 2 * len)
    invariant(k <= MLKEM_N / 2 && 2 * len * k == start + MLKEM_N)
    invariant(array_abs_bound(r, 0, start, layer * MLKEM_Q + MLKEM_Q))
    invariant(array_abs_bound(r, start, MLKEM_N, layer * MLKEM_Q))
    decreases(MLKEM_N - start))
  {
    int16_t zeta = mlk_zetas[k++];
    mlk_ntt_butterfly_block(r, zeta, start, len, layer * MLKEM_Q);
  }
}

/*
 * Compute full forward NTT
 * NOTE: This particular implementation satisfies a much tighter
 * bound on the output coefficients (5*q) than the contractual one (8*q),
 * but this is not needed in the calling code. Should we change the
 * base multiplication strategy to require smaller NTT output bounds,
 * the proof may need strengthening.
 */

/* Reference: `ntt()` in the reference implementation @[REF].
 * - Iterate over `layer` instead of `len` in the outer loop
 *   to simplify computation of zeta index. */
MLK_STATIC_TESTABLE __attribute__((aligned(4))) void mlk_poly_ntt_c(mlk_poly *p)
__contract__(
  requires(memory_no_alias(p, sizeof(mlk_poly)))
  requires(array_abs_bound(p->coeffs, 0, MLKEM_N, MLKEM_Q))
  assigns(memory_slice(p, sizeof(mlk_poly)))
  ensures(array_abs_bound(p->coeffs, 0, MLKEM_N, MLK_NTT_BOUND))
)
{
  int16_t *r=p->coeffs;

  /* Shape parameters and offset depend only on the public transform layer. */
  for(unsigned len=64;len>=4;len>>=2) {
    unsigned k=64/len;const int32_t offset=len==64?13316:0;
    for(unsigned start=0;start<256;start+=4*len,++k) {
      const uint32_t t0=(uint32_t)lc_zetas_positive[k]*1806234369u;
      const uint32_t t1=(uint32_t)lc_zetas_positive[2*k]*1806234369u;
      const uint32_t t2=(uint32_t)lc_zetas_positive[2*k+1]*1806234369u;
      for(unsigned j=start;j<start+len;++j) {
        int32_t a=r[j]+offset,b=r[j+len]+offset;
        int32_t c=r[j+2*len]+offset,d=r[j+3*len]+offset;
#if defined(__riscv) && (__riscv_xlen == 32)
        int32_t h,g;
        __asm__("mul %4,%2,%6\n"
                "mulh %4,%4,%9\n"
                "mul %5,%3,%6\n"
                "mulh %5,%5,%9\n"
                "sub %2,%0,%4\n"
                "add %0,%0,%4\n"
                "sub %3,%1,%5\n"
                "add %1,%1,%5\n"
                "mul %4,%3,%7\n"
                "mulh %4,%4,%9\n"
                "mul %5,%1,%8\n"
                "mulh %5,%5,%9\n"
                "sub %3,%2,%4\n"
                "add %2,%2,%4\n"
                "sub %1,%0,%5\n"
                "add %0,%0,%5\n"
                : "+&r"(a),"+&r"(b),"+&r"(c),"+&r"(d),"=&r"(h),"=&r"(g)
                : "r"(t0),"r"(t1),"r"(t2),"r"(3329));
        r[j]=(int16_t)d;r[j+len]=(int16_t)c;
        r[j+2*len]=(int16_t)b;r[j+3*len]=(int16_t)a;
#else
        int32_t h=lc_positive_neg(c,t0),g=lc_positive_neg(d,t0);
        int32_t x=a-h,z=a+h;
        int32_t v=lc_positive_neg(b-g,t1),w=lc_positive_neg(b+g,t2);
        r[j]=(int16_t)(x-v);r[j+len]=(int16_t)(x+v);
        r[j+2*len]=(int16_t)(z-w);r[j+3*len]=(int16_t)(z+w);
#endif
      }
    }
  }
  for(unsigned start=0;start<256;start+=4) {
    const uint32_t T=(uint32_t)lc_zetas_positive[64+start/4]*1806234369u;
    for(unsigned j=start;j<start+2;j++) {
      int32_t x=r[j]-13316,h=lc_positive_neg(r[j+2],T);
      r[j]=(int16_t)(x-h);r[j+2]=(int16_t)(x+h);
    }
  }
}




MLK_INTERNAL_API
void mlk_poly_ntt(mlk_poly *r)
{
#if defined(MLK_USE_NATIVE_NTT)
  int ret;
  mlk_assert_abs_bound(r, MLKEM_N, MLKEM_Q);
  ret = mlk_ntt_native(r->coeffs);
  if (ret == MLK_NATIVE_FUNC_SUCCESS)
  {
    mlk_assert_abs_bound(r, MLKEM_N, MLK_NTT_BOUND);
    return;
  }
#endif /* MLK_USE_NATIVE_NTT */

#if defined(LC_CANONICAL)
  uint32_t x[256]; unsigned i;
  for(i=0;i<256;i++){int32_t v=r->coeffs[i];v%=3329;v+=3329 & -(v<0);x[i]=(uint32_t)v;}
  lc_poly_ntt(3329,x);for(i=0;i<256;i++)r->coeffs[i]=(int16_t)x[i];mlk_zeroize(x,sizeof x);
#else
  mlk_poly_ntt_c(r);
#endif
}


#if !defined(MLK_CONFIG_NO_ENCAPS_API) || !defined(MLK_CONFIG_NO_DECAPS_API)
/* Compute one layer of inverse NTT */

/* Reference: Embedded into `invntt()` in the reference implementation @[REF] */
static void mlk_invntt_layer(int16_t *r, unsigned layer)
__contract__(
  requires(memory_no_alias(r, sizeof(int16_t) * MLKEM_N))
  requires(1 <= layer && layer <= 7)
  requires(array_abs_bound(r, 0, MLKEM_N, MLKEM_Q))
  assigns(memory_slice(r, sizeof(int16_t) * MLKEM_N))
  ensures(array_abs_bound(r, 0, MLKEM_N, MLKEM_Q)))
{
  unsigned start, k, len;
  len = (unsigned)MLKEM_N >> layer;
  k = (1u << layer) - 1;
  for (start = 0; start < MLKEM_N; start += 2 * len)
  __loop__(
    invariant(array_abs_bound(r, 0, MLKEM_N, MLKEM_Q))
    invariant(start <= MLKEM_N && k <= 127)
    /* Normalised form of k == MLKEM_N / len - 1 - start / (2 * len) */
    invariant(2 * len * k + start == 2 * MLKEM_N - 2 * len)
    decreases(MLKEM_N - start))
  {
    unsigned j;
    int16_t zeta = mlk_zetas[k--];
    for (j = start; j < start + len; j++)
    __loop__(
      invariant(start <= j && j <= start + len)
      invariant(start <= MLKEM_N && k <= 127)
      invariant(array_abs_bound(r, 0, MLKEM_N, MLKEM_Q))
      decreases(start + len - j))
    {
      int16_t t = r[j];
      /* The preconditions imply that the arithmetic does not overflow. */
      r[j] = mlk_barrett_reduce((int16_t)(t + r[j + len]));
      r[j + len] = (int16_t)(r[j + len] - t);
      r[j + len] = mlk_fqmul(r[j + len], zeta);
    }
  }
}

/* Reference: `invntt()` in the reference implementation @[REF]
 *            - The selected paired GS implementation incorporates the
 *              normalization into its final layer. This allows us to drop a call to `poly_reduce()`
 *              from the base multiplication. */
MLK_STATIC_TESTABLE __attribute__((aligned(4))) void mlk_poly_invntt_tomont_c(mlk_poly *p)
__contract__(
  requires(memory_no_alias(p, sizeof(mlk_poly)))
  assigns(memory_slice(p, sizeof(mlk_poly)))
  ensures(array_abs_bound(p->coeffs, 0, MLKEM_N, MLK_INVNTT_BOUND))
)
{
  int16_t *r=p->coeffs;
  /* Two GS layers use four loaded coefficients. Each pair changes the common sign orientation. Only the unmultiplied
   * four-input sum is recentered; the second sum consists of two already
   * centered products. Public40q lifts make multiplied inputs nonnegative and at most266232.
   * Stored outputs are bounded by3328, independently of prior stages. */
  for(unsigned len=2;len<=32;len*=4) {
    unsigned k0=256/len-1,k1=128/len-1;
    for(unsigned start=0;start<256;start+=4*len,k0-=2,--k1) {
      uint32_t t0=(uint32_t)lc_zetas_positive[k0]*1806234369u;
      uint32_t t1=(uint32_t)lc_zetas_positive[k0-1]*1806234369u;
      uint32_t t2=(uint32_t)lc_zetas_positive[k1]*1806234369u;
      for(unsigned j=start;j<start+len;++j) {
        int32_t a=r[j],b=r[j+len],c=r[j+2*len],d=r[j+3*len];
#if defined(__riscv) && (__riscv_xlen == 32)
        int32_t g,h;
        __asm__("sub %4,%1,%0\n"
                "add %0,%0,%1\n"
                "sub %5,%3,%2\n"
                "add %2,%2,%3\n"
                "add %4,%4,%11\n"
                "mul %4,%4,%6\n"
                "mulh %4,%4,%9\n"
                "add %5,%5,%11\n"
                "mul %5,%5,%7\n"
                "mulh %5,%5,%9\n"
                "sub %1,%2,%0\n"
                "add %0,%2,%0\n"
                "sub %3,%4,%5\n"
                "add %2,%5,%4\n"
                "add %0,%0,%11\n"
                "mul %0,%0,%10\n"
                "mulh %0,%0,%9\n"
                "add %1,%1,%11\n"
                "mul %1,%1,%8\n"
                "mulh %1,%1,%9\n"
                "add %3,%3,%11\n"
                "mul %3,%3,%8\n"
                "mulh %3,%3,%9\n"
                : "+&r"(a),"+&r"(b),"+&r"(c),"+&r"(d),"=&r"(g),"=&r"(h)
                : "r"(t0),"r"(t1),"r"(t2),"r"(3329),"r"(4293677129u),"r"(133160));
        r[j]=(int16_t)a;r[j+len]=(int16_t)c;
        r[j+2*len]=(int16_t)b;r[j+3*len]=(int16_t)d;
#else
        int32_t u=a+b,g=lc_positive_neg(b-a+133160,t0);
        int32_t w=c+d,h=lc_positive_neg(d-c+133160,t1);
        r[j]=(int16_t)lc_positive_neg(u+w+133160,4293677129u);
        r[j+len]=(int16_t)(g+h);
        r[j+2*len]=(int16_t)lc_positive_neg(w-u+133160,t2);
        r[j+3*len]=(int16_t)lc_positive_neg(g-h+133160,t2);
#endif
      }
    }
  }
  for(unsigned j=0;j<128;++j) {
    int32_t x=r[j],y=r[j+128];
    r[j]=(int16_t)lc_positive_neg(x+y+133160,3634401584u);
    r[j+128]=(int16_t)lc_positive_neg(y-x+133160,343184531u);
  }
}


MLK_INTERNAL_API
void mlk_poly_invntt_tomont(mlk_poly *r)
{
#if defined(MLK_USE_NATIVE_INTT)
  int ret;
  ret = mlk_intt_native(r->coeffs);
  if (ret == MLK_NATIVE_FUNC_SUCCESS)
  {
    mlk_assert_abs_bound(r, MLKEM_N, MLK_INVNTT_BOUND);
    return;
  }
#endif /* MLK_USE_NATIVE_INTT */

#if defined(LC_CANONICAL)
  uint32_t x[256]; unsigned i;
  for(i=0;i<256;i++){int32_t v=r->coeffs[i];v%=3329;v+=3329 & -(v<0);x[i]=(uint32_t)v;}
  lc_poly_intt(3329,x);for(i=0;i<256;i++)r->coeffs[i]=(int16_t)((x[i]*2285u)%3329u);mlk_zeroize(x,sizeof x);
#else
  mlk_poly_invntt_tomont_c(r);
#endif
}
#endif /* !MLK_CONFIG_NO_ENCAPS_API || !MLK_CONFIG_NO_DECAPS_API */
#else  /* !MLK_CONFIG_MULTILEVEL_NO_SHARED */

MLK_EMPTY_CU(mlk_poly)

#endif /* MLK_CONFIG_MULTILEVEL_NO_SHARED */
