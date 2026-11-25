/*
 * Copyright (c) The mldsa-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* References
 * ==========
 *
 * - [FIPS204]
 *   FIPS 204 Module-Lattice-Based Digital Signature Standard
 *   National Institute of Standards and Technology
 *   https://csrc.nist.gov/pubs/fips/204/final
 */

/*
 * Eager and lazy variants of polynomial vector types.
 *
 * In eager mode, full vectors are precomputed and stored in memory.
 * In lazy mode, data is stored in packed form and expanded on demand,
 * trading computation for reduced memory usage.
 *
 * MLD_CONFIG_REDUCE_RAM selects which variant is used.
 */

#ifndef MLD_POLYVEC_LAZY_H
#define MLD_POLYVEC_LAZY_H

#if !defined(MLD_CONFIG_NO_KEYPAIR_API) || !defined(MLD_CONFIG_NO_SIGN_API) || \
    !defined(MLD_CONFIG_NO_VERIFY_API)

#include "poly.h"
#include "poly_kl.h"
#include "polyvec.h"
#if LC_DSA_STREAM_CACHE24
#include "fips202/fips202.h"
#endif

#ifndef LC_DSA_S1_CACHE_POLYS
#define LC_DSA_S1_CACHE_POLYS 0
#endif
#if LC_DSA_S1_CACHE_DISABLE87 && MLD_CONFIG_PARAMETER_SET == 87
#undef LC_DSA_S1_CACHE_POLYS
#define LC_DSA_S1_CACHE_POLYS 0
#endif
#if LC_DSA_S1_CACHE_POLYS < 0 || LC_DSA_S1_CACHE_POLYS > 3
#error "s1 prefix must contain 0..3 polynomials"
#endif

/* Parameter set namespacing */
#define mld_sk_s1hat_eager MLD_ADD_PARAM_SET(mld_sk_s1hat_eager)
#define mld_sk_s1hat_lazy MLD_ADD_PARAM_SET(mld_sk_s1hat_lazy)
#define mld_sk_s1hat MLD_ADD_PARAM_SET(mld_sk_s1hat)
#define mld_unpack_sk_s1hat_eager MLD_ADD_PARAM_SET(mld_unpack_sk_s1hat_eager)
#define mld_unpack_sk_s1hat_lazy MLD_ADD_PARAM_SET(mld_unpack_sk_s1hat_lazy)
#define mld_sk_s1hat_get_poly_eager \
  MLD_ADD_PARAM_SET(mld_sk_s1hat_get_poly_eager)
#define mld_sk_s1hat_get_poly_lazy MLD_ADD_PARAM_SET(mld_sk_s1hat_get_poly_lazy)
#define mld_sk_s2hat_eager MLD_ADD_PARAM_SET(mld_sk_s2hat_eager)
#define mld_sk_s2hat_lazy MLD_ADD_PARAM_SET(mld_sk_s2hat_lazy)
#define mld_sk_s2hat MLD_ADD_PARAM_SET(mld_sk_s2hat)
#define mld_unpack_sk_s2hat_eager MLD_ADD_PARAM_SET(mld_unpack_sk_s2hat_eager)
#define mld_unpack_sk_s2hat_lazy MLD_ADD_PARAM_SET(mld_unpack_sk_s2hat_lazy)
#define mld_sk_s2hat_get_poly_eager \
  MLD_ADD_PARAM_SET(mld_sk_s2hat_get_poly_eager)
#define mld_sk_s2hat_get_poly_lazy MLD_ADD_PARAM_SET(mld_sk_s2hat_get_poly_lazy)
#define mld_sk_t0hat_eager MLD_ADD_PARAM_SET(mld_sk_t0hat_eager)
#define mld_sk_t0hat_lazy MLD_ADD_PARAM_SET(mld_sk_t0hat_lazy)
#define mld_sk_t0hat MLD_ADD_PARAM_SET(mld_sk_t0hat)
#define mld_unpack_sk_t0hat_eager MLD_ADD_PARAM_SET(mld_unpack_sk_t0hat_eager)
#define mld_unpack_sk_t0hat_lazy MLD_ADD_PARAM_SET(mld_unpack_sk_t0hat_lazy)
#define mld_sk_t0hat_get_poly_eager \
  MLD_ADD_PARAM_SET(mld_sk_t0hat_get_poly_eager)
#define mld_sk_t0hat_get_poly_lazy MLD_ADD_PARAM_SET(mld_sk_t0hat_get_poly_lazy)
#define mld_polymat MLD_ADD_PARAM_SET(mld_polymat)
#define mld_polymat_eager MLD_ADD_PARAM_SET(mld_polymat_eager)
#define mld_polymat_lazy MLD_ADD_PARAM_SET(mld_polymat_lazy)
#define mld_poly_permute_bitrev_to_custom_optional \
  MLD_ADD_PARAM_SET(mld_poly_permute_bitrev_to_custom_optional)
#define mld_polyvec_matrix_expand_eager \
  MLD_NAMESPACE_KL(polyvec_matrix_expand_eager)
#define mld_polyvec_matrix_expand_lazy \
  MLD_NAMESPACE_KL(polyvec_matrix_expand_lazy)
#define mld_polyvec_matrix_pointwise_montgomery \
  MLD_NAMESPACE_KL(polyvec_matrix_pointwise_montgomery)
#define mld_polyvec_matrix_pointwise_montgomery_row_eager \
  MLD_NAMESPACE_KL(polyvec_matrix_pointwise_montgomery_row_eager)
#define mld_polyvec_matrix_pointwise_montgomery_row_lazy \
  MLD_NAMESPACE_KL(polyvec_matrix_pointwise_montgomery_row_lazy)
#define mld_polyvec_matrix_pointwise_montgomery_yvec_eager \
  MLD_NAMESPACE_KL(polyvec_matrix_pointwise_montgomery_yvec_eager)
#define mld_polyvec_matrix_pointwise_montgomery_yvec_lazy \
  MLD_NAMESPACE_KL(polyvec_matrix_pointwise_montgomery_yvec_lazy)
#define mld_yvec_eager MLD_ADD_PARAM_SET(mld_yvec_eager)
#define mld_yvec_lazy MLD_ADD_PARAM_SET(mld_yvec_lazy)
#define mld_yvec MLD_ADD_PARAM_SET(mld_yvec)
#define mld_yvec_scratch MLD_ADD_PARAM_SET(mld_yvec_scratch)
#define mld_yvec_scratch_eager MLD_ADD_PARAM_SET(mld_yvec_scratch_eager)
#define mld_yvec_scratch_lazy MLD_ADD_PARAM_SET(mld_yvec_scratch_lazy)
#define mld_yvec_init_eager MLD_ADD_PARAM_SET(mld_yvec_init_eager)
#define mld_yvec_init_lazy MLD_ADD_PARAM_SET(mld_yvec_init_lazy)
#define mld_yvec_get_poly_eager MLD_ADD_PARAM_SET(mld_yvec_get_poly_eager)
#define mld_yvec_get_poly_lazy MLD_ADD_PARAM_SET(mld_yvec_get_poly_lazy)
/* End of parameter set namespacing */

/** Eager s1hat: precomputed s1 vector in NTT domain. */
typedef struct
{
  mld_polyvecl vec; /**< s1 vector in NTT domain. */
} mld_sk_s1hat_eager;

/** Eager s2hat: precomputed s2 vector in NTT domain. */
typedef struct
{
  mld_polyveck vec; /**< s2 vector in NTT domain. */
} mld_sk_s2hat_eager;

/** Eager t0hat: precomputed t0 vector in NTT domain. */
typedef struct
{
  mld_polyveck vec; /**< t0 vector in NTT domain. */
} mld_sk_t0hat_eager;

/** Lazy s1hat: borrow packed s1, unpack and convert to NTT domain on demand. */
typedef struct
{
  const uint8_t *packed; /**< Pointer to packed s1 in the secret key. */
#if LC_DSA_S1_CACHE_POLYS > 0
  const mld_poly *prefix; /**< Call-owned, cleared NTT prefix; NULL before fill. */
#endif
} mld_sk_s1hat_lazy;

/** Lazy s2hat: borrow packed s2, unpack and convert to NTT domain on demand. */
typedef struct
{
  const uint8_t *packed; /**< Pointer to packed s2 in the secret key. */
} mld_sk_s2hat_lazy;

/** Lazy t0hat: borrow packed t0, unpack and convert to NTT domain on demand. */
typedef struct
{
  const uint8_t *packed; /**< Pointer to packed t0 in the secret key. */
} mld_sk_t0hat_lazy;

/** Eager yvec: precomputed and stored full signing masking vector y. */
typedef struct
{
  mld_polyvecl vec; /**< Masking vector y. */
} mld_yvec_eager;

/** Scratch for the eager matrix-vector product: holds NTT(y) in full. */
typedef mld_polyvecl mld_yvec_scratch_eager;

#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#ifndef LC_DSA_MIXED_HEAD65
#define LC_DSA_MIXED_HEAD65 0
#endif
#if LC_DSA_MIXED_HEAD65 && MLDSA_K == 6
#include "lc_gamma_neon.h"
#endif
#ifndef LC_DSA_RAW_Y4_CACHE
#define LC_DSA_RAW_Y4_CACHE 0
#endif
#ifndef LC_DSA_RAW_Y_PREFIX65
#define LC_DSA_RAW_Y_PREFIX65 0
#endif
#ifndef LC_DSA_RAW_Y_PREFIX87
#define LC_DSA_RAW_Y_PREFIX87 0
#endif
#define LC_DSA_Y_CACHE_COUNT (MLDSA_K==4 ? 4*LC_DSA_RAW_Y4_CACHE : \
                              MLDSA_K==6 ? LC_DSA_RAW_Y_PREFIX65 : LC_DSA_RAW_Y_PREFIX87)
#define LC_DSA_Y_CACHE_BYTES (LC_DSA_Y_CACHE_COUNT*MLDSA_POLYZ_PACKEDBYTES)
#else
#endif
#ifndef LC_DSA_NATURAL_SIG_Y_ACTIVE
#define LC_DSA_NATURAL_SIG_Y_ACTIVE 0
#endif
#if LC_DSA_NATURAL_SIG_Y_ACTIVE
#include "ct.h"
#if !defined(__AVX2__) || !LC_DSA_BORROW_SIG_Y_ACTIVE || LC_DSA_RAW_Y_ALL_CACHE || LC_DSA_STREAM_CACHE24 || (defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE)
#error "Natural masking retention requires the compact AVX2 schedule and borrowed signature output"
#endif
#endif
#ifndef LC_DSA_RAW_Y_ALL_CACHE
#define LC_DSA_RAW_Y_ALL_CACHE 0
#endif
#if LC_DSA_RAW_Y_ALL_CACHE && !(defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE)
#undef LC_DSA_FIRST_GAMMA_CACHE
#define LC_DSA_FIRST_GAMMA_CACHE 0
#endif
/** Lazy yvec: store seed and base counter kappa, regenerate y[i] on demand. */
typedef struct
{
  const uint8_t *rhoprime; /**< Pointer to seed used to derive y. */
  uint16_t kappa;          /**< Base counter; component i uses kappa + i. */
#if LC_DSA_NATURAL_SIG_Y_ACTIVE || LC_DSA_PORTABLE_SIG_Y
  uint16_t natural_ready; /* Public phase: zero in A*y, one after all rows exist. */
#endif
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if LC_DSA_MIXED_HEAD65 && MLDSA_K == 6
  const uint8_t *head_gamma; /**< Immutable first raw mask, owned by the attempt. */
#endif
#if LC_DSA_Y_CACHE_COUNT > 0
  const uint8_t *encoded;  /**< Public-count prefix of standard gamma encodings. */
#endif
#else
#if LC_DSA_NATURAL_SIG_Y_ACTIVE || LC_DSA_PORTABLE_SIG_Y
  uint8_t *encoded;
#elif (LC_DSA_RAW_Y4_CACHE && MLDSA_K == 4) || LC_DSA_RAW_Y_ALL_CACHE
  const uint8_t *encoded;
#endif
#if LC_DSA_FIRST_GAMMA_CACHE && MLD_CONFIG_PARAMETER_SET != 44
#if LC_DSA_NATURAL_SIG_Y_ACTIVE || LC_DSA_PORTABLE_SIG_Y
  uint8_t *first_gamma; /* Same owner as the first signature z row. */
#else
  uint8_t first_gamma[MLDSA_POLYZ_PACKEDBYTES];
#endif
#endif
#endif
} mld_yvec_lazy;
#if LC_DSA_NATURAL_SIG_Y_ACTIVE || LC_DSA_PORTABLE_SIG_Y
_Static_assert(((sizeof(mld_yvec_lazy)+31)&~(size_t)31)==32,
               "Natural mask descriptor remains in one arena slot");
#endif
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if LC_DSA_Y_CACHE_COUNT > 0
#include "fips202/fips202.h"
#include "lc_gamma_neon.h"
_Static_assert(LC_DSA_Y_CACHE_COUNT<=MLDSA_L,"Cached prefix remains within the standard vector");
_Static_assert(((sizeof(mld_yvec_lazy)+31)&~(size_t)31)==32,
               "The additional cache pointer stays in the same32-byte allocation");
#endif
#else
#endif

/** Scratch for the lazy matrix-vector product: holds one element of y. */
typedef mld_poly mld_yvec_scratch_lazy;

#if !defined(MLD_CONFIG_NO_KEYPAIR_API) || !defined(MLD_CONFIG_NO_SIGN_API)
/* s1vec */

#if !defined(MLD_CONFIG_REDUCE_RAM) || defined(MLD_UNIT_TEST)
static MLD_INLINE void mld_unpack_sk_s1hat_eager(
    mld_sk_s1hat_eager *s1,
    const uint8_t packed_s1[MLDSA_L * MLDSA_POLYETA_PACKEDBYTES])
__contract__(
  requires(memory_no_alias(s1, sizeof(mld_sk_s1hat_eager)))
  requires(memory_no_alias(packed_s1, MLDSA_L * MLDSA_POLYETA_PACKEDBYTES))
  assigns(memory_slice(s1, sizeof(mld_sk_s1hat_eager)))
  ensures(forall(k1, 0, MLDSA_L,
    array_abs_bound(s1->vec.vec[k1].coeffs, 0, MLDSA_N, MLD_NTT_BOUND)))
)
{
  mld_polyvecl_unpack_eta(&s1->vec, packed_s1);
  mld_polyvecl_ntt(&s1->vec);
}

#if !defined(MLD_CONFIG_NO_SIGN_API)
static MLD_INLINE void mld_sk_s1hat_get_poly_eager(mld_poly *buf,
                                                   const mld_sk_s1hat_eager *s1,
                                                   unsigned int i)
__contract__(
  requires(memory_no_alias(buf, sizeof(mld_poly)))
  requires(memory_no_alias(s1, sizeof(mld_sk_s1hat_eager)))
  requires(i < MLDSA_L)
  requires(array_abs_bound(s1->vec.vec[i].coeffs, 0, MLDSA_N, MLD_NTT_BOUND))
  assigns(memory_slice(buf, sizeof(mld_poly)))
  ensures(array_abs_bound(buf->coeffs, 0, MLDSA_N, MLD_NTT_BOUND))
) { *buf = s1->vec.vec[i]; }
#endif /* !MLD_CONFIG_NO_SIGN_API */
#endif /* !MLD_CONFIG_REDUCE_RAM || MLD_UNIT_TEST */
#if defined(MLD_CONFIG_REDUCE_RAM) || defined(MLD_UNIT_TEST)
static MLD_INLINE void mld_unpack_sk_s1hat_lazy(
    mld_sk_s1hat_lazy *s1,
    const uint8_t packed_s1[MLDSA_L * MLDSA_POLYETA_PACKEDBYTES])
__contract__(
  requires(memory_no_alias(s1, sizeof(mld_sk_s1hat_lazy)))
  assigns(memory_slice(s1, sizeof(mld_sk_s1hat_lazy)))
  ensures(s1->packed == old(packed_s1))
) {
  s1->packed = packed_s1;
#if LC_DSA_S1_CACHE_POLYS > 0
  s1->prefix = NULL;
#endif
}

#if !defined(MLD_CONFIG_NO_SIGN_API)
static MLD_INLINE void mld_sk_s1hat_get_poly_lazy(mld_poly *buf,
                                                  const mld_sk_s1hat_lazy *s1,
                                                  unsigned int i)
__contract__(
  requires(memory_no_alias(buf, sizeof(mld_poly)))
  requires(memory_no_alias(s1, sizeof(mld_sk_s1hat_lazy)))
  requires(i < MLDSA_L)
  requires(memory_no_alias(s1->packed, MLDSA_L * MLDSA_POLYETA_PACKEDBYTES))
  assigns(memory_slice(buf, sizeof(mld_poly)))
  ensures(array_abs_bound(buf->coeffs, 0, MLDSA_N, MLD_NTT_BOUND))
)
{
#if LC_DSA_S1_CACHE_POLYS > 0
  if (s1->prefix != NULL && i < LC_DSA_S1_CACHE_POLYS) {
    *buf=s1->prefix[i];
    return;
  }
#endif
  mld_polyeta_unpack(buf, s1->packed + i * MLDSA_POLYETA_PACKEDBYTES);
  mld_poly_ntt(buf);
}
#endif /* !MLD_CONFIG_NO_SIGN_API */
#endif /* MLD_CONFIG_REDUCE_RAM || MLD_UNIT_TEST */

/* s2vec */

#if (!defined(MLD_CONFIG_NO_SIGN_API) || defined(MLD_UNIT_TEST)) && \
    (!defined(MLD_CONFIG_REDUCE_RAM) || defined(MLD_UNIT_TEST))
static MLD_INLINE void mld_unpack_sk_s2hat_eager(
    mld_sk_s2hat_eager *s2,
    const uint8_t packed_s2[MLDSA_K * MLDSA_POLYETA_PACKEDBYTES])
__contract__(
  requires(memory_no_alias(s2, sizeof(mld_sk_s2hat_eager)))
  requires(memory_no_alias(packed_s2, MLDSA_K * MLDSA_POLYETA_PACKEDBYTES))
  assigns(memory_slice(s2, sizeof(mld_sk_s2hat_eager)))
  ensures(forall(k1, 0, MLDSA_K,
    array_abs_bound(s2->vec.vec[k1].coeffs, 0, MLDSA_N, MLD_NTT_BOUND)))
)
{
  mld_polyveck_unpack_eta(&s2->vec, packed_s2);
  mld_polyveck_ntt(&s2->vec);
}

#if !defined(MLD_CONFIG_NO_SIGN_API)
static MLD_INLINE void mld_sk_s2hat_get_poly_eager(mld_poly *buf,
                                                   const mld_sk_s2hat_eager *s2,
                                                   unsigned int i)
__contract__(
  requires(memory_no_alias(buf, sizeof(mld_poly)))
  requires(memory_no_alias(s2, sizeof(mld_sk_s2hat_eager)))
  requires(i < MLDSA_K)
  requires(array_abs_bound(s2->vec.vec[i].coeffs, 0, MLDSA_N, MLD_NTT_BOUND))
  assigns(memory_slice(buf, sizeof(mld_poly)))
  ensures(array_abs_bound(buf->coeffs, 0, MLDSA_N, MLD_NTT_BOUND))
) { *buf = s2->vec.vec[i]; }
#endif /* !MLD_CONFIG_NO_SIGN_API */
#endif /* (!MLD_CONFIG_NO_SIGN_API || MLD_UNIT_TEST) && \
          (!MLD_CONFIG_REDUCE_RAM || MLD_UNIT_TEST) */
#if defined(MLD_CONFIG_REDUCE_RAM) || defined(MLD_UNIT_TEST)
static MLD_INLINE void mld_unpack_sk_s2hat_lazy(
    mld_sk_s2hat_lazy *s2,
    const uint8_t packed_s2[MLDSA_K * MLDSA_POLYETA_PACKEDBYTES])
__contract__(
  requires(memory_no_alias(s2, sizeof(mld_sk_s2hat_lazy)))
  assigns(memory_slice(s2, sizeof(mld_sk_s2hat_lazy)))
  ensures(s2->packed == old(packed_s2))
) { s2->packed = packed_s2; }

#if !defined(MLD_CONFIG_NO_SIGN_API)
static MLD_INLINE void mld_sk_s2hat_get_poly_lazy(mld_poly *buf,
                                                  const mld_sk_s2hat_lazy *s2,
                                                  unsigned int i)
__contract__(
  requires(memory_no_alias(buf, sizeof(mld_poly)))
  requires(memory_no_alias(s2, sizeof(mld_sk_s2hat_lazy)))
  requires(i < MLDSA_K)
  requires(memory_no_alias(s2->packed, MLDSA_K * MLDSA_POLYETA_PACKEDBYTES))
  assigns(memory_slice(buf, sizeof(mld_poly)))
  ensures(array_abs_bound(buf->coeffs, 0, MLDSA_N, MLD_NTT_BOUND))
)
{
  mld_polyeta_unpack(buf, s2->packed + i * MLDSA_POLYETA_PACKEDBYTES);
  mld_poly_ntt(buf);
}
#endif /* !MLD_CONFIG_NO_SIGN_API */
#endif /* MLD_CONFIG_REDUCE_RAM || MLD_UNIT_TEST */

/* t0vec */

#if (!defined(MLD_CONFIG_NO_SIGN_API) || defined(MLD_UNIT_TEST)) && \
    (!defined(MLD_CONFIG_REDUCE_RAM) || defined(MLD_UNIT_TEST))
static MLD_INLINE void mld_unpack_sk_t0hat_eager(
    mld_sk_t0hat_eager *t0,
    const uint8_t packed_t0[MLDSA_K * MLDSA_POLYT0_PACKEDBYTES])
__contract__(
  requires(memory_no_alias(t0, sizeof(mld_sk_t0hat_eager)))
  requires(memory_no_alias(packed_t0, MLDSA_K * MLDSA_POLYT0_PACKEDBYTES))
  assigns(memory_slice(t0, sizeof(mld_sk_t0hat_eager)))
  ensures(forall(k1, 0, MLDSA_K,
    array_abs_bound(t0->vec.vec[k1].coeffs, 0, MLDSA_N, MLD_NTT_BOUND)))
)
{
  unsigned int i;
  for (i = 0; i < MLDSA_K; i++)
  __loop__(
    assigns(i, memory_slice(t0, sizeof(mld_sk_t0hat_eager)))
    invariant(i <= MLDSA_K)
    invariant(forall(k0, 0, i,
      array_bound(t0->vec.vec[k0].coeffs, 0, MLDSA_N,
                  -(1 << (MLDSA_D - 1)) + 1, (1 << (MLDSA_D - 1)) + 1)))
    decreases(MLDSA_K - i)
  )
  {
    mld_polyt0_unpack(&t0->vec.vec[i],
                      packed_t0 + i * MLDSA_POLYT0_PACKEDBYTES);
  }
  mld_polyveck_ntt(&t0->vec);
}

#if !defined(MLD_CONFIG_NO_SIGN_API)
static MLD_INLINE void mld_sk_t0hat_get_poly_eager(mld_poly *buf,
                                                   const mld_sk_t0hat_eager *t0,
                                                   unsigned int i)
__contract__(
  requires(memory_no_alias(buf, sizeof(mld_poly)))
  requires(memory_no_alias(t0, sizeof(mld_sk_t0hat_eager)))
  requires(i < MLDSA_K)
  requires(array_abs_bound(t0->vec.vec[i].coeffs, 0, MLDSA_N, MLD_NTT_BOUND))
  assigns(memory_slice(buf, sizeof(mld_poly)))
  ensures(array_abs_bound(buf->coeffs, 0, MLDSA_N, MLD_NTT_BOUND))
) { *buf = t0->vec.vec[i]; }
#endif /* !MLD_CONFIG_NO_SIGN_API */
#endif /* (!MLD_CONFIG_NO_SIGN_API || MLD_UNIT_TEST) && \
          (!MLD_CONFIG_REDUCE_RAM || MLD_UNIT_TEST) */
#if defined(MLD_CONFIG_REDUCE_RAM) || defined(MLD_UNIT_TEST)
static MLD_INLINE void mld_unpack_sk_t0hat_lazy(
    mld_sk_t0hat_lazy *t0,
    const uint8_t packed_t0[MLDSA_K * MLDSA_POLYT0_PACKEDBYTES])
__contract__(
  requires(memory_no_alias(t0, sizeof(mld_sk_t0hat_lazy)))
  assigns(memory_slice(t0, sizeof(mld_sk_t0hat_lazy)))
  ensures(t0->packed == old(packed_t0))
) { t0->packed = packed_t0; }

#if !defined(MLD_CONFIG_NO_SIGN_API)
static MLD_INLINE void mld_sk_t0hat_get_poly_lazy(mld_poly *buf,
                                                  const mld_sk_t0hat_lazy *t0,
                                                  unsigned int i)
__contract__(
  requires(memory_no_alias(buf, sizeof(mld_poly)))
  requires(memory_no_alias(t0, sizeof(mld_sk_t0hat_lazy)))
  requires(i < MLDSA_K)
  requires(memory_no_alias(t0->packed, MLDSA_K * MLDSA_POLYT0_PACKEDBYTES))
  assigns(memory_slice(buf, sizeof(mld_poly)))
  ensures(array_abs_bound(buf->coeffs, 0, MLDSA_N, MLD_NTT_BOUND))
)
{
  mld_polyt0_unpack(buf, t0->packed + i * MLDSA_POLYT0_PACKEDBYTES);
  mld_poly_ntt(buf);
}
#endif /* !MLD_CONFIG_NO_SIGN_API */
#endif /* MLD_CONFIG_REDUCE_RAM || MLD_UNIT_TEST */
#endif /* !MLD_CONFIG_NO_KEYPAIR_API || !MLD_CONFIG_NO_SIGN_API */

/* yvec */

#if !defined(MLD_CONFIG_NO_SIGN_API) && \
    (!defined(MLD_CONFIG_REDUCE_RAM) || defined(MLD_UNIT_TEST))
static MLD_INLINE void mld_yvec_init_eager(
    mld_yvec_eager *y, const uint8_t rhoprime[MLDSA_CRHBYTES], uint16_t kappa)
__contract__(
  requires(memory_no_alias(y, sizeof(mld_yvec_eager)))
  requires(memory_no_alias(rhoprime, MLDSA_CRHBYTES))
  requires(kappa <= MLD_MAX_KAPPA)
  assigns(memory_slice(y, sizeof(mld_yvec_eager)))
  ensures(forall(k1, 0, MLDSA_L,
    array_bound(y->vec.vec[k1].coeffs, 0, MLDSA_N, -(MLDSA_GAMMA1 - 1), MLDSA_GAMMA1 + 1)))
)
{
  mld_polyvecl_uniform_gamma1(&y->vec, rhoprime, kappa);
}

static MLD_INLINE void mld_yvec_get_poly_eager(mld_poly *buf,
                                               const mld_yvec_eager *y,
                                               unsigned int i)
__contract__(
  requires(memory_no_alias(buf, sizeof(mld_poly)))
  requires(memory_no_alias(y, sizeof(mld_yvec_eager)))
  requires(i < MLDSA_L)
  requires(array_bound(y->vec.vec[i].coeffs, 0, MLDSA_N, -(MLDSA_GAMMA1 - 1), MLDSA_GAMMA1 + 1))
  assigns(memory_slice(buf, sizeof(mld_poly)))
  ensures(array_bound(buf->coeffs, 0, MLDSA_N, -(MLDSA_GAMMA1 - 1), MLDSA_GAMMA1 + 1))
) { *buf = y->vec.vec[i]; }
#endif /* !MLD_CONFIG_NO_SIGN_API && (!MLD_CONFIG_REDUCE_RAM || MLD_UNIT_TEST) \
        */
#if !defined(MLD_CONFIG_NO_SIGN_API) && \
    (defined(MLD_CONFIG_REDUCE_RAM) || defined(MLD_UNIT_TEST))
static MLD_INLINE void mld_yvec_init_lazy(
    mld_yvec_lazy *y, const uint8_t rhoprime[MLDSA_CRHBYTES], uint16_t kappa
#if LC_DSA_NATURAL_SIG_Y_ACTIVE || LC_DSA_PORTABLE_SIG_Y
 ,uint8_t *lc_encoded
#endif
#if LC_DSA_XOF_OWNER
 ,mld_poly *xof_scratch
#endif
)
#if LC_DSA_XOF_OWNER
__contract__(
  requires(memory_no_alias(y, sizeof(mld_yvec_lazy)))
#if LC_DSA_NATURAL_SIG_Y_ACTIVE || LC_DSA_PORTABLE_SIG_Y
  requires(memory_no_alias(lc_encoded, MLDSA_L * MLDSA_POLYZ_PACKEDBYTES))
#endif
  requires(memory_no_alias(rhoprime, MLDSA_CRHBYTES))
  requires(memory_no_alias(xof_scratch, sizeof(mld_poly)))
  assigns(memory_slice(y, sizeof(mld_yvec_lazy)),
          memory_slice(xof_scratch, sizeof(mld_poly))
#if LC_DSA_NATURAL_SIG_Y_ACTIVE || LC_DSA_PORTABLE_SIG_Y
          , memory_slice(lc_encoded, MLDSA_POLYZ_PACKEDBYTES)
#endif
          )
  ensures(y->rhoprime == old(rhoprime))
  ensures(y->kappa == old(kappa))
)
#else
__contract__(
  requires(memory_no_alias(y, sizeof(mld_yvec_lazy)))
#if LC_DSA_NATURAL_SIG_Y_ACTIVE || LC_DSA_PORTABLE_SIG_Y
  requires(memory_no_alias(lc_encoded, MLDSA_L * MLDSA_POLYZ_PACKEDBYTES))
#endif
  assigns(memory_slice(y, sizeof(mld_yvec_lazy))
#if LC_DSA_NATURAL_SIG_Y_ACTIVE || LC_DSA_PORTABLE_SIG_Y
          , memory_slice(lc_encoded, MLDSA_POLYZ_PACKEDBYTES)
#endif
          )
  ensures(y->rhoprime == old(rhoprime))
  ensures(y->kappa == old(kappa))
)
#endif
{
  y->rhoprime = rhoprime;
  y->kappa = kappa;
#if LC_DSA_NATURAL_SIG_Y_ACTIVE || LC_DSA_PORTABLE_SIG_Y
  y->natural_ready=0;
  y->encoded=lc_encoded;
#if LC_DSA_FIRST_GAMMA_CACHE && MLD_CONFIG_PARAMETER_SET != 44
  y->first_gamma=lc_encoded;
#endif
#endif
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if LC_DSA_MIXED_HEAD65 && MLDSA_K == 6
  y->head_gamma = NULL;
#endif
#if LC_DSA_Y_CACHE_COUNT > 0
  y->encoded = NULL;
#endif
#else
#if !LC_DSA_NATURAL_SIG_Y_ACTIVE && ((LC_DSA_RAW_Y4_CACHE && MLDSA_K == 4) || LC_DSA_RAW_Y_ALL_CACHE)
  y->encoded = NULL;
#endif
#if LC_DSA_FIRST_GAMMA_CACHE && MLD_CONFIG_PARAMETER_SET != 44
  mld_poly_uniform_gamma1_bytes(y->first_gamma,rhoprime,kappa
#if LC_DSA_XOF_OWNER
    ,xof_scratch
#endif
  );
#endif
#endif
}

static MLD_INLINE void mld_yvec_get_poly_lazy(mld_poly *buf,
                                              const mld_yvec_lazy *y,
                                              unsigned int i)
__contract__(
  requires(memory_no_alias(buf, sizeof(mld_poly)))
  requires(memory_no_alias(y, sizeof(mld_yvec_lazy)))
  requires(i < MLDSA_L)
#if LC_DSA_NATURAL_SIG_Y_ACTIVE || LC_DSA_PORTABLE_SIG_Y
  requires(memory_no_alias(y->encoded, MLDSA_L * MLDSA_POLYZ_PACKEDBYTES))
#endif
  requires(memory_no_alias(y->rhoprime, MLDSA_CRHBYTES))
  requires(y->kappa <= MLD_MAX_KAPPA)
  assigns(memory_slice(buf, sizeof(mld_poly))
#if LC_DSA_NATURAL_SIG_Y_ACTIVE || LC_DSA_PORTABLE_SIG_Y
          , memory_slice(y->encoded + i * MLDSA_POLYZ_PACKEDBYTES, MLDSA_POLYZ_PACKEDBYTES)
#endif
          )
  ensures(array_bound(buf->coeffs, 0, MLDSA_N, -(MLDSA_GAMMA1 - 1), MLDSA_GAMMA1 + 1))
)
{
  /* Safety: y->kappa <= MLD_MAX_KAPPA and i < MLDSA_L, so y->kappa + i
   * fits in uint16_t. See MLD_MAX_KAPPA comment in params.h. */
#if LC_DSA_PORTABLE_SIG_Y
  /* The unchanged matrix pass visits every column exactly once before the
   * public phase transition. Response construction reads each retained row
   * before its final signature encoding overwrites precisely that row. */
  if (!y->natural_ready)
    mld_poly_uniform_gamma1_bytes(y->encoded+i*MLDSA_POLYZ_PACKEDBYTES,
                                y->rhoprime,(uint16_t)(y->kappa+i));
  mld_polyz_unpack(buf,y->encoded+i*MLDSA_POLYZ_PACKEDBYTES);
  return;
#endif
#if LC_DSA_NATURAL_SIG_Y_ACTIVE && MLDSA_K > 4
  if(y->natural_ready || i==0) {
    mld_polyz_unpack(buf,y->encoded+i*MLDSA_POLYZ_PACKEDBYTES);
    return;
  }
  /* First construction of this public column: retain the exact existing
   * nonce stream in its final caller-owned slice before decoding to NTT.
   * The complete A*y pass precedes the public ready transition. */
#if LC_DSA_XOF_OWNER
  /* The caller's current polynomial is dead until decoding. Reuse its
   * established SHAKE state/seed regions directly, avoiding a nested sampler
   * frame while preserving the same output and prompt temporary erasure. */
  uint8_t *extseed=buf->xof.extseed;
  mld_shake256ctx *state=&buf->xof.state;
  const uint16_t nonce=(uint16_t)(y->kappa+i);
  mld_memcpy(extseed,y->rhoprime,MLDSA_CRHBYTES);
  extseed[MLDSA_CRHBYTES]=(uint8_t)nonce;
  extseed[MLDSA_CRHBYTES+1]=(uint8_t)(nonce>>8);
  mld_shake256_init(state);
  mld_shake256_absorb(state,extseed,MLDSA_CRHBYTES+2);
  mld_shake256_finalize(state);
  mld_shake256_squeeze(y->encoded+i*MLDSA_POLYZ_PACKEDBYTES,
                       MLDSA_POLYZ_PACKEDBYTES,state);
  mld_shake256_release(state);
  mld_zeroize(extseed,MLDSA_CRHBYTES+2);
#else
#error "Natural masking retention requires the existing polynomial XOF owner"
#endif
  mld_polyz_unpack(buf,y->encoded+i*MLDSA_POLYZ_PACKEDBYTES);
  return;
#endif
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if LC_DSA_Y_CACHE_COUNT > 0
  if (y->encoded != NULL && i<LC_DSA_Y_CACHE_COUNT) {
    mld_memcpy(buf->coeffs,y->encoded+i*MLDSA_POLYZ_PACKEDBYTES,MLDSA_POLYZ_PACKEDBYTES);
    lc_expand_gamma_neon(buf->coeffs,MLDSA_GAMMA1==(1<<17)?18:20,MLDSA_GAMMA1);
    return;
  }
#endif
#if LC_DSA_MIXED_HEAD65 && MLDSA_K == 6
  if(i==0 && y->head_gamma!=NULL) {
    mld_memcpy(buf->coeffs,y->head_gamma,640);
    lc_expand_gamma_neon(buf->coeffs,20,MLDSA_GAMMA1);
    return;
  }
#endif
#else
#if LC_DSA_FIRST_GAMMA_CACHE && MLD_CONFIG_PARAMETER_SET != 44
  if(i==0) {mld_polyz_unpack(buf,y->first_gamma);return;}
#endif
#if (LC_DSA_RAW_Y4_CACHE && MLDSA_K == 4) || LC_DSA_RAW_Y_ALL_CACHE
  if(y->encoded != NULL) {mld_polyz_unpack(buf,y->encoded+MLDSA_POLYZ_PACKEDBYTES*i);return;}
#endif
#endif
  mld_poly_uniform_gamma1(buf, y->rhoprime, (uint16_t)(y->kappa + i));
}
#endif /* !MLD_CONFIG_NO_SIGN_API && (MLD_CONFIG_REDUCE_RAM || MLD_UNIT_TEST) \
        */

/* polymat */

#if !defined(MLD_CONFIG_REDUCE_RAM) || defined(MLD_UNIT_TEST)
/** Eager polymat: precomputed and stored full MLDSA_K x MLDSA_L matrix. */
typedef struct
{
  mld_polyvecl vec[MLDSA_K]; /**< Rows of the matrix. */
} mld_polymat_eager;
#endif /* !MLD_CONFIG_REDUCE_RAM || MLD_UNIT_TEST */

/* A bounded, public prefix in column-major order can be retained within one
 * operation. Its values are already in the backend's NTT permutation and in
 * [0,Q); 24 unsigned bits preserve every coefficient exactly. */
#ifndef LC_DSA_A_CACHE_POLYS
#define LC_DSA_A_CACHE_POLYS 0
#endif
#ifndef LC_DSA_A_CACHE_87_CAP
#define LC_DSA_A_CACHE_87_CAP 56
#endif
#if MLD_CONFIG_PARAMETER_SET == 87 && LC_DSA_A_CACHE_POLYS > LC_DSA_A_CACHE_87_CAP
#undef LC_DSA_A_CACHE_POLYS
#define LC_DSA_A_CACHE_POLYS LC_DSA_A_CACHE_87_CAP
#endif
#ifndef LC_DSA_A_CACHE_BITS
#define LC_DSA_A_CACHE_BITS 24
#endif
#ifndef LC_DSA_A_CACHE_SIGN_ONLY
#define LC_DSA_A_CACHE_SIGN_ONLY 0
#endif
#ifndef LC_DSA_A_CACHE_BATCH4
#define LC_DSA_A_CACHE_BATCH4 0
#endif
#ifndef LC_DSA_A_STREAM_BATCH4
#define LC_DSA_A_STREAM_BATCH4 0
#endif
#ifndef LC_DSA_ROW_BATCH4
#define LC_DSA_ROW_BATCH4 0
#endif
#if LC_DSA_A_STREAM_BATCH4 && LC_DSA_A_CACHE_POLYS == 0
#error "four-way streaming requires a nonempty public matrix cache"
#endif
#if LC_DSA_A_CACHE_POLYS < 0 || LC_DSA_A_CACHE_POLYS > 56
#error "matrix cache prefix must contain 0..56 polynomials"
#endif
/* Public parameter sets44/65 fit a32 matrix beneath the87 common peak. */
#ifndef LC_DSA_PARAMETER_A32
#define LC_DSA_PARAMETER_A32 0
#endif
#if LC_DSA_PARAMETER_A32 && MLD_CONFIG_PARAMETER_SET != 87
#undef LC_DSA_A_CACHE_BITS
#define LC_DSA_A_CACHE_BITS 32
#undef LC_DSA_A_PLANES24
#define LC_DSA_A_PLANES24 0
#endif
#if LC_DSA_A_CACHE_BITS != 24 && LC_DSA_A_CACHE_BITS != 32
#error "matrix cache representation must be 24 or 32 bits"
#endif
#define LC_DSA_A_CACHE_COUNT ((LC_DSA_A_CACHE_POLYS < MLDSA_K*MLDSA_L) ? LC_DSA_A_CACHE_POLYS : MLDSA_K*MLDSA_L)

/** Lazy polymat: seed, one working element and optional public prefix. */
typedef struct
{
#if LC_DSA_MATRIX_STREAM_DIRECT4
  union {
    mld_poly cur;
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#else
#if LC_DSA_SPARSE_PRODUCT
    struct { uint8_t big[768]; uint8_t index[61]; } sign_challenge;
#endif
#endif
    struct { uint64_t state[100]; uint8_t rate[168]; } stream4;
#if LC_DSA_STREAM_CACHE24
    mld_shake256ctx stream_cache_gamma;
#endif
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if LC_DSA_Y_CACHE_COUNT > 0
    mld_shake256ctx gamma_state;
#endif
#else
#if LC_DSA_HYBRID_NEXTY
    uint64_t stream5[125];
#endif
#endif
  };
#else
  mld_poly cur; /**< On-demand sampled matrix element A[k][l]. */
#endif
  uint8_t rho[MLDSA_SEEDBYTES]; /**< Public seed used to expand A. */
#if LC_DSA_A_CACHE_POLYS > 0
#if LC_DSA_A_CACHE_SIGN_ONLY
  uint8_t (*cache)[MLDSA_N*LC_DSA_A_CACHE_BITS/8];
#else
  uint8_t cache[LC_DSA_A_CACHE_COUNT][MLDSA_N*LC_DSA_A_CACHE_BITS/8];
#endif
  unsigned cache_ready; /**< Set only after a complete first A*y product. */
#if LC_DSA_MASK_PIPELINE && MLDSA_K > 4
  uint8_t *mask_future;
  unsigned mask_nonce,mask_count;
#endif
#endif
#if LC_DSA_ROW_BATCH4
  mld_poly *row_tile; /**< Three retained public entries; cur is lane zero. */
  unsigned row_batch_base; /**< Public row-major index of the current group. */
  unsigned row_next_index; /**< Next untouched lane, allowing arbitrary row calls. */
#endif
} mld_polymat_lazy;

#if LC_DSA_A_CACHE_POLYS > 0 && LC_DSA_A_CACHE_BATCH4
#define mld_polymat_cache_prefill MLD_ADD_PARAM_SET(mld_polymat_cache_prefill)
MLD_INTERNAL_API void mld_polymat_cache_prefill(mld_polymat_lazy *mat,
                                               mld_poly scratch[3]);
#endif

#if LC_DSA_A_STREAM_BATCH4 && LC_DSA_A_CACHE_COUNT < MLDSA_K*MLDSA_L && !defined(MLD_CONFIG_SERIAL_FIPS202_ONLY)
#define mld_polyvec_matrix_pointwise_montgomery_yvec_stream4 MLD_ADD_PARAM_SET(mld_polyvec_matrix_pointwise_montgomery_yvec_stream4)
/* The three-polynomial tile is disjoint from mat, w, y, and y_scratch.
 * It is owned by the caller only during this product. */
MLD_INTERNAL_API void mld_polyvec_matrix_pointwise_montgomery_yvec_stream4(
    mld_polyveck *w, mld_polymat_lazy *mat, const mld_yvec_lazy *y,
    mld_yvec_scratch_lazy *y_scratch, mld_poly tile[3]);
#endif

static MLD_INLINE void mld_poly_permute_bitrev_to_custom_optional(mld_poly *p)
__contract__(
  /* We don't specify that this is a permutation, only that it preserves
   * the bounds.
   * When the native NTT backend does not use the custom order, this is a no-op. */
  requires(memory_no_alias(p, sizeof(mld_poly)))
  requires(array_bound(p->coeffs, 0, MLDSA_N, 0, MLDSA_Q))
  assigns(memory_slice(p, sizeof(mld_poly)))
  ensures(array_bound(p->coeffs, 0, MLDSA_N, 0, MLDSA_Q))
)
{
#if defined(MLD_USE_NATIVE_NTT_CUSTOM_ORDER)
  mld_poly_permute_bitrev_to_custom(p->coeffs);
#else
  (void)p;
#endif
}

#if !defined(MLD_CONFIG_REDUCE_RAM) || defined(MLD_UNIT_TEST)
/**
 * Generates matrix A with uniformly random coefficients a_{i,j} by performing
 * rejection sampling on the output stream of SHAKE128(rho|j|i).
 *
 * @spec{Implements @[FIPS204, Algorithm 32, ExpandA].}
 *
 * @param[out] mat Pointer to output matrix.
 * @param[in]  rho Byte array containing seed rho.
 */
MLD_INTERNAL_API
void mld_polyvec_matrix_expand_eager(mld_polymat_eager *mat,
                                     const uint8_t rho[MLDSA_SEEDBYTES])
__contract__(
  requires(memory_no_alias(mat, sizeof(mld_polymat_eager)))
  requires(memory_no_alias(rho, MLDSA_SEEDBYTES))
  assigns(memory_slice(mat, sizeof(mld_polymat_eager)))
  ensures(forall(k1, 0, MLDSA_K, forall(l1, 0, MLDSA_L,
    array_bound(mat->vec[k1].vec[l1].coeffs, 0, MLDSA_N, 0, MLDSA_Q))))
);

/**
 * Compute row i of matrix-vector multiplication in NTT domain with pointwise
 * multiplication and multiplication by 2^{-32}.
 *
 * Input matrix and vector must be in NTT domain representation. Output
 * coefficients are bounded by MLDSA_Q in absolute value.
 *
 * @param[out] t_row Pointer to output row polynomial.
 * @param[in]  mat   Pointer to input matrix.
 * @param[in]  v     Pointer to input vector v.
 * @param      i     Row index, 0 <= i < MLDSA_K.
 */
MLD_INTERNAL_API
void mld_polyvec_matrix_pointwise_montgomery_row_eager(mld_poly *t_row,
                                                       mld_polymat_eager *mat,
                                                       const mld_polyvecl *v,
                                                       unsigned int i)
__contract__(
  requires(memory_no_alias(t_row, sizeof(mld_poly)))
  requires(memory_no_alias(mat, sizeof(mld_polymat_eager)))
  requires(memory_no_alias(v, sizeof(mld_polyvecl)))
  requires(i < MLDSA_K)
  requires(forall(l1, 0, MLDSA_L,
                  array_bound(mat->vec[i].vec[l1].coeffs, 0, MLDSA_N, 0, MLDSA_Q)))
  requires(forall(l2, 0, MLDSA_L,
                  array_abs_bound(v->vec[l2].coeffs, 0, MLDSA_N, MLD_NTT_BOUND)))
  assigns(memory_slice(t_row, sizeof(mld_poly)))
  ensures(array_abs_bound(t_row->coeffs, 0, MLDSA_N, MLDSA_Q))
);

#if !defined(MLD_CONFIG_NO_SIGN_API)
/**
 * Compute w = invNTT(A * NTT(y)) for the signing y vector.
 *
 * The eager variant copies y into the scratch polyvecl, NTTs it in place,
 * calls the standard matrix-vector multiply, and finally inverse-NTTs the
 * result into w.
 *
 * @param[out] w       Pointer to output vector.
 * @param[in]  mat     Pointer to input matrix.
 * @param[in]  y       Pointer to (non-NTT) y vector.
 * @param[out] scratch Scratch polyvecl for NTT'd copy of y.
 */
MLD_INTERNAL_API
void mld_polyvec_matrix_pointwise_montgomery_yvec_eager(
    mld_polyveck *w, mld_polymat_eager *mat, const mld_yvec_eager *y,
    mld_yvec_scratch_eager *scratch)
__contract__(
  requires(memory_no_alias(w, sizeof(mld_polyveck)))
  requires(memory_no_alias(mat, sizeof(mld_polymat_eager)))
  requires(memory_no_alias(y, sizeof(mld_yvec_eager)))
  requires(memory_no_alias(scratch, sizeof(mld_yvec_scratch_eager)))
  requires(forall(k1, 0, MLDSA_K, forall(l1, 0, MLDSA_L,
    array_bound(mat->vec[k1].vec[l1].coeffs, 0, MLDSA_N, 0, MLDSA_Q))))
  requires(forall(l2, 0, MLDSA_L,
    array_bound(y->vec.vec[l2].coeffs, 0, MLDSA_N, -(MLDSA_GAMMA1 - 1), MLDSA_GAMMA1 + 1)))
  assigns(memory_slice(w, sizeof(mld_polyveck)))
  assigns(memory_slice(scratch, sizeof(mld_yvec_scratch_eager)))
  ensures(forall(k0, 0, MLDSA_K,
    array_abs_bound(w->vec[k0].coeffs, 0, MLDSA_N, MLD_INTT_BOUND)))
);
#endif /* !MLD_CONFIG_NO_SIGN_API */
#endif /* !MLD_CONFIG_REDUCE_RAM || MLD_UNIT_TEST */

#if defined(MLD_CONFIG_REDUCE_RAM) || defined(MLD_UNIT_TEST)
MLD_INTERNAL_API
void mld_polyvec_matrix_expand_lazy(mld_polymat_lazy *mat,
                                    const uint8_t rho[MLDSA_SEEDBYTES])
__contract__(
  requires(memory_no_alias(mat, sizeof(mld_polymat_lazy)))
  requires(memory_no_alias(rho, MLDSA_SEEDBYTES))
  assigns(memory_slice(mat, sizeof(mld_polymat_lazy)))
);

#if !defined(MLD_CONFIG_NO_KEYPAIR_API) || !defined(MLD_CONFIG_NO_VERIFY_API)
/**
 * Compute row i of matrix-vector multiplication in NTT domain with pointwise
 * multiplication and multiplication by 2^{-32}.
 *
 * Input vector must be in NTT domain representation; the matrix entries are
 * sampled on demand from the seed stored in mat->rho, using mat->cur as
 * scratch. Output coefficients are bounded by MLDSA_Q in absolute value.
 *
 * @param[out]    t_row Pointer to output row polynomial.
 * @param[in,out] mat   Pointer to input matrix (seed + scratch).
 * @param[in]     v     Pointer to input vector v.
 * @param         i     Row index, 0 <= i < MLDSA_K.
 */
MLD_INTERNAL_API
void mld_polyvec_matrix_pointwise_montgomery_row_lazy(mld_poly *t_row,
                                                      mld_polymat_lazy *mat,
                                                      const mld_polyvecl *v,
                                                      unsigned int i)
__contract__(
  requires(memory_no_alias(t_row, sizeof(mld_poly)))
  requires(memory_no_alias(mat, sizeof(mld_polymat_lazy)))
  requires(memory_no_alias(v, sizeof(mld_polyvecl)))
  requires(i < MLDSA_K)
  requires(forall(l1, 0, MLDSA_L,
                  array_abs_bound(v->vec[l1].coeffs, 0, MLDSA_N, MLD_NTT_BOUND)))
  assigns(memory_slice(t_row, sizeof(mld_poly)))
  assigns(memory_slice(mat, sizeof(mld_polymat_lazy)))
  ensures(array_abs_bound(t_row->coeffs, 0, MLDSA_N, MLDSA_Q))
);
#endif /* !MLD_CONFIG_NO_KEYPAIR_API || !MLD_CONFIG_NO_VERIFY_API */

#if !defined(MLD_CONFIG_NO_SIGN_API)
/**
 * Compute w = invNTT(A * NTT(y)) for the signing y vector.
 *
 * The lazy variant samples one element of y at a time, NTTs it into scratch,
 * and accumulates the matrix-vector product column-by-column with on-demand
 * sampling of A[k][l].
 *
 * @param[out]    w       Pointer to output vector.
 * @param[in,out] mat     Pointer to input matrix.
 * @param[in]     y       Pointer to y seed/kappa.
 * @param[out]    scratch Scratch for the NTT of the current element of y.
 */
MLD_INTERNAL_API
void mld_polyvec_matrix_pointwise_montgomery_yvec_lazy(
    mld_polyveck *w, mld_polymat_lazy *mat, const mld_yvec_lazy *y,
    mld_yvec_scratch_lazy *scratch)
__contract__(
  requires(memory_no_alias(w, sizeof(mld_polyveck)))
  requires(memory_no_alias(mat, sizeof(mld_polymat_lazy)))
  requires(memory_no_alias(y, sizeof(mld_yvec_lazy)))
  requires(memory_no_alias(scratch, sizeof(mld_yvec_scratch_lazy)))
  requires(memory_no_alias(y->rhoprime, MLDSA_CRHBYTES))
  requires(y->kappa <= MLD_MAX_KAPPA)
  assigns(memory_slice(w, sizeof(mld_polyveck)))
  assigns(memory_slice(mat, sizeof(mld_polymat_lazy)))
  assigns(memory_slice(scratch, sizeof(mld_yvec_scratch_lazy)))
  ensures(forall(k0, 0, MLDSA_K,
    array_abs_bound(w->vec[k0].coeffs, 0, MLDSA_N, MLD_INTT_BOUND)))
);
#endif /* !MLD_CONFIG_NO_SIGN_API */
#endif /* MLD_CONFIG_REDUCE_RAM || MLD_UNIT_TEST */

/* Dispatch: typedef and define based on MLD_CONFIG_REDUCE_RAM */
#if defined(MLD_CONFIG_REDUCE_RAM)
typedef mld_sk_s1hat_lazy mld_sk_s1hat;
typedef mld_sk_s2hat_lazy mld_sk_s2hat;
typedef mld_sk_t0hat_lazy mld_sk_t0hat;
typedef mld_polymat_lazy mld_polymat;
typedef mld_yvec_lazy mld_yvec;
typedef mld_yvec_scratch_lazy mld_yvec_scratch;
#define mld_unpack_sk_s1hat mld_unpack_sk_s1hat_lazy
#define mld_unpack_sk_s2hat mld_unpack_sk_s2hat_lazy
#define mld_unpack_sk_t0hat mld_unpack_sk_t0hat_lazy
#if !defined(MLD_CONFIG_NO_SIGN_API)
#define mld_sk_s1hat_get_poly mld_sk_s1hat_get_poly_lazy
#define mld_sk_s2hat_get_poly mld_sk_s2hat_get_poly_lazy
#define mld_sk_t0hat_get_poly mld_sk_t0hat_get_poly_lazy
#endif
#define mld_polyvec_matrix_expand mld_polyvec_matrix_expand_lazy
#define mld_polyvec_matrix_pointwise_montgomery_row \
  mld_polyvec_matrix_pointwise_montgomery_row_lazy
#define mld_yvec_init mld_yvec_init_lazy
#define mld_yvec_get_poly mld_yvec_get_poly_lazy
#define mld_polyvec_matrix_pointwise_montgomery_yvec \
  mld_polyvec_matrix_pointwise_montgomery_yvec_lazy
#else /* MLD_CONFIG_REDUCE_RAM */
typedef mld_sk_s1hat_eager mld_sk_s1hat;
typedef mld_sk_s2hat_eager mld_sk_s2hat;
typedef mld_sk_t0hat_eager mld_sk_t0hat;
typedef mld_polymat_eager mld_polymat;
typedef mld_yvec_eager mld_yvec;
typedef mld_yvec_scratch_eager mld_yvec_scratch;
#define mld_unpack_sk_s1hat mld_unpack_sk_s1hat_eager
#define mld_unpack_sk_s2hat mld_unpack_sk_s2hat_eager
#define mld_unpack_sk_t0hat mld_unpack_sk_t0hat_eager
#if !defined(MLD_CONFIG_NO_SIGN_API)
#define mld_sk_s2hat_get_poly mld_sk_s2hat_get_poly_eager
#define mld_sk_s1hat_get_poly mld_sk_s1hat_get_poly_eager
#define mld_sk_t0hat_get_poly mld_sk_t0hat_get_poly_eager
#endif
#define mld_polyvec_matrix_expand mld_polyvec_matrix_expand_eager
#define mld_polyvec_matrix_pointwise_montgomery_row \
  mld_polyvec_matrix_pointwise_montgomery_row_eager
#define mld_yvec_init mld_yvec_init_eager
#define mld_yvec_get_poly mld_yvec_get_poly_eager
#define mld_polyvec_matrix_pointwise_montgomery_yvec \
  mld_polyvec_matrix_pointwise_montgomery_yvec_eager
#endif /* !MLD_CONFIG_REDUCE_RAM */

#endif /* !MLD_CONFIG_NO_KEYPAIR_API || !MLD_CONFIG_NO_SIGN_API || \
          !MLD_CONFIG_NO_VERIFY_API */
#endif /* !MLD_POLYVEC_LAZY_H */
