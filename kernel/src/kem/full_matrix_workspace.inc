/*
 * Copyright (c) The mlkem-native project authors
 * Modified: call-owned matrix/noise sampling workspace, one-block SHAKE256
 * PRF with buffer reuse, and allocation failure propagation.
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
 */

#include "../../build/adapted_mlkem/src/indcpa.h"
#if MLKEM_K != 3 || MLKEM_ETA1 != 2 || MLKEM_ETA2 != 2 || MLKEM_SYMBYTES != 32 || MLKEM_N != 256
#error "This workspace schedule is specialized to ML-KEM-768"
#endif

#include "../../build/adapted_mlkem/src/debug.h"
#include "../../build/adapted_mlkem/src/randombytes.h"
#include "../../build/adapted_mlkem/src/sampling.h"
#include "../../build/adapted_mlkem/src/symmetric.h"
#include "../../build/adapted_mlkem/src/verify.h"
#ifndef LC_KEM_FULL_NOISE_NEON
#define LC_KEM_FULL_NOISE_NEON 0
#endif
#if LC_KEM_FULL_NOISE_NEON
#include "lc_noise_neon.h"
#define lc_full_cbd2(p, b) lc_cbd_neon((p)->coeffs, (b), 2)
#else
#define lc_full_cbd2(p, b) mlk_poly_cbd2((p), (b))
#endif
#if SHAKE256_RATE != 136
#error "The noise workspace uses a single SHAKE256 rate block"
#endif

/* Parameter set namespacing
 * This is to facilitate building multiple instances
 * of mlkem-native (e.g. with varying parameter sets)
 * within a single compilation unit. */
#define mlk_pack_pk MLK_ADD_PARAM_SET(mlk_pack_pk)
#define mlk_unpack_pk MLK_ADD_PARAM_SET(mlk_unpack_pk)
#define mlk_pack_sk MLK_ADD_PARAM_SET(mlk_pack_sk)
#define mlk_unpack_sk MLK_ADD_PARAM_SET(mlk_unpack_sk)
#define mlk_pack_ciphertext MLK_ADD_PARAM_SET(mlk_pack_ciphertext)
#define mlk_unpack_ciphertext MLK_ADD_PARAM_SET(mlk_unpack_ciphertext)
#define mlk_matvec_mul MLK_ADD_PARAM_SET(mlk_matvec_mul)
#define mlk_polymat_permute_bitrev_to_custom \
  MLK_ADD_PARAM_SET(mlk_polymat_permute_bitrev_to_custom)
#define mlk_keypair_getnoise_eta1 MLK_ADD_PARAM_SET(mlk_keypair_getnoise_eta1)
#define mlk_enc_getnoise_eta1_eta2 MLK_ADD_PARAM_SET(mlk_enc_getnoise_eta1_eta2)
/* End of parameter set namespacing */

/**
 * Serialize the public key as the concatenation of the serialized vector of
 * polynomials pk and the public seed used to generate the matrix A.
 *
 * @spec{Implements @[FIPS203, Algorithm 13 (K-PKE.KeyGen), L19].}
 *
 * @param[out] r    Output serialized public key.
 * @param[in]  pk   Input public-key polyvec. Must have coefficients within
 *                  [0,..,MLKEM_Q-1].
 * @param[in]  seed Input public seed.
 */
#if !defined(MLK_CONFIG_NO_KEYPAIR_API)
static void mlk_pack_pk(uint8_t r[MLKEM_INDCPA_PUBLICKEYBYTES],
                        const mlk_polyvec *pk,
                        const uint8_t seed[MLKEM_SYMBYTES])
{
  mlk_assert_bound_2d(pk->vec, MLKEM_K, MLKEM_N, 0, MLKEM_Q);
  mlk_polyvec_tobytes(r, pk);
  mlk_memcpy(r + MLKEM_POLYVECBYTES, seed, MLKEM_SYMBYTES);
}
#endif /* !MLK_CONFIG_NO_KEYPAIR_API */

/**
 * De-serialize public key from a byte array; approximate inverse of
 * mlk_pack_pk.
 *
 * @spec{Implements @[FIPS203, Algorithm 14 (K-PKE.Encrypt), L2-3].}
 *
 * @param[out] pk       Output public-key polynomial vector. Coefficients
 *                      will be normalized to [0,1,..,MLKEM_Q-1].
 * @param[out] seed     Output seed to generate matrix A.
 * @param[in]  packedpk Input serialized public key.
 */
#if !defined(MLK_CONFIG_NO_ENCAPS_API) || !defined(MLK_CONFIG_NO_DECAPS_API)
static void mlk_unpack_pk(mlk_polyvec *pk, uint8_t seed[MLKEM_SYMBYTES],
                          const uint8_t packedpk[MLKEM_INDCPA_PUBLICKEYBYTES])
{
  mlk_polyvec_frombytes(pk, packedpk);
  mlk_memcpy(seed, packedpk + MLKEM_POLYVECBYTES, MLKEM_SYMBYTES);

  /* NOTE: If a modulus check was conducted on the PK, we know at this
   * point that the coefficients of `pk` are unsigned canonical. The
   * specifications and proofs, however, do _not_ assume this, and instead
   * work with the easily provable bound by MLKEM_UINT12_LIMIT. */
}
#endif /* !MLK_CONFIG_NO_ENCAPS_API || !MLK_CONFIG_NO_DECAPS_API */

/**
 * Serialize the secret key.
 *
 * @spec{Implements @[FIPS203, Algorithm 13 (K-PKE.KeyGen), L20].}
 *
 * @param[out] r  Output serialized secret key.
 * @param[in]  sk Input vector of polynomials (secret key).
 */
#if !defined(MLK_CONFIG_NO_KEYPAIR_API)
static void mlk_pack_sk(uint8_t r[MLKEM_INDCPA_SECRETKEYBYTES],
                        const mlk_polyvec *sk)
{
  mlk_assert_bound_2d(sk->vec, MLKEM_K, MLKEM_N, 0, MLKEM_Q);
  mlk_polyvec_tobytes(r, sk);
}
#endif /* !MLK_CONFIG_NO_KEYPAIR_API */

/**
 * De-serialize the secret key; inverse of mlk_pack_sk.
 *
 * @spec{Implements @[FIPS203, Algorithm 15 (K-PKE.Decrypt), L5].}
 *
 * @param[out] sk       Output vector of polynomials (secret key).
 * @param[in]  packedsk Input serialized secret key.
 */
#if !defined(MLK_CONFIG_NO_DECAPS_API)
static void mlk_unpack_sk(mlk_polyvec *sk,
                          const uint8_t packedsk[MLKEM_INDCPA_SECRETKEYBYTES])
{
  mlk_polyvec_frombytes(sk, packedsk);
}
#endif /* !MLK_CONFIG_NO_DECAPS_API */

/**
 * Serialize the ciphertext as the concatenation of the compressed and
 * serialized vector of polynomials b and the compressed and serialized
 * polynomial v.
 *
 * @spec{Implements @[FIPS203, Algorithm 14 (K-PKE.Encrypt), L22-23].}
 *
 * @param[out] r Output serialized ciphertext.
 * @param[in]  b Input vector of polynomials b.
 * @param[in]  v Input polynomial v.
 */
#if !defined(MLK_CONFIG_NO_ENCAPS_API) || !defined(MLK_CONFIG_NO_DECAPS_API)
static void mlk_pack_ciphertext(uint8_t r[MLKEM_INDCPA_BYTES],
                                const mlk_polyvec *b, mlk_poly *v)
{
  mlk_polyvec_compress_du(r, b);
  mlk_poly_compress_dv(r + MLKEM_POLYVECCOMPRESSEDBYTES_DU, v);
}
#endif /* !MLK_CONFIG_NO_ENCAPS_API || !MLK_CONFIG_NO_DECAPS_API */

/**
 * De-serialize and decompress ciphertext from a byte array; approximate
 * inverse of mlk_pack_ciphertext.
 *
 * @spec{Implements @[FIPS203, Algorithm 15 (K-PKE.Decrypt), L1-4].}
 *
 * @param[out] b Output vector of polynomials b.
 * @param[out] v Output polynomial v.
 * @param[in]  c Input serialized ciphertext.
 */
#if !defined(MLK_CONFIG_NO_DECAPS_API)
static void mlk_unpack_ciphertext(mlk_polyvec *b, mlk_poly *v,
                                  const uint8_t c[MLKEM_INDCPA_BYTES])
{
  mlk_polyvec_decompress_du(b, c);
  mlk_poly_decompress_dv(v, c + MLKEM_POLYVECCOMPRESSEDBYTES_DU);
}
#endif /* !MLK_CONFIG_NO_DECAPS_API */

static void mlk_polymat_permute_bitrev_to_custom(mlk_polymat *a)
__contract__(
  /* We don't specify that this should be a permutation, but only
   * that it does not change the bound established at the end of mlk_gen_matrix. */
  requires(memory_no_alias(a, sizeof(mlk_polymat)))
  requires(forall(x, 0, MLKEM_K, forall(y, 0, MLKEM_K,
    array_bound(a->vec[x].vec[y].coeffs, 0, MLKEM_N, 0, MLKEM_Q))))
  assigns(memory_slice(a, sizeof(mlk_polymat)))
  ensures(forall(x, 0, MLKEM_K, forall(y, 0, MLKEM_K,
    array_bound(a->vec[x].vec[y].coeffs, 0, MLKEM_N, 0, MLKEM_Q)))))
{
#if defined(MLK_USE_NATIVE_NTT_CUSTOM_ORDER)
  unsigned i, j;
  for (i = 0; i < MLKEM_K; i++)
  __loop__(
    assigns(i, j, memory_slice(a, sizeof(mlk_polymat)))
    invariant(i <= MLKEM_K)
    invariant(forall(x2, 0, MLKEM_K, forall(y2, 0, MLKEM_K,
      array_bound(a->vec[x2].vec[y2].coeffs, 0, MLKEM_N, 0, MLKEM_Q))))
    decreases(MLKEM_K - i))
  {
    for (j = 0; j < MLKEM_K; j++)
    __loop__(
      assigns(j, memory_slice(a, sizeof(mlk_polymat)))
      invariant(i <= MLKEM_K)
      invariant(j <= MLKEM_K)
      invariant(forall(x3, 0, MLKEM_K, forall(y3, 0, MLKEM_K,
        array_bound(a->vec[x3].vec[y3].coeffs, 0, MLKEM_N, 0, MLKEM_Q))))
      decreases(MLKEM_K - j))
    {
      mlk_poly_permute_bitrev_to_custom(a->vec[i].vec[j].coeffs);
    }
  }
#else  /* MLK_USE_NATIVE_NTT_CUSTOM_ORDER */
  /* Nothing to do */
  (void)a;
#endif /* !MLK_USE_NATIVE_NTT_CUSTOM_ORDER */
}

/* Reference: `gen_matrix()` in the reference implementation @[REF].
 *            - We use a special subroutine to generate 4 polynomials
 *              at a time, to be able to leverage batched Keccak-f1600
 *              implementations. The reference implementation generates
 *              one matrix entry a time.
 *
 * Not static for benchmarking */
MLK_INTERNAL_API
void mlk_gen_matrix(mlk_polymat *a, const uint8_t seed[MLKEM_SYMBYTES],
                    int transposed)
{
  unsigned i, j;
  MLK_ALIGN uint8_t seed_ext[4][MLK_ALIGN_UP(MLKEM_SYMBYTES + 2)];

  for (j = 0; j < 4; j++)
  {
    mlk_memcpy(seed_ext[j], seed, MLKEM_SYMBYTES);
  }

#if !defined(MLK_CONFIG_SERIAL_FIPS202_ONLY)
  /* Sample 4 matrix entries a time. */
  for (i = 0; i < (MLKEM_K * MLKEM_K / 4) * 4; i += 4)
  {
    for (j = 0; j < 4; j++)
    {
      uint8_t x, y;
      /* MLKEM_K <= 4, so the values fit in uint8_t. */
      x = (uint8_t)((i + j) / MLKEM_K);
      y = (uint8_t)((i + j) % MLKEM_K);
      if (transposed)
      {
        seed_ext[j][MLKEM_SYMBYTES + 0] = x;
        seed_ext[j][MLKEM_SYMBYTES + 1] = y;
      }
      else
      {
        seed_ext[j][MLKEM_SYMBYTES + 0] = y;
        seed_ext[j][MLKEM_SYMBYTES + 1] = x;
      }
    }

    mlk_poly_rej_uniform_x4(&a->vec[i / MLKEM_K].vec[i % MLKEM_K],
                            &a->vec[(i + 1) / MLKEM_K].vec[(i + 1) % MLKEM_K],
                            &a->vec[(i + 2) / MLKEM_K].vec[(i + 2) % MLKEM_K],
                            &a->vec[(i + 3) / MLKEM_K].vec[(i + 3) % MLKEM_K],
                            seed_ext);
  }
#else  /* !MLK_CONFIG_SERIAL_FIPS202_ONLY */
  /* When using serial FIPS202, sample all entries individually. */
  i = 0;
#endif /* MLK_CONFIG_SERIAL_FIPS202_ONLY */

  /* For MLKEM_K == 3, sample the last entry individually.
   * When MLK_CONFIG_SERIAL_FIPS202_ONLY is set, sample all entries
   * individually. */
  for (; i < MLKEM_K * MLKEM_K; i++)
  {
    uint8_t x, y;
    /* MLKEM_K <= 4, so the values fit in uint8_t. */
    x = (uint8_t)(i / MLKEM_K);
    y = (uint8_t)(i % MLKEM_K);

    if (transposed)
    {
      seed_ext[0][MLKEM_SYMBYTES + 0] = x;
      seed_ext[0][MLKEM_SYMBYTES + 1] = y;
    }
    else
    {
      seed_ext[0][MLKEM_SYMBYTES + 0] = y;
      seed_ext[0][MLKEM_SYMBYTES + 1] = x;
    }

    mlk_poly_rej_uniform(&a->vec[i / MLKEM_K].vec[i % MLKEM_K], seed_ext[0]);
  }

  mlk_assert(i == MLKEM_K * MLKEM_K);

  /*
   * The public matrix is generated in NTT domain. If the native backend
   * uses a custom order in NTT domain, permute A accordingly.
   */
  mlk_polymat_permute_bitrev_to_custom(a);

  /* Specification: Partially implements
   * @[FIPS203, Section 3.3, Destruction of intermediate values] */
  mlk_zeroize(seed_ext, sizeof(seed_ext));
}

/* The owner is separate from every output polynomial and the public seed.
 * Its lifetime ends before noise generation, so later stages reuse its arena
 * space. All bytes, including aligned padding, are erased at release. */
#if defined(MLK_CONFIG_SERIAL_FIPS202_ONLY) || !defined(MLK_CONFIG_CONTEXT_PARAMETER)
#error "matrix sampling workspace requires the hosted four-way context API"
#endif
#ifndef MLKEM_GEN_MATRIX_NBLOCKS
#define MLKEM_GEN_MATRIX_NBLOCKS \
  ((12 * MLKEM_N / 8 * ((uint32_t)1 << 12) / MLKEM_Q + MLK_XOF_RATE) / MLK_XOF_RATE)
#endif
typedef struct {
  MLK_ALIGN uint8_t seed_ext[4][MLK_ALIGN_UP(MLKEM_SYMBYTES + 2)];
  MLK_ALIGN uint8_t buf[4][MLK_ALIGN_UP(MLKEM_GEN_MATRIX_NBLOCKS * MLK_XOF_RATE)];
  union {
    mlk_xof_x4_ctx statex;
    mlk_xof_ctx scalar;
  } state;
} lc_kem_matrix4_workspace;
/* The shared rejection routine is defined by the existing sampling module. */
static unsigned mlk_rej_uniform(int16_t *r, unsigned target, unsigned offset,
                                const uint8_t *buf, unsigned buflen);
static void lc_kem_poly_rej_uniform4_arena(mlk_poly *vec0, mlk_poly *vec1, mlk_poly *vec2,
                             mlk_poly *vec3,
                             uint8_t seed[4][MLK_ALIGN_UP(MLKEM_SYMBYTES + 2)],
                             lc_kem_matrix4_workspace *workspace)
{
  /* Temporary buffers for XOF output before rejection sampling */
#define buf (workspace->buf)

  /* Tracks the number of coefficients we have already sampled */
  unsigned ctr[4];
#define statex (workspace->state.statex)
  unsigned buflen;

  mlk_xof_x4_init(&statex);
  mlk_xof_x4_absorb(&statex, seed, MLKEM_SYMBYTES + 2);

  /*
   * Initially, squeeze heuristic number of MLKEM_GEN_MATRIX_NBLOCKS.
   * This should generate the matrix entries with high probability.
   */
  mlk_xof_x4_squeezeblocks(buf, MLKEM_GEN_MATRIX_NBLOCKS, &statex);
  buflen = MLKEM_GEN_MATRIX_NBLOCKS * MLK_XOF_RATE;
  ctr[0] = mlk_rej_uniform(vec0->coeffs, MLKEM_N, 0, buf[0], buflen);
  ctr[1] = mlk_rej_uniform(vec1->coeffs, MLKEM_N, 0, buf[1], buflen);
  ctr[2] = mlk_rej_uniform(vec2->coeffs, MLKEM_N, 0, buf[2], buflen);
  ctr[3] = mlk_rej_uniform(vec3->coeffs, MLKEM_N, 0, buf[3], buflen);

  /*
   * So long as not all matrix entries have been generated, squeeze
   * one more block a time until we're done.
   */
  buflen = MLK_XOF_RATE;
  while (ctr[0] < MLKEM_N || ctr[1] < MLKEM_N || ctr[2] < MLKEM_N ||
         ctr[3] < MLKEM_N)
  __loop__(
    assigns(ctr, memory_slice(workspace, sizeof(*workspace)),
            memory_slice(vec0, sizeof(mlk_poly)),
            memory_slice(vec1, sizeof(mlk_poly)),
            memory_slice(vec2, sizeof(mlk_poly)),
            memory_slice(vec3, sizeof(mlk_poly)),
            object_whole(buf))
    invariant(ctr[0] <= MLKEM_N && ctr[1] <= MLKEM_N)
    invariant(ctr[2] <= MLKEM_N && ctr[3] <= MLKEM_N)
    invariant(array_bound(vec0->coeffs, 0, ctr[0], 0, MLKEM_Q))
    invariant(array_bound(vec1->coeffs, 0, ctr[1], 0, MLKEM_Q))
    invariant(array_bound(vec2->coeffs, 0, ctr[2], 0, MLKEM_Q))
    invariant(array_bound(vec3->coeffs, 0, ctr[3], 0, MLKEM_Q)))
  {
    mlk_xof_x4_squeezeblocks(buf, 1, &statex);
    ctr[0] = mlk_rej_uniform(vec0->coeffs, MLKEM_N, ctr[0], buf[0], buflen);
    ctr[1] = mlk_rej_uniform(vec1->coeffs, MLKEM_N, ctr[1], buf[1], buflen);
    ctr[2] = mlk_rej_uniform(vec2->coeffs, MLKEM_N, ctr[2], buf[2], buflen);
    ctr[3] = mlk_rej_uniform(vec3->coeffs, MLKEM_N, ctr[3], buf[3], buflen);
  }

  mlk_xof_x4_release(&statex);

  /* Specification: Partially implements
   * @[FIPS203, Section 3.3, Destruction of intermediate values] */
  mlk_zeroize(buf, sizeof(buf));
#undef buf
#undef statex
}

/* The four-lane state has been released before this function begins. The
 * scalar union member and first output buffer now have their own last uses. */
static void lc_kem_poly_rej_uniform1_arena(mlk_poly *entry,
    uint8_t seed[MLKEM_SYMBYTES + 2], lc_kem_matrix4_workspace *workspace)
{
#define state (workspace->state.scalar)
#define buf (workspace->buf[0])
  unsigned ctr, buflen;

  mlk_xof_init(&state);
  mlk_xof_absorb(&state, seed, MLKEM_SYMBYTES + 2);

  /* Initially, squeeze + sample heuristic number of MLKEM_GEN_MATRIX_NBLOCKS.
   */
  /* This should generate the matrix entry with high probability. */
  mlk_xof_squeezeblocks(buf, MLKEM_GEN_MATRIX_NBLOCKS, &state);
  buflen = MLKEM_GEN_MATRIX_NBLOCKS * MLK_XOF_RATE;
  ctr = mlk_rej_uniform(entry->coeffs, MLKEM_N, 0, buf, buflen);

  /* Squeeze + sample one more block a time until we're done */
  buflen = MLK_XOF_RATE;
  while (ctr < MLKEM_N)
  __loop__(
    assigns(ctr, memory_slice(workspace, sizeof(*workspace)), memory_slice(entry, sizeof(mlk_poly)))
    invariant(ctr <= MLKEM_N)
    invariant(array_bound(entry->coeffs, 0, ctr, 0, MLKEM_Q)))
  {
    mlk_xof_squeezeblocks(buf, 1, &state);
    ctr = mlk_rej_uniform(entry->coeffs, MLKEM_N, ctr, buf, buflen);
  }

  mlk_xof_release(&state);

  /* Specification: Partially implements
   * @[FIPS203, Section 3.3, Destruction of intermediate values] */
  mlk_zeroize(buf, sizeof(buf));
#undef buf
#undef state
}

#include "lc_joint_noise3.h"

static int lc_kem_gen_matrix_arena(mlk_polymat *a, const uint8_t seed[MLKEM_SYMBYTES],
                    int transposed, MLK_CONFIG_CONTEXT_PARAMETER_TYPE context
#if LC_KEM_JOINT_NOISE3
                    , mlk_polyvec *initial_noise, const uint8_t private_seed[32]
#endif
                    )
{
  unsigned i, j;
  MLK_ALLOC(workspace, lc_kem_matrix4_workspace, 1, context);
  if (workspace == NULL) return MLK_ERR_OUT_OF_MEMORY;
#define seed_ext (workspace->seed_ext)

  for (j = 0; j < 4; j++)
  {
    mlk_memcpy(seed_ext[j], seed, MLKEM_SYMBYTES);
  }

#if !defined(MLK_CONFIG_SERIAL_FIPS202_ONLY)
  /* Sample 4 matrix entries a time. */
  for (i = 0; i < (MLKEM_K * MLKEM_K / 4) * 4; i += 4)
  {
    for (j = 0; j < 4; j++)
    {
      uint8_t x, y;
      /* MLKEM_K <= 4, so the values fit in uint8_t. */
      x = (uint8_t)((i + j) / MLKEM_K);
      y = (uint8_t)((i + j) % MLKEM_K);
      if (transposed)
      {
        seed_ext[j][MLKEM_SYMBYTES + 0] = x;
        seed_ext[j][MLKEM_SYMBYTES + 1] = y;
      }
      else
      {
        seed_ext[j][MLKEM_SYMBYTES + 0] = y;
        seed_ext[j][MLKEM_SYMBYTES + 1] = x;
      }
    }

    lc_kem_poly_rej_uniform4_arena(&a->vec[i / MLKEM_K].vec[i % MLKEM_K],
                            &a->vec[(i + 1) / MLKEM_K].vec[(i + 1) % MLKEM_K],
                            &a->vec[(i + 2) / MLKEM_K].vec[(i + 2) % MLKEM_K],
                            &a->vec[(i + 3) / MLKEM_K].vec[(i + 3) % MLKEM_K],
                            seed_ext, workspace);
  }
#else  /* !MLK_CONFIG_SERIAL_FIPS202_ONLY */
  /* When using serial FIPS202, sample all entries individually. */
  i = 0;
#endif /* MLK_CONFIG_SERIAL_FIPS202_ONLY */

  /* For MLKEM_K == 3, sample the last entry individually.
   * When MLK_CONFIG_SERIAL_FIPS202_ONLY is set, sample all entries
   * individually. */
  for (; i < MLKEM_K * MLKEM_K; i++)
  {
    uint8_t x, y;
    /* MLKEM_K <= 4, so the values fit in uint8_t. */
    x = (uint8_t)(i / MLKEM_K);
    y = (uint8_t)(i % MLKEM_K);

    if (transposed)
    {
      seed_ext[0][MLKEM_SYMBYTES + 0] = x;
      seed_ext[0][MLKEM_SYMBYTES + 1] = y;
    }
    else
    {
      seed_ext[0][MLKEM_SYMBYTES + 0] = y;
      seed_ext[0][MLKEM_SYMBYTES + 1] = x;
    }

#if LC_KEM_JOINT_NOISE3
    lc_kem_joint_tail_noise(&a->vec[i / MLKEM_K].vec[i % MLKEM_K],
                           initial_noise, seed, private_seed, workspace);
#else
    lc_kem_poly_rej_uniform1_arena(&a->vec[i / MLKEM_K].vec[i % MLKEM_K],
                          seed_ext[0], workspace);
#endif
  }

  mlk_assert(i == MLKEM_K * MLKEM_K);

  /*
   * The public matrix is generated in NTT domain. If the native backend
   * uses a custom order in NTT domain, permute A accordingly.
   */
  mlk_polymat_permute_bitrev_to_custom(a);

  /* Specification: Partially implements
   * @[FIPS203, Section 3.3, Destruction of intermediate values] */
  MLK_FREE(workspace, lc_kem_matrix4_workspace, 1, context);
#undef seed_ext
  return 0;
}


/**
 * Compute matrix-vector product in NTT domain, via Montgomery multiplication.
 *
 * @spec{Implements @[FIPS203, Section 2.4.7, Eq (2.12), (2.13)].}
 *
 * @param[out] out Output polynomial vector.
 * @param[in]  a   Input matrix. Must be in NTT domain and have coefficients
 *                 of absolute value < 4096.
 * @param[in]  v   Input polynomial vector. Must be in NTT domain.
 * @param[in]  vc  Mulcache for @p v, computed via
 *                 mlk_polyvec_mulcache_compute().
 */
static void mlk_matvec_mul(mlk_polyvec *out, const mlk_polymat *a,
                           const mlk_polyvec *v, const mlk_polyvec_mulcache *vc)
__contract__(
  requires(memory_no_alias(out, sizeof(mlk_polyvec)))
  requires(memory_no_alias(a, sizeof(mlk_polymat)))
  requires(memory_no_alias(v, sizeof(mlk_polyvec)))
  requires(memory_no_alias(vc, sizeof(mlk_polyvec_mulcache)))
  requires(forall(k0, 0, MLKEM_K,
    forall(k1, 0, MLKEM_K,
      array_bound(a->vec[k0].vec[k1].coeffs, 0, MLKEM_N, 0, MLKEM_UINT12_LIMIT))))
  assigns(memory_slice(out, sizeof(mlk_polyvec))))
{
  unsigned i;
  for (i = 0; i < MLKEM_K; i++)
  __loop__(
    assigns(i, memory_slice(out, sizeof(mlk_polyvec)))
    invariant(i <= MLKEM_K)
    decreases(MLKEM_K - i))
  {
    mlk_polyvec_basemul_acc_montgomery_cached(&out->vec[i], &a->vec[i], v, vc);
  }
}

/* ML-KEM-768 PRF input is seed[32] || nonce[1], with 128 output
 * bytes. It occupies one SHAKE256 rate block. The owner holds four padded
 * inputs and the Keccak state; after absorption those input buffers become
 * the output buffers. All lanes and both noise groups keep their original
 * nonces. The state is accessed only through the existing Keccak API. */
typedef struct {
  MLK_ALIGN uint8_t block[4][MLK_ALIGN_UP(SHAKE256_RATE)];
  mlk_shake128x4ctx state;
} lc_kem_noise4_workspace;

static void lc_kem_noise4_arena(mlk_poly *r0, mlk_poly *r1, mlk_poly *r2,
    mlk_poly *r3, const uint8_t seed[MLKEM_SYMBYTES],
    uint8_t nonce0, uint8_t nonce1, uint8_t nonce2, uint8_t nonce3,
    lc_kem_noise4_workspace *workspace)
{
  unsigned lane;
  mlk_memset(workspace, 0, sizeof(*workspace));
  for (lane = 0; lane < 4; ++lane)
  {
    mlk_memcpy(workspace->block[lane], seed, MLKEM_SYMBYTES);
    workspace->block[lane][MLKEM_SYMBYTES + 1] = 0x1f;
    workspace->block[lane][SHAKE256_RATE - 1] = 0x80;
  }
  workspace->block[0][MLKEM_SYMBYTES] = nonce0;
  workspace->block[1][MLKEM_SYMBYTES] = nonce1;
  workspace->block[2][MLKEM_SYMBYTES] = nonce2;
  workspace->block[3][MLKEM_SYMBYTES] = nonce3;
  mlk_keccakf1600x4_xor_bytes(workspace->state.ctx,
      workspace->block[0], workspace->block[1], workspace->block[2],
      workspace->block[3], 0, SHAKE256_RATE);
  mlk_keccakf1600x4_permute(workspace->state.ctx);
  mlk_keccakf1600x4_extract_bytes(workspace->state.ctx,
      workspace->block[0], workspace->block[1], workspace->block[2],
      workspace->block[3], 0, 2 * MLKEM_N / 4);
  lc_full_cbd2(r0, workspace->block[0]);
  lc_full_cbd2(r1, workspace->block[1]);
  lc_full_cbd2(r2, workspace->block[2]);
  if (r3 != NULL) lc_full_cbd2(r3, workspace->block[3]);
}

#if !defined(MLK_CONFIG_NO_KEYPAIR_API)
static int mlk_keypair_getnoise_eta1(mlk_polyvec *pv, mlk_polyvec *e,
    const uint8_t seed[MLKEM_SYMBYTES],
    MLK_CONFIG_CONTEXT_PARAMETER_TYPE context)
{
  MLK_ALLOC(workspace, lc_kem_noise4_workspace, 1, context);
  if (workspace == NULL) return MLK_ERR_OUT_OF_MEMORY;
#if !LC_KEM_JOINT_NOISE3
  lc_kem_noise4_arena(&pv->vec[0], &pv->vec[1], &pv->vec[2], NULL,
      seed, 0, 1, 2, 0xff, workspace);
#else
  (void)pv;
#endif
  lc_kem_noise4_arena(&e->vec[0], &e->vec[1], &e->vec[2], NULL,
      seed, 3, 4, 5, 0xff, workspace);
  MLK_FREE(workspace, lc_kem_noise4_workspace, 1, context);
  return 0;
}
#endif

#if !defined(MLK_CONFIG_NO_ENCAPS_API) || !defined(MLK_CONFIG_NO_DECAPS_API)
static int mlk_enc_getnoise_eta1_eta2(mlk_polyvec *sp, mlk_polyvec *ep,
    mlk_poly *epp, const uint8_t coins[MLKEM_SYMBYTES],
    MLK_CONFIG_CONTEXT_PARAMETER_TYPE context)
{
  MLK_ALLOC(workspace, lc_kem_noise4_workspace, 1, context);
  if (workspace == NULL) return MLK_ERR_OUT_OF_MEMORY;
#if !LC_KEM_JOINT_NOISE3
  lc_kem_noise4_arena(&sp->vec[0], &sp->vec[1], &sp->vec[2], NULL,
      coins, 0, 1, 2, 0xff, workspace);
#else
  (void)sp;
#endif
  lc_kem_noise4_arena(&ep->vec[0], &ep->vec[1], &ep->vec[2], epp,
      coins, 3, 4, 5, 6, workspace);
  MLK_FREE(workspace, lc_kem_noise4_workspace, 1, context);
  return 0;
}
#endif

/* Reference: `indcpa_keypair_derand()` in the reference implementation @[REF].
 *            - We use a different implementation of `gen_matrix()` which
 *              uses x4-batched Keccak-f1600 (see `mlk_gen_matrix()` above).
 *            - We use a mulcache to speed up matrix-vector multiplication.
 *            - We include buffer zeroization.
 */
#if !defined(MLK_CONFIG_NO_KEYPAIR_API)
MLK_INTERNAL_API
int mlk_indcpa_keypair_derand(uint8_t pk[MLKEM_INDCPA_PUBLICKEYBYTES],
                              uint8_t sk[MLKEM_INDCPA_SECRETKEYBYTES],
                              const uint8_t coins[MLKEM_SYMBYTES],
                              MLK_CONFIG_CONTEXT_PARAMETER_TYPE context)
{
  int ret = 0;
  const uint8_t *publicseed;
  const uint8_t *noiseseed;
  MLK_ALLOC(buf, uint8_t, 2 * MLKEM_SYMBYTES, context);
  MLK_ALLOC(coins_with_domain_separator, uint8_t, MLKEM_SYMBYTES + 1, context);
  MLK_ALLOC(a, mlk_polymat, 1, context);
  MLK_ALLOC(e, mlk_polyvec, 1, context);
  MLK_ALLOC(pkpv, mlk_polyvec, 1, context);
  MLK_ALLOC(skpv, mlk_polyvec, 1, context);
  MLK_ALLOC(skpv_cache, mlk_polyvec_mulcache, 1, context);

  if (buf == NULL || coins_with_domain_separator == NULL || a == NULL ||
      e == NULL || pkpv == NULL || skpv == NULL || skpv_cache == NULL)
  {
    ret = MLK_ERR_OUT_OF_MEMORY;
    goto cleanup;
  }

  publicseed = buf;
  noiseseed = buf + MLKEM_SYMBYTES;

  /* Concatenate coins with MLKEM_K for domain separation of security levels */
  mlk_memcpy(coins_with_domain_separator, coins, MLKEM_SYMBYTES);
  coins_with_domain_separator[MLKEM_SYMBYTES] = MLKEM_K;

  mlk_hash_g(buf, coins_with_domain_separator, MLKEM_SYMBYTES + 1);

  /*
   * Declassify the public seed.
   * Required to use it in conditional-branches in rejection sampling.
   * This is needed because all output of randombytes is marked as secret
   * (=undefined)
   */
  MLK_CT_TESTING_DECLASSIFY(publicseed, MLKEM_SYMBYTES);

  ret = lc_kem_gen_matrix_arena(a, publicseed, 0 /* no transpose */, context
#if LC_KEM_JOINT_NOISE3
                              , skpv, noiseseed
#endif
                              );
  if (ret != 0) goto cleanup;

  ret = mlk_keypair_getnoise_eta1(skpv, e, noiseseed, context);
  if (ret != 0) goto cleanup;

  mlk_polyvec_ntt(skpv);
  mlk_polyvec_ntt(e);

  mlk_polyvec_mulcache_compute(skpv_cache, skpv);
  mlk_matvec_mul(pkpv, a, skpv, skpv_cache);
  mlk_polyvec_tomont(pkpv);

  mlk_polyvec_add(pkpv, e);
  mlk_polyvec_reduce(pkpv);
  mlk_polyvec_reduce(skpv);

  mlk_pack_sk(sk, skpv);
  mlk_pack_pk(pk, pkpv, publicseed);

cleanup:
  /* Specification: Partially implements
   * @[FIPS203, Section 3.3, Destruction of intermediate values] */
  MLK_FREE(skpv_cache, mlk_polyvec_mulcache, 1, context);
  MLK_FREE(skpv, mlk_polyvec, 1, context);
  MLK_FREE(pkpv, mlk_polyvec, 1, context);
  MLK_FREE(e, mlk_polyvec, 1, context);
  MLK_FREE(a, mlk_polymat, 1, context);
  MLK_FREE(coins_with_domain_separator, uint8_t, MLKEM_SYMBYTES + 1, context);
  MLK_FREE(buf, uint8_t, 2 * MLKEM_SYMBYTES, context);
  return ret;
}
#endif /* !MLK_CONFIG_NO_KEYPAIR_API */

/* Reference: `indcpa_enc()` in the reference implementation @[REF].
 *            - We use x4-batched versions of `poly_getnoise` to leverage
 *              batched x4-batched Keccak-f1600.
 *            - We use a different implementation of `gen_matrix()` which
 *              uses x4-batched Keccak-f1600 (see `mlk_gen_matrix()` above).
 *            - We use a mulcache to speed up matrix-vector multiplication.
 *            - We include buffer zeroization.
 */
#if !defined(MLK_CONFIG_NO_ENCAPS_API) || !defined(MLK_CONFIG_NO_DECAPS_API)
MLK_INTERNAL_API
int mlk_indcpa_enc(uint8_t c[MLKEM_INDCPA_BYTES],
                   const uint8_t m[MLKEM_INDCPA_MSGBYTES],
                   const uint8_t pk[MLKEM_INDCPA_PUBLICKEYBYTES],
                   const uint8_t coins[MLKEM_SYMBYTES],
                   MLK_CONFIG_CONTEXT_PARAMETER_TYPE context)
{
  int ret = 0;
  MLK_ALLOC(seed, uint8_t, MLKEM_SYMBYTES, context);
  MLK_ALLOC(at, mlk_polymat, 1, context);
  MLK_ALLOC(sp, mlk_polyvec, 1, context);
  MLK_ALLOC(pkpv, mlk_polyvec, 1, context);
  MLK_ALLOC(ep, mlk_polyvec, 1, context);
  MLK_ALLOC(b, mlk_polyvec, 1, context);
  MLK_ALLOC(v, mlk_poly, 1, context);
  MLK_ALLOC(k, mlk_poly, 1, context);
  MLK_ALLOC(epp, mlk_poly, 1, context);
  MLK_ALLOC(sp_cache, mlk_polyvec_mulcache, 1, context);

  if (seed == NULL || at == NULL || sp == NULL || pkpv == NULL || ep == NULL ||
      b == NULL || v == NULL || k == NULL || epp == NULL || sp_cache == NULL)
  {
    ret = MLK_ERR_OUT_OF_MEMORY;
    goto cleanup;
  }

  mlk_unpack_pk(pkpv, seed, pk);
  mlk_poly_frommsg(k, m);

  /*
   * Declassify the public seed.
   * Required to use it in conditional-branches in rejection sampling.
   * This is needed because in re-encryption the publicseed originated from sk
   * which is marked undefined.
   */
  MLK_CT_TESTING_DECLASSIFY(seed, MLKEM_SYMBYTES);

  ret = lc_kem_gen_matrix_arena(at, seed, 1 /* transpose */, context
#if LC_KEM_JOINT_NOISE3
                              , sp, coins
#endif
                              );
  if (ret != 0) goto cleanup;

  ret = mlk_enc_getnoise_eta1_eta2(sp, ep, epp, coins, context);
  if (ret != 0) goto cleanup;

  mlk_polyvec_ntt(sp);

  mlk_polyvec_mulcache_compute(sp_cache, sp);
  mlk_matvec_mul(b, at, sp, sp_cache);
  mlk_polyvec_basemul_acc_montgomery_cached(v, pkpv, sp, sp_cache);

  mlk_polyvec_invntt_tomont(b);
  mlk_poly_invntt_tomont(v);

  mlk_polyvec_add(b, ep);
  mlk_poly_add(v, epp);
  mlk_poly_add(v, k);

  mlk_polyvec_reduce(b);
  mlk_poly_reduce(v);

  mlk_pack_ciphertext(c, b, v);

cleanup:
  /* Specification: Partially implements
   * @[FIPS203, Section 3.3, Destruction of intermediate values] */
  MLK_FREE(sp_cache, mlk_polyvec_mulcache, 1, context);
  MLK_FREE(epp, mlk_poly, 1, context);
  MLK_FREE(k, mlk_poly, 1, context);
  MLK_FREE(v, mlk_poly, 1, context);
  MLK_FREE(b, mlk_polyvec, 1, context);
  MLK_FREE(ep, mlk_polyvec, 1, context);
  MLK_FREE(pkpv, mlk_polyvec, 1, context);
  MLK_FREE(sp, mlk_polyvec, 1, context);
  MLK_FREE(at, mlk_polymat, 1, context);
  MLK_FREE(seed, uint8_t, MLKEM_SYMBYTES, context);
  return ret;
}
#endif /* !MLK_CONFIG_NO_ENCAPS_API || !MLK_CONFIG_NO_DECAPS_API */

/* Reference: `indcpa_dec()` in the reference implementation @[REF].
 *            - We use a mulcache for the scalar product.
 *            - We include buffer zeroization. */
#if !defined(MLK_CONFIG_NO_DECAPS_API)
MLK_INTERNAL_API
int mlk_indcpa_dec(uint8_t m[MLKEM_INDCPA_MSGBYTES],
                   const uint8_t c[MLKEM_INDCPA_BYTES],
                   const uint8_t sk[MLKEM_INDCPA_SECRETKEYBYTES],
                   MLK_CONFIG_CONTEXT_PARAMETER_TYPE context)
{
  int ret = 0;
  MLK_ALLOC(b, mlk_polyvec, 1, context);
  MLK_ALLOC(skpv, mlk_polyvec, 1, context);
  MLK_ALLOC(v, mlk_poly, 1, context);
  MLK_ALLOC(sb, mlk_poly, 1, context);
  MLK_ALLOC(b_cache, mlk_polyvec_mulcache, 1, context);

  if (b == NULL || skpv == NULL || v == NULL || sb == NULL || b_cache == NULL)
  {
    ret = MLK_ERR_OUT_OF_MEMORY;
    goto cleanup;
  }

  mlk_unpack_ciphertext(b, v, c);
  mlk_unpack_sk(skpv, sk);

  mlk_polyvec_ntt(b);
  mlk_polyvec_mulcache_compute(b_cache, b);
  mlk_polyvec_basemul_acc_montgomery_cached(sb, skpv, b, b_cache);
  mlk_poly_invntt_tomont(sb);

  mlk_poly_sub(v, sb);
  mlk_poly_reduce(v);

  mlk_poly_tomsg(m, v);

cleanup:
  /* Specification: Partially implements
   * @[FIPS203, Section 3.3, Destruction of intermediate values] */
  MLK_FREE(b_cache, mlk_polyvec_mulcache, 1, context);
  MLK_FREE(sb, mlk_poly, 1, context);
  MLK_FREE(v, mlk_poly, 1, context);
  MLK_FREE(skpv, mlk_polyvec, 1, context);
  MLK_FREE(b, mlk_polyvec, 1, context);
  return ret;
}
#endif /* !MLK_CONFIG_NO_DECAPS_API */

/* To facilitate single-compilation-unit (SCU) builds, undefine all macros.
 * Don't modify by hand -- this is auto-generated by scripts/autogen. */
#undef mlk_pack_pk
#undef mlk_unpack_pk
#undef mlk_pack_sk
#undef mlk_unpack_sk
#undef mlk_pack_ciphertext
#undef mlk_unpack_ciphertext
#undef mlk_matvec_mul
#undef mlk_polymat_permute_bitrev_to_custom
#undef mlk_keypair_getnoise_eta1
#undef mlk_enc_getnoise_eta1_eta2
