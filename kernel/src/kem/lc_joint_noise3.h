/* Copyright (c) 2026 A1-27 project authors
 * SPDX-License-Identifier: Apache-2.0
 * ML-KEM-768: A[2][2] and the three initial CBD streams share their first
 * Keccak permutation. Each lane retains its own SHAKE domain and rate.
 * The public lane is then continued through the scalar XOF interface.
 */
#ifndef LC_KEM_JOINT_NOISE3
#define LC_KEM_JOINT_NOISE3 0
#endif
#if LC_KEM_JOINT_NOISE3
#if !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "Canonical matrix/noise state continuation requires little-endian words"
#endif
_Static_assert(MLKEM_K == 3 && MLKEM_ETA1 == 2, "rank-three eta2 schedule");
_Static_assert(MLKEM_GEN_MATRIX_NBLOCKS >= 2, "initial public XOF buffer");
#if defined(MLK_CONFIG_SERIAL_FIPS202_ONLY)
#error "Joint schedule requires the four-lane permutation interface"
#endif
static MLK_NOINLINE
#if defined(__GNUC__) && !defined(__clang__)
__attribute__((noclone))
#endif
void lc_kem_joint_tail_noise(mlk_poly *tail, mlk_polyvec *noise,
    const uint8_t public_seed[32], const uint8_t private_seed[32],
    lc_kem_matrix4_workspace *workspace)
{
  unsigned lane, count;
  mlk_memset(workspace->state.statex.ctx, 0,
             sizeof(workspace->state.statex.ctx));
  for (lane = 0; lane < 4; ++lane) {
    uint8_t *block = workspace->buf[lane];
    mlk_memset(block, 0, 200);
    mlk_memcpy(block, lane == 3 ? public_seed : private_seed, 32);
    if (lane == 3) {
      block[32] = 2; block[33] = 2; block[34] = 0x1f;
      block[SHAKE128_RATE - 1] = 0x80;
    } else {
      block[32] = (uint8_t)lane; block[33] = 0x1f;
      block[SHAKE256_RATE - 1] = 0x80;
    }
  }
  mlk_keccakf1600x4_xor_bytes(workspace->state.statex.ctx,
      workspace->buf[0], workspace->buf[1], workspace->buf[2],
      workspace->buf[3], 0, 200);
  mlk_keccakf1600x4_permute(workspace->state.statex.ctx);
  /* Extracting complete canonical lanes keeps this code independent of
   * the native permutation's internal register and memory ordering. */
  mlk_keccakf1600x4_extract_bytes(workspace->state.statex.ctx,
      workspace->buf[0], workspace->buf[1], workspace->buf[2],
      workspace->buf[3], 0, 200);
  for (lane = 0; lane < 3; ++lane)
    lc_full_cbd2(&noise->vec[lane], workspace->buf[lane]);
  /* All private lanes have had their last read. The scalar state occupies
   * the same owner; only the public lane is retained for continuation. */
  mlk_memcpy(workspace->state.scalar.ctx, workspace->buf[3], 200);
  mlk_zeroize((uint8_t *)&workspace->state + 200,
              sizeof(workspace->state) - 200);
  for (lane = 0; lane < 3; ++lane)
    mlk_zeroize(workspace->buf[lane], sizeof(workspace->buf[lane]));
  mlk_xof_squeezeblocks(workspace->buf[3] + SHAKE128_RATE,
                        MLKEM_GEN_MATRIX_NBLOCKS - 1,
                        &workspace->state.scalar);
  count = mlk_rej_uniform(tail->coeffs, MLKEM_N, 0, workspace->buf[3],
                         MLKEM_GEN_MATRIX_NBLOCKS * MLK_XOF_RATE);
  while (count < MLKEM_N) {
    mlk_xof_squeezeblocks(workspace->buf[3], 1, &workspace->state.scalar);
    count = mlk_rej_uniform(tail->coeffs, MLKEM_N, count,
                           workspace->buf[3], MLK_XOF_RATE);
  }
  mlk_zeroize(workspace->state.scalar.ctx, 200);
  mlk_zeroize(workspace->buf[3], sizeof(workspace->buf[3]));
}
#endif
