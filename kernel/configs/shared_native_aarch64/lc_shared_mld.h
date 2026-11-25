/*
 * Copyright (c) The mlkem-native project authors
 * Copyright (c) The mldsa-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 *
 * The six-parameter library owns one copy of each AArch64 permutation in
 * the ML-KEM compilation unit. Both algorithms use the identical state ABI
 * and round constants. Arithmetic backends remain independently selected.
 */
#ifndef LC_SHARED_NATIVE_AARCH64_MLD_H
#define LC_SHARED_NATIVE_AARCH64_MLD_H
#if !defined(__aarch64__)
#error "Shared AArch64 Keccak requires an AArch64 build"
#endif
#define MLD_USE_NATIVE_FIPS202_X1
#define MLD_USE_NATIVE_FIPS202_X4
#ifndef __ASSEMBLER__
#include "src/fips202/native/api.h"
extern const uint64_t lc_base_mlk_keccakf1600_round_constants[24];
void lc_base_mlk_keccak_f1600_x1_scalar_aarch64_asm(uint64_t state[25],
                                                const uint64_t rc[24]);
void lc_base_mlk_keccak_f1600_x4_v8a_scalar_hybrid_aarch64_asm(
    uint64_t state[100], const uint64_t rc[24]);
MLD_MUST_CHECK_RETURN_VALUE
static MLD_INLINE int mld_keccak_f1600_x1_native(uint64_t *state)
{
  lc_base_mlk_keccak_f1600_x1_scalar_aarch64_asm(
      state, lc_base_mlk_keccakf1600_round_constants);
  return MLD_NATIVE_FUNC_SUCCESS;
}
MLD_MUST_CHECK_RETURN_VALUE
static MLD_INLINE int mld_keccak_f1600_x4_native(uint64_t *state)
{
  if (!mld_sys_check_capability(MLD_SYS_CAP_AARCH64_NEON))
    return MLD_NATIVE_FUNC_FALLBACK;
  lc_base_mlk_keccak_f1600_x4_v8a_scalar_hybrid_aarch64_asm(
      state, lc_base_mlk_keccakf1600_round_constants);
  return MLD_NATIVE_FUNC_SUCCESS;
}
#endif
#endif
