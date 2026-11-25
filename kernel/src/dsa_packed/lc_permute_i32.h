/* Copyright (c) 2026 A1-27 project authors
 * SPDX-License-Identifier: Apache-2.0
 * Project contract for the fixed 8x8 transpose within each 64 coefficients.
 * This interface binds the existing native machine-code entity. Its domain
 * is established separately by instruction and bit-basis checks; the upstream
 * declarations and HOL-Light contracts retain their original domains. */
#ifndef LC_PERMUTE_I32_H
#define LC_PERMUTE_I32_H
#if !defined(__AVX2__) || !defined(MLD_ARITH_BACKEND_X86_64_DEFAULT)
#error "The full-int32 permutation interface requires the AVX2 backend"
#endif
#define LC_PERMUTE_STRINGIFY_INNER(x) #x
#define LC_PERMUTE_STRINGIFY(x) LC_PERMUTE_STRINGIFY_INNER(x)
/* Requires AVX2 execution, one disjoint writable 1024-byte object, and a
 * 32-byte-aligned address for the native vmovdqa instructions. Every signed
 * int32 bit pattern is admitted, including INT32_MIN and INT32_MAX. SysV
 * passes the object in rdi; the compiler supplies the Windows-to-SysV bridge. */
MLD_SYSV_ABI
void lc_dsa_permute_i32_asm(int32_t r[256])
    __asm__(LC_PERMUTE_STRINGIFY(MLD_ASM_NAMESPACE(nttunpack_avx2_asm)))
__contract__(
  requires(memory_no_alias(r, 256 * sizeof(int32_t)))
  requires(((uintptr_t)r & 31u) == 0)
  assigns(memory_slice(r, 256 * sizeof(int32_t)))
  ensures(forall(i, 0, 256,
    r[(i & 192u) | ((i & 7u) << 3) | ((i & 56u) >> 3)] ==
      old(*(int32_t (*)[256])r)[i]))
);
static inline void lc_flat_permute_i32(mld_poly *p) {
  lc_dsa_permute_i32_asm(p->coeffs);
}
#undef LC_PERMUTE_STRINGIFY
#undef LC_PERMUTE_STRINGIFY_INNER
#endif
