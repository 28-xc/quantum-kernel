/*
 * Copyright (c) The mldsa-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* References
 * ==========
 *
 * - [REF_AVX2]
 *   CRYSTALS-Dilithium optimized AVX2 implementation
 *   Bai, Ducas, Kiltz, Lepoint, Lyubashevsky, Schwabe, Seiler, Stehlé
 *   https://github.com/pq-crystals/dilithium/tree/master/avx2
 */

/*
 * This file is derived from the public domain
 * AVX2 Dilithium implementation @[REF_AVX2].
 */


/*yaml
  Name: polyz_unpack_19_avx2_asm
  Description: x86_64 AVX2 unpacking of 19-bit packed coefficients.
    Unpack polynomial z with 20-bit packed coefficients (GAMMA1 = 2^19),
    mapping packed [0, 2^20-1] to signed [-(2^19-1), 2^19] via GAMMA1 - x.
  Signature: void mld_polyz_unpack_19_avx2_asm(int32_t *r, const uint8_t *a)
  ABI:
    Architecture: x86_64
    CallingConvention: SysV
    Features: [AVX2]
    rdi:
      type: buffer
      size_bytes: 1024
      permissions: write-only
      c_parameter: int32_t *r
      description: Output polynomial (256 x int32_t)
    rsi:
      type: buffer
      size_bytes: 640
      permissions: read-only
      c_parameter: const uint8_t *a
      description: Packed input bytes
*/

#include "../../../common.h"

#if defined(MLD_ARITH_BACKEND_X86_64_DEFAULT) &&   \
    (!defined(MLD_CONFIG_NO_SIGN_API) ||           \
     !defined(MLD_CONFIG_NO_VERIFY_API)) &&        \
    !defined(MLD_CONFIG_MULTILEVEL_NO_SHARED) &&   \
    (defined(MLD_CONFIG_MULTILEVEL_WITH_SHARED) || \
     (MLD_CONFIG_PARAMETER_SET == 65 || MLD_CONFIG_PARAMETER_SET == 87))


/*
 * WARNING: This file is auto-derived from the mldsa-native source file
 *   dev/x86_64/src/mldsa_polyz_unpack_19_avx2_asm.S using scripts/simpasm. Do not modify it directly.
 */

/* Project adaptation: retain the upstream initializer and first four
 * eight-coefficient groups; a public fixed eight-iteration loop executes the
 * same32 original groups. Standard encoding, SysV ABI and SEH stay intact.
 */
.text
.balign 4
.global MLD_ASM_NAMESPACE(polyz_unpack_19_avx2_asm)
MLD_ASM_FN_SYMBOL(polyz_unpack_19_avx2_asm)

        #if defined(_WIN32)
.cfi_sections .debug_frame
.seh_proc MLD_ASM_NAMESPACE(polyz_unpack_19_avx2_asm)
.seh_endprologue
#endif
.cfi_startproc
        movabsq $-0xfbfcfd00fdff00, %rax # imm = 0xFF040302FF020100
        vmovq %rax, %xmm1
        movabsq $-0xf6f7f800f8f9fb, %rax # imm = 0xFF090807FF070605
        vpinsrq $0x1, %rax, %xmm1, %xmm1
        movabsq $-0xe5e6e700e7e8ea, %rax # imm = 0xFF1A1918FF181716
        vmovq %rax, %xmm5
        movabsq $-0xe0e1e200e2e3e5, %rax # imm = 0xFF1F1E1DFF1D1C1B
        vpinsrq $0x1, %rax, %xmm5, %xmm5
        vinserti128 $0x1, %xmm5, %ymm1, %ymm1
        movabsq $0x400000000, %rax      # imm = 0x400000000
        vmovq %rax, %xmm2
        movabsq $0x400000000, %rax      # imm = 0x400000000
        vpinsrq $0x1, %rax, %xmm2, %xmm2
        vinserti128 $0x1, %xmm2, %ymm2, %ymm2
        movl $0xfffff, %eax          # imm = 0xFFFFF
        vmovd %eax, %xmm3
        vpbroadcastd %xmm3, %ymm3
        movl $0x80000, %eax          # imm = 0x80000
        vmovd %eax, %xmm4
        vpbroadcastd %xmm4, %ymm4
        leaq 1024(%rdi), %rax
.L_lc_polyz_group4:
        vmovdqu (%rsi), %xmm0
        vmovdqu 0x4(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm0, %ymm0
        vpshufb %ymm1, %ymm0, %ymm0
        vpsrlvd %ymm2, %ymm0, %ymm0
        vpand %ymm3, %ymm0, %ymm0
        vpsubd %ymm0, %ymm4, %ymm0
        vmovdqa %ymm0, (%rdi)
        vmovdqu 0x14(%rsi), %xmm0
        vmovdqu 0x18(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm0, %ymm0
        vpshufb %ymm1, %ymm0, %ymm0
        vpsrlvd %ymm2, %ymm0, %ymm0
        vpand %ymm3, %ymm0, %ymm0
        vpsubd %ymm0, %ymm4, %ymm0
        vmovdqa %ymm0, 0x20(%rdi)
        vmovdqu 0x28(%rsi), %xmm0
        vmovdqu 0x2c(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm0, %ymm0
        vpshufb %ymm1, %ymm0, %ymm0
        vpsrlvd %ymm2, %ymm0, %ymm0
        vpand %ymm3, %ymm0, %ymm0
        vpsubd %ymm0, %ymm4, %ymm0
        vmovdqa %ymm0, 0x40(%rdi)
        vmovdqu 0x3c(%rsi), %xmm0
        vmovdqu 0x40(%rsi), %xmm5
        vinserti128 $0x1, %xmm5, %ymm0, %ymm0
        vpshufb %ymm1, %ymm0, %ymm0
        vpsrlvd %ymm2, %ymm0, %ymm0
        vpand %ymm3, %ymm0, %ymm0
        vpsubd %ymm0, %ymm4, %ymm0
        vmovdqa %ymm0, 0x60(%rdi)
        addq $80, %rsi
        addq $128, %rdi
        cmpq %rax, %rdi
        jb .L_lc_polyz_group4
        vzeroupper
        retq
        .cfi_endproc
#if defined(_WIN32)
.seh_endproc
#endif

MLD_ASM_FN_SIZE(polyz_unpack_19_avx2_asm)


#endif /* MLD_ARITH_BACKEND_X86_64_DEFAULT && (!MLD_CONFIG_NO_SIGN_API || \
          !MLD_CONFIG_NO_VERIFY_API) && !MLD_CONFIG_MULTILEVEL_NO_SHARED && \
          (MLD_CONFIG_MULTILEVEL_WITH_SHARED || MLD_CONFIG_PARAMETER_SET == 65 \
          || MLD_CONFIG_PARAMETER_SET == 87) */

#if defined(__ELF__)
.section .note.GNU-stack,"",%progbits
#endif
