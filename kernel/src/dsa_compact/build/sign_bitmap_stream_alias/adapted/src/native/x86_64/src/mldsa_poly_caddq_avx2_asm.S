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
  Name: poly_caddq_avx2_asm
  Description: x86_64 AVX2 conditional addition of q to each coefficient.
    For all coefficients of the in/out polynomial, add Q if the coefficient
    is negative.
  Signature: void mld_poly_caddq_avx2_asm(int32_t *r)
  ABI:
    Architecture: x86_64
    CallingConvention: SysV
    Features: [AVX2]
    rdi:
      type: buffer
      size_bytes: 1024
      permissions: read/write
      c_parameter: int32_t *r
      description: Input/output polynomial (256 x int32_t)
*/

#include "../../../common.h"

#if defined(MLD_ARITH_BACKEND_X86_64_DEFAULT) && \
    !defined(MLD_CONFIG_MULTILEVEL_NO_SHARED)


/*
 * WARNING: This file is auto-derived from the mldsa-native source file
 *   dev/x86_64/src/mldsa_poly_caddq_avx2_asm.S using scripts/simpasm. Do not modify it directly.
 */

/* Project adaptation: four unchanged8-coefficient groups execute in
 * eight fixed public iterations. The original SysV contract, alignment,
 * constant arithmetic, CFI and SEH remain. The upstream proof identifies
 * its original body; this changed loop is separately qualified.
 */
.text
.balign 4
.global MLD_ASM_NAMESPACE(poly_caddq_avx2_asm)
MLD_ASM_FN_SYMBOL(poly_caddq_avx2_asm)

        #if defined(_WIN32)
.cfi_sections .debug_frame
.seh_proc MLD_ASM_NAMESPACE(poly_caddq_avx2_asm)
.seh_endprologue
#endif
.cfi_startproc
        vpxor %xmm2, %xmm2, %xmm2
        movl $0x7fe001, %eax         # imm = 0x7FE001
        vmovd %eax, %xmm1
        vpbroadcastd %xmm1, %ymm1
        leaq 1024(%rdi), %rax
.Lcaddq_loop:
        vpcmpgtd (%rdi), %ymm2, %ymm0
        vpand %ymm1, %ymm0, %ymm0
        vpaddd (%rdi), %ymm0, %ymm0
        vmovdqa %ymm0, (%rdi)
        vpcmpgtd 0x20(%rdi), %ymm2, %ymm3
        vpand %ymm1, %ymm3, %ymm3
        vpaddd 0x20(%rdi), %ymm3, %ymm3
        vmovdqa %ymm3, 0x20(%rdi)
        vpcmpgtd 0x40(%rdi), %ymm2, %ymm4
        vpand %ymm1, %ymm4, %ymm4
        vpaddd 0x40(%rdi), %ymm4, %ymm4
        vmovdqa %ymm4, 0x40(%rdi)
        vpcmpgtd 0x60(%rdi), %ymm2, %ymm5
        vpand %ymm1, %ymm5, %ymm5
        vpaddd 0x60(%rdi), %ymm5, %ymm5
        vmovdqa %ymm5, 0x60(%rdi)
        addq $128, %rdi
        cmpq %rax, %rdi
        jne .Lcaddq_loop
        vzeroupper
        retq
        .cfi_endproc
#if defined(_WIN32)
.seh_endproc
#endif

MLD_ASM_FN_SIZE(poly_caddq_avx2_asm)


#endif /* MLD_ARITH_BACKEND_X86_64_DEFAULT && !MLD_CONFIG_MULTILEVEL_NO_SHARED \
        */

#if defined(__ELF__)
.section .note.GNU-stack,"",%progbits
#endif
