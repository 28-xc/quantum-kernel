/*
 * Copyright (c) The mlkem-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* References
 * ==========
 *
 * - [AVX2_NTT]
 *   Faster AVX2 optimized NTT multiplication for Ring-LWE lattice cryptography.
 *   Gregor Seiler
 *   https://eprint.iacr.org/2018/039
 *
 * - [REF_AVX2]
 *   CRYSTALS-Kyber optimized AVX2 implementation
 *   Bos, Ducas, Kiltz, Lepoint, Lyubashevsky, Schanck, Schwabe, Seiler, Stehlé
 *   https://github.com/pq-crystals/kyber/tree/main/avx2
 */

/*
 * This file is derived from the public domain
 * AVX2 Kyber implementation @[REF_AVX2].
 *
 * The core ideas behind the implementation are described in @[AVX2_NTT].
 *
 * Changes:
 * - Different placement of modular reductions to simplify
 *   reasoning of non-overflow
 */

#include "../../../common.h"
#if defined(MLK_ARITH_BACKEND_X86_64_DEFAULT) && \
    !defined(MLK_CONFIG_MULTILEVEL_NO_SHARED) && \
    (!defined(MLK_CONFIG_NO_ENCAPS_API) || \
     !defined(MLK_CONFIG_NO_DECAPS_API))
/*yaml
  Name: invntt_avx2_asm
  Description: x86_64 AVX2 inverse NTT
  Signature: void mlk_invntt_avx2_asm(int16_t *r, const int16_t *qdata)
  ABI:
    Architecture: x86_64
    CallingConvention: SysV
    Features: [AVX2]
    rdi:
      type: buffer
      size_bytes: 512
      permissions: read/write
      c_parameter: int16_t *r
      description: Input/output polynomial (256 x int16_t)
    rsi:
      type: buffer
      size_bytes: 1248
      permissions: read-only
      c_parameter: const int16_t *qdata
      description: Precomputed constants (624 x int16_t)
*/


/*
 * WARNING: This file is auto-derived from the mlkem-native source file
 *   dev/x86_64/src/mlkem_intt_avx2_asm.S using scripts/simpasm. Do not modify it directly.
 */

.text
.balign 4
.global MLK_ASM_NAMESPACE(invntt_avx2_asm)
MLK_ASM_FN_SYMBOL(invntt_avx2_asm)

        #if defined(_WIN32)
.cfi_sections .debug_frame
.seh_proc MLK_ASM_NAMESPACE(invntt_avx2_asm)
.seh_endprologue
#endif
.cfi_startproc
        movl $0xd010d01, %eax        # imm = 0xD010D01
        vmovd %eax, %xmm0
        vpbroadcastd %xmm0, %ymm0
        # Two fixed public blocks; arithmetic and effective addresses match the unrolled source.
        xorl %ecx, %ecx
        xorl %edx, %edx
.Llc_kem_intt_block0:
        movl $0xd8a1d8a1, %eax
        vmovd %eax, %xmm2
        vpbroadcastd %xmm2, %ymm2
        movl $0x5a105a1, %eax
        vmovd %eax, %xmm3
        vpbroadcastd %xmm3, %ymm3
        vmovdqa (%rdi,%rcx), %ymm4
        vmovdqa 0x40(%rdi,%rcx), %ymm6
        vmovdqa 0x20(%rdi,%rcx), %ymm5
        vmovdqa 0x60(%rdi,%rcx), %ymm7
        vpmullw %ymm2, %ymm4, %ymm12
        vpmulhw %ymm3, %ymm4, %ymm4
        vpmulhw %ymm0, %ymm12, %ymm12
        vpsubw %ymm12, %ymm4, %ymm4
        vpmullw %ymm2, %ymm6, %ymm12
        vpmulhw %ymm3, %ymm6, %ymm6
        vpmulhw %ymm0, %ymm12, %ymm12
        vpsubw %ymm12, %ymm6, %ymm6
        vpmullw %ymm2, %ymm5, %ymm12
        vpmulhw %ymm3, %ymm5, %ymm5
        vpmulhw %ymm0, %ymm12, %ymm12
        vpsubw %ymm12, %ymm5, %ymm5
        vpmullw %ymm2, %ymm7, %ymm12
        vpmulhw %ymm3, %ymm7, %ymm7
        vpmulhw %ymm0, %ymm12, %ymm12
        vpsubw %ymm12, %ymm7, %ymm7
        vmovdqa 0x80(%rdi,%rcx), %ymm8
        vmovdqa 0xc0(%rdi,%rcx), %ymm10
        vmovdqa 0xa0(%rdi,%rcx), %ymm9
        vmovdqa 0xe0(%rdi,%rcx), %ymm11
        vpmullw %ymm2, %ymm8, %ymm12
        vpmulhw %ymm3, %ymm8, %ymm8
        vpmulhw %ymm0, %ymm12, %ymm12
        vpsubw %ymm12, %ymm8, %ymm8
        vpmullw %ymm2, %ymm10, %ymm12
        vpmulhw %ymm3, %ymm10, %ymm10
        vpmulhw %ymm0, %ymm12, %ymm12
        vpsubw %ymm12, %ymm10, %ymm10
        vpmullw %ymm2, %ymm9, %ymm12
        vpmulhw %ymm3, %ymm9, %ymm9
        vpmulhw %ymm0, %ymm12, %ymm12
        vpsubw %ymm12, %ymm9, %ymm9
        vpmullw %ymm2, %ymm11, %ymm12
        vpmulhw %ymm3, %ymm11, %ymm11
        vpmulhw %ymm0, %ymm12, %ymm12
        vpsubw %ymm12, %ymm11, %ymm11
        vpermq $0x4e, 0x3a0(%rsi,%rdx), %ymm15
        vpermq $0x4e, 0x360(%rsi,%rdx), %ymm1
        vpermq $0x4e, 0x3c0(%rsi,%rdx), %ymm2
        vpermq $0x4e, 0x380(%rsi,%rdx), %ymm3
        vmovdqa (%rsi), %ymm12
        vpshufb %ymm12, %ymm15, %ymm15
        vpshufb %ymm12, %ymm1, %ymm1
        vpshufb %ymm12, %ymm2, %ymm2
        vpshufb %ymm12, %ymm3, %ymm3
        vpsubw %ymm4, %ymm6, %ymm12
        vpaddw %ymm6, %ymm4, %ymm4
        vpsubw %ymm5, %ymm7, %ymm13
        vpmullw %ymm15, %ymm12, %ymm6
        vpaddw %ymm7, %ymm5, %ymm5
        vpsubw %ymm8, %ymm10, %ymm14
        vpmullw %ymm15, %ymm13, %ymm7
        vpaddw %ymm10, %ymm8, %ymm8
        vpsubw %ymm9, %ymm11, %ymm15
        vpmullw %ymm1, %ymm14, %ymm10
        vpaddw %ymm11, %ymm9, %ymm9
        vpmullw %ymm1, %ymm15, %ymm11
        vpmulhw %ymm2, %ymm12, %ymm12
        vpmulhw %ymm2, %ymm13, %ymm13
        vpmulhw %ymm3, %ymm14, %ymm14
        vpmulhw %ymm3, %ymm15, %ymm15
        vpmulhw %ymm0, %ymm6, %ymm6
        vpmulhw %ymm0, %ymm7, %ymm7
        vpmulhw %ymm0, %ymm10, %ymm10
        vpmulhw %ymm0, %ymm11, %ymm11
        vpsubw %ymm6, %ymm12, %ymm6
        vpsubw %ymm7, %ymm13, %ymm7
        vpsubw %ymm10, %ymm14, %ymm10
        vpsubw %ymm11, %ymm15, %ymm11
        vpermq $0x4e, 0x320(%rsi,%rdx), %ymm2
        vpermq $0x4e, 0x340(%rsi,%rdx), %ymm3
        vmovdqa (%rsi), %ymm1
        vpshufb %ymm1, %ymm2, %ymm2
        vpshufb %ymm1, %ymm3, %ymm3
        vpsubw %ymm4, %ymm8, %ymm12
        vpaddw %ymm8, %ymm4, %ymm4
        vpsubw %ymm5, %ymm9, %ymm13
        vpmullw %ymm2, %ymm12, %ymm8
        vpaddw %ymm9, %ymm5, %ymm5
        vpsubw %ymm6, %ymm10, %ymm14
        vpmullw %ymm2, %ymm13, %ymm9
        vpaddw %ymm10, %ymm6, %ymm6
        vpsubw %ymm7, %ymm11, %ymm15
        vpmullw %ymm2, %ymm14, %ymm10
        vpaddw %ymm11, %ymm7, %ymm7
        vpmullw %ymm2, %ymm15, %ymm11
        vpmulhw %ymm3, %ymm12, %ymm12
        vpmulhw %ymm3, %ymm13, %ymm13
        vpmulhw %ymm3, %ymm14, %ymm14
        vpmulhw %ymm3, %ymm15, %ymm15
        vpmulhw %ymm0, %ymm8, %ymm8
        vpmulhw %ymm0, %ymm9, %ymm9
        vpmulhw %ymm0, %ymm10, %ymm10
        vpmulhw %ymm0, %ymm11, %ymm11
        vpsubw %ymm8, %ymm12, %ymm8
        vpsubw %ymm9, %ymm13, %ymm9
        vpsubw %ymm10, %ymm14, %ymm10
        vpsubw %ymm11, %ymm15, %ymm11
        vpslld $0x10, %ymm5, %ymm3
        vpblendw $0xaa, %ymm3, %ymm4, %ymm3
        vpsrld $0x10, %ymm4, %ymm4
        vpblendw $0xaa, %ymm5, %ymm4, %ymm5
        vpslld $0x10, %ymm7, %ymm4
        vpblendw $0xaa, %ymm4, %ymm6, %ymm4
        vpsrld $0x10, %ymm6, %ymm6
        vpblendw $0xaa, %ymm7, %ymm6, %ymm7
        vpslld $0x10, %ymm9, %ymm6
        vpblendw $0xaa, %ymm6, %ymm8, %ymm6
        vpsrld $0x10, %ymm8, %ymm8
        vpblendw $0xaa, %ymm9, %ymm8, %ymm9
        vpslld $0x10, %ymm11, %ymm8
        vpblendw $0xaa, %ymm8, %ymm10, %ymm8
        vpsrld $0x10, %ymm10, %ymm10
        vpblendw $0xaa, %ymm11, %ymm10, %ymm11
        vmovdqa 0x20(%rsi), %ymm12
        vpermd 0x2e0(%rsi,%rdx), %ymm12, %ymm2
        vpermd 0x300(%rsi,%rdx), %ymm12, %ymm10
        vpsubw %ymm3, %ymm5, %ymm12
        vpaddw %ymm5, %ymm3, %ymm3
        vpsubw %ymm4, %ymm7, %ymm13
        vpmullw %ymm2, %ymm12, %ymm5
        vpaddw %ymm7, %ymm4, %ymm4
        vpsubw %ymm6, %ymm9, %ymm14
        vpmullw %ymm2, %ymm13, %ymm7
        vpaddw %ymm9, %ymm6, %ymm6
        vpsubw %ymm8, %ymm11, %ymm15
        vpmullw %ymm2, %ymm14, %ymm9
        vpaddw %ymm11, %ymm8, %ymm8
        vpmullw %ymm2, %ymm15, %ymm11
        vpmulhw %ymm10, %ymm12, %ymm12
        vpmulhw %ymm10, %ymm13, %ymm13
        vpmulhw %ymm10, %ymm14, %ymm14
        vpmulhw %ymm10, %ymm15, %ymm15
        vpmulhw %ymm0, %ymm5, %ymm5
        vpmulhw %ymm0, %ymm7, %ymm7
        vpmulhw %ymm0, %ymm9, %ymm9
        vpmulhw %ymm0, %ymm11, %ymm11
        vpsubw %ymm5, %ymm12, %ymm5
        vpsubw %ymm7, %ymm13, %ymm7
        vpsubw %ymm9, %ymm14, %ymm9
        vpsubw %ymm11, %ymm15, %ymm11
        movl $0x4ebf4ebf, %eax
        vmovd %eax, %xmm1
        vpbroadcastd %xmm1, %ymm1
        vpmulhw %ymm1, %ymm3, %ymm12
        vpsraw $0xa, %ymm12, %ymm12
        vpmullw %ymm0, %ymm12, %ymm12
        vpsubw %ymm12, %ymm3, %ymm3
        vmovsldup %ymm4, %ymm10
        vpblendd $0xaa, %ymm10, %ymm3, %ymm10
        vpsrlq $0x20, %ymm3, %ymm3
        vpblendd $0xaa, %ymm4, %ymm3, %ymm4
        vmovsldup %ymm8, %ymm3
        vpblendd $0xaa, %ymm3, %ymm6, %ymm3
        vpsrlq $0x20, %ymm6, %ymm6
        vpblendd $0xaa, %ymm8, %ymm6, %ymm8
        vmovsldup %ymm7, %ymm6
        vpblendd $0xaa, %ymm6, %ymm5, %ymm6
        vpsrlq $0x20, %ymm5, %ymm5
        vpblendd $0xaa, %ymm7, %ymm5, %ymm7
        vmovsldup %ymm11, %ymm5
        vpblendd $0xaa, %ymm5, %ymm9, %ymm5
        vpsrlq $0x20, %ymm9, %ymm9
        vpblendd $0xaa, %ymm11, %ymm9, %ymm11
        vpermq $0x1b, 0x2a0(%rsi,%rdx), %ymm2
        vpermq $0x1b, 0x2c0(%rsi,%rdx), %ymm9
        vpsubw %ymm10, %ymm4, %ymm12
        vpaddw %ymm4, %ymm10, %ymm10
        vpsubw %ymm3, %ymm8, %ymm13
        vpmullw %ymm2, %ymm12, %ymm4
        vpaddw %ymm8, %ymm3, %ymm3
        vpsubw %ymm6, %ymm7, %ymm14
        vpmullw %ymm2, %ymm13, %ymm8
        vpaddw %ymm7, %ymm6, %ymm6
        vpsubw %ymm5, %ymm11, %ymm15
        vpmullw %ymm2, %ymm14, %ymm7
        vpaddw %ymm11, %ymm5, %ymm5
        vpmullw %ymm2, %ymm15, %ymm11
        vpmulhw %ymm9, %ymm12, %ymm12
        vpmulhw %ymm9, %ymm13, %ymm13
        vpmulhw %ymm9, %ymm14, %ymm14
        vpmulhw %ymm9, %ymm15, %ymm15
        vpmulhw %ymm0, %ymm4, %ymm4
        vpmulhw %ymm0, %ymm8, %ymm8
        vpmulhw %ymm0, %ymm7, %ymm7
        vpmulhw %ymm0, %ymm11, %ymm11
        vpsubw %ymm4, %ymm12, %ymm4
        vpsubw %ymm8, %ymm13, %ymm8
        vpsubw %ymm7, %ymm14, %ymm7
        vpsubw %ymm11, %ymm15, %ymm11
        vpmulhw %ymm1, %ymm10, %ymm12
        vpsraw $0xa, %ymm12, %ymm12
        vpmullw %ymm0, %ymm12, %ymm12
        vpsubw %ymm12, %ymm10, %ymm10
        vpunpcklqdq %ymm3, %ymm10, %ymm9
        vpunpckhqdq %ymm3, %ymm10, %ymm3
        vpunpcklqdq %ymm5, %ymm6, %ymm10
        vpunpckhqdq %ymm5, %ymm6, %ymm5
        vpunpcklqdq %ymm8, %ymm4, %ymm6
        vpunpckhqdq %ymm8, %ymm4, %ymm8
        vpunpcklqdq %ymm11, %ymm7, %ymm4
        vpunpckhqdq %ymm11, %ymm7, %ymm11
        vpermq $0x4e, 0x260(%rsi,%rdx), %ymm2
        vpermq $0x4e, 0x280(%rsi,%rdx), %ymm7
        vpsubw %ymm9, %ymm3, %ymm12
        vpaddw %ymm3, %ymm9, %ymm9
        vpsubw %ymm10, %ymm5, %ymm13
        vpmullw %ymm2, %ymm12, %ymm3
        vpaddw %ymm5, %ymm10, %ymm10
        vpsubw %ymm6, %ymm8, %ymm14
        vpmullw %ymm2, %ymm13, %ymm5
        vpaddw %ymm8, %ymm6, %ymm6
        vpsubw %ymm4, %ymm11, %ymm15
        vpmullw %ymm2, %ymm14, %ymm8
        vpaddw %ymm11, %ymm4, %ymm4
        vpmullw %ymm2, %ymm15, %ymm11
        vpmulhw %ymm7, %ymm12, %ymm12
        vpmulhw %ymm7, %ymm13, %ymm13
        vpmulhw %ymm7, %ymm14, %ymm14
        vpmulhw %ymm7, %ymm15, %ymm15
        vpmulhw %ymm0, %ymm3, %ymm3
        vpmulhw %ymm0, %ymm5, %ymm5
        vpmulhw %ymm0, %ymm8, %ymm8
        vpmulhw %ymm0, %ymm11, %ymm11
        vpsubw %ymm3, %ymm12, %ymm3
        vpsubw %ymm5, %ymm13, %ymm5
        vpsubw %ymm8, %ymm14, %ymm8
        vpsubw %ymm11, %ymm15, %ymm11
        vpmulhw %ymm1, %ymm9, %ymm12
        vpsraw $0xa, %ymm12, %ymm12
        vpmullw %ymm0, %ymm12, %ymm12
        vpsubw %ymm12, %ymm9, %ymm9
        vperm2i128 $0x20, %ymm10, %ymm9, %ymm7
        vperm2i128 $0x31, %ymm10, %ymm9, %ymm10
        vperm2i128 $0x20, %ymm4, %ymm6, %ymm9
        vperm2i128 $0x31, %ymm4, %ymm6, %ymm4
        vperm2i128 $0x20, %ymm5, %ymm3, %ymm6
        vperm2i128 $0x31, %ymm5, %ymm3, %ymm5
        vperm2i128 $0x20, %ymm11, %ymm8, %ymm3
        vperm2i128 $0x31, %ymm11, %ymm8, %ymm11
        vmovdqa 0x220(%rsi,%rdx), %ymm2
        vmovdqa 0x240(%rsi,%rdx), %ymm8
        vpsubw %ymm7, %ymm10, %ymm12
        vpaddw %ymm10, %ymm7, %ymm7
        vpsubw %ymm9, %ymm4, %ymm13
        vpmullw %ymm2, %ymm12, %ymm10
        vpaddw %ymm4, %ymm9, %ymm9
        vpsubw %ymm6, %ymm5, %ymm14
        vpmullw %ymm2, %ymm13, %ymm4
        vpaddw %ymm5, %ymm6, %ymm6
        vpsubw %ymm3, %ymm11, %ymm15
        vpmullw %ymm2, %ymm14, %ymm5
        vpaddw %ymm11, %ymm3, %ymm3
        vpmullw %ymm2, %ymm15, %ymm11
        vpmulhw %ymm8, %ymm12, %ymm12
        vpmulhw %ymm8, %ymm13, %ymm13
        vpmulhw %ymm8, %ymm14, %ymm14
        vpmulhw %ymm8, %ymm15, %ymm15
        vpmulhw %ymm0, %ymm10, %ymm10
        vpmulhw %ymm0, %ymm4, %ymm4
        vpmulhw %ymm0, %ymm5, %ymm5
        vpmulhw %ymm0, %ymm11, %ymm11
        vpsubw %ymm10, %ymm12, %ymm10
        vpsubw %ymm4, %ymm13, %ymm4
        vpsubw %ymm5, %ymm14, %ymm5
        vpsubw %ymm11, %ymm15, %ymm11
        vpmulhw %ymm1, %ymm7, %ymm12
        vpsraw $0xa, %ymm12, %ymm12
        vpmullw %ymm0, %ymm12, %ymm12
        vpsubw %ymm12, %ymm7, %ymm7
        vmovdqa %ymm7, (%rdi,%rcx)
        vmovdqa %ymm9, 0x20(%rdi,%rcx)
        vmovdqa %ymm6, 0x40(%rdi,%rcx)
        vmovdqa %ymm3, 0x60(%rdi,%rcx)
        vmovdqa %ymm10, 0x80(%rdi,%rcx)
        vmovdqa %ymm4, 0xa0(%rdi,%rcx)
        vmovdqa %ymm5, 0xc0(%rdi,%rcx)
        vmovdqa %ymm11, 0xe0(%rdi,%rcx)
        addq $256, %rcx
        addq $-448, %rdx
        cmpq $512, %rcx
        jne .Llc_kem_intt_block0
        # Two fixed public blocks; arithmetic and effective addresses match the unrolled source.
        xorl %ecx, %ecx
.Llc_kem_intt_block1:
        vmovdqa (%rdi,%rcx), %ymm4
        vmovdqa 0x100(%rdi,%rcx), %ymm8
        vmovdqa 0x20(%rdi,%rcx), %ymm5
        vmovdqa 0x120(%rdi,%rcx), %ymm9
        vpbroadcastq 0x40(%rsi), %ymm2
        vmovdqa 0x40(%rdi,%rcx), %ymm6
        vmovdqa 0x140(%rdi,%rcx), %ymm10
        vmovdqa 0x60(%rdi,%rcx), %ymm7
        vmovdqa 0x160(%rdi,%rcx), %ymm11
        vpbroadcastq 0x48(%rsi), %ymm3
        vpsubw %ymm4, %ymm8, %ymm12
        vpaddw %ymm8, %ymm4, %ymm4
        vpsubw %ymm5, %ymm9, %ymm13
        vpmullw %ymm2, %ymm12, %ymm8
        vpaddw %ymm9, %ymm5, %ymm5
        vpsubw %ymm6, %ymm10, %ymm14
        vpmullw %ymm2, %ymm13, %ymm9
        vpaddw %ymm10, %ymm6, %ymm6
        vpsubw %ymm7, %ymm11, %ymm15
        vpmullw %ymm2, %ymm14, %ymm10
        vpaddw %ymm11, %ymm7, %ymm7
        vpmullw %ymm2, %ymm15, %ymm11
        vpmulhw %ymm3, %ymm12, %ymm12
        vpmulhw %ymm3, %ymm13, %ymm13
        vpmulhw %ymm3, %ymm14, %ymm14
        vpmulhw %ymm3, %ymm15, %ymm15
        vpmulhw %ymm0, %ymm8, %ymm8
        vpmulhw %ymm0, %ymm9, %ymm9
        vpmulhw %ymm0, %ymm10, %ymm10
        vpmulhw %ymm0, %ymm11, %ymm11
        vpsubw %ymm8, %ymm12, %ymm8
        vpsubw %ymm9, %ymm13, %ymm9
        vpsubw %ymm10, %ymm14, %ymm10
        vpsubw %ymm11, %ymm15, %ymm11
        vmovdqa %ymm4, (%rdi,%rcx)
        vmovdqa %ymm5, 0x20(%rdi,%rcx)
        vmovdqa %ymm6, 0x40(%rdi,%rcx)
        vmovdqa %ymm7, 0x60(%rdi,%rcx)
        vmovdqa %ymm8, 0x100(%rdi,%rcx)
        vmovdqa %ymm9, 0x120(%rdi,%rcx)
        vmovdqa %ymm10, 0x140(%rdi,%rcx)
        vmovdqa %ymm11, 0x160(%rdi,%rcx)
        addq $128, %rcx
        cmpq $256, %rcx
        jne .Llc_kem_intt_block1
        vzeroupper
        retq
        .cfi_endproc
#if defined(_WIN32)
.seh_endproc
#endif

MLK_ASM_FN_SIZE(invntt_avx2_asm)

#endif /* MLK_ARITH_BACKEND_X86_64_DEFAULT && !MLK_CONFIG_MULTILEVEL_NO_SHARED \
          && (!MLK_CONFIG_NO_ENCAPS_API || !MLK_CONFIG_NO_DECAPS_API) */

#if defined(__ELF__)
.section .note.GNU-stack,"",%progbits
#endif
