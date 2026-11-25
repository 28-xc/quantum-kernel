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
 */

#include "../../../common.h"
#if defined(MLK_ARITH_BACKEND_X86_64_DEFAULT) && \
    !defined(MLK_CONFIG_MULTILEVEL_NO_SHARED)
/*yaml
  Name: ntt_avx2_asm
  Description: x86_64 AVX2 forward NTT
  Signature: void mlk_ntt_avx2_asm(int16_t *r, const int16_t *qdata)
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
 *   dev/x86_64/src/mlkem_ntt_avx2_asm.S using scripts/simpasm. Do not modify it directly.
 */

.text
.balign 4
.global MLK_ASM_NAMESPACE(ntt_avx2_asm)
MLK_ASM_FN_SYMBOL(ntt_avx2_asm)

        #if defined(_WIN32)
.cfi_sections .debug_frame
.seh_proc MLK_ASM_NAMESPACE(ntt_avx2_asm)
.seh_endprologue
#endif
.cfi_startproc
        movl $0xd010d01, %eax        # imm = 0xD010D01
        vmovd %eax, %xmm0
        vpbroadcastd %xmm0, %ymm0
        # Two fixed public blocks; arithmetic and effective addresses match the unrolled source.
        xorl %ecx, %ecx
.Llc_kem_ntt_block0:
        vpbroadcastq 0x40(%rsi), %ymm15
        vmovdqa 0x100(%rdi,%rcx), %ymm8
        vmovdqa 0x120(%rdi,%rcx), %ymm9
        vmovdqa 0x140(%rdi,%rcx), %ymm10
        vmovdqa 0x160(%rdi,%rcx), %ymm11
        vpbroadcastq 0x48(%rsi), %ymm2
        vpmullw %ymm15, %ymm8, %ymm12
        vpmullw %ymm15, %ymm9, %ymm13
        vpmullw %ymm15, %ymm10, %ymm14
        vpmullw %ymm15, %ymm11, %ymm15
        vpmulhw %ymm2, %ymm8, %ymm8
        vpmulhw %ymm2, %ymm9, %ymm9
        vpmulhw %ymm2, %ymm10, %ymm10
        vpmulhw %ymm2, %ymm11, %ymm11
        vmovdqa (%rdi,%rcx), %ymm4
        vmovdqa 0x20(%rdi,%rcx), %ymm5
        vmovdqa 0x40(%rdi,%rcx), %ymm6
        vmovdqa 0x60(%rdi,%rcx), %ymm7
        vpmulhw %ymm0, %ymm12, %ymm12
        vpmulhw %ymm0, %ymm13, %ymm13
        vpmulhw %ymm0, %ymm14, %ymm14
        vpmulhw %ymm0, %ymm15, %ymm15
        vpaddw %ymm8, %ymm4, %ymm3
        vpsubw %ymm8, %ymm4, %ymm8
        vpaddw %ymm9, %ymm5, %ymm4
        vpsubw %ymm9, %ymm5, %ymm9
        vpaddw %ymm10, %ymm6, %ymm5
        vpsubw %ymm10, %ymm6, %ymm10
        vpaddw %ymm11, %ymm7, %ymm6
        vpsubw %ymm11, %ymm7, %ymm11
        vpsubw %ymm12, %ymm3, %ymm3
        vpaddw %ymm12, %ymm8, %ymm8
        vpsubw %ymm13, %ymm4, %ymm4
        vpaddw %ymm13, %ymm9, %ymm9
        vpsubw %ymm14, %ymm5, %ymm5
        vpaddw %ymm14, %ymm10, %ymm10
        vpsubw %ymm15, %ymm6, %ymm6
        vpaddw %ymm15, %ymm11, %ymm11
        vmovdqa %ymm3, (%rdi,%rcx)
        vmovdqa %ymm4, 0x20(%rdi,%rcx)
        vmovdqa %ymm5, 0x40(%rdi,%rcx)
        vmovdqa %ymm6, 0x60(%rdi,%rcx)
        vmovdqa %ymm8, 0x100(%rdi,%rcx)
        vmovdqa %ymm9, 0x120(%rdi,%rcx)
        vmovdqa %ymm10, 0x140(%rdi,%rcx)
        vmovdqa %ymm11, 0x160(%rdi,%rcx)
        addq $128, %rcx
        cmpq $256, %rcx
        jne .Llc_kem_ntt_block0
        # Two fixed public blocks; arithmetic and effective addresses match the unrolled source.
        xorl %edx, %edx
        xorl %ecx, %ecx
.Llc_kem_ntt_block1:
        vmovdqa 0x60(%rsi,%rdx), %ymm15
        vmovdqa 0x80(%rdi,%rcx), %ymm8
        vmovdqa 0xa0(%rdi,%rcx), %ymm9
        vmovdqa 0xc0(%rdi,%rcx), %ymm10
        vmovdqa 0xe0(%rdi,%rcx), %ymm11
        vmovdqa 0x80(%rsi,%rdx), %ymm2
        vpmullw %ymm15, %ymm8, %ymm12
        vpmullw %ymm15, %ymm9, %ymm13
        vpmullw %ymm15, %ymm10, %ymm14
        vpmullw %ymm15, %ymm11, %ymm15
        vpmulhw %ymm2, %ymm8, %ymm8
        vpmulhw %ymm2, %ymm9, %ymm9
        vpmulhw %ymm2, %ymm10, %ymm10
        vpmulhw %ymm2, %ymm11, %ymm11
        vmovdqa (%rdi,%rcx), %ymm4
        vmovdqa 0x20(%rdi,%rcx), %ymm5
        vmovdqa 0x40(%rdi,%rcx), %ymm6
        vmovdqa 0x60(%rdi,%rcx), %ymm7
        vpmulhw %ymm0, %ymm12, %ymm12
        vpmulhw %ymm0, %ymm13, %ymm13
        vpmulhw %ymm0, %ymm14, %ymm14
        vpmulhw %ymm0, %ymm15, %ymm15
        vpaddw %ymm8, %ymm4, %ymm3
        vpsubw %ymm8, %ymm4, %ymm8
        vpaddw %ymm9, %ymm5, %ymm4
        vpsubw %ymm9, %ymm5, %ymm9
        vpaddw %ymm10, %ymm6, %ymm5
        vpsubw %ymm10, %ymm6, %ymm10
        vpaddw %ymm11, %ymm7, %ymm6
        vpsubw %ymm11, %ymm7, %ymm11
        vpsubw %ymm12, %ymm3, %ymm3
        vpaddw %ymm12, %ymm8, %ymm8
        vpsubw %ymm13, %ymm4, %ymm4
        vpaddw %ymm13, %ymm9, %ymm9
        vpsubw %ymm14, %ymm5, %ymm5
        vpaddw %ymm14, %ymm10, %ymm10
        vpsubw %ymm15, %ymm6, %ymm6
        vpaddw %ymm15, %ymm11, %ymm11
        vperm2i128 $0x20, %ymm10, %ymm5, %ymm7
        vperm2i128 $0x31, %ymm10, %ymm5, %ymm10
        vperm2i128 $0x20, %ymm11, %ymm6, %ymm5
        vperm2i128 $0x31, %ymm11, %ymm6, %ymm11
        vmovdqa 0xa0(%rsi,%rdx), %ymm15
        vmovdqa 0xc0(%rsi,%rdx), %ymm2
        vpmullw %ymm15, %ymm7, %ymm12
        vpmullw %ymm15, %ymm10, %ymm13
        vpmullw %ymm15, %ymm5, %ymm14
        vpmullw %ymm15, %ymm11, %ymm15
        vpmulhw %ymm2, %ymm7, %ymm7
        vpmulhw %ymm2, %ymm10, %ymm10
        vpmulhw %ymm2, %ymm5, %ymm5
        vpmulhw %ymm2, %ymm11, %ymm11
        vperm2i128 $0x20, %ymm8, %ymm3, %ymm6
        vperm2i128 $0x31, %ymm8, %ymm3, %ymm8
        vperm2i128 $0x20, %ymm9, %ymm4, %ymm3
        vperm2i128 $0x31, %ymm9, %ymm4, %ymm9
        vpmulhw %ymm0, %ymm12, %ymm12
        vpmulhw %ymm0, %ymm13, %ymm13
        vpmulhw %ymm0, %ymm14, %ymm14
        vpmulhw %ymm0, %ymm15, %ymm15
        vpaddw %ymm7, %ymm6, %ymm4
        vpsubw %ymm7, %ymm6, %ymm7
        vpaddw %ymm10, %ymm8, %ymm6
        vpsubw %ymm10, %ymm8, %ymm10
        vpaddw %ymm5, %ymm3, %ymm8
        vpsubw %ymm5, %ymm3, %ymm5
        vpaddw %ymm11, %ymm9, %ymm3
        vpsubw %ymm11, %ymm9, %ymm11
        vpsubw %ymm12, %ymm4, %ymm4
        vpaddw %ymm12, %ymm7, %ymm7
        vpsubw %ymm13, %ymm6, %ymm6
        vpaddw %ymm13, %ymm10, %ymm10
        vpsubw %ymm14, %ymm8, %ymm8
        vpaddw %ymm14, %ymm5, %ymm5
        vpsubw %ymm15, %ymm3, %ymm3
        vpaddw %ymm15, %ymm11, %ymm11
        vpunpcklqdq %ymm5, %ymm8, %ymm9
        vpunpckhqdq %ymm5, %ymm8, %ymm5
        vpunpcklqdq %ymm11, %ymm3, %ymm8
        vpunpckhqdq %ymm11, %ymm3, %ymm11
        vmovdqa 0xe0(%rsi,%rdx), %ymm15
        vmovdqa 0x100(%rsi,%rdx), %ymm2
        vpmullw %ymm15, %ymm9, %ymm12
        vpmullw %ymm15, %ymm5, %ymm13
        vpmullw %ymm15, %ymm8, %ymm14
        vpmullw %ymm15, %ymm11, %ymm15
        vpmulhw %ymm2, %ymm9, %ymm9
        vpmulhw %ymm2, %ymm5, %ymm5
        vpmulhw %ymm2, %ymm8, %ymm8
        vpmulhw %ymm2, %ymm11, %ymm11
        vpunpcklqdq %ymm7, %ymm4, %ymm3
        vpunpckhqdq %ymm7, %ymm4, %ymm7
        vpunpcklqdq %ymm10, %ymm6, %ymm4
        vpunpckhqdq %ymm10, %ymm6, %ymm10
        vpmulhw %ymm0, %ymm12, %ymm12
        vpmulhw %ymm0, %ymm13, %ymm13
        vpmulhw %ymm0, %ymm14, %ymm14
        vpmulhw %ymm0, %ymm15, %ymm15
        vpaddw %ymm9, %ymm3, %ymm6
        vpsubw %ymm9, %ymm3, %ymm9
        vpaddw %ymm5, %ymm7, %ymm3
        vpsubw %ymm5, %ymm7, %ymm5
        vpaddw %ymm8, %ymm4, %ymm7
        vpsubw %ymm8, %ymm4, %ymm8
        vpaddw %ymm11, %ymm10, %ymm4
        vpsubw %ymm11, %ymm10, %ymm11
        vpsubw %ymm12, %ymm6, %ymm6
        vpaddw %ymm12, %ymm9, %ymm9
        vpsubw %ymm13, %ymm3, %ymm3
        vpaddw %ymm13, %ymm5, %ymm5
        vpsubw %ymm14, %ymm7, %ymm7
        vpaddw %ymm14, %ymm8, %ymm8
        vpsubw %ymm15, %ymm4, %ymm4
        vpaddw %ymm15, %ymm11, %ymm11
        vmovsldup %ymm8, %ymm10
        vpblendd $0xaa, %ymm10, %ymm7, %ymm10
        vpsrlq $0x20, %ymm7, %ymm7
        vpblendd $0xaa, %ymm8, %ymm7, %ymm8
        vmovsldup %ymm11, %ymm7
        vpblendd $0xaa, %ymm7, %ymm4, %ymm7
        vpsrlq $0x20, %ymm4, %ymm4
        vpblendd $0xaa, %ymm11, %ymm4, %ymm11
        vmovdqa 0x120(%rsi,%rdx), %ymm15
        vmovdqa 0x140(%rsi,%rdx), %ymm2
        vpmullw %ymm15, %ymm10, %ymm12
        vpmullw %ymm15, %ymm8, %ymm13
        vpmullw %ymm15, %ymm7, %ymm14
        vpmullw %ymm15, %ymm11, %ymm15
        vpmulhw %ymm2, %ymm10, %ymm10
        vpmulhw %ymm2, %ymm8, %ymm8
        vpmulhw %ymm2, %ymm7, %ymm7
        vpmulhw %ymm2, %ymm11, %ymm11
        vmovsldup %ymm9, %ymm4
        vpblendd $0xaa, %ymm4, %ymm6, %ymm4
        vpsrlq $0x20, %ymm6, %ymm6
        vpblendd $0xaa, %ymm9, %ymm6, %ymm9
        vmovsldup %ymm5, %ymm6
        vpblendd $0xaa, %ymm6, %ymm3, %ymm6
        vpsrlq $0x20, %ymm3, %ymm3
        vpblendd $0xaa, %ymm5, %ymm3, %ymm5
        vpmulhw %ymm0, %ymm12, %ymm12
        vpmulhw %ymm0, %ymm13, %ymm13
        vpmulhw %ymm0, %ymm14, %ymm14
        vpmulhw %ymm0, %ymm15, %ymm15
        vpaddw %ymm10, %ymm4, %ymm3
        vpsubw %ymm10, %ymm4, %ymm10
        vpaddw %ymm8, %ymm9, %ymm4
        vpsubw %ymm8, %ymm9, %ymm8
        vpaddw %ymm7, %ymm6, %ymm9
        vpsubw %ymm7, %ymm6, %ymm7
        vpaddw %ymm11, %ymm5, %ymm6
        vpsubw %ymm11, %ymm5, %ymm11
        vpsubw %ymm12, %ymm3, %ymm3
        vpaddw %ymm12, %ymm10, %ymm10
        vpsubw %ymm13, %ymm4, %ymm4
        vpaddw %ymm13, %ymm8, %ymm8
        vpsubw %ymm14, %ymm9, %ymm9
        vpaddw %ymm14, %ymm7, %ymm7
        vpsubw %ymm15, %ymm6, %ymm6
        vpaddw %ymm15, %ymm11, %ymm11
        vpslld $0x10, %ymm7, %ymm5
        vpblendw $0xaa, %ymm5, %ymm9, %ymm5
        vpsrld $0x10, %ymm9, %ymm9
        vpblendw $0xaa, %ymm7, %ymm9, %ymm7
        vpslld $0x10, %ymm11, %ymm9
        vpblendw $0xaa, %ymm9, %ymm6, %ymm9
        vpsrld $0x10, %ymm6, %ymm6
        vpblendw $0xaa, %ymm11, %ymm6, %ymm11
        vmovdqa 0x160(%rsi,%rdx), %ymm15
        vmovdqa 0x180(%rsi,%rdx), %ymm2
        vpmullw %ymm15, %ymm5, %ymm12
        vpmullw %ymm15, %ymm7, %ymm13
        vpmullw %ymm15, %ymm9, %ymm14
        vpmullw %ymm15, %ymm11, %ymm15
        vpmulhw %ymm2, %ymm5, %ymm5
        vpmulhw %ymm2, %ymm7, %ymm7
        vpmulhw %ymm2, %ymm9, %ymm9
        vpmulhw %ymm2, %ymm11, %ymm11
        vpslld $0x10, %ymm10, %ymm6
        vpblendw $0xaa, %ymm6, %ymm3, %ymm6
        vpsrld $0x10, %ymm3, %ymm3
        vpblendw $0xaa, %ymm10, %ymm3, %ymm10
        vpslld $0x10, %ymm8, %ymm3
        vpblendw $0xaa, %ymm3, %ymm4, %ymm3
        vpsrld $0x10, %ymm4, %ymm4
        vpblendw $0xaa, %ymm8, %ymm4, %ymm8
        vpmulhw %ymm0, %ymm12, %ymm12
        vpmulhw %ymm0, %ymm13, %ymm13
        vpmulhw %ymm0, %ymm14, %ymm14
        vpmulhw %ymm0, %ymm15, %ymm15
        vpaddw %ymm5, %ymm6, %ymm4
        vpsubw %ymm5, %ymm6, %ymm5
        vpaddw %ymm7, %ymm10, %ymm6
        vpsubw %ymm7, %ymm10, %ymm7
        vpaddw %ymm9, %ymm3, %ymm10
        vpsubw %ymm9, %ymm3, %ymm9
        vpaddw %ymm11, %ymm8, %ymm3
        vpsubw %ymm11, %ymm8, %ymm11
        vpsubw %ymm12, %ymm4, %ymm4
        vpaddw %ymm12, %ymm5, %ymm5
        vpsubw %ymm13, %ymm6, %ymm6
        vpaddw %ymm13, %ymm7, %ymm7
        vpsubw %ymm14, %ymm10, %ymm10
        vpaddw %ymm14, %ymm9, %ymm9
        vpsubw %ymm15, %ymm3, %ymm3
        vpaddw %ymm15, %ymm11, %ymm11
        vmovdqa 0x1a0(%rsi,%rdx), %ymm14
        vmovdqa 0x1e0(%rsi,%rdx), %ymm15
        vmovdqa 0x1c0(%rsi,%rdx), %ymm8
        vmovdqa 0x200(%rsi,%rdx), %ymm2
        vpmullw %ymm14, %ymm10, %ymm12
        vpmullw %ymm14, %ymm3, %ymm13
        vpmullw %ymm15, %ymm9, %ymm14
        vpmullw %ymm15, %ymm11, %ymm15
        vpmulhw %ymm8, %ymm10, %ymm10
        vpmulhw %ymm8, %ymm3, %ymm3
        vpmulhw %ymm2, %ymm9, %ymm9
        vpmulhw %ymm2, %ymm11, %ymm11
        vpmulhw %ymm0, %ymm12, %ymm12
        vpmulhw %ymm0, %ymm13, %ymm13
        vpmulhw %ymm0, %ymm14, %ymm14
        vpmulhw %ymm0, %ymm15, %ymm15
        vpaddw %ymm10, %ymm4, %ymm8
        vpsubw %ymm10, %ymm4, %ymm10
        vpaddw %ymm3, %ymm6, %ymm4
        vpsubw %ymm3, %ymm6, %ymm3
        vpaddw %ymm9, %ymm5, %ymm6
        vpsubw %ymm9, %ymm5, %ymm9
        vpaddw %ymm11, %ymm7, %ymm5
        vpsubw %ymm11, %ymm7, %ymm11
        vpsubw %ymm12, %ymm8, %ymm8
        vpaddw %ymm12, %ymm10, %ymm10
        vpsubw %ymm13, %ymm4, %ymm4
        vpaddw %ymm13, %ymm3, %ymm3
        vpsubw %ymm14, %ymm6, %ymm6
        vpaddw %ymm14, %ymm9, %ymm9
        vpsubw %ymm15, %ymm5, %ymm5
        vpaddw %ymm15, %ymm11, %ymm11
        vmovdqa %ymm8, (%rdi,%rcx)
        vmovdqa %ymm4, 0x20(%rdi,%rcx)
        vmovdqa %ymm10, 0x40(%rdi,%rcx)
        vmovdqa %ymm3, 0x60(%rdi,%rcx)
        vmovdqa %ymm6, 0x80(%rdi,%rcx)
        vmovdqa %ymm5, 0xa0(%rdi,%rcx)
        vmovdqa %ymm9, 0xc0(%rdi,%rcx)
        vmovdqa %ymm11, 0xe0(%rdi,%rcx)
        addq $448, %rdx
        addq $256, %rcx
        cmpq $512, %rcx
        jne .Llc_kem_ntt_block1
        vzeroupper
        retq
        .cfi_endproc
#if defined(_WIN32)
.seh_endproc
#endif

MLK_ASM_FN_SIZE(ntt_avx2_asm)

#endif /* MLK_ARITH_BACKEND_X86_64_DEFAULT && !MLK_CONFIG_MULTILEVEL_NO_SHARED \
        */

#if defined(__ELF__)
.section .note.GNU-stack,"",%progbits
#endif
