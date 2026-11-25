/*
 * Copyright (c) The mlkem-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* References
 * ==========
 *
 * - [REF_AVX2]
 *   CRYSTALS-Kyber optimized AVX2 implementation
 *   Bos, Ducas, Kiltz, Lepoint, Lyubashevsky, Schanck, Schwabe, Seiler, Stehlé
 *   https://github.com/pq-crystals/kyber/tree/main/avx2
 */

/*
 * This file is derived from the public domain
 * AVX2 Kyber implementation @[REF_AVX2].
 */

/*************************************************
 * Name:        mlk_poly_compress_d11_avx2_asm
 *
 * Description: Compression of a polynomial to 11 bits per coefficient.
 *
 * Arguments:   - uint8_t *r:       pointer to output byte array
 *                                  (of length MLKEM_POLYCOMPRESSEDBYTES_D11)
 *              - const int16_t *a: pointer to input polynomial
 *              - const uint8_t *data: pointer to constants
 *                                  (srlvqidx[0:32], shufbidx[32:64])
 **************************************************/

#include "../../../common.h"

#if defined(MLK_ARITH_BACKEND_X86_64_DEFAULT) && \
    !defined(MLK_CONFIG_MULTILEVEL_NO_SHARED) && \
    (!defined(MLK_CONFIG_NO_ENCAPS_API) || \
     !defined(MLK_CONFIG_NO_DECAPS_API)) && \
    (defined(MLK_CONFIG_MULTILEVEL_WITH_SHARED) || MLKEM_K == 4)
/*yaml
  Name: poly_compress_d11_avx2_asm
  Description: x86_64 AVX2 polynomial compression (d=11)
  Signature: void mlk_poly_compress_d11_avx2_asm(uint8_t *r, const int16_t *a, const uint8_t *data)
  ABI:
    Architecture: x86_64
    CallingConvention: SysV
    Features: [AVX2]
    rdi:
      type: buffer
      size_bytes: 352
      permissions: write-only
      c_parameter: uint8_t *r
      description: Output compressed polynomial
    rsi:
      type: buffer
      size_bytes: 512
      permissions: read-only
      c_parameter: const int16_t *a
      description: Input polynomial (256 x int16_t)
    rdx:
      type: buffer
      size_bytes: 64
      permissions: read-only
      c_parameter: const uint8_t *data
      description: Precomputed compression constants
*/


/*
 * WARNING: This file is auto-derived from the mlkem-native source file
 *   dev/x86_64/src/mlkem_poly_compress_d11_avx2_asm.S using scripts/simpasm. Do not modify it directly.
 */

/* Project adaptation: four unchanged16-coefficient groups per iteration;
 * four public fixed iterations preserve the original256-coefficient encoding.
 * Constant data, arithmetic, alignment contracts, SysV ABI and SEH stay intact.
 */
.text
.balign 4
.global MLK_ASM_NAMESPACE(poly_compress_d11_avx2_asm)
MLK_ASM_FN_SYMBOL(poly_compress_d11_avx2_asm)

        #if defined(_WIN32)
.cfi_sections .debug_frame
.seh_proc MLK_ASM_NAMESPACE(poly_compress_d11_avx2_asm)
.seh_endprologue
#endif
.cfi_startproc
        movl $0x4ebf4ebf, %eax       # imm = 0x4EBF4EBF
        vmovd %eax, %xmm0
        vpbroadcastd %xmm0, %ymm0
        vpsllw $0x3, %ymm0, %ymm1
        movl $0x240024, %eax         # imm = 0x240024
        vmovd %eax, %xmm2
        vpbroadcastd %xmm2, %ymm2
        movl $0x20002000, %eax       # imm = 0x20002000
        vmovd %eax, %xmm3
        vpbroadcastd %xmm3, %ymm3
        movl $0x7ff07ff, %eax        # imm = 0x7FF07FF
        vmovd %eax, %xmm4
        vpbroadcastd %xmm4, %ymm4
        movabsq $0x800000108000001, %rax # imm = 0x800000108000001
        vmovq %rax, %xmm5
        vpbroadcastq %xmm5, %ymm5
        movl $0xa, %eax
        vmovq %rax, %xmm6
        vpbroadcastq %xmm6, %ymm6
        vmovdqa (%rdx), %ymm7
        vmovdqa 0x20(%rdx), %ymm8
        leaq 512(%rsi), %rax
.L_lc_compress_group4:
        vmovdqa (%rsi), %ymm9
        vpmullw %ymm1, %ymm9, %ymm10
        vpaddw %ymm2, %ymm9, %ymm11
        vpsllw $0x3, %ymm9, %ymm9
        vpmulhw %ymm0, %ymm9, %ymm9
        vpsubw %ymm11, %ymm10, %ymm11
        vpandn %ymm11, %ymm10, %ymm10
        vpsrlw $0xf, %ymm10, %ymm10
        vpsubw %ymm10, %ymm9, %ymm9
        vpmulhrsw %ymm3, %ymm9, %ymm9
        vpand %ymm4, %ymm9, %ymm9
        vpmaddwd %ymm5, %ymm9, %ymm9
        vpsllvd %ymm6, %ymm9, %ymm9
        vpsrldq $0x8, %ymm9, %ymm10     # ymm10 = ymm9[8,9,10,11,12,13,14,15],zero,zero,zero,zero,zero,zero,zero,zero,ymm9[24,25,26,27,28,29,30,31],zero,zero,zero,zero,zero,zero,zero,zero
        vpsrlvq %ymm7, %ymm9, %ymm9
        vpsllq $0x22, %ymm10, %ymm10
        vpaddq %ymm10, %ymm9, %ymm9
        vpshufb %ymm8, %ymm9, %ymm9
        vextracti128 $0x1, %ymm9, %xmm10
        vpblendvb %xmm8, %xmm10, %xmm9, %xmm9
        vmovdqu %xmm9, (%rdi)
        vmovd %xmm10, 0x10(%rdi)
        vpextrw $0x2, %xmm10, 0x14(%rdi)
        vmovdqa 0x20(%rsi), %ymm9
        vpmullw %ymm1, %ymm9, %ymm10
        vpaddw %ymm2, %ymm9, %ymm11
        vpsllw $0x3, %ymm9, %ymm9
        vpmulhw %ymm0, %ymm9, %ymm9
        vpsubw %ymm11, %ymm10, %ymm11
        vpandn %ymm11, %ymm10, %ymm10
        vpsrlw $0xf, %ymm10, %ymm10
        vpsubw %ymm10, %ymm9, %ymm9
        vpmulhrsw %ymm3, %ymm9, %ymm9
        vpand %ymm4, %ymm9, %ymm9
        vpmaddwd %ymm5, %ymm9, %ymm9
        vpsllvd %ymm6, %ymm9, %ymm9
        vpsrldq $0x8, %ymm9, %ymm10     # ymm10 = ymm9[8,9,10,11,12,13,14,15],zero,zero,zero,zero,zero,zero,zero,zero,ymm9[24,25,26,27,28,29,30,31],zero,zero,zero,zero,zero,zero,zero,zero
        vpsrlvq %ymm7, %ymm9, %ymm9
        vpsllq $0x22, %ymm10, %ymm10
        vpaddq %ymm10, %ymm9, %ymm9
        vpshufb %ymm8, %ymm9, %ymm9
        vextracti128 $0x1, %ymm9, %xmm10
        vpblendvb %xmm8, %xmm10, %xmm9, %xmm9
        vmovdqu %xmm9, 0x16(%rdi)
        vmovd %xmm10, 0x26(%rdi)
        vpextrw $0x2, %xmm10, 0x2a(%rdi)
        vmovdqa 0x40(%rsi), %ymm9
        vpmullw %ymm1, %ymm9, %ymm10
        vpaddw %ymm2, %ymm9, %ymm11
        vpsllw $0x3, %ymm9, %ymm9
        vpmulhw %ymm0, %ymm9, %ymm9
        vpsubw %ymm11, %ymm10, %ymm11
        vpandn %ymm11, %ymm10, %ymm10
        vpsrlw $0xf, %ymm10, %ymm10
        vpsubw %ymm10, %ymm9, %ymm9
        vpmulhrsw %ymm3, %ymm9, %ymm9
        vpand %ymm4, %ymm9, %ymm9
        vpmaddwd %ymm5, %ymm9, %ymm9
        vpsllvd %ymm6, %ymm9, %ymm9
        vpsrldq $0x8, %ymm9, %ymm10     # ymm10 = ymm9[8,9,10,11,12,13,14,15],zero,zero,zero,zero,zero,zero,zero,zero,ymm9[24,25,26,27,28,29,30,31],zero,zero,zero,zero,zero,zero,zero,zero
        vpsrlvq %ymm7, %ymm9, %ymm9
        vpsllq $0x22, %ymm10, %ymm10
        vpaddq %ymm10, %ymm9, %ymm9
        vpshufb %ymm8, %ymm9, %ymm9
        vextracti128 $0x1, %ymm9, %xmm10
        vpblendvb %xmm8, %xmm10, %xmm9, %xmm9
        vmovdqu %xmm9, 0x2c(%rdi)
        vmovd %xmm10, 0x3c(%rdi)
        vpextrw $0x2, %xmm10, 0x40(%rdi)
        vmovdqa 0x60(%rsi), %ymm9
        vpmullw %ymm1, %ymm9, %ymm10
        vpaddw %ymm2, %ymm9, %ymm11
        vpsllw $0x3, %ymm9, %ymm9
        vpmulhw %ymm0, %ymm9, %ymm9
        vpsubw %ymm11, %ymm10, %ymm11
        vpandn %ymm11, %ymm10, %ymm10
        vpsrlw $0xf, %ymm10, %ymm10
        vpsubw %ymm10, %ymm9, %ymm9
        vpmulhrsw %ymm3, %ymm9, %ymm9
        vpand %ymm4, %ymm9, %ymm9
        vpmaddwd %ymm5, %ymm9, %ymm9
        vpsllvd %ymm6, %ymm9, %ymm9
        vpsrldq $0x8, %ymm9, %ymm10     # ymm10 = ymm9[8,9,10,11,12,13,14,15],zero,zero,zero,zero,zero,zero,zero,zero,ymm9[24,25,26,27,28,29,30,31],zero,zero,zero,zero,zero,zero,zero,zero
        vpsrlvq %ymm7, %ymm9, %ymm9
        vpsllq $0x22, %ymm10, %ymm10
        vpaddq %ymm10, %ymm9, %ymm9
        vpshufb %ymm8, %ymm9, %ymm9
        vextracti128 $0x1, %ymm9, %xmm10
        vpblendvb %xmm8, %xmm10, %xmm9, %xmm9
        vmovdqu %xmm9, 0x42(%rdi)
        vmovd %xmm10, 0x52(%rdi)
        vpextrw $0x2, %xmm10, 0x56(%rdi)
        addq $128, %rsi
        addq $88, %rdi
        cmpq %rax, %rsi
        jb .L_lc_compress_group4
        vzeroupper
        retq
        .cfi_endproc
#if defined(_WIN32)
.seh_endproc
#endif

MLK_ASM_FN_SIZE(poly_compress_d11_avx2_asm)

#endif /* MLK_ARITH_BACKEND_X86_64_DEFAULT && !MLK_CONFIG_MULTILEVEL_NO_SHARED \
          && (!MLK_CONFIG_NO_ENCAPS_API || !MLK_CONFIG_NO_DECAPS_API) && \
          (MLK_CONFIG_MULTILEVEL_WITH_SHARED || MLKEM_K == 4) */

#if defined(__ELF__)
.section .note.GNU-stack,"",%progbits
#endif
