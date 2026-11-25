/*
 * Copyright (c) The mlkem-native project authors
 * Copyright (c) The mldsa-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* References
 * ==========
 *
 * - [REF_AVX2]
 *   CRYSTALS-Dilithium optimized AVX2 implementation
 *   Bai, Ducas, Kiltz, Lepoint, Lyubashevsky, Schwabe, Seiler, Stehl茅
 *   https://github.com/pq-crystals/dilithium/tree/master/avx2
 */

 /*
  * This file is derived from the public domain
  * AVX2 Dilithium implementation @[REF_AVX2].
  */

/*yaml
  Name: ntt_avx2_asm
  Description: x86_64 AVX2 forward NTT
  Signature: void mld_ntt_avx2_asm(int32_t *r, const int32_t *qdata)
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
    rsi:
      type: buffer
      size_bytes: 2496
      permissions: read-only
      c_parameter: const int32_t *qdata
      description: Precomputed constants (624 x int32_t)
*/

#include "../../../common.h"
#if defined(MLD_ARITH_BACKEND_X86_64_DEFAULT) && \
    !defined(MLD_CONFIG_MULTILEVEL_NO_SHARED)

/*
 * WARNING: This file is auto-derived from the mldsa-native source file
 *   dev/x86_64/src/mldsa_ntt_avx2_asm.S using scripts/simpasm. Do not modify it directly.
 */

#if defined(__ELF__)
.section .text.lc_mldsa_mldsa_ntt_avx2_asm,"ax",@progbits
#else
.section .text$lc_mldsa_mldsa_ntt_avx2_asm,"xr"
#endif
.balign 4
.global MLD_ASM_NAMESPACE(ntt_avx2_asm)
MLD_ASM_FN_SYMBOL(ntt_avx2_asm)

        #if defined(_WIN32)
.cfi_sections .debug_frame
.seh_proc MLD_ASM_NAMESPACE(ntt_avx2_asm)
.seh_endprologue
#endif
.cfi_startproc
        vmovdqa (%rsi), %ymm0
        # Public four-block loop; expansion mechanically equals upstream instructions.
        xorl %eax, %eax
.Llc_ntt_affine0:
        vpbroadcastd 0x84(%rsi), %ymm1
        vpbroadcastd 0x524(%rsi), %ymm2
        vmovdqa (%rdi,%rax), %ymm4
        vmovdqa 0x80(%rdi,%rax), %ymm5
        vmovdqa 0x100(%rdi,%rax), %ymm6
        vmovdqa 0x180(%rdi,%rax), %ymm7
        vmovdqa 0x200(%rdi,%rax), %ymm8
        vmovdqa 0x280(%rdi,%rax), %ymm9
        vmovdqa 0x300(%rdi,%rax), %ymm10
        vmovdqa 0x380(%rdi,%rax), %ymm11
        vpmuldq %ymm1, %ymm8, %ymm13
        vmovshdup %ymm8, %ymm12
        vpmuldq %ymm1, %ymm12, %ymm14
        vpmuldq %ymm2, %ymm8, %ymm8
        vpmuldq %ymm2, %ymm12, %ymm12
        vpmuldq %ymm0, %ymm13, %ymm13
        vpmuldq %ymm0, %ymm14, %ymm14
        vmovshdup %ymm8, %ymm8
        vpblendd $0xaa, %ymm12, %ymm8, %ymm8
        vpsubd %ymm8, %ymm4, %ymm12
        vpaddd %ymm4, %ymm8, %ymm4
        vmovshdup %ymm13, %ymm13
        vpblendd $0xaa, %ymm14, %ymm13, %ymm13
        vpaddd %ymm13, %ymm12, %ymm8
        vpsubd %ymm13, %ymm4, %ymm4
        vpmuldq %ymm1, %ymm9, %ymm13
        vmovshdup %ymm9, %ymm12
        vpmuldq %ymm1, %ymm12, %ymm14
        vpmuldq %ymm2, %ymm9, %ymm9
        vpmuldq %ymm2, %ymm12, %ymm12
        vpmuldq %ymm0, %ymm13, %ymm13
        vpmuldq %ymm0, %ymm14, %ymm14
        vmovshdup %ymm9, %ymm9
        vpblendd $0xaa, %ymm12, %ymm9, %ymm9
        vpsubd %ymm9, %ymm5, %ymm12
        vpaddd %ymm5, %ymm9, %ymm5
        vmovshdup %ymm13, %ymm13
        vpblendd $0xaa, %ymm14, %ymm13, %ymm13
        vpaddd %ymm13, %ymm12, %ymm9
        vpsubd %ymm13, %ymm5, %ymm5
        vpmuldq %ymm1, %ymm10, %ymm13
        vmovshdup %ymm10, %ymm12
        vpmuldq %ymm1, %ymm12, %ymm14
        vpmuldq %ymm2, %ymm10, %ymm10
        vpmuldq %ymm2, %ymm12, %ymm12
        vpmuldq %ymm0, %ymm13, %ymm13
        vpmuldq %ymm0, %ymm14, %ymm14
        vmovshdup %ymm10, %ymm10
        vpblendd $0xaa, %ymm12, %ymm10, %ymm10
        vpsubd %ymm10, %ymm6, %ymm12
        vpaddd %ymm6, %ymm10, %ymm6
        vmovshdup %ymm13, %ymm13
        vpblendd $0xaa, %ymm14, %ymm13, %ymm13
        vpaddd %ymm13, %ymm12, %ymm10
        vpsubd %ymm13, %ymm6, %ymm6
        vpmuldq %ymm1, %ymm11, %ymm13
        vmovshdup %ymm11, %ymm12
        vpmuldq %ymm1, %ymm12, %ymm14
        vpmuldq %ymm2, %ymm11, %ymm11
        vpmuldq %ymm2, %ymm12, %ymm12
        vpmuldq %ymm0, %ymm13, %ymm13
        vpmuldq %ymm0, %ymm14, %ymm14
        vmovshdup %ymm11, %ymm11
        vpblendd $0xaa, %ymm12, %ymm11, %ymm11
        vpsubd %ymm11, %ymm7, %ymm12
        vpaddd %ymm7, %ymm11, %ymm7
        vmovshdup %ymm13, %ymm13
        vpblendd $0xaa, %ymm14, %ymm13, %ymm13
        vpaddd %ymm13, %ymm12, %ymm11
        vpsubd %ymm13, %ymm7, %ymm7
        vpbroadcastd 0x88(%rsi), %ymm1
        vpbroadcastd 0x528(%rsi), %ymm2
        vpmuldq %ymm1, %ymm6, %ymm13
        vmovshdup %ymm6, %ymm12
        vpmuldq %ymm1, %ymm12, %ymm14
        vpmuldq %ymm2, %ymm6, %ymm6
        vpmuldq %ymm2, %ymm12, %ymm12
        vpmuldq %ymm0, %ymm13, %ymm13
        vpmuldq %ymm0, %ymm14, %ymm14
        vmovshdup %ymm6, %ymm6
        vpblendd $0xaa, %ymm12, %ymm6, %ymm6
        vpsubd %ymm6, %ymm4, %ymm12
        vpaddd %ymm6, %ymm4, %ymm4
        vmovshdup %ymm13, %ymm13
        vpblendd $0xaa, %ymm14, %ymm13, %ymm13
        vpaddd %ymm13, %ymm12, %ymm6
        vpsubd %ymm13, %ymm4, %ymm4
        vpmuldq %ymm1, %ymm7, %ymm13
        vmovshdup %ymm7, %ymm12
        vpmuldq %ymm1, %ymm12, %ymm14
        vpmuldq %ymm2, %ymm7, %ymm7
        vpmuldq %ymm2, %ymm12, %ymm12
        vpmuldq %ymm0, %ymm13, %ymm13
        vpmuldq %ymm0, %ymm14, %ymm14
        vmovshdup %ymm7, %ymm7
        vpblendd $0xaa, %ymm12, %ymm7, %ymm7
        vpsubd %ymm7, %ymm5, %ymm12
        vpaddd %ymm7, %ymm5, %ymm5
        vmovshdup %ymm13, %ymm13
        vpblendd $0xaa, %ymm14, %ymm13, %ymm13
        vpaddd %ymm13, %ymm12, %ymm7
        vpsubd %ymm13, %ymm5, %ymm5
        vpbroadcastd 0x8c(%rsi), %ymm1
        vpbroadcastd 0x52c(%rsi), %ymm2
        vpmuldq %ymm1, %ymm10, %ymm13
        vmovshdup %ymm10, %ymm12
        vpmuldq %ymm1, %ymm12, %ymm14
        vpmuldq %ymm2, %ymm10, %ymm10
        vpmuldq %ymm2, %ymm12, %ymm12
        vpmuldq %ymm0, %ymm13, %ymm13
        vpmuldq %ymm0, %ymm14, %ymm14
        vmovshdup %ymm10, %ymm10
        vpblendd $0xaa, %ymm12, %ymm10, %ymm10
        vpsubd %ymm10, %ymm8, %ymm12
        vpaddd %ymm10, %ymm8, %ymm8
        vmovshdup %ymm13, %ymm13
        vpblendd $0xaa, %ymm14, %ymm13, %ymm13
        vpaddd %ymm13, %ymm12, %ymm10
        vpsubd %ymm13, %ymm8, %ymm8
        vpmuldq %ymm1, %ymm11, %ymm13
        vmovshdup %ymm11, %ymm12
        vpmuldq %ymm1, %ymm12, %ymm14
        vpmuldq %ymm2, %ymm11, %ymm11
        vpmuldq %ymm2, %ymm12, %ymm12
        vpmuldq %ymm0, %ymm13, %ymm13
        vpmuldq %ymm0, %ymm14, %ymm14
        vmovshdup %ymm11, %ymm11
        vpblendd $0xaa, %ymm12, %ymm11, %ymm11
        vpsubd %ymm11, %ymm9, %ymm12
        vpaddd %ymm11, %ymm9, %ymm9
        vmovshdup %ymm13, %ymm13
        vpblendd $0xaa, %ymm14, %ymm13, %ymm13
        vpaddd %ymm13, %ymm12, %ymm11
        vpsubd %ymm13, %ymm9, %ymm9
        vmovdqa %ymm4, (%rdi,%rax)
        vmovdqa %ymm5, 0x80(%rdi,%rax)
        vmovdqa %ymm6, 0x100(%rdi,%rax)
        vmovdqa %ymm7, 0x180(%rdi,%rax)
        vmovdqa %ymm8, 0x200(%rdi,%rax)
        vmovdqa %ymm9, 0x280(%rdi,%rax)
        vmovdqa %ymm10, 0x300(%rdi,%rax)
        vmovdqa %ymm11, 0x380(%rdi,%rax)
        addq $32, %rax
        cmpq $128, %rax
        jne .Llc_ntt_affine0
        # Public four-block loop; expansion mechanically equals upstream instructions.
        xorl %eax, %eax
        xorl %ecx, %ecx
        xorl %edx, %edx
.Llc_ntt_affine1:
        vmovdqa (%rdi,%rax), %ymm4
        vmovdqa 0x20(%rdi,%rax), %ymm5
        vmovdqa 0x40(%rdi,%rax), %ymm6
        vmovdqa 0x60(%rdi,%rax), %ymm7
        vmovdqa 0x80(%rdi,%rax), %ymm8
        vmovdqa 0xa0(%rdi,%rax), %ymm9
        vmovdqa 0xc0(%rdi,%rax), %ymm10
        vmovdqa 0xe0(%rdi,%rax), %ymm11
        vpbroadcastd 0x90(%rsi,%rcx), %ymm1
        vpbroadcastd 0x530(%rsi,%rcx), %ymm2
        vpmuldq %ymm1, %ymm8, %ymm13
        vmovshdup %ymm8, %ymm12
        vpmuldq %ymm1, %ymm12, %ymm14
        vpmuldq %ymm2, %ymm8, %ymm8
        vpmuldq %ymm2, %ymm12, %ymm12
        vpmuldq %ymm0, %ymm13, %ymm13
        vpmuldq %ymm0, %ymm14, %ymm14
        vmovshdup %ymm8, %ymm8
        vpblendd $0xaa, %ymm12, %ymm8, %ymm8
        vpsubd %ymm8, %ymm4, %ymm12
        vpaddd %ymm4, %ymm8, %ymm4
        vmovshdup %ymm13, %ymm13
        vpblendd $0xaa, %ymm14, %ymm13, %ymm13
        vpaddd %ymm13, %ymm12, %ymm8
        vpsubd %ymm13, %ymm4, %ymm4
        vpmuldq %ymm1, %ymm9, %ymm13
        vmovshdup %ymm9, %ymm12
        vpmuldq %ymm1, %ymm12, %ymm14
        vpmuldq %ymm2, %ymm9, %ymm9
        vpmuldq %ymm2, %ymm12, %ymm12
        vpmuldq %ymm0, %ymm13, %ymm13
        vpmuldq %ymm0, %ymm14, %ymm14
        vmovshdup %ymm9, %ymm9
        vpblendd $0xaa, %ymm12, %ymm9, %ymm9
        vpsubd %ymm9, %ymm5, %ymm12
        vpaddd %ymm5, %ymm9, %ymm5
        vmovshdup %ymm13, %ymm13
        vpblendd $0xaa, %ymm14, %ymm13, %ymm13
        vpaddd %ymm13, %ymm12, %ymm9
        vpsubd %ymm13, %ymm5, %ymm5
        vpmuldq %ymm1, %ymm10, %ymm13
        vmovshdup %ymm10, %ymm12
        vpmuldq %ymm1, %ymm12, %ymm14
        vpmuldq %ymm2, %ymm10, %ymm10
        vpmuldq %ymm2, %ymm12, %ymm12
        vpmuldq %ymm0, %ymm13, %ymm13
        vpmuldq %ymm0, %ymm14, %ymm14
        vmovshdup %ymm10, %ymm10
        vpblendd $0xaa, %ymm12, %ymm10, %ymm10
        vpsubd %ymm10, %ymm6, %ymm12
        vpaddd %ymm6, %ymm10, %ymm6
        vmovshdup %ymm13, %ymm13
        vpblendd $0xaa, %ymm14, %ymm13, %ymm13
        vpaddd %ymm13, %ymm12, %ymm10
        vpsubd %ymm13, %ymm6, %ymm6
        vpmuldq %ymm1, %ymm11, %ymm13
        vmovshdup %ymm11, %ymm12
        vpmuldq %ymm1, %ymm12, %ymm14
        vpmuldq %ymm2, %ymm11, %ymm11
        vpmuldq %ymm2, %ymm12, %ymm12
        vpmuldq %ymm0, %ymm13, %ymm13
        vpmuldq %ymm0, %ymm14, %ymm14
        vmovshdup %ymm11, %ymm11
        vpblendd $0xaa, %ymm12, %ymm11, %ymm11
        vpsubd %ymm11, %ymm7, %ymm12
        vpaddd %ymm7, %ymm11, %ymm7
        vmovshdup %ymm13, %ymm13
        vpblendd $0xaa, %ymm14, %ymm13, %ymm13
        vpaddd %ymm13, %ymm12, %ymm11
        vpsubd %ymm13, %ymm7, %ymm7
        vperm2i128 $0x20, %ymm8, %ymm4, %ymm3
        vperm2i128 $0x31, %ymm8, %ymm4, %ymm8
        vperm2i128 $0x20, %ymm9, %ymm5, %ymm4
        vperm2i128 $0x31, %ymm9, %ymm5, %ymm9
        vperm2i128 $0x20, %ymm10, %ymm6, %ymm5
        vperm2i128 $0x31, %ymm10, %ymm6, %ymm10
        vperm2i128 $0x20, %ymm11, %ymm7, %ymm6
        vperm2i128 $0x31, %ymm11, %ymm7, %ymm11
        vmovdqa 0xa0(%rsi,%rdx), %ymm1
        vmovdqa 0x540(%rsi,%rdx), %ymm2
        vpmuldq %ymm1, %ymm5, %ymm13
        vmovshdup %ymm5, %ymm12
        vpmuldq %ymm1, %ymm12, %ymm14
        vpmuldq %ymm2, %ymm5, %ymm5
        vpmuldq %ymm2, %ymm12, %ymm12
        vpmuldq %ymm0, %ymm13, %ymm13
        vpmuldq %ymm0, %ymm14, %ymm14
        vmovshdup %ymm5, %ymm5
        vpblendd $0xaa, %ymm12, %ymm5, %ymm5
        vpsubd %ymm5, %ymm3, %ymm12
        vpaddd %ymm5, %ymm3, %ymm3
        vmovshdup %ymm13, %ymm13
        vpblendd $0xaa, %ymm14, %ymm13, %ymm13
        vpaddd %ymm13, %ymm12, %ymm5
        vpsubd %ymm13, %ymm3, %ymm3
        vpmuldq %ymm1, %ymm10, %ymm13
        vmovshdup %ymm10, %ymm12
        vpmuldq %ymm1, %ymm12, %ymm14
        vpmuldq %ymm2, %ymm10, %ymm10
        vpmuldq %ymm2, %ymm12, %ymm12
        vpmuldq %ymm0, %ymm13, %ymm13
        vpmuldq %ymm0, %ymm14, %ymm14
        vmovshdup %ymm10, %ymm10
        vpblendd $0xaa, %ymm12, %ymm10, %ymm10
        vpsubd %ymm10, %ymm8, %ymm12
        vpaddd %ymm10, %ymm8, %ymm8
        vmovshdup %ymm13, %ymm13
        vpblendd $0xaa, %ymm14, %ymm13, %ymm13
        vpaddd %ymm13, %ymm12, %ymm10
        vpsubd %ymm13, %ymm8, %ymm8
        vpmuldq %ymm1, %ymm6, %ymm13
        vmovshdup %ymm6, %ymm12
        vpmuldq %ymm1, %ymm12, %ymm14
        vpmuldq %ymm2, %ymm6, %ymm6
        vpmuldq %ymm2, %ymm12, %ymm12
        vpmuldq %ymm0, %ymm13, %ymm13
        vpmuldq %ymm0, %ymm14, %ymm14
        vmovshdup %ymm6, %ymm6
        vpblendd $0xaa, %ymm12, %ymm6, %ymm6
        vpsubd %ymm6, %ymm4, %ymm12
        vpaddd %ymm6, %ymm4, %ymm4
        vmovshdup %ymm13, %ymm13
        vpblendd $0xaa, %ymm14, %ymm13, %ymm13
        vpaddd %ymm13, %ymm12, %ymm6
        vpsubd %ymm13, %ymm4, %ymm4
        vpmuldq %ymm1, %ymm11, %ymm13
        vmovshdup %ymm11, %ymm12
        vpmuldq %ymm1, %ymm12, %ymm14
        vpmuldq %ymm2, %ymm11, %ymm11
        vpmuldq %ymm2, %ymm12, %ymm12
        vpmuldq %ymm0, %ymm13, %ymm13
        vpmuldq %ymm0, %ymm14, %ymm14
        vmovshdup %ymm11, %ymm11
        vpblendd $0xaa, %ymm12, %ymm11, %ymm11
        vpsubd %ymm11, %ymm9, %ymm12
        vpaddd %ymm11, %ymm9, %ymm9
        vmovshdup %ymm13, %ymm13
        vpblendd $0xaa, %ymm14, %ymm13, %ymm13
        vpaddd %ymm13, %ymm12, %ymm11
        vpsubd %ymm13, %ymm9, %ymm9
        vpunpcklqdq %ymm5, %ymm3, %ymm7
        vpunpckhqdq %ymm5, %ymm3, %ymm5
        vpunpcklqdq %ymm10, %ymm8, %ymm3
        vpunpckhqdq %ymm10, %ymm8, %ymm10
        vpunpcklqdq %ymm6, %ymm4, %ymm8
        vpunpckhqdq %ymm6, %ymm4, %ymm6
        vpunpcklqdq %ymm11, %ymm9, %ymm4
        vpunpckhqdq %ymm11, %ymm9, %ymm11
        vmovdqa 0x120(%rsi,%rdx), %ymm1
        vmovdqa 0x5c0(%rsi,%rdx), %ymm2
        vpmuldq %ymm1, %ymm8, %ymm13
        vmovshdup %ymm8, %ymm12
        vpmuldq %ymm1, %ymm12, %ymm14
        vpmuldq %ymm2, %ymm8, %ymm8
        vpmuldq %ymm2, %ymm12, %ymm12
        vpmuldq %ymm0, %ymm13, %ymm13
        vpmuldq %ymm0, %ymm14, %ymm14
        vmovshdup %ymm8, %ymm8
        vpblendd $0xaa, %ymm12, %ymm8, %ymm8
        vpsubd %ymm8, %ymm7, %ymm12
        vpaddd %ymm7, %ymm8, %ymm7
        vmovshdup %ymm13, %ymm13
        vpblendd $0xaa, %ymm14, %ymm13, %ymm13
        vpaddd %ymm13, %ymm12, %ymm8
        vpsubd %ymm13, %ymm7, %ymm7
        vpmuldq %ymm1, %ymm6, %ymm13
        vmovshdup %ymm6, %ymm12
        vpmuldq %ymm1, %ymm12, %ymm14
        vpmuldq %ymm2, %ymm6, %ymm6
        vpmuldq %ymm2, %ymm12, %ymm12
        vpmuldq %ymm0, %ymm13, %ymm13
        vpmuldq %ymm0, %ymm14, %ymm14
        vmovshdup %ymm6, %ymm6
        vpblendd $0xaa, %ymm12, %ymm6, %ymm6
        vpsubd %ymm6, %ymm5, %ymm12
        vpaddd %ymm6, %ymm5, %ymm5
        vmovshdup %ymm13, %ymm13
        vpblendd $0xaa, %ymm14, %ymm13, %ymm13
        vpaddd %ymm13, %ymm12, %ymm6
        vpsubd %ymm13, %ymm5, %ymm5
        vpmuldq %ymm1, %ymm4, %ymm13
        vmovshdup %ymm4, %ymm12
        vpmuldq %ymm1, %ymm12, %ymm14
        vpmuldq %ymm2, %ymm4, %ymm4
        vpmuldq %ymm2, %ymm12, %ymm12
        vpmuldq %ymm0, %ymm13, %ymm13
        vpmuldq %ymm0, %ymm14, %ymm14
        vmovshdup %ymm4, %ymm4
        vpblendd $0xaa, %ymm12, %ymm4, %ymm4
        vpsubd %ymm4, %ymm3, %ymm12
        vpaddd %ymm4, %ymm3, %ymm3
        vmovshdup %ymm13, %ymm13
        vpblendd $0xaa, %ymm14, %ymm13, %ymm13
        vpaddd %ymm13, %ymm12, %ymm4
        vpsubd %ymm13, %ymm3, %ymm3
        vpmuldq %ymm1, %ymm11, %ymm13
        vmovshdup %ymm11, %ymm12
        vpmuldq %ymm1, %ymm12, %ymm14
        vpmuldq %ymm2, %ymm11, %ymm11
        vpmuldq %ymm2, %ymm12, %ymm12
        vpmuldq %ymm0, %ymm13, %ymm13
        vpmuldq %ymm0, %ymm14, %ymm14
        vmovshdup %ymm11, %ymm11
        vpblendd $0xaa, %ymm12, %ymm11, %ymm11
        vpsubd %ymm11, %ymm10, %ymm12
        vpaddd %ymm11, %ymm10, %ymm10
        vmovshdup %ymm13, %ymm13
        vpblendd $0xaa, %ymm14, %ymm13, %ymm13
        vpaddd %ymm13, %ymm12, %ymm11
        vpsubd %ymm13, %ymm10, %ymm10
        vmovsldup %ymm8, %ymm9
        vpblendd $0xaa, %ymm9, %ymm7, %ymm9
        vpsrlq $0x20, %ymm7, %ymm7
        vpblendd $0xaa, %ymm8, %ymm7, %ymm8
        vmovsldup %ymm6, %ymm7
        vpblendd $0xaa, %ymm7, %ymm5, %ymm7
        vpsrlq $0x20, %ymm5, %ymm5
        vpblendd $0xaa, %ymm6, %ymm5, %ymm6
        vmovsldup %ymm4, %ymm5
        vpblendd $0xaa, %ymm5, %ymm3, %ymm5
        vpsrlq $0x20, %ymm3, %ymm3
        vpblendd $0xaa, %ymm4, %ymm3, %ymm4
        vmovsldup %ymm11, %ymm3
        vpblendd $0xaa, %ymm3, %ymm10, %ymm3
        vpsrlq $0x20, %ymm10, %ymm10
        vpblendd $0xaa, %ymm11, %ymm10, %ymm11
        vmovdqa 0x1a0(%rsi,%rdx), %ymm1
        vmovdqa 0x640(%rsi,%rdx), %ymm2
        vpsrlq $0x20, %ymm1, %ymm10
        vmovshdup %ymm2, %ymm15
        vpmuldq %ymm1, %ymm5, %ymm13
        vmovshdup %ymm5, %ymm12
        vpmuldq %ymm10, %ymm12, %ymm14
        vpmuldq %ymm2, %ymm5, %ymm5
        vpmuldq %ymm15, %ymm12, %ymm12
        vpmuldq %ymm0, %ymm13, %ymm13
        vpmuldq %ymm0, %ymm14, %ymm14
        vmovshdup %ymm5, %ymm5
        vpblendd $0xaa, %ymm12, %ymm5, %ymm5
        vpsubd %ymm5, %ymm9, %ymm12
        vpaddd %ymm5, %ymm9, %ymm9
        vmovshdup %ymm13, %ymm13
        vpblendd $0xaa, %ymm14, %ymm13, %ymm13
        vpaddd %ymm13, %ymm12, %ymm5
        vpsubd %ymm13, %ymm9, %ymm9
        vpmuldq %ymm1, %ymm4, %ymm13
        vmovshdup %ymm4, %ymm12
        vpmuldq %ymm10, %ymm12, %ymm14
        vpmuldq %ymm2, %ymm4, %ymm4
        vpmuldq %ymm15, %ymm12, %ymm12
        vpmuldq %ymm0, %ymm13, %ymm13
        vpmuldq %ymm0, %ymm14, %ymm14
        vmovshdup %ymm4, %ymm4
        vpblendd $0xaa, %ymm12, %ymm4, %ymm4
        vpsubd %ymm4, %ymm8, %ymm12
        vpaddd %ymm4, %ymm8, %ymm8
        vmovshdup %ymm13, %ymm13
        vpblendd $0xaa, %ymm14, %ymm13, %ymm13
        vpaddd %ymm13, %ymm12, %ymm4
        vpsubd %ymm13, %ymm8, %ymm8
        vpmuldq %ymm1, %ymm3, %ymm13
        vmovshdup %ymm3, %ymm12
        vpmuldq %ymm10, %ymm12, %ymm14
        vpmuldq %ymm2, %ymm3, %ymm3
        vpmuldq %ymm15, %ymm12, %ymm12
        vpmuldq %ymm0, %ymm13, %ymm13
        vpmuldq %ymm0, %ymm14, %ymm14
        vmovshdup %ymm3, %ymm3
        vpblendd $0xaa, %ymm12, %ymm3, %ymm3
        vpsubd %ymm3, %ymm7, %ymm12
        vpaddd %ymm3, %ymm7, %ymm7
        vmovshdup %ymm13, %ymm13
        vpblendd $0xaa, %ymm14, %ymm13, %ymm13
        vpaddd %ymm13, %ymm12, %ymm3
        vpsubd %ymm13, %ymm7, %ymm7
        vpmuldq %ymm1, %ymm11, %ymm13
        vmovshdup %ymm11, %ymm12
        vpmuldq %ymm10, %ymm12, %ymm14
        vpmuldq %ymm2, %ymm11, %ymm11
        vpmuldq %ymm15, %ymm12, %ymm12
        vpmuldq %ymm0, %ymm13, %ymm13
        vpmuldq %ymm0, %ymm14, %ymm14
        vmovshdup %ymm11, %ymm11
        vpblendd $0xaa, %ymm12, %ymm11, %ymm11
        vpsubd %ymm11, %ymm6, %ymm12
        vpaddd %ymm6, %ymm11, %ymm6
        vmovshdup %ymm13, %ymm13
        vpblendd $0xaa, %ymm14, %ymm13, %ymm13
        vpaddd %ymm13, %ymm12, %ymm11
        vpsubd %ymm13, %ymm6, %ymm6
        vmovdqa 0x220(%rsi,%rdx), %ymm1
        vmovdqa 0x6c0(%rsi,%rdx), %ymm2
        vpsrlq $0x20, %ymm1, %ymm10
        vmovshdup %ymm2, %ymm15
        vpmuldq %ymm1, %ymm7, %ymm13
        vmovshdup %ymm7, %ymm12
        vpmuldq %ymm10, %ymm12, %ymm14
        vpmuldq %ymm2, %ymm7, %ymm7
        vpmuldq %ymm15, %ymm12, %ymm12
        vpmuldq %ymm0, %ymm13, %ymm13
        vpmuldq %ymm0, %ymm14, %ymm14
        vmovshdup %ymm7, %ymm7
        vpblendd $0xaa, %ymm12, %ymm7, %ymm7
        vpsubd %ymm7, %ymm9, %ymm12
        vpaddd %ymm7, %ymm9, %ymm9
        vmovshdup %ymm13, %ymm13
        vpblendd $0xaa, %ymm14, %ymm13, %ymm13
        vpaddd %ymm13, %ymm12, %ymm7
        vpsubd %ymm13, %ymm9, %ymm9
        vpmuldq %ymm1, %ymm6, %ymm13
        vmovshdup %ymm6, %ymm12
        vpmuldq %ymm10, %ymm12, %ymm14
        vpmuldq %ymm2, %ymm6, %ymm6
        vpmuldq %ymm15, %ymm12, %ymm12
        vpmuldq %ymm0, %ymm13, %ymm13
        vpmuldq %ymm0, %ymm14, %ymm14
        vmovshdup %ymm6, %ymm6
        vpblendd $0xaa, %ymm12, %ymm6, %ymm6
        vpsubd %ymm6, %ymm8, %ymm12
        vpaddd %ymm6, %ymm8, %ymm8
        vmovshdup %ymm13, %ymm13
        vpblendd $0xaa, %ymm14, %ymm13, %ymm13
        vpaddd %ymm13, %ymm12, %ymm6
        vpsubd %ymm13, %ymm8, %ymm8
        vmovdqa 0x2a0(%rsi,%rdx), %ymm1
        vmovdqa 0x740(%rsi,%rdx), %ymm2
        vpsrlq $0x20, %ymm1, %ymm10
        vmovshdup %ymm2, %ymm15
        vpmuldq %ymm1, %ymm3, %ymm13
        vmovshdup %ymm3, %ymm12
        vpmuldq %ymm10, %ymm12, %ymm14
        vpmuldq %ymm2, %ymm3, %ymm3
        vpmuldq %ymm15, %ymm12, %ymm12
        vpmuldq %ymm0, %ymm13, %ymm13
        vpmuldq %ymm0, %ymm14, %ymm14
        vmovshdup %ymm3, %ymm3
        vpblendd $0xaa, %ymm12, %ymm3, %ymm3
        vpsubd %ymm3, %ymm5, %ymm12
        vpaddd %ymm3, %ymm5, %ymm5
        vmovshdup %ymm13, %ymm13
        vpblendd $0xaa, %ymm14, %ymm13, %ymm13
        vpaddd %ymm13, %ymm12, %ymm3
        vpsubd %ymm13, %ymm5, %ymm5
        vpmuldq %ymm1, %ymm11, %ymm13
        vmovshdup %ymm11, %ymm12
        vpmuldq %ymm10, %ymm12, %ymm14
        vpmuldq %ymm2, %ymm11, %ymm11
        vpmuldq %ymm15, %ymm12, %ymm12
        vpmuldq %ymm0, %ymm13, %ymm13
        vpmuldq %ymm0, %ymm14, %ymm14
        vmovshdup %ymm11, %ymm11
        vpblendd $0xaa, %ymm12, %ymm11, %ymm11
        vpsubd %ymm11, %ymm4, %ymm12
        vpaddd %ymm4, %ymm11, %ymm4
        vmovshdup %ymm13, %ymm13
        vpblendd $0xaa, %ymm14, %ymm13, %ymm13
        vpaddd %ymm13, %ymm12, %ymm11
        vpsubd %ymm13, %ymm4, %ymm4
        vmovdqa 0x320(%rsi,%rdx), %ymm1
        vmovdqa 0x7c0(%rsi,%rdx), %ymm2
        vpsrlq $0x20, %ymm1, %ymm10
        vmovshdup %ymm2, %ymm15
        vpmuldq %ymm1, %ymm8, %ymm13
        vmovshdup %ymm8, %ymm12
        vpmuldq %ymm10, %ymm12, %ymm14
        vpmuldq %ymm2, %ymm8, %ymm8
        vpmuldq %ymm15, %ymm12, %ymm12
        vpmuldq %ymm0, %ymm13, %ymm13
        vpmuldq %ymm0, %ymm14, %ymm14
        vmovshdup %ymm8, %ymm8
        vpblendd $0xaa, %ymm12, %ymm8, %ymm8
        vpsubd %ymm8, %ymm9, %ymm12
        vpaddd %ymm8, %ymm9, %ymm9
        vmovshdup %ymm13, %ymm13
        vpblendd $0xaa, %ymm14, %ymm13, %ymm13
        vpaddd %ymm13, %ymm12, %ymm8
        vpsubd %ymm13, %ymm9, %ymm9
        vmovdqa 0x3a0(%rsi,%rdx), %ymm1
        vmovdqa 0x840(%rsi,%rdx), %ymm2
        vpsrlq $0x20, %ymm1, %ymm10
        vmovshdup %ymm2, %ymm15
        vpmuldq %ymm1, %ymm6, %ymm13
        vmovshdup %ymm6, %ymm12
        vpmuldq %ymm10, %ymm12, %ymm14
        vpmuldq %ymm2, %ymm6, %ymm6
        vpmuldq %ymm15, %ymm12, %ymm12
        vpmuldq %ymm0, %ymm13, %ymm13
        vpmuldq %ymm0, %ymm14, %ymm14
        vmovshdup %ymm6, %ymm6
        vpblendd $0xaa, %ymm12, %ymm6, %ymm6
        vpsubd %ymm6, %ymm7, %ymm12
        vpaddd %ymm6, %ymm7, %ymm7
        vmovshdup %ymm13, %ymm13
        vpblendd $0xaa, %ymm14, %ymm13, %ymm13
        vpaddd %ymm13, %ymm12, %ymm6
        vpsubd %ymm13, %ymm7, %ymm7
        vmovdqa 0x420(%rsi,%rdx), %ymm1
        vmovdqa 0x8c0(%rsi,%rdx), %ymm2
        vpsrlq $0x20, %ymm1, %ymm10
        vmovshdup %ymm2, %ymm15
        vpmuldq %ymm1, %ymm4, %ymm13
        vmovshdup %ymm4, %ymm12
        vpmuldq %ymm10, %ymm12, %ymm14
        vpmuldq %ymm2, %ymm4, %ymm4
        vpmuldq %ymm15, %ymm12, %ymm12
        vpmuldq %ymm0, %ymm13, %ymm13
        vpmuldq %ymm0, %ymm14, %ymm14
        vmovshdup %ymm4, %ymm4
        vpblendd $0xaa, %ymm12, %ymm4, %ymm4
        vpsubd %ymm4, %ymm5, %ymm12
        vpaddd %ymm4, %ymm5, %ymm5
        vmovshdup %ymm13, %ymm13
        vpblendd $0xaa, %ymm14, %ymm13, %ymm13
        vpaddd %ymm13, %ymm12, %ymm4
        vpsubd %ymm13, %ymm5, %ymm5
        vmovdqa 0x4a0(%rsi,%rdx), %ymm1
        vmovdqa 0x940(%rsi,%rdx), %ymm2
        vpsrlq $0x20, %ymm1, %ymm10
        vmovshdup %ymm2, %ymm15
        vpmuldq %ymm1, %ymm11, %ymm13
        vmovshdup %ymm11, %ymm12
        vpmuldq %ymm10, %ymm12, %ymm14
        vpmuldq %ymm2, %ymm11, %ymm11
        vpmuldq %ymm15, %ymm12, %ymm12
        vpmuldq %ymm0, %ymm13, %ymm13
        vpmuldq %ymm0, %ymm14, %ymm14
        vmovshdup %ymm11, %ymm11
        vpblendd $0xaa, %ymm12, %ymm11, %ymm11
        vpsubd %ymm11, %ymm3, %ymm12
        vpaddd %ymm3, %ymm11, %ymm3
        vmovshdup %ymm13, %ymm13
        vpblendd $0xaa, %ymm14, %ymm13, %ymm13
        vpaddd %ymm13, %ymm12, %ymm11
        vpsubd %ymm13, %ymm3, %ymm3
        vmovdqa %ymm9, (%rdi,%rax)
        vmovdqa %ymm8, 0x20(%rdi,%rax)
        vmovdqa %ymm7, 0x40(%rdi,%rax)
        vmovdqa %ymm6, 0x60(%rdi,%rax)
        vmovdqa %ymm5, 0x80(%rdi,%rax)
        vmovdqa %ymm4, 0xa0(%rdi,%rax)
        vmovdqa %ymm3, 0xc0(%rdi,%rax)
        vmovdqa %ymm11, 0xe0(%rdi,%rax)
        addq $256, %rax
        addq $4, %rcx
        addq $32, %rdx
        cmpq $1024, %rax
        jne .Llc_ntt_affine1
        vzeroupper
        retq
        .cfi_endproc
#if defined(_WIN32)
.seh_endproc
#endif

MLD_ASM_FN_SIZE(ntt_avx2_asm)

#endif /* MLD_ARITH_BACKEND_X86_64_DEFAULT && !MLD_CONFIG_MULTILEVEL_NO_SHARED \
        */

#if defined(__ELF__)
.section .note.GNU-stack,"",%progbits
#endif
