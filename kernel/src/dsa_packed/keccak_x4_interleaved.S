/* Copyright (c) The mlkem-native project authors
 * Copyright (c) The mldsa-native project authors
 * Copyright (c) 2026 A1-27 project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 * Derived unchanged round arithmetic from native AVX2 Keccak.
 * Internal state: 25 four-lane vectors ordered by slot_to_word in header.
 * SysV ABI: rdi=800B state, rsi=24 round constants, rdx=rho8, rcx=rho56.
 * Exact-sized memory reads use vmovdqu; state alignment is unrestricted.
 */
.text
.balign 32
.global lc_keccak_x4_interleaved
#if defined(__ELF__)
.type lc_keccak_x4_interleaved,@function
#endif
lc_keccak_x4_interleaved:
        #if defined(_WIN32)
.cfi_sections .debug_frame
.seh_proc lc_keccak_x4_interleaved
.seh_endprologue
#endif
.cfi_startproc
        vmovdqu 0x200(%rdi), %ymm10
        vmovdqu 0x220(%rdi), %ymm14
        vmovdqu 0x240(%rdi), %ymm8
        vmovdqu 0x260(%rdi), %ymm15
        vmovdqu 0x280(%rdi), %ymm9
        vmovdqu 0x2a0(%rdi), %ymm13
        vmovdqu 0x2c0(%rdi), %ymm3
        vmovdqu 0x2e0(%rdi), %ymm7
        vmovdqu 0x300(%rdi), %ymm2
        movq $0, %r10
.Llc_keccak_interleaved_round:
        vmovdqu 0xa0(%rdi), %ymm4
        vpxor 0x1c0(%rdi), %ymm9, %ymm0
        vmovdqu %ymm9, 0x200(%rdi)
        vmovdqu %ymm10, %ymm9
        vmovdqu 0xc0(%rdi), %ymm11
        vmovdqu 0x160(%rdi), %ymm12
        vmovdqu %ymm3, 0x240(%rdi)
        vpxor 0x100(%rdi), %ymm4, %ymm1
        vmovdqu 0x40(%rdi), %ymm10
        vmovdqu %ymm4, 0x220(%rdi)
        vpxor %ymm3, %ymm12, %ymm12
        vmovdqu 0x20(%rdi), %ymm6
        vmovdqu 0x140(%rdi), %ymm4
        vmovdqu %ymm14, 0x2a0(%rdi)
        vpxor %ymm1, %ymm0, %ymm0
        vpxor %ymm8, %ymm11, %ymm1
        vpxor 0x180(%rdi), %ymm7, %ymm11
        vmovdqu %ymm10, 0x280(%rdi)
        vpxor %ymm1, %ymm12, %ymm12
        vpxor %ymm15, %ymm9, %ymm1
        vmovdqu 0xe0(%rdi), %ymm3
        vmovdqu %ymm8, 0x260(%rdi)
        vpxor %ymm1, %ymm11, %ymm11
        vpxor 0x120(%rdi), %ymm14, %ymm1
        vpxor %ymm6, %ymm12, %ymm12
        vmovdqu 0x60(%rdi), %ymm8
        vpxor %ymm10, %ymm11, %ymm11
        vpxor 0x1e0(%rdi), %ymm13, %ymm10
        vpxor %ymm4, %ymm3, %ymm3
        vmovdqu %ymm4, 0x2c0(%rdi)
        vpsrlq $0x3f, %ymm12, %ymm4
        vpsrlq $0x3f, %ymm11, %ymm5
        vpxor (%rdi), %ymm0, %ymm0
        vpxor %ymm1, %ymm10, %ymm10
        vmovdqu 0x80(%rdi), %ymm1
        vpxor %ymm8, %ymm10, %ymm10
        vmovdqu %ymm1, %ymm14
        vpxor 0x1a0(%rdi), %ymm2, %ymm1
        vmovdqu %ymm14, 0x2e0(%rdi)
        vpxor %ymm3, %ymm1, %ymm1
        vpsllq $0x1, %ymm12, %ymm3
        vpor %ymm4, %ymm3, %ymm3
        vpsllq $0x1, %ymm11, %ymm4
        vpxor %ymm14, %ymm1, %ymm1
        vpor %ymm5, %ymm4, %ymm4
        vpsrlq $0x3f, %ymm10, %ymm14
        vpxor %ymm1, %ymm3, %ymm3
        vpsllq $0x1, %ymm10, %ymm5
        vpxor %ymm0, %ymm4, %ymm4
        vpor %ymm14, %ymm5, %ymm5
        vpxor %ymm6, %ymm4, %ymm6
        vpxor %ymm12, %ymm5, %ymm5
        vpsrlq $0x3f, %ymm1, %ymm12
        vpsllq $0x1, %ymm1, %ymm1
        vpxor %ymm7, %ymm5, %ymm7
        vpxor %ymm9, %ymm5, %ymm9
        vpor %ymm12, %ymm1, %ymm1
        vpxor (%rdi), %ymm3, %ymm12
        vpxor %ymm11, %ymm1, %ymm1
        vpsrlq $0x3f, %ymm0, %ymm11
        vpsllq $0x1, %ymm0, %ymm0
        vpxor %ymm13, %ymm1, %ymm13
        vpxor %ymm8, %ymm1, %ymm8
        vpor %ymm11, %ymm0, %ymm0
        vpxor %ymm10, %ymm0, %ymm0
        vpxor 0xc0(%rdi), %ymm4, %ymm10
        vpxor %ymm2, %ymm0, %ymm2
        vpsrlq $0x14, %ymm10, %ymm11
        vpsllq $0x2c, %ymm10, %ymm10
        vpor %ymm11, %ymm10, %ymm10
        vpxor %ymm15, %ymm5, %ymm11
        vpbroadcastq (%rsi), %ymm15
        vpsrlq $0x15, %ymm11, %ymm14
        vpsllq $0x2b, %ymm11, %ymm11
        vpor %ymm14, %ymm11, %ymm11
        vpandn %ymm11, %ymm10, %ymm14
        vpxor %ymm15, %ymm14, %ymm14
        vpxor %ymm12, %ymm14, %ymm15
        vpsrlq $0x2b, %ymm13, %ymm14
        vpsllq $0x15, %ymm13, %ymm13
        vmovdqu %ymm15, (%rdi)
        vpor %ymm14, %ymm13, %ymm13
        vpandn %ymm13, %ymm11, %ymm14
        vpxor %ymm10, %ymm14, %ymm15
        vpsrlq $0x32, %ymm2, %ymm14
        vpsllq $0xe, %ymm2, %ymm2
        vmovdqu %ymm15, 0x20(%rdi)
        vpor %ymm14, %ymm2, %ymm2
        vpandn %ymm2, %ymm13, %ymm14
        vpxor %ymm11, %ymm14, %ymm11
        vmovdqu %ymm11, 0x40(%rdi)
        vpandn %ymm12, %ymm2, %ymm11
        vpandn %ymm10, %ymm12, %ymm12
        vpxor %ymm13, %ymm11, %ymm11
        vmovdqu %ymm11, 0x60(%rdi)
        vpxor %ymm2, %ymm12, %ymm11
        vpsrlq $0x24, %ymm8, %ymm2
        vpsllq $0x1c, %ymm8, %ymm8
        vmovdqu %ymm11, 0x80(%rdi)
        vpor %ymm2, %ymm8, %ymm8
        vpxor 0xe0(%rdi), %ymm0, %ymm2
        vpsrlq $0x2c, %ymm2, %ymm10
        vpsllq $0x14, %ymm2, %ymm2
        vpor %ymm10, %ymm2, %ymm2
        vpxor 0x100(%rdi), %ymm3, %ymm10
        vpsrlq $0x3d, %ymm10, %ymm11
        vpsllq $0x3, %ymm10, %ymm10
        vpor %ymm11, %ymm10, %ymm10
        vpandn %ymm10, %ymm2, %ymm11
        vpxor %ymm8, %ymm11, %ymm11
        vmovdqu %ymm11, 0xa0(%rdi)
        vpxor 0x160(%rdi), %ymm4, %ymm11
        vpsrlq $0x13, %ymm11, %ymm12
        vpsllq $0x2d, %ymm11, %ymm11
        vpor %ymm12, %ymm11, %ymm11
        vpandn %ymm11, %ymm10, %ymm12
        vpxor %ymm2, %ymm12, %ymm12
        vmovdqu %ymm12, 0xc0(%rdi)
        vpsrlq $0x3, %ymm7, %ymm12
        vpsllq $0x3d, %ymm7, %ymm7
        vpor %ymm12, %ymm7, %ymm7
        vpandn %ymm7, %ymm11, %ymm12
        vpxor %ymm10, %ymm12, %ymm10
        vpandn %ymm8, %ymm7, %ymm12
        vpandn %ymm2, %ymm8, %ymm8
        vpsrlq $0x3f, %ymm6, %ymm2
        vpsllq $0x1, %ymm6, %ymm6
        vpxor %ymm11, %ymm12, %ymm14
        vpor %ymm2, %ymm6, %ymm6
        vpsrlq $0x3a, %ymm9, %ymm2
        vpxor %ymm7, %ymm8, %ymm12
        vpsllq $0x6, %ymm9, %ymm9
        vmovdqu %ymm12, 0xe0(%rdi)
        vpxor 0x1a0(%rdi), %ymm0, %ymm7
        vpor %ymm2, %ymm9, %ymm9
        vpxor 0x120(%rdi), %ymm1, %ymm2
        vpshufb (%rdx), %ymm7, %ymm7
        vpsrlq $0x27, %ymm2, %ymm11
        vpsllq $0x19, %ymm2, %ymm2
        vpor %ymm2, %ymm11, %ymm11
        vpandn %ymm11, %ymm9, %ymm2
        vpandn %ymm7, %ymm11, %ymm8
        vpxor %ymm6, %ymm2, %ymm12
        vpxor 0x1c0(%rdi), %ymm3, %ymm2
        vpxor %ymm9, %ymm8, %ymm8
        vmovdqu %ymm12, 0x100(%rdi)
        vpsrlq $0x2e, %ymm2, %ymm12
        vpsllq $0x12, %ymm2, %ymm2
        vpor %ymm2, %ymm12, %ymm2
        vpandn %ymm2, %ymm7, %ymm12
        vpxor %ymm11, %ymm12, %ymm15
        vpandn %ymm6, %ymm2, %ymm11
        vpandn %ymm9, %ymm6, %ymm6
        vpxor %ymm7, %ymm11, %ymm12
        vmovdqu %ymm12, 0x120(%rdi)
        vpxor %ymm2, %ymm6, %ymm12
        vpxor 0x2e0(%rdi), %ymm0, %ymm6
        vpxor 0x2c0(%rdi), %ymm0, %ymm0
        vmovdqu %ymm12, 0x140(%rdi)
        vpsrlq $0x25, %ymm6, %ymm2
        vpsllq $0x1b, %ymm6, %ymm6
        vpor %ymm6, %ymm2, %ymm2
        vpxor 0x220(%rdi), %ymm3, %ymm6
        vpxor 0x200(%rdi), %ymm3, %ymm3
        vpsrlq $0x1c, %ymm6, %ymm7
        vpsllq $0x24, %ymm6, %ymm6
        vpor %ymm6, %ymm7, %ymm7
        vpxor 0x260(%rdi), %ymm4, %ymm6
        vpxor 0x240(%rdi), %ymm4, %ymm4
        vpsrlq $0x36, %ymm6, %ymm12
        vpsllq $0xa, %ymm6, %ymm6
        vpor %ymm6, %ymm12, %ymm12
        vpxor 0x180(%rdi), %ymm5, %ymm6
        vpxor 0x280(%rdi), %ymm5, %ymm5
        vpandn %ymm12, %ymm7, %ymm9
        vpsrlq $0x31, %ymm6, %ymm11
        vpsllq $0xf, %ymm6, %ymm6
        vpxor %ymm2, %ymm9, %ymm9
        vpor %ymm6, %ymm11, %ymm11
        vpandn %ymm11, %ymm12, %ymm6
        vpxor %ymm7, %ymm6, %ymm6
        vmovdqu %ymm6, 0x160(%rdi)
        vpxor 0x1e0(%rdi), %ymm1, %ymm6
        vpxor 0x2a0(%rdi), %ymm1, %ymm1
        vpshufb (%rcx), %ymm6, %ymm6
        vpandn %ymm6, %ymm11, %ymm13
        vpxor %ymm12, %ymm13, %ymm13
        vmovdqu %ymm13, 0x180(%rdi)
        vpandn %ymm2, %ymm6, %ymm13
        vpandn %ymm7, %ymm2, %ymm2
        vpxor %ymm6, %ymm2, %ymm2
        vpsrlq $0x3e, %ymm4, %ymm6
        vpxor %ymm11, %ymm13, %ymm13
        vmovdqu %ymm2, 0x1a0(%rdi)
        vpsrlq $0x2, %ymm5, %ymm2
        vpsllq $0x3e, %ymm5, %ymm5
        vpor %ymm5, %ymm2, %ymm2
        vpsrlq $0x9, %ymm1, %ymm5
        vpsllq $0x37, %ymm1, %ymm1
        vpsllq $0x2, %ymm4, %ymm4
        vpor %ymm1, %ymm5, %ymm1
        vpsrlq $0x19, %ymm0, %ymm5
        vpor %ymm4, %ymm6, %ymm4
        vpsllq $0x27, %ymm0, %ymm0
        vpor %ymm0, %ymm5, %ymm5
        vpandn %ymm5, %ymm1, %ymm0
        vpxor %ymm2, %ymm0, %ymm0
        vmovdqu %ymm0, 0x1c0(%rdi)
        vpsrlq $0x17, %ymm3, %ymm0
        vpsllq $0x29, %ymm3, %ymm3
        vpor %ymm3, %ymm0, %ymm0
        vpandn %ymm4, %ymm0, %ymm7
        vpandn %ymm0, %ymm5, %ymm3
        vpxor %ymm5, %ymm7, %ymm7
        vpandn %ymm2, %ymm4, %ymm5
        vpandn %ymm1, %ymm2, %ymm2
        vpxor %ymm0, %ymm5, %ymm5
        vpxor %ymm1, %ymm3, %ymm3
        vpxor %ymm4, %ymm2, %ymm2
        vmovdqu %ymm5, 0x1e0(%rdi)
        addq $0x8, %rsi
        addq $0x1, %r10
        cmpq $0x18, %r10
        jne .Llc_keccak_interleaved_round
        vmovdqu %ymm10, 0x200(%rdi)
        vmovdqu %ymm14, 0x220(%rdi)
        vmovdqu %ymm8, 0x240(%rdi)
        vmovdqu %ymm15, 0x260(%rdi)
        vmovdqu %ymm9, 0x280(%rdi)
        vmovdqu %ymm13, 0x2a0(%rdi)
        vmovdqu %ymm3, 0x2c0(%rdi)
        vmovdqu %ymm7, 0x2e0(%rdi)
        vmovdqu %ymm2, 0x300(%rdi)
        retq
        .cfi_endproc
#if defined(_WIN32)
.seh_endproc
#endif
#if defined(__ELF__)
.size lc_keccak_x4_interleaved,.-lc_keccak_x4_interleaved
.section .note.GNU-stack,"",@progbits
#endif
