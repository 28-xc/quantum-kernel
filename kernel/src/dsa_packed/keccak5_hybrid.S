/* SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 * SIMD round arithmetic derived from the pinned mlkem-native/mldsa-native
 * AVX2 routine. Scalar round generated directly from Keccak-f1600 steps.
 * SysV ABI: RDI=1000-byte states; RSI=200-byte disjoint scratch;
 * RDX=24 constants. Four interleaved SIMD states plus canonical fifth.
 * Six saved GPRs plus constant endpoint occupy56 stack bytes. Scratch
 * is cleared with exact192+8-byte stores after every complete call. */
.text
.balign 32
.global lc_keccak5_hybrid
#if defined(__ELF__)
.type lc_keccak5_hybrid,@function
#else
.seh_proc lc_keccak5_hybrid
#endif
lc_keccak5_hybrid:
#if defined(_WIN32)
.cfi_sections .debug_frame
#endif
.cfi_startproc
pushq %rbx
.cfi_def_cfa_offset 16
.cfi_offset rbx, -16
#if !defined(__ELF__)
.seh_pushreg rbx
#endif
pushq %rbp
.cfi_def_cfa_offset 24
.cfi_offset rbp, -24
#if !defined(__ELF__)
.seh_pushreg rbp
#endif
pushq %r12
.cfi_def_cfa_offset 32
.cfi_offset r12, -32
#if !defined(__ELF__)
.seh_pushreg r12
#endif
pushq %r13
.cfi_def_cfa_offset 40
.cfi_offset r13, -40
#if !defined(__ELF__)
.seh_pushreg r13
#endif
pushq %r14
.cfi_def_cfa_offset 48
.cfi_offset r14, -48
#if !defined(__ELF__)
.seh_pushreg r14
#endif
pushq %r15
.cfi_def_cfa_offset 56
.cfi_offset r15, -56
#if !defined(__ELF__)
.seh_pushreg r15
#endif
movq %rsi, %rcx
movq %rdx, %rsi
leaq 800(%rdi), %rdx
leaq 192(%rsi), %rax
pushq %rax
.cfi_def_cfa_offset 64
#if !defined(__ELF__)
.seh_stackalloc 8
.seh_endprologue
#endif
vmovdqu 0x200(%rdi), %ymm10
vmovdqu 0x220(%rdi), %ymm14
vmovdqu 0x240(%rdi), %ymm8
vmovdqu 0x260(%rdi), %ymm15
vmovdqu 0x280(%rdi), %ymm9
vmovdqu 0x2a0(%rdi), %ymm13
vmovdqu 0x2c0(%rdi), %ymm3
vmovdqu 0x2e0(%rdi), %ymm7
vmovdqu 0x300(%rdi), %ymm2
.Lhybrid_round:
vmovdqu 0xa0(%rdi), %ymm4
vpxor 0x1c0(%rdi), %ymm9, %ymm0
movq 0(%rdx), %r8
vmovdqu %ymm9, 0x200(%rdi)
xorq 40(%rdx), %r8
vmovdqu %ymm10, %ymm9
xorq 80(%rdx), %r8
vmovdqu 0xc0(%rdi), %ymm11
xorq 120(%rdx), %r8
vmovdqu 0x160(%rdi), %ymm12
xorq 160(%rdx), %r8
vmovdqu %ymm3, 0x240(%rdi)
vpxor 0x100(%rdi), %ymm4, %ymm1
movq 8(%rdx), %r9
vmovdqu 0x40(%rdi), %ymm10
xorq 48(%rdx), %r9
vmovdqu %ymm4, 0x220(%rdi)
xorq 88(%rdx), %r9
vpxor %ymm3, %ymm12, %ymm12
xorq 128(%rdx), %r9
vmovdqu 0x20(%rdi), %ymm6
xorq 168(%rdx), %r9
vmovdqu 0x140(%rdi), %ymm4
vmovdqu %ymm14, 0x2a0(%rdi)
movq 16(%rdx), %r10
vpxor %ymm1, %ymm0, %ymm0
xorq 56(%rdx), %r10
vpxor %ymm8, %ymm11, %ymm1
xorq 96(%rdx), %r10
vpxor 0x180(%rdi), %ymm7, %ymm11
xorq 136(%rdx), %r10
vmovdqu %ymm10, 0x280(%rdi)
xorq 176(%rdx), %r10
vpxor %ymm1, %ymm12, %ymm12
vpxor %ymm15, %ymm9, %ymm1
movq 24(%rdx), %r11
vmovdqu 0xe0(%rdi), %ymm3
xorq 64(%rdx), %r11
vmovdqu %ymm8, 0x260(%rdi)
xorq 104(%rdx), %r11
vpxor %ymm1, %ymm11, %ymm11
xorq 144(%rdx), %r11
vpxor 0x120(%rdi), %ymm14, %ymm1
xorq 184(%rdx), %r11
vpxor %ymm6, %ymm12, %ymm12
movq 32(%rdx), %r12
vmovdqu 0x60(%rdi), %ymm8
vpxor %ymm10, %ymm11, %ymm11
xorq 72(%rdx), %r12
vpxor 0x1e0(%rdi), %ymm13, %ymm10
xorq 112(%rdx), %r12
vpxor %ymm4, %ymm3, %ymm3
xorq 152(%rdx), %r12
vmovdqu %ymm4, 0x2c0(%rdi)
xorq 192(%rdx), %r12
vpsrlq $0x3f, %ymm12, %ymm4
rorxq $63, %r9, %rax
vpsrlq $0x3f, %ymm11, %ymm5
vpxor (%rdi), %ymm0, %ymm0
xorq %r12, %rax
vpxor %ymm1, %ymm10, %ymm10
rorxq $63, %r10, %rbx
vmovdqu 0x80(%rdi), %ymm1
xorq %r8, %rbx
vpxor %ymm8, %ymm10, %ymm10
rorxq $63, %r11, %rbp
vmovdqu %ymm1, %ymm14
xorq %r9, %rbp
vpxor 0x1a0(%rdi), %ymm2, %ymm1
vmovdqu %ymm14, 0x2e0(%rdi)
rorxq $63, %r12, %r13
vpxor %ymm3, %ymm1, %ymm1
xorq %r10, %r13
vpsllq $0x1, %ymm12, %ymm3
rorxq $63, %r8, %r14
vpor %ymm4, %ymm3, %ymm3
xorq %r11, %r14
vpsllq $0x1, %ymm11, %ymm4
movq 0(%rdx), %r8
vpxor %ymm14, %ymm1, %ymm1
xorq %rax, %r8
vpor %ymm5, %ymm4, %ymm4
vpsrlq $0x3f, %ymm10, %ymm14
movq 48(%rdx), %r9
vpxor %ymm1, %ymm3, %ymm3
xorq %rbx, %r9
vpsllq $0x1, %ymm10, %ymm5
rorxq $20, %r9, %r9
vpxor %ymm0, %ymm4, %ymm4
movq 96(%rdx), %r10
vpor %ymm14, %ymm5, %ymm5
xorq %rbp, %r10
vpxor %ymm6, %ymm4, %ymm6
vpxor %ymm12, %ymm5, %ymm5
rorxq $21, %r10, %r10
vpsrlq $0x3f, %ymm1, %ymm12
movq 144(%rdx), %r11
vpsllq $0x1, %ymm1, %ymm1
xorq %r13, %r11
vpxor %ymm7, %ymm5, %ymm7
rorxq $43, %r11, %r11
vpxor %ymm9, %ymm5, %ymm9
movq 192(%rdx), %r12
vpor %ymm12, %ymm1, %ymm1
vpxor (%rdi), %ymm3, %ymm12
xorq %r14, %r12
vpxor %ymm11, %ymm1, %ymm1
rorxq $50, %r12, %r12
vpsrlq $0x3f, %ymm0, %ymm11
andnq %r10, %r9, %r15
vpsllq $0x1, %ymm0, %ymm0
xorq %r8, %r15
vpxor %ymm13, %ymm1, %ymm13
xorq (%rsi), %r15
vpxor %ymm8, %ymm1, %ymm8
vpor %ymm11, %ymm0, %ymm0
movq %r15, 0(%rcx)
vpxor %ymm10, %ymm0, %ymm0
andnq %r11, %r10, %r15
vpxor 0xc0(%rdi), %ymm4, %ymm10
xorq %r9, %r15
vpxor %ymm2, %ymm0, %ymm2
movq %r15, 8(%rcx)
vpsrlq $0x14, %ymm10, %ymm11
andnq %r12, %r11, %r15
vpsllq $0x2c, %ymm10, %ymm10
xorq %r10, %r15
vpor %ymm11, %ymm10, %ymm10
vpxor %ymm15, %ymm5, %ymm11
movq %r15, 16(%rcx)
vpbroadcastq (%rsi), %ymm15
andnq %r8, %r12, %r15
vpsrlq $0x15, %ymm11, %ymm14
xorq %r11, %r15
vpsllq $0x2b, %ymm11, %ymm11
movq %r15, 24(%rcx)
vpor %ymm14, %ymm11, %ymm11
andnq %r9, %r8, %r15
vpandn %ymm11, %ymm10, %ymm14
vpxor %ymm15, %ymm14, %ymm14
xorq %r12, %r15
vpxor %ymm12, %ymm14, %ymm15
movq %r15, 32(%rcx)
vpsrlq $0x2b, %ymm13, %ymm14
movq 24(%rdx), %r8
vpsllq $0x15, %ymm13, %ymm13
xorq %r13, %r8
vmovdqu %ymm15, (%rdi)
rorxq $36, %r8, %r8
vpor %ymm14, %ymm13, %ymm13
vpandn %ymm13, %ymm11, %ymm14
movq 72(%rdx), %r9
vpxor %ymm10, %ymm14, %ymm15
xorq %r14, %r9
vpsrlq $0x32, %ymm2, %ymm14
rorxq $44, %r9, %r9
vpsllq $0xe, %ymm2, %ymm2
movq 80(%rdx), %r10
vmovdqu %ymm15, 0x20(%rdi)
xorq %rax, %r10
vpor %ymm14, %ymm2, %ymm2
rorxq $61, %r10, %r10
vpandn %ymm2, %ymm13, %ymm14
vpxor %ymm11, %ymm14, %ymm11
movq 128(%rdx), %r11
vmovdqu %ymm11, 0x40(%rdi)
xorq %rbx, %r11
vpandn %ymm12, %ymm2, %ymm11
rorxq $19, %r11, %r11
vpandn %ymm10, %ymm12, %ymm12
movq 176(%rdx), %r12
vpxor %ymm13, %ymm11, %ymm11
xorq %rbp, %r12
vmovdqu %ymm11, 0x60(%rdi)
vpxor %ymm2, %ymm12, %ymm11
rorxq $3, %r12, %r12
vpsrlq $0x24, %ymm8, %ymm2
andnq %r10, %r9, %r15
vpsllq $0x1c, %ymm8, %ymm8
xorq %r8, %r15
vmovdqu %ymm11, 0x80(%rdi)
movq %r15, 40(%rcx)
vpor %ymm2, %ymm8, %ymm8
andnq %r11, %r10, %r15
vpxor 0xe0(%rdi), %ymm0, %ymm2
vpsrlq $0x2c, %ymm2, %ymm10
xorq %r9, %r15
vpsllq $0x14, %ymm2, %ymm2
movq %r15, 48(%rcx)
vpor %ymm10, %ymm2, %ymm2
andnq %r12, %r11, %r15
vpxor 0x100(%rdi), %ymm3, %ymm10
xorq %r10, %r15
vpsrlq $0x3d, %ymm10, %ymm11
movq %r15, 56(%rcx)
vpsllq $0x3, %ymm10, %ymm10
vpor %ymm11, %ymm10, %ymm10
andnq %r8, %r12, %r15
vpandn %ymm10, %ymm2, %ymm11
xorq %r11, %r15
vpxor %ymm8, %ymm11, %ymm11
movq %r15, 64(%rcx)
vmovdqu %ymm11, 0xa0(%rdi)
andnq %r9, %r8, %r15
vpxor 0x160(%rdi), %ymm4, %ymm11
xorq %r12, %r15
vpsrlq $0x13, %ymm11, %ymm12
movq %r15, 72(%rcx)
vpsllq $0x2d, %ymm11, %ymm11
vpor %ymm12, %ymm11, %ymm11
movq 8(%rdx), %r8
vpandn %ymm11, %ymm10, %ymm12
xorq %rbx, %r8
vpxor %ymm2, %ymm12, %ymm12
rorxq $63, %r8, %r8
vmovdqu %ymm12, 0xc0(%rdi)
movq 56(%rdx), %r9
vpsrlq $0x3, %ymm7, %ymm12
xorq %rbp, %r9
vpsllq $0x3d, %ymm7, %ymm7
vpor %ymm12, %ymm7, %ymm7
rorxq $58, %r9, %r9
vpandn %ymm7, %ymm11, %ymm12
movq 104(%rdx), %r10
vpxor %ymm10, %ymm12, %ymm10
xorq %r13, %r10
vpandn %ymm8, %ymm7, %ymm12
rorxq $39, %r10, %r10
vpandn %ymm2, %ymm8, %ymm8
movq 152(%rdx), %r11
vpsrlq $0x3f, %ymm6, %ymm2
vpsllq $0x1, %ymm6, %ymm6
xorq %r14, %r11
vpxor %ymm11, %ymm12, %ymm14
rorxq $56, %r11, %r11
vpor %ymm2, %ymm6, %ymm6
movq 160(%rdx), %r12
vpsrlq $0x3a, %ymm9, %ymm2
xorq %rax, %r12
vpxor %ymm7, %ymm8, %ymm12
rorxq $46, %r12, %r12
vpsllq $0x6, %ymm9, %ymm9
andnq %r10, %r9, %r15
vmovdqu %ymm12, 0xe0(%rdi)
vpxor 0x1a0(%rdi), %ymm0, %ymm7
xorq %r8, %r15
vpor %ymm2, %ymm9, %ymm9
movq %r15, 80(%rcx)
vpxor 0x120(%rdi), %ymm1, %ymm2
andnq %r11, %r10, %r15
vpshufb lc_base_mlk_keccak_rho8(%rip), %ymm7, %ymm7
xorq %r9, %r15
vpsrlq $0x27, %ymm2, %ymm11
movq %r15, 88(%rcx)
vpsllq $0x19, %ymm2, %ymm2
vpor %ymm2, %ymm11, %ymm11
andnq %r12, %r11, %r15
vpandn %ymm11, %ymm9, %ymm2
xorq %r10, %r15
vpandn %ymm7, %ymm11, %ymm8
movq %r15, 96(%rcx)
vpxor %ymm6, %ymm2, %ymm12
andnq %r8, %r12, %r15
vpxor 0x1c0(%rdi), %ymm3, %ymm2
xorq %r11, %r15
vpxor %ymm9, %ymm8, %ymm8
vmovdqu %ymm12, 0x100(%rdi)
movq %r15, 104(%rcx)
vpsrlq $0x2e, %ymm2, %ymm12
andnq %r9, %r8, %r15
vpsllq $0x12, %ymm2, %ymm2
xorq %r12, %r15
vpor %ymm2, %ymm12, %ymm2
movq %r15, 112(%rcx)
vpandn %ymm2, %ymm7, %ymm12
movq 32(%rdx), %r8
vpxor %ymm11, %ymm12, %ymm15
vpandn %ymm6, %ymm2, %ymm11
xorq %r14, %r8
vpandn %ymm9, %ymm6, %ymm6
rorxq $37, %r8, %r8
vpxor %ymm7, %ymm11, %ymm12
movq 40(%rdx), %r9
vmovdqu %ymm12, 0x120(%rdi)
xorq %rax, %r9
vpxor %ymm2, %ymm6, %ymm12
rorxq $28, %r9, %r9
vpxor 0x2e0(%rdi), %ymm0, %ymm6
movq 88(%rdx), %r10
vpxor 0x2c0(%rdi), %ymm0, %ymm0
vmovdqu %ymm12, 0x140(%rdi)
xorq %rbx, %r10
vpsrlq $0x25, %ymm6, %ymm2
rorxq $54, %r10, %r10
vpsllq $0x1b, %ymm6, %ymm6
movq 136(%rdx), %r11
vpor %ymm6, %ymm2, %ymm2
xorq %rbp, %r11
vpxor 0x220(%rdi), %ymm3, %ymm6
rorxq $49, %r11, %r11
vpxor 0x200(%rdi), %ymm3, %ymm3
vpsrlq $0x1c, %ymm6, %ymm7
movq 184(%rdx), %r12
vpsllq $0x24, %ymm6, %ymm6
xorq %r13, %r12
vpor %ymm6, %ymm7, %ymm7
rorxq $8, %r12, %r12
vpxor 0x260(%rdi), %ymm4, %ymm6
andnq %r10, %r9, %r15
vpxor 0x240(%rdi), %ymm4, %ymm4
xorq %r8, %r15
vpsrlq $0x36, %ymm6, %ymm12
vpsllq $0xa, %ymm6, %ymm6
movq %r15, 120(%rcx)
vpor %ymm6, %ymm12, %ymm12
andnq %r11, %r10, %r15
vpxor 0x180(%rdi), %ymm5, %ymm6
xorq %r9, %r15
vpxor 0x280(%rdi), %ymm5, %ymm5
movq %r15, 128(%rcx)
vpandn %ymm12, %ymm7, %ymm9
andnq %r12, %r11, %r15
vpsrlq $0x31, %ymm6, %ymm11
xorq %r10, %r15
vpsllq $0xf, %ymm6, %ymm6
vpxor %ymm2, %ymm9, %ymm9
movq %r15, 136(%rcx)
vpor %ymm6, %ymm11, %ymm11
andnq %r8, %r12, %r15
vpandn %ymm11, %ymm12, %ymm6
xorq %r11, %r15
vpxor %ymm7, %ymm6, %ymm6
movq %r15, 144(%rcx)
vmovdqu %ymm6, 0x160(%rdi)
andnq %r9, %r8, %r15
vpxor 0x1e0(%rdi), %ymm1, %ymm6
vpxor 0x2a0(%rdi), %ymm1, %ymm1
xorq %r12, %r15
vpshufb lc_base_mlk_keccak_rho56(%rip), %ymm6, %ymm6
movq %r15, 152(%rcx)
vpandn %ymm6, %ymm11, %ymm13
movq 16(%rdx), %r8
vpxor %ymm12, %ymm13, %ymm13
xorq %rbp, %r8
vmovdqu %ymm13, 0x180(%rdi)
rorxq $2, %r8, %r8
vpandn %ymm2, %ymm6, %ymm13
vpandn %ymm7, %ymm2, %ymm2
movq 64(%rdx), %r9
vpxor %ymm6, %ymm2, %ymm2
xorq %r13, %r9
vpsrlq $0x3e, %ymm4, %ymm6
rorxq $9, %r9, %r9
vpxor %ymm11, %ymm13, %ymm13
movq 112(%rdx), %r10
vmovdqu %ymm2, 0x1a0(%rdi)
xorq %r14, %r10
vpsrlq $0x2, %ymm5, %ymm2
vpsllq $0x3e, %ymm5, %ymm5
rorxq $25, %r10, %r10
vpor %ymm5, %ymm2, %ymm2
movq 120(%rdx), %r11
vpsrlq $0x9, %ymm1, %ymm5
xorq %rax, %r11
vpsllq $0x37, %ymm1, %ymm1
rorxq $23, %r11, %r11
vpsllq $0x2, %ymm4, %ymm4
movq 168(%rdx), %r12
vpor %ymm1, %ymm5, %ymm1
xorq %rbx, %r12
vpsrlq $0x19, %ymm0, %ymm5
vpor %ymm4, %ymm6, %ymm4
rorxq $62, %r12, %r12
vpsllq $0x27, %ymm0, %ymm0
andnq %r10, %r9, %r15
vpor %ymm0, %ymm5, %ymm5
xorq %r8, %r15
vpandn %ymm5, %ymm1, %ymm0
movq %r15, 160(%rcx)
vpxor %ymm2, %ymm0, %ymm0
andnq %r11, %r10, %r15
vmovdqu %ymm0, 0x1c0(%rdi)
vpsrlq $0x17, %ymm3, %ymm0
xorq %r9, %r15
vpsllq $0x29, %ymm3, %ymm3
movq %r15, 168(%rcx)
vpor %ymm3, %ymm0, %ymm0
andnq %r12, %r11, %r15
vpandn %ymm4, %ymm0, %ymm7
xorq %r10, %r15
vpandn %ymm0, %ymm5, %ymm3
movq %r15, 176(%rcx)
vpxor %ymm5, %ymm7, %ymm7
vpandn %ymm2, %ymm4, %ymm5
andnq %r8, %r12, %r15
vpandn %ymm1, %ymm2, %ymm2
xorq %r11, %r15
vpxor %ymm0, %ymm5, %ymm5
movq %r15, 184(%rcx)
vpxor %ymm1, %ymm3, %ymm3
andnq %r9, %r8, %r15
vpxor %ymm4, %ymm2, %ymm2
xorq %r12, %r15
vmovdqu %ymm5, 0x1e0(%rdi)
movq %r15, 192(%rcx)
xchgq %rdx, %rcx
addq $8, %rsi
cmpq (%rsp), %rsi
jne .Lhybrid_round
vmovdqu %ymm10, 0x200(%rdi)
vmovdqu %ymm14, 0x220(%rdi)
vmovdqu %ymm8, 0x240(%rdi)
vmovdqu %ymm15, 0x260(%rdi)
vmovdqu %ymm9, 0x280(%rdi)
vmovdqu %ymm13, 0x2a0(%rdi)
vmovdqu %ymm3, 0x2c0(%rdi)
vmovdqu %ymm7, 0x2e0(%rdi)
vmovdqu %ymm2, 0x300(%rdi)
vpxor %ymm0, %ymm0, %ymm0
vmovdqu %ymm0, 0(%rcx)
vmovdqu %ymm0, 32(%rcx)
vmovdqu %ymm0, 64(%rcx)
vmovdqu %ymm0, 96(%rcx)
vmovdqu %ymm0, 128(%rcx)
vmovdqu %ymm0, 160(%rcx)
movq $0, 192(%rcx)
addq $8, %rsp
.cfi_def_cfa_offset 56
popq %r15
.cfi_restore r15
.cfi_def_cfa_offset 48
popq %r14
.cfi_restore r14
.cfi_def_cfa_offset 40
popq %r13
.cfi_restore r13
.cfi_def_cfa_offset 32
popq %r12
.cfi_restore r12
.cfi_def_cfa_offset 24
popq %rbp
.cfi_restore rbp
.cfi_def_cfa_offset 16
popq %rbx
.cfi_restore rbx
.cfi_def_cfa_offset 8
retq
.cfi_endproc
#if defined(__ELF__)
.size lc_keccak5_hybrid,.-lc_keccak5_hybrid
.section .note.GNU-stack,"",@progbits
#else
.seh_endproc
#endif
