/* Generated from lc_kem_vnni_dot_v1.h with GCC15.2 -O3 -mavx2 -mavxvnni.
 * Runtime instructions unchanged from the qualified component.
 * CFI describes actual SysV frame and restores state for out-of-line paths. */
#if defined(__ELF__)
.section .text.lc_kem_vnni_dot_v1,"ax",@progbits
#else
.section .text$lc_kem_vnni_dot_v1,"xr"
#endif
	.p2align 4
	.globl	lc_kem_vnni_dot_v1
#if defined(__ELF__)
.type lc_kem_vnni_dot_v1,@function
#else
	.def	lc_kem_vnni_dot_v1;	.scl	2;	.type	32;	.endef
#endif
#if defined(_WIN32)
	.cfi_sections .debug_frame
	.seh_proc lc_kem_vnni_dot_v1
#endif
lc_kem_vnni_dot_v1:
	.cfi_startproc
	pushq	%rbp
#if defined(_WIN32)
	.seh_pushreg rbp
#endif
	.cfi_def_cfa_offset 16
	.cfi_offset 6,-16
	vmovdqu	.LC2(%rip), %ymm6
	movq	%rdi, %r9
	movq	%rcx, %r11
	vmovdqu	.LC1(%rip), %ymm7
	vmovdqu	.LC0(%rip), %ymm5
	movq	%rsi, %rdi
	xorl	%ecx, %ecx
	movq	%rdx, %rsi
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	pushq	%rbx
#if defined(_WIN32)
	.seh_pushreg rbx
	.seh_endprologue
#endif
	.cfi_offset 3,-24
	xorl	%ebx, %ebx
	.p2align 4
	.p2align 3
.L6:
	testl	%r8d, %r8d
	je	.L7
	movl	%ebx, %edx
	leaq	(%rcx,%rcx), %r10
	andl	$1, %edx
	jne	.L8
	vpxor	%xmm12, %xmm12, %xmm12
	vmovdqa	%ymm12, %ymm11
	vmovdqa	%ymm12, %ymm10
	vmovdqa	%ymm12, %ymm9
	.p2align 4
	.p2align 3
.L4:
	movl	%edx, %eax
	vmovdqa	%ymm12, %ymm8
	vmovdqa	%ymm11, %ymm3
	sall	$8, %eax
	addq	%r10, %rax
	vmovdqu	32(%rdi,%rax,2), %ymm0
	vmovdqu	(%rdi,%rax,2), %ymm1
	vmovdqu	32(%rsi,%rax,2), %ymm2
	vpunpcklwd	%ymm0, %ymm1, %ymm13
	vpunpckhwd	%ymm0, %ymm1, %ymm1
	vmovdqu	(%rsi,%rax,2), %ymm0
	movl	%edx, %eax
	sall	$7, %eax
	addl	$1, %edx
	vpunpcklwd	%ymm0, %ymm2, %ymm4
	addq	%rcx, %rax
	vpunpckhwd	%ymm0, %ymm2, %ymm2
	{vex} vpdpwssd	%ymm2, %ymm1, %ymm8
	vmovdqu	(%r11,%rax,2), %ymm2
	{vex} vpdpwssd	%ymm4, %ymm13, %ymm3
	vmovdqa	%ymm9, %ymm4
	vpunpcklwd	%ymm2, %ymm0, %ymm14
	vpunpckhwd	%ymm2, %ymm0, %ymm0
	vmovdqa	%ymm10, %ymm2
	{vex} vpdpwssd	%ymm14, %ymm13, %ymm4
	{vex} vpdpwssd	%ymm0, %ymm1, %ymm2
	vmovdqa	%ymm8, %ymm12
	vmovdqa	%ymm3, %ymm11
	vmovdqa	%ymm4, %ymm9
	vmovdqa	%ymm2, %ymm10
	cmpl	%edx, %r8d
	jne	.L4
.L5:
	vpmullw	%ymm3, %ymm7, %ymm1
	vpmullw	%ymm8, %ymm7, %ymm9
	vmovdqa	%ymm4, %ymm0
	vpmullw	%ymm2, %ymm7, %ymm10
	vpmullw	%ymm4, %ymm7, %ymm4
.L2:
	vpmaddwd	%ymm6, %ymm10, %ymm10
	vpmaddwd	%ymm6, %ymm4, %ymm4
	addl	$1, %ebx
	vpmaddwd	%ymm6, %ymm9, %ymm9
	vpmaddwd	%ymm6, %ymm1, %ymm1
	vpsubd	%ymm10, %ymm2, %ymm2
	vpsubd	%ymm4, %ymm0, %ymm0
	vpsubd	%ymm9, %ymm8, %ymm8
	vpsubd	%ymm1, %ymm3, %ymm3
	vpsrad	$16, %ymm2, %ymm2
	vpsrad	$16, %ymm0, %ymm0
	vpsrad	$16, %ymm8, %ymm8
	vpsrad	$16, %ymm3, %ymm3
	vpackssdw	%ymm2, %ymm0, %ymm0
	vpackssdw	%ymm8, %ymm3, %ymm3
	vmovdqu	%ymm0, (%r9,%rcx,4)
	vmovdqu	%ymm3, 32(%r9,%rcx,4)
	addq	$16, %rcx
	cmpq	$128, %rcx
	jne	.L6
	vzeroupper
	.cfi_remember_state
#if defined(_WIN32)
	popq	%rbx
	.cfi_restore 3
	popq	%rbp
#else
	movq	-8(%rbp), %rbx
	.cfi_restore 3
	leave
#endif
	.cfi_def_cfa 7,8
	.cfi_restore 6
	ret
	.cfi_restore_state
	.p2align 4,,10
	.p2align 3
.L8:
	vpxor	%xmm12, %xmm12, %xmm12
	xorl	%edx, %edx
	vmovdqa	%ymm12, %ymm11
	vmovdqa	%ymm12, %ymm10
	vmovdqa	%ymm12, %ymm9
	.p2align 4
	.p2align 3
.L3:
	movl	%edx, %eax
	vmovdqa	%ymm11, %ymm3
	sall	$8, %eax
	addq	%r10, %rax
	vmovdqu	32(%rdi,%rax,2), %ymm2
	vmovdqu	(%rdi,%rax,2), %ymm1
	vmovdqu	32(%rsi,%rax,2), %ymm4
	vpunpcklwd	%ymm2, %ymm1, %ymm0
	vpunpckhwd	%ymm2, %ymm1, %ymm1
	vmovdqu	(%rsi,%rax,2), %ymm2
	movl	%edx, %eax
	sall	$7, %eax
	addl	$1, %edx
	addq	%rcx, %rax
	vpunpcklwd	%ymm2, %ymm4, %ymm8
	vpunpckhwd	%ymm2, %ymm4, %ymm4
	{vex} vpdpwssd	%ymm8, %ymm0, %ymm3
	vmovdqu	(%r11,%rax,2), %ymm13
	vmovdqa	%ymm12, %ymm8
	vpsignw	%ymm5, %ymm0, %ymm0
	{vex} vpdpwssd	%ymm4, %ymm1, %ymm8
	vmovdqa	%ymm9, %ymm4
	vpsignw	%ymm5, %ymm1, %ymm1
	vpunpcklwd	%ymm13, %ymm2, %ymm14
	{vex} vpdpwssd	%ymm14, %ymm0, %ymm4
	vpunpckhwd	%ymm13, %ymm2, %ymm0
	vmovdqa	%ymm10, %ymm2
	{vex} vpdpwssd	%ymm0, %ymm1, %ymm2
	vmovdqa	%ymm3, %ymm11
	vmovdqa	%ymm8, %ymm12
	vmovdqa	%ymm4, %ymm9
	vmovdqa	%ymm2, %ymm10
	cmpl	%edx, %r8d
	jne	.L3
	jmp	.L5
	.p2align 4,,10
	.p2align 3
.L7:
	vpxor	%xmm10, %xmm10, %xmm10
	vpxor	%xmm2, %xmm2, %xmm2
	vmovdqa	%ymm10, %ymm4
	vmovdqa	%ymm2, %ymm0
	vmovdqa	%ymm10, %ymm9
	vmovdqa	%ymm2, %ymm8
	vmovdqa	%ymm10, %ymm1
	vmovdqa	%ymm2, %ymm3
	jmp	.L2
	.cfi_endproc
#if defined(_WIN32)
	.seh_endproc
#endif
#if defined(__ELF__)
.size lc_kem_vnni_dot_v1,.-lc_kem_vnni_dot_v1
.section .rodata
#else
	.section .rdata,"dr"
#endif
	.align 32
.LC0:
	.word	1
	.word	-1
	.word	1
	.word	-1
	.word	1
	.word	-1
	.word	1
	.word	-1
	.word	1
	.word	-1
	.word	1
	.word	-1
	.word	1
	.word	-1
	.word	1
	.word	-1
	.align 32
.LC1:
	.word	-3327
	.word	0
	.word	-3327
	.word	0
	.word	-3327
	.word	0
	.word	-3327
	.word	0
	.word	-3327
	.word	0
	.word	-3327
	.word	0
	.word	-3327
	.word	0
	.word	-3327
	.word	0
	.align 32
.LC2:
	.word	3329
	.word	0
	.word	3329
	.word	0
	.word	3329
	.word	0
	.word	3329
	.word	0
	.word	3329
	.word	0
	.word	3329
	.word	0
	.word	3329
	.word	0
	.word	3329
	.word	0
#if !defined(__clang__)
	.ident	"GCC: (Rev9, Built by MSYS2 project) 15.2.0"
#endif

#if defined(__ELF__)
.section .note.GNU-stack,"",@progbits
#endif
