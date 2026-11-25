/* SysV x86-64: RDI=job, RSI=aligned top, RDX=callback. Red zone is counted. */
.text
.p2align 4
.globl lc_memory_call_at
.type lc_memory_call_at,@function
lc_memory_call_at:
.cfi_startproc
    pushq %r12
    .cfi_def_cfa_offset 16
    .cfi_offset %r12,-16
    movq %rsp,%r12
    .cfi_def_cfa_register %r12
    movq %rsi,%rsp
    call *%rdx
    movq %r12,%rsp
    popq %r12
    .cfi_def_cfa %rsp,8
    .cfi_restore %r12
    ret
.cfi_endproc
.size lc_memory_call_at,.-lc_memory_call_at
.section .note.GNU-stack,"",@progbits
