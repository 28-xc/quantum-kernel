/* AAPCS64: x0=job, x1=16-byte-aligned top, x2=callback. x19/LR preserved.
 * The measured interval includes the C dispatcher and all downstream calls. */
.text
.p2align 4
.global lc_memory_call_at
.type lc_memory_call_at,%function
lc_memory_call_at:
.cfi_startproc
    stp x19,x30,[sp,#-16]!
    .cfi_def_cfa_offset 16
    .cfi_offset 19,-16
    .cfi_offset 30,-8
    mov x19,sp
    .cfi_def_cfa_register 19
    mov sp,x1
    blr x2
    mov sp,x19
    ldp x19,x30,[sp],#16
    .cfi_def_cfa sp,0
    .cfi_restore 19
    .cfi_restore 30
    ret
.cfi_endproc
.size lc_memory_call_at,.-lc_memory_call_at
.section .note.GNU-stack,"",%progbits
