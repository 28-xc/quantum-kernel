/* Windows x64 ABI. RCX=job, RDX=top of enforced stack, R8=callback.
 * The original stack remains above top and is outside the measured region.
 * R12 is a nonvolatile frame register, enabling normal Win64 unwind metadata
 * to recover the original stack if an exception traverses this wrapper. */
.text
.p2align 4
.globl lc_memory_call_at
.def lc_memory_call_at; .scl 2; .type 32; .endef
.seh_proc lc_memory_call_at
lc_memory_call_at:
    pushq %r12
    .seh_pushreg %r12
    movq %rsp,%r12
    .seh_setframe %r12,0
    .seh_endprologue
    movq %rdx,%rsp
    subq $32,%rsp
    call *%r8
    movq %r12,%rsp
    popq %r12
    ret
.seh_endproc
