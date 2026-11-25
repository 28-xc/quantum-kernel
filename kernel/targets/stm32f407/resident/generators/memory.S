/* ARMv7-M aligned bulk copy/fill. No out-of-range read or write.
 * Control flow depends only on public buffer alignment and size.
 * The caller of memset for sensitive buffers retains its existing compiler barrier. */
.syntax unified
.thumb
.section .text.fastcopy,"ax",%progbits
.p2align 2
.global __wrap_memcpy
.type __wrap_memcpy,%function
.thumb_func
__wrap_memcpy:
    mov r12,r0
    cbz r2,6f
    eor r3,r0,r1
    tst r3,#3
    bne 5f
1:  tst r12,#3
    beq 2f
    ldrb r3,[r1],#1
    strb r3,[r12],#1
    subs r2,#1
    beq 6f
    b 1b
2:  cmp r2,#16
    blo 4f
    push {r4-r7}
3:  ldmia r1!,{r4-r7}
    stmia r12!,{r4-r7}
    subs r2,#16
    cmp r2,#16
    bhs 3b
    pop {r4-r7}
4:  cmp r2,#4
    blo 5f
    ldr r3,[r1],#4
    str r3,[r12],#4
    subs r2,#4
    b 4b
5:  cbz r2,6f
    ldrb r3,[r1],#1
    strb r3,[r12],#1
    subs r2,#1
    bne 5b
6:  bx lr
.size __wrap_memcpy,.-__wrap_memcpy
.section .text.fastset,"ax",%progbits
.p2align 2
.global __wrap_memset
.type __wrap_memset,%function
.thumb_func
__wrap_memset:
    mov r12,r0
    cbz r2,6f
    uxtb r1,r1
1:  tst r12,#3
    beq 2f
    strb r1,[r12],#1
    subs r2,#1
    beq 6f
    b 1b
2:  orr r1,r1,r1,lsl #8
    orr r1,r1,r1,lsl #16
    cmp r2,#16
    blo 4f
    push {r4-r6}
    mov r4,r1
    mov r5,r1
    mov r6,r1
3:  stmia r12!,{r1,r4-r6}
    subs r2,#16
    cmp r2,#16
    bhs 3b
    pop {r4-r6}
4:  cmp r2,#4
    blo 5f
    str r1,[r12],#4
    subs r2,#4
    b 4b
5:  cbz r2,6f
    strb r1,[r12],#1
    subs r2,#1
    bne 5b
6:  bx lr
.size __wrap_memset,.-__wrap_memset

