.syntax unified
.thumb
.cpu cortex-m4
.text
.balign 4

.macro dot out,src,initial
    ldr r3,[\src],#4
    smull r1,r3,r0,r3
    mul r2,r1,r9
    smlal r1,r3,r2,r8
    .if !\initial
    ldrh r1,[\out]
    ldrsb r2,[\out,#2]
    orr r1,r1,r2,lsl #16
    add r3,r3,r1
    .endif
    add r1,r3,#4194304
    asr r1,r1,#23
    mls r3,r1,r8,r3
    strh r3,[\out],#2
    lsr r3,r3,#16
    strb r3,[\out],#1
.endm

.global a127_cached_row
.type a127_cached_row,%function
.thumb_func
a127_cached_row:
    push.w {r4-r11,lr}
    mov r5,r0
    add r10,r5,#768
    mov r6,r1
    mov r7,r2
    mov r11,r3
    ldr r12,[sp,#36]
    ldr r2,[sp,#40]
    movw r8,#57345
    movt r8,#127
    movw r9,#57343
    movt r9,#64639
    cmp r2,#0
    beq .Lcache_add
.macro cache_loop tag,init
.Lcache_\tag:
    ldrh r0,[r5],#2
    ldrb r1,[r5],#1
    orr r0,r0,r1,lsl #16
    dot r6,r7,\init
    cmp r11,#0
    beq 1f
    dot r11,r12,\init
1:  cmp r5,r10
    bne .Lcache_\tag
    pop.w {r4-r11,pc}
.endm
cache_loop init,1
cache_loop add,0
.size a127_cached_row,.-a127_cached_row
