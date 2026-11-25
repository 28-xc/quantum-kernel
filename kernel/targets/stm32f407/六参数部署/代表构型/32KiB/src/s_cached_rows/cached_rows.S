/* All 256 entries in this matrix cache are public, reduced, 24-bit values. */
.syntax unified
.thumb
.cpu cortex-m4
.text
.align 2
.macro cmac out,operand,first
    ldr r3,[\operand],#4
    smull r1,r3,r0,r3
    mul r2,r1,r9
    smlal r1,r3,r2,r8
    .if !\first
        ldrh r1,[\out]
        ldrsb r2,[\out,#2]
        orr r1,r1,r2,lsl #16
        add r3,r3,r1
    .endif
    add r1,r3,#4194304
    asr r1,r1,#23
    mls r3,r1,r8,r3
    strh r3,[\out]
    lsr r3,r3,#16
    strb r3,[\out,#2]
    add \out,\out,#3
.endm
.macro walk id,second,first
.L\id:
    ldr r0,[r5],#3
    ubfx r0,r0,#0,#24
    cmac r6,r7,\first
    .if \second
        cmac r11,r12,\first
    .endif
    ldr r0,[r5],#3
    ubfx r0,r0,#0,#24
    cmac r6,r7,\first
    .if \second
        cmac r11,r12,\first
    .endif
    ldr r0,[r5],#3
    ubfx r0,r0,#0,#24
    cmac r6,r7,\first
    .if \second
        cmac r11,r12,\first
    .endif
    ldrh r0,[r5]
    ldrb r1,[r5,#2]
    add r5,r5,#3
    orr r0,r0,r1,lsl #16
    cmac r6,r7,\first
    .if \second
        cmac r11,r12,\first
    .endif
    cmp r5,r10
    bne .L\id
    pop.w {r4-r11,pc}
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
    cmp r11,#0
    beq .Lmono
    cmp r2,#0
    beq .Lbothadd
    walk bothfirst,1,1
    walk bothadd,1,0
.Lmono:
    cmp r2,#0
    beq .Loneadd
    walk onefirst,0,1
    walk oneadd,0,0
.size a127_cached_row, .-a127_cached_row
