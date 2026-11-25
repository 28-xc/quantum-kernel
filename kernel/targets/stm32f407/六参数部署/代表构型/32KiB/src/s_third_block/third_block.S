/* Share one FIPS 204 public 23-bit rejection stream among three independently
   transformed masks. Each byte and halfword is within its own 768-byte row. */
.syntax unified
.thumb
.cpu cortex-m4
.text
.align 2
.macro add_product out, operand, init
    ldr r3,[\operand],#4
    smull r1,r3,r0,r3
    mul r2,r1,r9
    smlal r1,r3,r2,r8
    .if !\init
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
.macro visit label, init
.L\label:
    cmp r4,#256
    bhs .Lreturn
    ldr r1,[sp,#0]
    cmp r5,r1
    bhs .Lreturn
    ldrh r0,[r5]
    ldrb r1,[r5,#2]
    add r5,r5,#3
    orr r0,r0,r1,lsl #16
    ubfx r0,r0,#0,#23
    cmp r0,r8
    bhs .L\label
    add_product r6,r7,\init
    add_product r11,r12,\init
    ldr lr,[sp,#4]
    add_product r10,lr,\init
    str lr,[sp,#4]
    add r4,r4,#1
    b .L\label
.endm
.global a127_three_block
.type a127_three_block,%function
.thumb_func
a127_three_block:
    push.w {r4-r11,lr}
    sub sp,#12
    mov r4,r0
    mov r5,r1
    add r0,r0,r0,lsl #1
    add r6,r2,r0
    add r7,r3,r4,lsl #2
    add r2,r5,#168
    str r2,[sp,#0]
    ldr r11,[sp,#48]
    add r11,r11,r0
    ldr r12,[sp,#52]
    add r12,r12,r4,lsl #2
    ldr r10,[sp,#56]
    add r10,r10,r0
    ldr lr,[sp,#60]
    add lr,lr,r4,lsl #2
    str lr,[sp,#4]
    movw r8,#57345
    movt r8,#127
    movw r9,#57343
    movt r9,#64639
    ldr r2,[sp,#64]
    cmp r2,#0
    bne .Linit
    visit accum,0
    visit init,1
.Lreturn:
    mov r0,r4
    add sp,#12
    pop.w {r4-r11,pc}
.size a127_three_block,.-a127_three_block
