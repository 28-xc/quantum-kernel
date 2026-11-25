.syntax unified
.thumb
.cpu cortex-m4
.text
.balign 4

.global a127_pair_block_plain
.type a127_pair_block_plain,%function
.thumb_func
a127_pair_block_plain:
    push.w {r4-r11,lr}
    mov r4,r0
    mov r5,r1
    add r0,r0,r0,lsl #1
    add r6,r2,r0
    add r7,r3,r4,lsl #2
    add r10,r5,#168
    ldr r11,[sp,#36]
    ldr r12,[sp,#40]
    ldr lr,[sp,#44]
    cmp lr,#0
    beq 1f
    add lr,lr,r0
1:  cmp r11,#0
    beq 2f
    add r11,r11,r0
    add r12,r12,r4,lsl #2
2:  ldr r1,[sp,#48]
    movw r8,#57345
    movt r8,#127
    movw r9,#57343
    movt r9,#64639
    cmp r1,#0
    bne .Lstream_initial
    b .Lstream_add
.macro loopstream lab, initial
.Lstream_\lab:
    cmp r5,r10
    bhs .Ldone
    cmp r4,#256
    bhs .Ldone
    ldrh r0,[r5],#2
    ldrb r1,[r5],#1
    orr r0,r0,r1,lsl #16
    bic r0,r0,#0x800000
    cmp r0,r8
    bhs .Lstream_\lab
    cmp lr,#0
    beq 1f
    strh r0,[lr],#2
    lsr r1,r0,#16
    strb r1,[lr],#1
1:  dot r6,r7,\initial
    cmp r11,#0
    beq 2f
    dot r11,r12,\initial
2:  adds r4,#1
    b .Lstream_\lab
.endm

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

loopstream initial,1
loopstream add,0
.Ldone:
    mov r0,r4
    pop.w {r4-r11,pc}
.size a127_pair_block_plain,.-a127_pair_block_plain
