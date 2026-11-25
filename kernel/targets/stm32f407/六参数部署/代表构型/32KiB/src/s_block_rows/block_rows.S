/* Packed 24-bit acc arrays and fixed-width SHAKE block. ARMv7E-M.
   count/block/destination/current in r0-r3; next/next-mask/cache/first on stack.
   All branches below use public input A, fixed loop counts, or public scheduling. */
.syntax unified
.thumb
.cpu cortex-m4
.text
.align 2
.macro transition out, multiplicand, init
    ldr r3, [\multiplicand], #4
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
.macro path name, dual, store, init
.L\name:
    cmp r5,r10
    bhs.w .Ldone
    cmp r4,#252
    bhi.w .L\name\()_tail
    ldr r0,[r5],#3
    ubfx r0,r0,#0,#23
    cmp r0,r8
    bhs .L\name\()_step0
    .if \store
       strh r0,[lr]
       lsr r1,r0,#16
       strb r1,[lr,#2]
       add lr,lr,#3
    .endif
    transition r6,r7,\init
    .if \dual
       transition r11,r12,\init
    .endif
    add r4,r4,#1
.L\name\()_step0:
    ldrh r0,[r5]
    ldrb r1,[r5,#2]
    add r5,r5,#3
    orr r0,r0,r1,lsl #16
    bic r0,r0,#0x800000
    cmp r0,r8
    bhs .L\name\()_step1
    .if \store
       strh r0,[lr]
       lsr r1,r0,#16
       strb r1,[lr,#2]
       add lr,lr,#3
    .endif
    transition r6,r7,\init
    .if \dual
       transition r11,r12,\init
    .endif
    add r4,r4,#1
.L\name\()_step1:
    b.w .L\name
.L\name\()_tail:
    cmp r5,r10
    bhs.w .Ldone
    cmp r4,#256
    bhs.w .Ldone
    ldrh r0,[r5]
    ldrb r1,[r5,#2]
    add r5,r5,#3
    orr r0,r0,r1,lsl #16
    bic r0,r0,#0x800000
    cmp r0,r8
    bhs .L\name\()_tail
    .if \store
       strh r0,[lr]
       lsr r1,r0,#16
       strb r1,[lr,#2]
       add lr,lr,#3
    .endif
    transition r6,r7,\init
    .if \dual
       transition r11,r12,\init
    .endif
    add r4,r4,#1
    b .L\name\()_tail
.endm
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
    ldr r2,[sp,#48]
    movw r8,#57345
    movt r8,#127
    movw r9,#57343
    movt r9,#64639
    cmp lr,#0
    beq .Lselectuncached
    add lr,lr,r0
    cmp r11,#0
    beq .Lcsingle
    add r11,r11,r0
    add r12,r12,r4,lsl #2
    cmp r2,#0
    bne .Lcdi
    b .Lcda
.Lcsingle:
    cmp r2,#0
    bne .Lcsi
    b .Lcsa
.Lselectuncached:
    cmp r11,#0
    beq .Lnsingle
    add r11,r11,r0
    add r12,r12,r4,lsl #2
    cmp r2,#0
    bne .Lndi
    b .Lnda
.Lnsingle:
    cmp r2,#0
    bne .Lnsi
    b .Lnsa
    path cdi,1,1,1
    path cda,1,1,0
    path csi,0,1,1
    path csa,0,1,0
    path ndi,1,0,1
    path nda,1,0,0
    path nsi,0,0,1
    path nsa,0,0,0
.Ldone:
    mov r0,r4
    pop.w {r4-r11,pc}
.size a127_pair_block_plain, .-a127_pair_block_plain
