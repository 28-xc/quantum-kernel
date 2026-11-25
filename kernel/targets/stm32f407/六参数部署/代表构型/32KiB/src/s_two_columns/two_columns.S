/* Each input is a copied public q coefficient (< q) or a signed NTT word.
   Exact R^-1 reduction of their sum. Four inputs fit inside 47 signed
   bits even for signed 24-bit transformed masks. */
.syntax unified
.thumb
.cpu cortex-m4
.text
.balign 4
.macro get24 d,p,tmp
    ldrh \d,[\p]
    ldrb \tmp,[\p,#2]
    add \p,\p,#3
    orr \d,\d,\tmp,lsl #16
.endm
.macro loop id,first
.Ltc\id:
    get24 r0,r5,r2
    ldr r1,[r7],#4
    smull r2,r3,r0,r1
    get24 r0,r6,r1
    ldr r1,[r8],#4
    smlal r2,r3,r0,r1
    mul r0,r2,r10
    smlal r2,r3,r0,r9
    .if !\first
        ldrh r0,[r4]
        ldrsb r1,[r4,#2]
        orr r0,r0,r1,lsl #16
        add r3,r3,r0
    .endif
    add r1,r3,#4194304
    asr r1,r1,#23
    mls r3,r1,r9,r3
    strh r3,[r4]
    asr r3,r3,#16
    strb r3,[r4,#2]
    add r4,r4,#3
    subs r11,r11,#1
    bne .Ltc\id
    pop.w {r4-r11,pc}
.endm
.global a127_two_column_sum
.type a127_two_column_sum,%function
.thumb_func
a127_two_column_sum:
    push.w {r4-r11,lr}
    mov r4,r0
    mov r5,r1
    mov r6,r2
    mov r7,r3
    ldr r8,[sp,#36]
    ldr r2,[sp,#40]
    movw r9,#57345
    movt r9,#127
    movw r10,#57343
    movt r10,#64639
    movw r11,#256
    cmp r2,#0
    beq .Ltcadd
    loop init,1
    loop add,0
.size a127_two_column_sum,.-a127_two_column_sum
