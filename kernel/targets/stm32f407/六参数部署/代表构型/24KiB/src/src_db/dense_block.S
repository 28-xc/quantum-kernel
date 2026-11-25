/* Decode 56 public matrix candidates from one SHAKE128 block, multiply dense
   row elements by packed, signed 24-bit NTT coefficients. The last byte of
   every three-byte field is addressed individually, including at array end. */
.syntax unified
.thumb
.cpu cortex-m4
.text
.align 2
.macro dot_loop label,init
.L\label:
    cmp r5,r10
    bhs.w .Ld_done
    cmp r4,#256
    bhs.w .Ld_done
    ldrh r0,[r5]
    ldrb r1,[r5,#2]
    add r5,r5,#3
    orr r0,r0,r1,lsl #16
    bic r0,r0,#0x800000
    cmp r0,r8
    bhs .L\label
    ldrh r2,[r7]
    ldrsb r3,[r7,#2]
    add r7,r7,#3
    orr r2,r2,r3,lsl #16
    smull r1,r3,r0,r2
    mul r2,r1,r9
    smlal r1,r3,r2,r8
    .if !\init
      ldr r1,[r6]
      add r3,r3,r1
    .endif
    str r3,[r6],#4
    add r4,r4,#1
    b .L\label
.endm
.global a127_dense_block
.type a127_dense_block,%function
.thumb_func
a127_dense_block:
    push.w {r4-r10,lr}
    mov r4,r0
    mov r5,r1
    add r6,r2,r4,lsl #2
    add r0,r4,r4,lsl #1
    add r7,r3,r0
    add r10,r5,#168
    movw r8,#57345
    movt r8,#127
    movw r9,#57343
    movt r9,#64639
    ldr r2,[sp,#32]
    cmp r2,#0
    beq .Ld_add
    dot_loop d_first,1
    dot_loop d_add,0
.Ld_done:
    mov r0,r4
    pop.w {r4-r10,pc}
.size a127_dense_block, .-a127_dense_block
