.macro load a, a0, a1, a2, a3, mem0, mem1, mem2, mem3
  ldr.w \a0, [\a, \mem0]
  ldr.w \a1, [\a, \mem1]
  ldr.w \a2, [\a, \mem2]
  ldr.w \a3, [\a, \mem3]
.endm
.macro store a, a0, a1, a2, a3, mem0, mem1, mem2, mem3
  str.w \a0, [\a, \mem0]
  str.w \a1, [\a, \mem1]
  str.w \a2, [\a, \mem2]
  str.w \a3, [\a, \mem3]
.endm
.macro doubleplant a, tmp, q, qa, plantconst
 smulwb \tmp, \plantconst, \a
 smulwt \a, \plantconst, \a
 smlabt \tmp, \tmp, \q, \qa
 smlabt \a, \a, \q, \qa
 pkhtb \a, \a, \tmp, asr#16
.endm
.macro doublebarrett a, tmp, tmp2, q, barrettconst
  smulbb \tmp, \a, \barrettconst
  smultb \tmp2, \a, \barrettconst
  asr \tmp, \tmp, #26
  asr \tmp2, \tmp2, #26
  smulbb \tmp, \tmp, \q
  smulbb \tmp2, \tmp2, \q
  pkhbt \tmp, \tmp, \tmp2, lsl#16
  usub16 \a, \a, \tmp
.endm
.macro plant_red q, qa, qinv, tmp
 mul \tmp, \tmp, \qinv
 smlatt \tmp, \tmp, \q, \qa
.endm
.syntax unified
.cpu cortex-m4
.thumb
.global basemul_asm_opt_16_32
.type basemul_asm_opt_16_32, %function
.align 2
basemul_asm_opt_16_32:
  push {r4-r11, lr}
  rptr_tmp .req r0
  aptr .req r1
  bptr .req r2
  aprimeptr .req r3
  poly0 .req r4
  poly1 .req r6
  poly2 .req r5
  poly3 .req r7
  q .req r8
  qa .req r9
  qinv .req r10
  tmp .req r11
  tmp2 .req r12
  loop .req r14
 ### qinv=0x6ba8f301
  movw loop, #64
  1:
    ldr poly0, [aptr], #4
    ldr poly1, [bptr], #4
    ldr poly2, [aptr], #4
    ldr poly3, [bptr], #4
    ldr.w tmp, [aprimeptr, #4]
    ldr tmp2, [aprimeptr], #8
    smuad tmp2, tmp2, poly1
    str tmp2, [rptr_tmp], #4
    smuadx tmp2, poly0, poly1
    str tmp2, [rptr_tmp], #4
    smuad tmp2, tmp, poly3
    str tmp2, [rptr_tmp], #4
    smuadx tmp2, poly2, poly3
    str tmp2, [rptr_tmp], #4
    subs.w loop, #1
  bne.w 1b
  pop {r4-r11, pc}
.global basemul_asm_acc_opt_32_32
.type basemul_asm_acc_opt_32_32, %function
.align 2
basemul_asm_acc_opt_32_32:
  push {r4-r11, lr}
  rptr_tmp .req r0
  aptr .req r1
  bptr .req r2
  aprimeptr .req r3
  poly0 .req r4
  poly1 .req r6
  res0 .req r5
  res1 .req r7
  q .req r8
  qa .req r9
  qinv .req r10
  tmp .req r11
  tmp2 .req r12
  loop .req r14
 ### qinv=0x6ba8f301
  movw loop, #64
  1:
    ldr poly0, [aptr], #4
    ldr poly1, [bptr], #4
    ldr.w res0, [rptr_tmp]
    ldr tmp2, [aprimeptr], #4
    ldr.w res1, [rptr_tmp, #4]
    smlad tmp2, tmp2, poly1, res0
    str tmp2, [rptr_tmp], #4
    smladx tmp, poly0, poly1, res1
    str tmp, [rptr_tmp], #4
    ldr poly0, [aptr], #4
    ldr poly1, [bptr], #4
    ldr.w res0, [rptr_tmp]
    ldr tmp2, [aprimeptr], #4
    ldr.w res1, [rptr_tmp, #4]
    smlad tmp2, tmp2, poly1, res0
    str tmp2, [rptr_tmp], #4
    smladx tmp, poly0, poly1, res1
    str tmp, [rptr_tmp], #4
    subs.w loop, #1
  bne.w 1b
  pop {r4-r11, pc}
.unreq rptr_tmp
.global basemul_asm_acc_opt_32_16
.type basemul_asm_acc_opt_32_16, %function
.align 2
basemul_asm_acc_opt_32_16:
  push {r4-r11, lr}
  rptr .req r0
  aptr .req r1
  bptr .req r2
  aprimeptr .req r3
  poly0 .req r4
  poly1 .req r6
  res0 .req r5
  res1 .req r7
  q .req r8
  qa .req r9
  qinv .req r10
  tmp2 .req r12
  rptr_tmp .req r11
  loop .req r14
  movw qa, #26632
 movt q, #3329
 ### qinv=0x6ba8f301
 movw qinv, #62209
 movt qinv, #27560
  ldr rptr_tmp, [sp, #9*4]
  movw loop, #64
  1:
    ldr poly0, [aptr], #4
    ldr poly1, [bptr], #4
    ldr.w res0, [rptr_tmp], #4
    ldr tmp2, [aprimeptr], #4
    ldr.w res1, [rptr_tmp], #4
    smlad res0, tmp2, poly1, res0
    plant_red q, qa, qinv, res0
    smladx res1, poly0, poly1, res1
    plant_red q, qa, qinv, res1
    pkhtb res0, res1, res0, asr#16
    str res0, [rptr], #4
    ldr poly0, [aptr], #4
    ldr poly1, [bptr], #4
    ldr.w res0, [rptr_tmp], #4
    ldr tmp2, [aprimeptr], #4
    ldr.w res1, [rptr_tmp], #4
    smlad res0, tmp2, poly1, res0
    plant_red q, qa, qinv, res0
    smladx res1, poly0, poly1, res1
    plant_red q, qa, qinv, res1
    pkhtb res0, res1, res0, asr#16
    str res0, [rptr], #4
    subs.w loop, #1
  bne.w 1b
  pop {r4-r11, pc}
