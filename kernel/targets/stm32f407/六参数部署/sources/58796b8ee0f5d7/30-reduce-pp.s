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
.global asm_barrett_reduce
.type asm_barrett_reduce,%function
.align 2
asm_barrett_reduce:
 push {r4-r11, r14}
 poly .req r0
 poly0 .req r1
 poly1 .req r2
 poly2 .req r3
 poly3 .req r4
 poly4 .req r5
 poly5 .req r6
 poly6 .req r7
 poly7 .req r8
 loop .req r9
 barrettconst .req r10
 q .req r11
 tmp .req r12
 tmp2 .req r14
 movw barrettconst, #20159
 movw q, #3329
 movw loop, #16
 1:
  ldm poly, {poly0-poly7}
  doublebarrett poly0, tmp, tmp2, q, barrettconst
  doublebarrett poly1, tmp, tmp2, q, barrettconst
  doublebarrett poly2, tmp, tmp2, q, barrettconst
  doublebarrett poly3, tmp, tmp2, q, barrettconst
  doublebarrett poly4, tmp, tmp2, q, barrettconst
  doublebarrett poly5, tmp, tmp2, q, barrettconst
  doublebarrett poly6, tmp, tmp2, q, barrettconst
  doublebarrett poly7, tmp, tmp2, q, barrettconst
  stm poly!, {poly0-poly7}
 subs.w loop, #1
 bne.w 1b
 .unreq poly
 .unreq poly0
 .unreq poly1
 .unreq poly2
 .unreq poly3
 .unreq poly4
 .unreq poly5
 .unreq poly6
 .unreq poly7
 .unreq loop
 .unreq barrettconst
 .unreq q
 .unreq tmp
 .unreq tmp2
 pop {r4-r11, pc}
.global asm_fromplant
.type asm_fromplant,%function
.align 2
asm_fromplant:
 push {r4-r11, r14}
 poly .req r0
 poly0 .req r1
 poly1 .req r2
 poly2 .req r3
 poly3 .req r4
 poly4 .req r5
 poly5 .req r6
 poly6 .req r7
 poly7 .req r8
 loop .req r9
 plantconst .req r10
 q .req r11
 qa .req r12
 tmp .req r14
 movw qa, #26632
 movt q, #3329
 ### movt qinv, #3327
 ### plant_constant=(Plant_const^2%M)*(p^-1) % 2^32
 movw plantconst, #20396
 movt plantconst, #38900
 movw loop, #16
 1:
  ldm poly, {poly0-poly7}
  doubleplant poly0, tmp, q, qa, plantconst
  doubleplant poly1, tmp, q, qa, plantconst
  doubleplant poly2, tmp, q, qa, plantconst
  doubleplant poly3, tmp, q, qa, plantconst
  doubleplant poly4, tmp, q, qa, plantconst
  doubleplant poly5, tmp, q, qa, plantconst
  doubleplant poly6, tmp, q, qa, plantconst
  doubleplant poly7, tmp, q, qa, plantconst
  stm poly!, {poly0-poly7}
 subs.w loop, #1
 bne.w 1b
 .unreq poly
 .unreq poly0
 .unreq poly1
 .unreq poly2
 .unreq poly3
 .unreq poly4
 .unreq poly5
 .unreq poly6
 .unreq poly7
 .unreq loop
 .unreq plantconst
 .unreq q
 .unreq qa
 .unreq tmp
 pop {r4-r11, pc}
