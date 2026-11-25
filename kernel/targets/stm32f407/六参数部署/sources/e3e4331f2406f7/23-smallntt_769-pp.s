.macro montgomery_mul_32 a, b, Qprime, Q, tmp, tmp2
    smull \tmp, \a, \a, \b
    mul \tmp2, \tmp, \Qprime
    smlal \tmp, \a, \tmp2, \Q
.endm
.macro addSub1 c0, c1
    add.w \c0, \c1
    sub.w \c1, \c0, \c1, lsl #1
.endm
.macro addSub2 c0, c1, c2, c3
    add \c0, \c1
    add \c2, \c3
    sub.w \c1, \c0, \c1, lsl #1
    sub.w \c3, \c2, \c3, lsl #1
.endm
.macro addSub4 c0, c1, c2, c3, c4, c5, c6, c7
    add \c0, \c1
    add \c2, \c3
    add \c4, \c5
    add \c6, \c7
    sub.w \c1, \c0, \c1, lsl #1
    sub.w \c3, \c2, \c3, lsl #1
    sub.w \c5, \c4, \c5, lsl #1
    sub.w \c7, \c6, \c7, lsl #1
.endm
.macro _2_layer_CT_32 c0, c1, c2, c3, zeta0, zeta1, zeta2, Qprime, Q, tmp, tmp2
    montgomery_mul_32 \c2, \zeta0, \Qprime, \Q, \tmp, \tmp2
    montgomery_mul_32 \c3, \zeta0, \Qprime, \Q, \tmp, \tmp2
    addSub2 \c0, \c2, \c1, \c3
    montgomery_mul_32 \c1, \zeta1, \Qprime, \Q, \tmp, \tmp2
    montgomery_mul_32 \c3, \zeta2, \Qprime, \Q, \tmp, \tmp2
    addSub2 \c0, \c1, \c2, \c3
.endm
.macro _2_layer_inv_CT_32 c0, c1, c2, c3, zeta0, zeta1, zeta2, Qprime, Q, tmp, tmp2
    montgomery_mul_32 \c1, \zeta0, \Qprime, \Q, \tmp, \tmp2
    montgomery_mul_32 \c3, \zeta0, \Qprime, \Q, \tmp, \tmp2
    addSub2 \c0, \c1, \c2, \c3
    montgomery_mul_32 \c2, \zeta1, \Qprime, \Q, \tmp, \tmp2
    montgomery_mul_32 \c3, \zeta2, \Qprime, \Q, \tmp, \tmp2
    addSub2 \c0, \c2, \c1, \c3
.endm
.macro _3_layer_CT_32 c0, c1, c2, c3, c4, c5, c6, c7, xi0, xi1, xi2, xi3, xi4, xi5, xi6, twiddle, Qprime, Q, tmp, tmp2
    vmov.w \twiddle, \xi0
    montgomery_mul_32 \c4, \twiddle, \Qprime, \Q, \tmp, \tmp2
    montgomery_mul_32 \c5, \twiddle, \Qprime, \Q, \tmp, \tmp2
    montgomery_mul_32 \c6, \twiddle, \Qprime, \Q, \tmp, \tmp2
    montgomery_mul_32 \c7, \twiddle, \Qprime, \Q, \tmp, \tmp2
    addSub4 \c0, \c4, \c1, \c5, \c2, \c6, \c3, \c7
    vmov.w \twiddle, \xi1
    montgomery_mul_32 \c2, \twiddle, \Qprime, \Q, \tmp, \tmp2
    montgomery_mul_32 \c3, \twiddle, \Qprime, \Q, \tmp, \tmp2
    vmov.w \twiddle, \xi2
    montgomery_mul_32 \c6, \twiddle, \Qprime, \Q, \tmp, \tmp2
    montgomery_mul_32 \c7, \twiddle, \Qprime, \Q, \tmp, \tmp2
    addSub4 \c0, \c2, \c1, \c3, \c4, \c6, \c5, \c7
    vmov.w \twiddle, \xi3
    montgomery_mul_32 \c1, \twiddle, \Qprime, \Q, \tmp, \tmp2
    vmov.w \twiddle, \xi4
    montgomery_mul_32 \c3, \twiddle, \Qprime, \Q, \tmp, \tmp2
    vmov.w \twiddle, \xi5
    montgomery_mul_32 \c5, \twiddle, \Qprime, \Q, \tmp, \tmp2
    vmov.w \twiddle, \xi6
    montgomery_mul_32 \c7, \twiddle, \Qprime, \Q, \tmp, \tmp2
    addSub4 \c0, \c1, \c2, \c3, \c4, \c5, \c6, \c7
.endm
.macro _3_layer_inv_CT_32 c0, c1, c2, c3, c4, c5, c6, c7, xi0, xi1, xi2, xi3, xi4, xi5, xi6, twiddle, Qprime, Q, tmp, tmp2
    vmov.w \twiddle, \xi0
    montgomery_mul_32 \c1, \twiddle, \Qprime, \Q, \tmp, \tmp2
    montgomery_mul_32 \c3, \twiddle, \Qprime, \Q, \tmp, \tmp2
    montgomery_mul_32 \c5, \twiddle, \Qprime, \Q, \tmp, \tmp2
    montgomery_mul_32 \c7, \twiddle, \Qprime, \Q, \tmp, \tmp2
    addSub4 \c0, \c1, \c2, \c3, \c4, \c5, \c6, \c7
    vmov.w \twiddle, \xi1
    montgomery_mul_32 \c2, \twiddle, \Qprime, \Q, \tmp, \tmp2
    montgomery_mul_32 \c6, \twiddle, \Qprime, \Q, \tmp, \tmp2
    vmov.w \twiddle, \xi2
    montgomery_mul_32 \c3, \twiddle, \Qprime, \Q, \tmp, \tmp2
    montgomery_mul_32 \c7, \twiddle, \Qprime, \Q, \tmp, \tmp2
    addSub4 \c0, \c2, \c1, \c3, \c4, \c6, \c5, \c7
    vmov.w \twiddle, \xi3
    montgomery_mul_32 \c4, \twiddle, \Qprime, \Q, \tmp, \tmp2
    vmov.w \twiddle, \xi4
    montgomery_mul_32 \c5, \twiddle, \Qprime, \Q, \tmp, \tmp2
    vmov.w \twiddle, \xi5
    montgomery_mul_32 \c6, \twiddle, \Qprime, \Q, \tmp, \tmp2
    vmov.w \twiddle, \xi6
    montgomery_mul_32 \c7, \twiddle, \Qprime, \Q, \tmp, \tmp2
    addSub4 \c0, \c4, \c1, \c5, \c2, \c6, \c3, \c7
.endm
.macro _3_layer_inv_butterfly_light_fast_first c0, c1, c2, c3, c4, c5, c6, c7, xi0, xi1, xi2, xi3, xi4, xi5, xi6, twiddle, Qprime, Q, tmp, tmp2
    addSub2 \c4, \c1, \c6, \c3
    addSub1 \c4, \c6
    vmov.w \tmp, \xi4
    vmov.w \tmp2, \xi6
    smull.w \c0, \c5, \c1, \tmp
    smlal.w \c0, \c5, \c3, \tmp2
    mul.w \twiddle, \c0, \Qprime
    smlal.w \c0, \c5, \twiddle, \Q
    smull.w \c2, \c7, \c1, \tmp2
    smlal.w \c2, \c7, \c3, \tmp
    mul.w \twiddle, \c2, \Qprime
    smlal.w \c2, \c7, \twiddle, \Q
.endm
.macro _3_layer_inv_butterfly_light_fast_second c0, c1, c2, c3, c4, c5, c6, c7, xi0, xi1, xi2, xi3, xi4, xi5, xi6, twiddle, Qprime, Q, tmp, tmp2
    addSub2 \c0, \c1, \c2, \c3
    vmov.w \twiddle, \xi2
    montgomery_mul_32 \c3, \twiddle, \Qprime, \Q, \tmp, \tmp2
    addSub2 \c0, \c2, \c1, \c3
    montgomery_mul_32 \c6, \twiddle, \Qprime, \Q, \tmp, \tmp2
    addSub4 \c0, \c4, \c1, \c5, \c2, \c6, \c3, \c7
.endm

.syntax unified
.cpu cortex-m4
.thumb
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
.macro mul_twiddle_plant a, twiddle, tmp, q, qa
 smulwb \tmp, \twiddle, \a
 smulwt \a, \twiddle, \a
 smlabt \tmp, \tmp, \q, \qa
 smlabt \a, \a, \q, \qa
 pkhtb \a, \a, \tmp, asr#16
.endm
.macro doublebutterfly_plant a0, a1, twiddle, tmp, q, qa
 smulwb \tmp, \twiddle, \a1
 smulwt \a1, \twiddle, \a1
 smlabt \tmp, \tmp, \q, \qa
 smlabt \a1, \a1, \q, \qa
 pkhtb \tmp, \a1, \tmp, asr#16
 usub16 \a1, \a0, \tmp
 uadd16 \a0, \a0, \tmp
.endm
.macro two_doublebutterfly_plant a0, a1, a2, a3, twiddle0, twiddle1, tmp, q, qa
 doublebutterfly_plant \a0, \a1, \twiddle0, \tmp, \q, \qa
 doublebutterfly_plant \a2, \a3, \twiddle1, \tmp, \q, \qa
.endm
.macro _3_layer_double_CT_16_plant c0, c1, c2, c3, c4, c5, c6, c7, twiddle1, twiddle2, twiddle_ptr, q, qa, tmp
 ldr.w \twiddle1, [\twiddle_ptr], #4
 two_doublebutterfly_plant \c0, \c4, \c1, \c5, \twiddle1, \twiddle1, \tmp, \q, \qa
 two_doublebutterfly_plant \c2, \c6, \c3, \c7, \twiddle1, \twiddle1, \tmp, \q, \qa
 ldrd \twiddle1, \twiddle2, [\twiddle_ptr], #8
 two_doublebutterfly_plant \c0, \c2, \c1, \c3, \twiddle1, \twiddle1, \tmp, \q, \qa
 two_doublebutterfly_plant \c4, \c6, \c5, \c7, \twiddle2, \twiddle2, \tmp, \q, \qa
 ldrd \twiddle1, \twiddle2, [\twiddle_ptr], #8
 two_doublebutterfly_plant \c0, \c1, \c2, \c3, \twiddle1, \twiddle2, \tmp, \q, \qa
 ldrd \twiddle1, \twiddle2, [\twiddle_ptr], #8
 two_doublebutterfly_plant \c4, \c5, \c6, \c7, \twiddle1, \twiddle2, \tmp, \q, \qa
.endm
.macro _3_layer_double_CT_16_plant_fp c0, c1, c2, c3, c4, c5, c6, c7, xi0, xi1, xi2, xi3, xi4, xi5, xi6, twiddle1, twiddle2, q, qa, tmp
 vmov \twiddle1, \xi0
 two_doublebutterfly_plant \c0, \c4, \c1, \c5, \twiddle1, \twiddle1, \tmp, \q, \qa
 two_doublebutterfly_plant \c2, \c6, \c3, \c7, \twiddle1, \twiddle1, \tmp, \q, \qa
 vmov \twiddle1, \xi1
 vmov \twiddle2, \xi2
 two_doublebutterfly_plant \c0, \c2, \c1, \c3, \twiddle1, \twiddle1, \tmp, \q, \qa
 two_doublebutterfly_plant \c4, \c6, \c5, \c7, \twiddle2, \twiddle2, \tmp, \q, \qa
 vmov \twiddle1, \xi3
 vmov \twiddle2, \xi4
 two_doublebutterfly_plant \c0, \c1, \c2, \c3, \twiddle1, \twiddle2, \tmp, \q, \qa
 vmov \twiddle1, \xi5
 vmov \twiddle2, \xi6
 two_doublebutterfly_plant \c4, \c5, \c6, \c7, \twiddle1, \twiddle2, \tmp, \q, \qa
.endm
.global small_ntt_asm_769
.type small_ntt_asm_769, %function
.align 2
small_ntt_asm_769:
 push {r4-r11, r14}
 vpush.w {s16-s24}
 poly .req r0
 twiddle_ptr .req r1
 poly0 .req r2
 poly1 .req r3
 poly2 .req r4
 poly3 .req r5
 poly4 .req r6
 poly5 .req r7
 poly6 .req r8
 poly7 .req r9
 twiddle1 .req r10
 twiddle2 .req r11
 ### qinv .req r11 ### q^-1 mod 2^2n; n=16
 q .req r12
 ### at the top of r12
 qa .req r0
 ### qa=2^a q;a=3; at the bottom of r12
 tmp .req r14
 movt q, #769
 ### LAYER 7+6+5+4
 .equ distance, 256
 .equ offset, 32
 .equ strincr, 4
 vldm twiddle_ptr!, {s8-s22}
 add tmp, poly, #strincr*8
 vmov s24, tmp
 1:
  vmov s23, poly
  load poly, poly0, poly1, poly2, poly3, #offset, #distance/4+offset, #2*distance/4+offset, #3*distance/4+offset
  load poly, poly4, poly5, poly6, poly7, #distance+offset, #5*distance/4+offset, #6*distance/4+offset, #7*distance/4+offset
  movw qa, #24608
  _3_layer_double_CT_16_plant_fp poly0, poly1, poly2, poly3, poly4, poly5, poly6, poly7, s8, s9, s10, s11, s12, s13, s14, twiddle1, twiddle2, q, qa, tmp
  vmov twiddle1, s15
  vmov twiddle2, s16
  mul_twiddle_plant poly0, twiddle1, tmp, q, qa
  mul_twiddle_plant poly1, twiddle2, tmp, q, qa
  vmov twiddle1, s17
  vmov twiddle2, s18
  mul_twiddle_plant poly2, twiddle1, tmp, q, qa
  mul_twiddle_plant poly3, twiddle2, tmp, q, qa
  vmov twiddle1, s19
  vmov twiddle2, s20
  mul_twiddle_plant poly4, twiddle1, tmp, q, qa
  mul_twiddle_plant poly5, twiddle2, tmp, q, qa
  vmov twiddle1, s21
  vmov twiddle2, s22
  mul_twiddle_plant poly6, twiddle1, tmp, q, qa
  mul_twiddle_plant poly7, twiddle2, tmp, q, qa
  vmov s0, poly0
  vmov s1, poly1
  vmov s2, poly2
  vmov s3, poly3
  vmov s4, poly4
  vmov s5, poly5
  vmov s6, poly6
  vmov s7, poly7
  vmov poly, s23
  load poly, poly0, poly1, poly2, poly3, #0, #distance/4, #2*distance/4, #3*distance/4
  load poly, poly4, poly5, poly6, poly7, #distance, #5*distance/4, #6*distance/4, #7*distance/4
  movw qa, #24608
  _3_layer_double_CT_16_plant_fp poly0, poly1, poly2, poly3, poly4, poly5, poly6, poly7, s8, s9, s10, s11, s12, s13, s14, twiddle1, twiddle2, q, qa, tmp
  vmov poly, s23
  vmov twiddle1, s1
  uadd16 tmp, poly1, twiddle1
  usub16 poly1, poly1, twiddle1
  str.w tmp, [poly, #1*distance/4]
  str.w poly1, [poly, #1*distance/4+offset]
  vmov twiddle1, s3
  uadd16 tmp, poly3, twiddle1
  usub16 poly3, poly3, twiddle1
  str.w tmp, [poly, #3*distance/4]
  str.w poly3, [poly, #3*distance/4+offset]
  vmov twiddle1, s5
  uadd16 tmp, poly5, twiddle1
  usub16 poly5, poly5, twiddle1
  str.w tmp, [poly, #5*distance/4]
  str.w poly5, [poly, #5*distance/4+offset]
  vmov twiddle1, s7
  uadd16 tmp, poly7, twiddle1
  usub16 poly7, poly7, twiddle1
  str.w tmp, [poly, #7*distance/4]
  str.w poly7, [poly, #7*distance/4+offset]
  vmov poly3, s2
  uadd16 tmp, poly2, poly3
  usub16 twiddle1, poly2, poly3
  str.w tmp, [poly, #2*distance/4]
  str.w twiddle1, [poly, #2*distance/4+offset]
  vmov poly5, s4
  uadd16 tmp, poly4, poly5
  usub16 twiddle1, poly4, poly5
  str.w tmp, [poly, #4*distance/4]
  str.w twiddle1, [poly, #4*distance/4+offset]
  vmov poly7, s6
  uadd16 tmp, poly6, poly7
  usub16 twiddle1, poly6, poly7
  str.w tmp, [poly, #6*distance/4]
  str.w twiddle1, [poly, #6*distance/4+offset]
  vmov poly1, s0
  uadd16 tmp, poly0, poly1
  usub16 twiddle1, poly0, poly1
  str.w twiddle1, [poly, #offset]
  str.w tmp, [poly], #4
 vmov tmp, s24
 cmp.w poly, tmp
 bne.w 1b
 sub.w poly, #8*strincr
 ### LAYER 3+2+1
 .equ distance, distance/16
 .equ strincr, 32
 add.w tmp, poly, #strincr*16
 vmov s13, tmp
 2:
  vmov s23, poly
  load poly, poly0, poly1, poly2, poly3, #0, #distance/4, #2*distance/4, #3*distance/4
  load poly, poly4, poly5, poly6, poly7, #distance, #5*distance/4, #6*distance/4, #7*distance/4
  movw qa, #24608
  _3_layer_double_CT_16_plant poly0, poly1, poly2, poly3, poly4, poly5, poly6, poly7, twiddle1, twiddle2, twiddle_ptr, q, qa, tmp
  vmov poly, s23
  store poly, poly4, poly5, poly6, poly7, #distance, #5*distance/4, #6*distance/4, #7*distance/4
  str.w poly1, [poly, #distance/4]
  str.w poly2, [poly, #2*distance/4]
  str.w poly3, [poly, #3*distance/4]
  str.w poly0, [poly], #strincr
 vmov tmp, s13
 cmp.w poly, tmp
 bne.w 2b
 vpop.w {s16-s24}
 pop {r4-r11, pc}
.unreq poly
.unreq twiddle_ptr
.unreq poly0
.unreq poly1
.unreq poly2
.unreq poly3
.unreq poly4
.unreq poly5
.unreq poly6
.unreq poly7
.unreq twiddle1
.unreq twiddle2
.unreq q
.unreq qa
.unreq tmp
.macro _3_layer_double_inv_CT_16_plant_light c0, c1, c2, c3, c4, c5, c6, c7, xi2, xi4, xi5, xi6, twiddle1, tmp2, q, qa, tmp
 sadd16.w \tmp, \c0, \c1
 ssub16.w \c1, \c0, \c1
 sadd16.w \tmp2, \c2, \c3
 ssub16.w \c3, \c2, \c3
 sadd16.w \c0, \c4, \c5
 ssub16.w \c5, \c4, \c5
 sadd16.w \c2, \c6, \c7
 ssub16.w \c7, \c6, \c7
 sadd16.w \c6, \tmp, \tmp2
 ssub16.w \tmp2, \tmp, \tmp2
 sadd16.w \c4, \c0, \c2
 ssub16.w \c2, \c0, \c2
 vmov.w \twiddle1, \xi2
 doublebutterfly_plant \c1, \c3, \twiddle1, \tmp, \q, \qa
 doublebutterfly_plant \c5, \c7, \twiddle1, \tmp, \q, \qa
 sadd16.w \c0, \c6, \c4
 ssub16.w \c4, \c6, \c4
 vmov.w \twiddle1, \xi4
 doublebutterfly_plant \c1, \c5, \twiddle1, \tmp, \q, \qa
 vmov.w \twiddle1, \xi5
 smulwb \tmp, \twiddle1, \c2
 smulwt \c2, \twiddle1, \c2
 smlabt \tmp, \tmp, \q, \qa
 smlabt \c2, \c2, \q, \qa
 pkhtb \tmp, \c2, \tmp, asr#16
 ssub16.w \c6, \tmp2, \tmp
 sadd16.w \c2, \tmp2, \tmp
 vmov.w \twiddle1, \xi6
 doublebutterfly_plant \c3, \c7, \twiddle1, \tmp, \q, \qa
.endm
.macro _3_layer_double_inv_CT_16_plant c0, c1, c2, c3, c4, c5, c6, c7, twiddle1, twiddle2, twiddle_ptr, q, qa, tmp
 ldr.w \twiddle1, [\twiddle_ptr], #4
 two_doublebutterfly_plant \c0, \c1, \c2, \c3, \twiddle1, \twiddle1, \tmp, \q, \qa
 two_doublebutterfly_plant \c4, \c5, \c6, \c7, \twiddle1, \twiddle1, \tmp, \q, \qa
 ldrd \twiddle1, \twiddle2, [\twiddle_ptr], #8
 two_doublebutterfly_plant \c0, \c2, \c1, \c3, \twiddle1, \twiddle2, \tmp, \q, \qa
 two_doublebutterfly_plant \c4, \c6, \c5, \c7, \twiddle1, \twiddle2, \tmp, \q, \qa
 ldrd \twiddle1, \twiddle2, [\twiddle_ptr], #8
 two_doublebutterfly_plant \c0, \c4, \c1, \c5, \twiddle1, \twiddle2, \tmp, \q, \qa
 ldrd \twiddle1, \twiddle2, [\twiddle_ptr], #8
 two_doublebutterfly_plant \c2, \c6, \c3, \c7, \twiddle1, \twiddle2, \tmp, \q, \qa
.endm
.macro _3_layer_double_inv_twist_16_plant c0, c1, c2, c3, c4, c5, c6, c7, twiddle1, twiddle2, twiddle_ptr, q, qa, tmp
 ldrd \twiddle1, \twiddle2, [\twiddle_ptr], #8
 mul_twiddle_plant \c0, \twiddle1, \tmp, \q, \qa
 mul_twiddle_plant \c1, \twiddle2, \tmp, \q, \qa
 ldrd \twiddle1, \twiddle2, [\twiddle_ptr], #8
 mul_twiddle_plant \c2, \twiddle1, \tmp, \q, \qa
 mul_twiddle_plant \c3, \twiddle2, \tmp, \q, \qa
 ldrd \twiddle1, \twiddle2, [\twiddle_ptr], #8
 mul_twiddle_plant \c4, \twiddle1, \tmp, \q, \qa
 mul_twiddle_plant \c5, \twiddle2, \tmp, \q, \qa
 ldrd \twiddle1, \twiddle2, [\twiddle_ptr], #8
 mul_twiddle_plant \c6, \twiddle1, \tmp, \q, \qa
 mul_twiddle_plant \c7, \twiddle2, \tmp, \q, \qa
.endm
 # input coefficients < 0.5q
.global small_invntt_asm_769
.type small_invntt_asm_769, %function
.align 2
small_invntt_asm_769:
 push {r4-r11, r14}
 vpush.w {s16-s23}
 poly .req r0
 twiddle_ptr .req r1
 poly0 .req r2
 poly1 .req r3
 poly2 .req r4
 poly3 .req r5
 poly4 .req r6
 poly5 .req r7
 poly6 .req r8
 poly7 .req r9
 twiddle1 .req r10
 twiddle2 .req r11
 q .req r12
 qa .req r0
 tmp .req r14
 movt q, #769
 ### LAYER 7+6+5+4
 .equ distance, 16
 .equ offset, 32
 .equ strincr, 64
 vldm twiddle_ptr!, {s8-s22}
 add.w tmp, poly, #8*strincr
 vmov s8, tmp
 1:
  vmov s23, poly
  load poly, poly0, poly1, poly2, poly3, #offset, #distance/4+offset, #2*distance/4+offset, #3*distance/4+offset
  load poly, poly4, poly5, poly6, poly7, #distance+offset, #5*distance/4+offset, #6*distance/4+offset, #7*distance/4+offset
  movw qa, #24608
  _3_layer_double_inv_CT_16_plant_light poly0, poly1, poly2, poly3, poly4, poly5, poly6, poly7, s10, s12, s13, s14, twiddle1, twiddle2, q, qa, tmp
  vmov twiddle2, s16
  mul_twiddle_plant poly1, twiddle2, tmp, q, qa
  vmov twiddle1, s17
  vmov twiddle2, s18
  mul_twiddle_plant poly2, twiddle1, tmp, q, qa
  mul_twiddle_plant poly3, twiddle2, tmp, q, qa
  vmov twiddle1, s19
  vmov twiddle2, s20
  mul_twiddle_plant poly4, twiddle1, tmp, q, qa
  mul_twiddle_plant poly5, twiddle2, tmp, q, qa
  vmov twiddle1, s21
  vmov twiddle2, s22
  mul_twiddle_plant poly6, twiddle1, tmp, q, qa
  mul_twiddle_plant poly7, twiddle2, tmp, q, qa
  vmov s0, poly0
  vmov s1, poly1
  vmov s2, poly2
  vmov s3, poly3
  vmov s4, poly4
  vmov s5, poly5
  vmov s6, poly6
  vmov s7, poly7
  vmov poly, s23
  load poly, poly0, poly1, poly2, poly3, #0, #distance/4, #2*distance/4, #3*distance/4
  load poly, poly4, poly5, poly6, poly7, #distance, #5*distance/4, #6*distance/4, #7*distance/4
  movw qa, #24608
  _3_layer_double_inv_CT_16_plant_light poly0, poly1, poly2, poly3, poly4, poly5, poly6, poly7, s10, s12, s13, s14, twiddle1, twiddle2, q, qa, tmp
  vmov poly, s23
  vmov twiddle2, s1
  uadd16 tmp, poly1, twiddle2
  usub16 poly1, poly1, twiddle2
  str.w tmp, [poly, #1*distance/4]
  str.w poly1, [poly, #1*distance/4+offset]
  vmov twiddle2, s3
  uadd16 tmp, poly3, twiddle2
  usub16 poly3, poly3, twiddle2
  str.w tmp, [poly, #3*distance/4]
  str.w poly3, [poly, #3*distance/4+offset]
  vmov twiddle2, s5
  uadd16 tmp, poly5, twiddle2
  usub16 poly5, poly5, twiddle2
  str.w tmp, [poly, #5*distance/4]
  str.w poly5, [poly, #5*distance/4+offset]
  vmov twiddle2, s7
  uadd16 tmp, poly7, twiddle2
  usub16 poly7, poly7, twiddle2
  str.w tmp, [poly, #7*distance/4]
  str.w poly7, [poly, #7*distance/4+offset]
  vmov poly3, s2
  uadd16 tmp, poly2, poly3
  usub16 twiddle2, poly2, poly3
  str.w tmp, [poly, #2*distance/4]
  str.w twiddle2, [poly, #2*distance/4+offset]
  vmov poly5, s4
  uadd16 tmp, poly4, poly5
  usub16 twiddle2, poly4, poly5
  str.w tmp, [poly, #4*distance/4]
  str.w twiddle2, [poly, #4*distance/4+offset]
  vmov poly7, s6
  uadd16 tmp, poly6, poly7
  usub16 twiddle2, poly6, poly7
  str.w tmp, [poly, #6*distance/4]
  str.w twiddle2, [poly, #6*distance/4+offset]
  vmov poly1, s0
  uadd16 tmp, poly0, poly1
  usub16 twiddle2, poly0, poly1
  str.w twiddle2, [poly, #offset]
  str.w tmp, [poly], #strincr
 vmov tmp, s8
 cmp.w poly, tmp
 bne.w 1b
 sub.w poly, #8*strincr
 ### LAYER 3+2+1
 .equ distance, distance*16
 .equ strincr, 4
 vmov s6, poly
 load poly, poly0, poly1, poly2, poly3, #0, #distance/4, #2*distance/4, #3*distance/4
 load poly, poly4, poly5, poly6, poly7, #distance, #5*distance/4, #6*distance/4, #7*distance/4
 vldm twiddle_ptr!, {s0-s5}
 movw qa, #24608
 _3_layer_double_inv_CT_16_plant_light poly0, poly1, poly2, poly3, poly4, poly5, poly6, poly7, s1, s3, s4, s5, twiddle1, twiddle2, q, qa, tmp
 _3_layer_double_inv_twist_16_plant poly0, poly1, poly2, poly3, poly4, poly5, poly6, poly7, twiddle1, twiddle2, twiddle_ptr, q, qa, tmp
 vmov poly, s6
 store poly, poly4, poly5, poly6, poly7, #distance, #5*distance/4, #6*distance/4, #7*distance/4
 str.w poly1, [poly, #distance/4]
 str.w poly2, [poly, #2*distance/4]
 str.w poly3, [poly, #3*distance/4]
 str.w poly0, [poly], #4
 add.w tmp, poly, #strincr*3*(5)
 vmov s14, tmp
 2:
  vmov s6, poly
  load poly, poly0, poly1, poly2, poly3, #0, #distance/4, #2*distance/4, #3*distance/4
  load poly, poly4, poly5, poly6, poly7, #distance, #5*distance/4, #6*distance/4, #7*distance/4
  movw qa, #24608
  _3_layer_double_inv_CT_16_plant poly0, poly1, poly2, poly3, poly4, poly5, poly6, poly7, twiddle1, twiddle2, twiddle_ptr, q, qa, tmp
  _3_layer_double_inv_twist_16_plant poly0, poly1, poly2, poly3, poly4, poly5, poly6, poly7, twiddle1, twiddle2, twiddle_ptr, q, qa, tmp
  vmov poly, s6
  store poly, poly4, poly5, poly6, poly7, #distance, #5*distance/4, #6*distance/4, #7*distance/4
  str.w poly1, [poly, #distance/4]
  str.w poly2, [poly, #2*distance/4]
  str.w poly3, [poly, #3*distance/4]
  str.w poly0, [poly], #4
 vmov tmp, s14
 cmp.w poly, tmp
 bne.w 2b
 vpop.w {s16-s23}
 pop {r4-r11, pc}
.unreq poly
.unreq twiddle_ptr
.unreq poly0
.unreq poly1
.unreq poly2
.unreq poly3
.unreq poly4
.unreq poly5
.unreq poly6
.unreq poly7
.unreq twiddle1
.unreq twiddle2
.unreq q
.unreq qa
.unreq tmp
.global small_basemul_asm_769
.type small_basemul_asm_769, %function
.align 2
small_basemul_asm_769:
 push {r4-r11, lr}
 rptr .req r0
 aptr .req r1
 bptr .req r2
 zetaptr .req r3
 poly0 .req r4
 poly1 .req r6
 poly2 .req r5
 poly3 .req r7
 q .req r8
 qa .req r14
 qinv .req r9
 tmp .req r10
 tmp2 .req r11
 zeta .req r12
 loop .req r14
 movt q, #769
 movw qinv, #64769
 movt qinv, #58632
 movw loop, #64
 1:
 vmov.w s0,loop
 movw qa, #24608
 ldrd poly0, poly2, [aptr], #8
 ldrd poly1, poly3, [bptr], #8
 ldr.w zeta, [zetaptr], #4
 smulwt tmp, zeta, poly1
 smlabt tmp, tmp, q, qa
 smultt tmp, poly0, tmp
 smlabb tmp, poly0, poly1, tmp
 plant_red q, qa, qinv, tmp
 smuadx tmp2, poly0, poly1
 plant_red q, qa, qinv, tmp2
 pkhtb tmp, tmp2, tmp, asr#16
 str tmp, [rptr], #4
 neg zeta, zeta
 smulwt tmp, zeta, poly3
 smlabt tmp, tmp, q, qa
 smultt tmp, poly2, tmp
 smlabb tmp, poly2, poly3, tmp
 plant_red q, qa, qinv, tmp
 smuadx tmp2, poly2, poly3
 plant_red q, qa, qinv, tmp2
 pkhtb tmp, tmp2, tmp, asr#16
 str tmp, [rptr], #4
 vmov.w loop,s0
 subs.w loop, #1
 bne.w 1b
 .unreq rptr
 .unreq aptr
 .unreq bptr
 .unreq zetaptr
 .unreq poly0
 .unreq poly1
 .unreq poly2
 .unreq poly3
 .unreq q
 .unreq qa
 .unreq qinv
 .unreq tmp
 .unreq tmp2
 .unreq zeta
 .unreq loop
 pop {r4-r11, pc}
