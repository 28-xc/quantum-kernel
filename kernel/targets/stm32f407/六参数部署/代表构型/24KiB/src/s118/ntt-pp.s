.syntax unified
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
smlad r0,r0,r0,r0
.global pqcrystals_dilithium_ntt
.type pqcrystals_dilithium_ntt,%function
.align 2
pqcrystals_dilithium_ntt:
  ptr_p .req R0
  ptr_zeta .req R1
  zeta .req R1
  qinv .req R2
  q .req R3
  cntr .req R4
  pol4 .req R4
  pol0 .req R5
  pol1 .req R6
  pol2 .req R7
  pol3 .req R8
  temp_h .req R9
  temp_l .req R10
  zeta0 .req R11
  zeta1 .req R12
  zeta2 .req R14
  pol5 .req R11
  pol6 .req R12
  pol7 .req R14
  push {R4-R11, R14}
  ldr.w qinv, inv_ntt_asm_smull_qinv
  ldr.w q, inv_ntt_asm_smull_q
  .equ distance, 512
  .equ strincr, 4
  ldr ptr_zeta, =#zetas_new332
  vldm ptr_zeta!, {s2-s8}
  vmov s0, ptr_zeta
  add.w temp_l, ptr_p, #32*strincr
  vmov s9, temp_l
  1:
    .rept 1
    ldr.w pol0, [ptr_p]
    ldr.w pol1, [ptr_p, #1*distance/4]
    ldr.w pol2, [ptr_p, #2*distance/4]
    ldr.w pol3, [ptr_p, #3*distance/4]
    ldr.w pol4, [ptr_p, #4*distance/4]
    ldr.w pol5, [ptr_p, #5*distance/4]
    ldr.w pol6, [ptr_p, #6*distance/4]
    ldr.w pol7, [ptr_p, #7*distance/4]
    _3_layer_CT_32 pol0, pol1, pol2, pol3, pol4, pol5, pol6, pol7, s2, s3, s4, s5, s6, s7, s8, zeta, qinv, q, temp_h, temp_l
    str.w pol1, [ptr_p, #1*distance/4]
    str.w pol2, [ptr_p, #2*distance/4]
    str.w pol3, [ptr_p, #3*distance/4]
    str.w pol4, [ptr_p, #4*distance/4]
    str.w pol5, [ptr_p, #5*distance/4]
    str.w pol6, [ptr_p, #6*distance/4]
    str.w pol7, [ptr_p, #7*distance/4]
    str.w pol0, [ptr_p], #strincr
    .endr
    vmov temp_l, s9
    cmp.w ptr_p, temp_l
    bne 1b
  sub ptr_p, #32*4
  .equ distance, 64
  add.w temp_l, ptr_p, #8*112+8*4*4
  vmov s9, temp_l
  1:
    add.w temp_l, ptr_p, #4*strincr
    vmov s10, temp_l
    vmov ptr_zeta, s0
    vldm ptr_zeta!, {s2-s8}
    vmov s0, ptr_zeta
    2:
      .rept 1
      ldr.w pol0, [ptr_p]
      ldr.w pol1, [ptr_p, #1*distance/4]
      ldr.w pol2, [ptr_p, #2*distance/4]
      ldr.w pol3, [ptr_p, #3*distance/4]
      ldr.w pol4, [ptr_p, #4*distance/4]
      ldr.w pol5, [ptr_p, #5*distance/4]
      ldr.w pol6, [ptr_p, #6*distance/4]
      ldr.w pol7, [ptr_p, #7*distance/4]
      _3_layer_CT_32 pol0, pol1, pol2, pol3, pol4, pol5, pol6, pol7, s2, s3, s4, s5, s6, s7, s8, zeta, qinv, q, temp_h, temp_l
      str.w pol1, [ptr_p, #1*distance/4]
      str.w pol2, [ptr_p, #2*distance/4]
      str.w pol3, [ptr_p, #3*distance/4]
      str.w pol4, [ptr_p, #4*distance/4]
      str.w pol5, [ptr_p, #5*distance/4]
      str.w pol6, [ptr_p, #6*distance/4]
      str.w pol7, [ptr_p, #7*distance/4]
      str.w pol0, [ptr_p], #4
      .endr
      vmov temp_l, s10
      cmp.w ptr_p, temp_l
      bne 2b
    add.w ptr_p, #112
    vmov temp_l, s9
    cmp.w ptr_p, temp_l
    bne 1b
    sub ptr_p, #4*4*8+112*8
    vmov ptr_zeta, s0
    add cntr, ptr_p, #1024
    1:
      ldr.w zeta1, [ptr_zeta, #3]
      sbfx zeta1, zeta1, #0, #24
      ldr.w zeta2, [ptr_zeta, #6]
      sbfx zeta2, zeta2, #0, #24
      ldr zeta0, [ptr_zeta], #9
      sbfx zeta0, zeta0, #0, #24
      ldr.w pol0, [ptr_p]
      ldr.w pol1, [ptr_p, #4]
      ldr.w pol2, [ptr_p, #8]
      ldr.w pol3, [ptr_p, #12]
      _2_layer_CT_32 pol0, pol1, pol2, pol3, zeta0, zeta1, zeta2, qinv, q, temp_h, temp_l
      str.w pol1, [ptr_p, #4]
      str.w pol2, [ptr_p, #8]
      str.w pol3, [ptr_p, #12]
      str pol0, [ptr_p], #16
      cmp.w cntr, ptr_p
      bne.w 1b
    pop {R4-R11, PC}
    .unreq ptr_p
    .unreq ptr_zeta
    .unreq qinv
    .unreq q
    .unreq cntr
    .unreq pol0
    .unreq pol1
    .unreq pol2
    .unreq pol3
    .unreq temp_h
    .unreq temp_l
    .unreq zeta0
    .unreq zeta1
    .unreq zeta2
.ltorg
.global pqcrystals_dilithium_invntt_tomont
.type pqcrystals_dilithium_invntt_tomont,%function
.align 2
pqcrystals_dilithium_invntt_tomont:
  ptr_p .req R0
  ptr_zeta .req R1
  zeta .req R1
  qinv .req R2
  q .req R3
  cntr .req R4
  pol4 .req R4
  pol0 .req R5
  pol1 .req R6
  pol2 .req R7
  pol3 .req R8
  temp_h .req R9
  temp_l .req R10
  zeta0 .req R11
  zeta1 .req R12
  zeta2 .req R14
  pol5 .req R11
  pol6 .req R12
  pol7 .req R14
  push {R4-R11, R14}
  ldr.w qinv, inv_ntt_asm_smull_qinv
  ldr.w q, inv_ntt_asm_smull_q
  .equ distance, 16
  .equ strincr, 32
  ldr ptr_zeta, =#zetas_new332inv
  vldm ptr_zeta!, {s2-s8}
  vmov s0, ptr_zeta
  add.w temp_l, ptr_p, #32*strincr
  vmov s9, temp_l
  1:
    ldr.w pol4, [ptr_p, #4*distance/4]
    ldr.w pol1, [ptr_p, #5*distance/4]
    ldr.w pol6, [ptr_p, #6*distance/4]
    ldr.w pol3, [ptr_p, #7*distance/4]
    _3_layer_inv_butterfly_light_fast_first pol0, pol1, pol2, pol3, pol4, pol5, pol6, pol7, s2, s3, s4, s5, s6, s7, s8, zeta, qinv, q, temp_h, temp_l
    ldr.w pol0, [ptr_p]
    ldr.w pol1, [ptr_p, #1*distance/4]
    ldr.w pol2, [ptr_p, #2*distance/4]
    ldr.w pol3, [ptr_p, #3*distance/4]
    _3_layer_inv_butterfly_light_fast_second pol0, pol1, pol2, pol3, pol4, pol5, pol6, pol7, s2, s3, s4, s5, s6, s7, s8, zeta, qinv, q, temp_h, temp_l
    str.w pol1, [ptr_p, #1*distance/4]
    str.w pol2, [ptr_p, #2*distance/4]
    str.w pol3, [ptr_p, #3*distance/4]
    str.w pol4, [ptr_p, #4*distance/4]
    str.w pol5, [ptr_p, #5*distance/4]
    str.w pol6, [ptr_p, #6*distance/4]
    str.w pol7, [ptr_p, #7*distance/4]
    str.w pol0, [ptr_p], #strincr
    vmov temp_l, s9
    cmp.w ptr_p, temp_l
  bne.w 1b
  sub ptr_p, #32*strincr
  .equ distance, 128
  .equ strincr, 256
  movw temp_l, #4
  add.w temp_l, ptr_p, #4*256
  vmov s10, temp_l
  vmov ptr_zeta, s0
  vldm ptr_zeta!, {s2-s8}
  vmov s0, ptr_zeta
  2:
    ldr.w pol4, [ptr_p, #4*distance/4]
    ldr.w pol1, [ptr_p, #5*distance/4]
    ldr.w pol6, [ptr_p, #6*distance/4]
    ldr.w pol3, [ptr_p, #7*distance/4]
    _3_layer_inv_butterfly_light_fast_first pol0, pol1, pol2, pol3, pol4, pol5, pol6, pol7, s2, s3, s4, s5, s6, s7, s8, zeta, qinv, q, temp_h, temp_l
    ldr.w pol0, [ptr_p]
    ldr.w pol1, [ptr_p, #1*distance/4]
    ldr.w pol2, [ptr_p, #2*distance/4]
    ldr.w pol3, [ptr_p, #3*distance/4]
    _3_layer_inv_butterfly_light_fast_second pol0, pol1, pol2, pol3, pol4, pol5, pol6, pol7, s2, s3, s4, s5, s6, s7, s8, zeta, qinv, q, temp_h, temp_l
    str.w pol1, [ptr_p, #1*distance/4]
    str.w pol2, [ptr_p, #2*distance/4]
    str.w pol3, [ptr_p, #3*distance/4]
    str.w pol4, [ptr_p, #4*distance/4]
    str.w pol5, [ptr_p, #5*distance/4]
    str.w pol6, [ptr_p, #6*distance/4]
    str.w pol7, [ptr_p, #7*distance/4]
    str.w pol0, [ptr_p]
    add.w ptr_p, #strincr
    vmov temp_l, s10
    cmp.w temp_l, ptr_p
  bne.w 2b
  sub.w ptr_p, #4*256-4
  add.w temp_l, ptr_p, #7*4
  vmov s9, temp_l
  1:
    add.w temp_l, ptr_p, #4*strincr
    vmov s10, temp_l
   vmov ptr_zeta, s0
    vldm ptr_zeta!, {s2-s8}
    vmov s0, ptr_zeta
    2:
     ldr.w pol0, [ptr_p]
     ldr.w pol1, [ptr_p, #1*distance/4]
     ldr.w pol2, [ptr_p, #2*distance/4]
     ldr.w pol3, [ptr_p, #3*distance/4]
     ldr.w pol4, [ptr_p, #4*distance/4]
     ldr.w pol5, [ptr_p, #5*distance/4]
     ldr.w pol6, [ptr_p, #6*distance/4]
     ldr.w pol7, [ptr_p, #7*distance/4]
     _3_layer_inv_CT_32 pol0, pol1, pol2, pol3, pol4, pol5, pol6, pol7, s2, s3, s4, s5, s6, s7, s8, zeta, qinv, q, temp_h, temp_l
     str.w pol1, [ptr_p, #1*distance/4]
     str.w pol2, [ptr_p, #2*distance/4]
     str.w pol3, [ptr_p, #3*distance/4]
     str.w pol4, [ptr_p, #4*distance/4]
     str.w pol5, [ptr_p, #5*distance/4]
     str.w pol6, [ptr_p, #6*distance/4]
     str.w pol7, [ptr_p, #7*distance/4]
     str.w pol0, [ptr_p]
     add.w ptr_p, #strincr
      vmov temp_l, s10
      cmp.w ptr_p, temp_l
    bne 2b
    sub.w ptr_p, #4*strincr-4
    vmov temp_l, s9
    cmp.w temp_l, ptr_p
  bne 1b
  sub ptr_p, #8*4
  vmov ptr_zeta, s0
  .equ strincr, 4
  add.w cntr, ptr_p, #64*strincr
  vmov s9, cntr
  vmov s11, ptr_zeta
  1:
    ldr.w zeta1, [ptr_zeta]
    sbfx zeta1, zeta1, #0, #24
    ldr.w zeta2, [ptr_zeta, #3]
    sbfx zeta2, zeta2, #0, #24
    vmov temp_l, s11
    ldr zeta0,[temp_l],#36
    vmov s11,temp_l
    add ptr_zeta,#6
    sbfx zeta0, zeta0, #0, #24
    ldr.w pol0, [ptr_p]
    ldr.w pol1, [ptr_p, #256]
    ldr.w pol2, [ptr_p, #512]
    ldr.w pol3, [ptr_p, #768]
    _2_layer_inv_CT_32 pol0, pol1, pol2, pol3, zeta0, zeta1, zeta2, qinv, q, temp_h, temp_l
    ldr.w zeta1, [ptr_zeta, #3]
    sbfx zeta1, zeta1, #0, #24
    ldr.w zeta2, [ptr_zeta, #6]
    sbfx zeta2, zeta2, #0, #24
    ldr.w zeta0, [ptr_zeta, #9]
    sbfx zeta0, zeta0, #0, #24
    ldr.w cntr, [ptr_zeta], #12
    sbfx cntr, cntr, #0, #24
    montgomery_mul_32 pol0, cntr, qinv, q, temp_h, temp_l
    montgomery_mul_32 pol1, zeta1, qinv, q, temp_h, temp_l
    montgomery_mul_32 pol2, zeta2, qinv, q, temp_h, temp_l
    montgomery_mul_32 pol3, zeta0, qinv, q, temp_h, temp_l
    str.w pol1, [ptr_p, #256]
    str.w pol2, [ptr_p, #512]
    str.w pol3, [ptr_p, #768]
    str pol0, [ptr_p], #strincr
    vmov cntr, s9
    sub temp_l,cntr,#128
    cmp temp_l,ptr_p
    bne 3f
    vmov temp_l,s0
    adds temp_l,#3
    vmov s11,temp_l
   3:
    cmp.w cntr, ptr_p
    bne.w 1b
    pop {R4-R11, PC}
    .unreq ptr_p
    .unreq ptr_zeta
    .unreq qinv
    .unreq q
    .unreq cntr
    .unreq pol0
    .unreq pol1
    .unreq pol2
    .unreq pol3
    .unreq temp_h
    .unreq temp_l
    .unreq zeta0
    .unreq zeta1
    .unreq zeta2
.align 2
inv_ntt_asm_smull_qinv:
.word 0xfc7fdfff
.align 2
inv_ntt_asm_smull_q:
.word 8380417
.section .rodata
.type zetas_new332, %object
.align 2
zetas_new332:
.word 25847, -2608894, -518909, 237124, -777960, -876248, 466468, 1826347, 2725464, 1024112, 2706023, 95776, 3077325, 3530437, 2353451, -1079900, 3585928, -1661693, -3592148, -2537516, 3915439, -359251, -549488, -1119584, -3861115, -3043716, 3574422, -2867647, -2091905, 2619752, -2108549, 3539968, -300467, 2348700, -539299, 3119733, -2118186, -3859737, -1699267, -1643818, 3505694, -3821735, -2884855, -1399561, -3277672, 3507263, -2140649, -1600420, 3699596, 3111497, 1757237, -19422, 811944, 531354, 954230, 3881043, 2680103, 4010497, 280005, 3900724, -2556880, 2071892, -2797779
.byte 229,6,196,147,234,31,90,255,51,129,172,232,212,88,35,248,65,58,207,225,199,114,255,204,251,61,34,25,152,209,159,171,218,34,164,201,93,214,233,245,18,4,135,37,37,238,9,53,240,36,237,93,155,53,199,53,33,160,72,202,252,162,198,187,207,231,86,187,237,222,69,207,117,207,236,94,190,13,26,94,28,114,151,29,230,224,13,90,127,12,114,176,193,131,143,7,138,98,231,246,188,240,4,87,255,252,6,248,128,82,207,33,0,246,246,90,208,174,210,207,132,0,31,134,239,48,224,144,200,125,185,201,214,252,247,202,239,1,146,69,244,194,33,201,242,16,52,25,57,5,12,97,4,133,254,240,65,205,218,27,176,62,56,198,32,231,114,52,59,0,205,159,110,41,199,124,26,36,25,3,163,183,210,229,94,43,153,17,41,75,164,199,58,122,216,113,77,19,109,186,249,28,225,61,132,9,19,9,52,218,81,240,37,70,90,24,130,194,245,24,133,198,190,20,19,19,65,237,145,56,40,144,219,201,59,166,255,137,80,210,63,133,28,247,9,236,75,11,29,166,246,239,221,43,250,190,168,235,27,225,18,212,149,20,62,94,205,47,45,234,99,69,28,228,29,249,199,6,20,98,44,234,131,114,50,110,13,226,233,251,204,83,121,236,153,64,29,240,10,4,120,37,217,173,5,235,23,196,7,5,228,22,231,219,11,136,69,47,232,29,34,207,248,51,0,173,0,52,185,247,12,202,212,190,54,239,248,127,230,87,209,227,68,205,13,27,145,216,18,44,199,90,103,60,216,16,9,31,94,198,202,43,199,88,70,225,139,29,37,126,222,255,183,115,37,143,124,253,72,57,25,152,221,29,152,104,51,192,105,206,187,212,2,167,147,237,108,117,36,190,108,207,28,124,2,223,199,252,8,170,24,113,253,45,161,152,11,165,92,12,154,55,25,8,232,235,103,161,199,61,140,228,108,228,2,60,161,209,57,197,53,8,200,201,21,1,59,192,29,4,194,54,48,247,196,33,244,27,241,246,191,227,231,53,26,14,52,7,147,60,219,69,125,249,208,76,26,224,74,253,174,124,228,104,38,29,5,19,20,152,142,230,51,38,239,146,119,20,218,5,252,219,127,197,37,158,19,100,39,211,175,225,221,224,208,231,221,147,249,9,29,221,68,153,243,147,204,2,5,24,241,2,8,234,42,156,24,169,229,201,162,238,209,80,138,247,44,207,59,156,199,196,78,67,255,223,54,235,87,160,200,202,21,60,104,94,21,217,151,58,182,22,243,206,41,30,0
.size zetas_new332,.-zetas_new332
.type zetas_new332inv, %object
.align 2
zetas_new332inv:
.word 4193792, 4193792, -25847, 4193792, 518909, -25847, 2608894, 4193792, 4193792, -25847, 4193792, 518909, -25847, 2608894, -466468, -2680103, -3111497, -280005, 19422, -4010497, -1757237, 518909, -466468, 876248, -2680103, 2884855, -3111497, -3119733, 777960, 2091905, 359251, 2108549, 1119584, -2619752, 549488, -25847, 518909, 2608894, -466468, 777960, 876248, -237124, 876248, 2884855, -3119733, 3277672, 3859737, 1399561, 2118186, 2608894, 777960, -237124, 2091905, -2353451, 359251, -1826347, -237124, -2353451, -1826347, -3585928, -1024112, 1079900, -2725464
.byte 0,254,63,9,155,255,250,163,0,16,38,46,33,170,60,24,78,237,39,104,197,169,95,55,180,226,229,130,135,58,246,102,7,165,169,195,211,176,42,172,98,224,4,205,212,149,209,214,248,36,242,54,6,221,158,211,21,157,186,227,223,43,200,148,151,53,69,94,28,86,120,231,59,186,251,255,205,194,253,232,10,218,164,22,122,10,240,49,8,241,248,23,20,95,103,244,189,106,241,211,27,56,153,6,60,122,127,41,163,58,8,100,41,220,216,77,25,245,149,234,236,24,27,207,116,218,54,16,254,32,111,55,15,72,16,170,181,58,70,197,63,209,55,25,217,26,215,183,133,208,173,237,210,30,168,251,162,66,38,213,13,251,110,136,235,251,236,235,112,226,60,247,99,223,182,73,193,117,112,62,116,140,199,164,107,24,2,134,23,34,78,53,16,55,53,23,29,38,247,203,37,147,69,6,188,64,25,143,60,20,158,51,216,47,1,214,133,44,32,152,6,216,156,6,28,79,242,44,39,223,226,8,35,11,166,152,195,188,50,242,103,191,31,180,187,23,57,6,203,122,206,225,81,65,196,44,184,38,140,96,242,64,141,247,2,198,208,164,12,10,69,48,24,57,202,222,90,51,51,67,201,228,136,109,42,94,182,200,220,225,248,216,94,13,197,62,249,11,128,38,84,140,212,188,204,199,254,247,21,188,102,12,63,208,11,148,168,207,165,164,28,141,250,51,173,199,196,138,112,241,98,185,252,101,244,237,22,112,37,192,102,222,9,246,19,197,89,0,70,37,55,196,152,32,31,69,22,53,234,221,104,3,50,9,91,21,88,3,6,213,251,195,128,28,63,70,99,2,64,150,49,184,198,230,22,94,24,234,170,9,225,138,41,34,138,247,191,193,43,106,117,201,40,85,15,98,236,2,183,145,60,157,184,17,10,67,15,142,79,62,251,169,48,195,88,54,179,77,200,207,66,53,129,235,31,83,123,5,220,22,228,179,108,199,209,230,245,238,118,17,10,64,28,62,201,207,183,139,23,116,176,211,236,248,22,212,26,233,167,80,58,226,129,202,238,44,219,22,165,59,112,161,237,87,122,54,97,145,214,200,57,223,213,147,11,241,198,59,207,38,219,13,96,231,120,72,201,92,122,16,68,27,15,234,4,245,72,124,41,86,125,34,120,186,208,233,59,248,160,11,244,189,29,224,227,236,39,127,243,61,59,33,202,51,11,209,91,51,228,103,78,29,45,220,60,163,65,31,231,103,46,49,30,56,16,45,241,25,109,33,144,68,35,94,37,238,253,234,7,254,206,39,216,63,19,63,92,224,159,91,241,88,62,60,100,56,59,94,17,46,87,131,235,70,252,238,62,198,54,100,144,226,208,3,39,204,122,196,6,69,51,166,213,26,83,204,220,27,230,227,44,106,235,35,212,5,114,15,230,169,171,48,38,227,53,78,135,237,222,75,0,203,47,229,73,110,45,67,219,39,53,134,214,131,109,232,33,56,3,148,138,219,230,81,31,118,57,214,104,96,36,45,33,249,179,149,4,0,252,201,241,233,25,196,248,193,73,44,246,228,255,238,82,45,48,128,173,48,137,215,240,20,30,222,140,144,44,65,219,3,247,4,44,139,101,208,41,192,22,85,120,255,62,127,237,127,107,207,32,181,2,109,195,36,102,155,205,201,134,219,151,11,214,72,247,9,233,169,32,193,123,202,175,218,198,235,92,226,47,159,204,36,187,41,181,91,56,93,72,45,139,68,21,191,87,218,173,64,27,126,19,231,96,21,17,112,98,8,156,230,212,186,197,235,119,80,222,142,77,216,66,201,16,0,83,255,148,20,53,120,126,218,45,83,231,68,238,38,212,207,54,253,90,25,73,82,24,179,221,4,181,161,204,80,149,47,18,246,202,163,41,22,142,145,57,165,189,21,112,64,204,244,167,9,232,222,11,188,97,252,5,121,31,79,4,62,156,134,33,72,202,238,32,47,24,219,97,236,157,136,38,75,82,242,131,196,226,87,88,27,102,228,247,88,156,243,201,81,14,238,180,245,165,229,43,75,106,60,237,190,18,126,61,10,8,156,18,8,51,197,67,37,40,108,109,223,25,229,58,42,82,32,131,225,218,31,233,41,1,247,10,128,23,220,130,33,0,54,212,56,220,119,255,169,45,21,44,122,5,80,125,24,132,113,46,123,234,58,250,177,19,136,245,48,215,188,38,242,251,233,142,104,226,139,48,19,245,100,250,102,10,236,190,8,4,157,227,39,213,22,220,213,33,228,114,74,31,178,8,9,9,227,253,128,65,35,248,55,54,148,27,253,143,93,214,90,101,192,177,255,255,68,171,58,42,21,25,195,237,25,184,162,7,230,87,11,17,108,13,74,158,208,123,1,15,14,239,203,149,223,10,73,164,255,229,231,56,207,148,240,144,95,240,168,105,214,127,248,219,251,140,227,26,193,58,120,169,35,16,245,251,23,4,51,219,160,58,214,207,63,126,119,194,225,200,60,224,137,254,153,181,214,249,248,3,86,141,38,137,135,30,199,15,15,127,83,23,27,249,59,23,193,209,185,248,208,88,195,219,31,5,28,0
.size zetas_new332inv,.-zetas_new332inv
