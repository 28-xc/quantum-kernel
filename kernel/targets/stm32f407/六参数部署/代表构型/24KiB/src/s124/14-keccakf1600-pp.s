@
@ Implementation by the Keccak, Keyak and Ketje Teams, namely, Guido Bertoni,
@ Joan Daemen, Micha毛l Peeters, Gilles Van Assche and Ronny Van Keer, hereby
@ denoted as "the implementer".
@ Additional optimizations by Alexandre Adomnicai.
@
@ For more information, feedback or questions, please refer to our websites:
@ http:
@ http:
@ http:
@
@ To the extent possible under law, the implementer has waived all copyright
@ and related or neighboring rights to the source code in this file.
@ http:
@
@ WARNING: These functions work only on little endian CPU with@ ARMv7m architecture (ARM Cortex-M3, ...).
 .thumb
 .syntax unified
.text
 @ Credit: Henry S. Warren, Hacker's Delight, Addison-Wesley, 2002
.macro toBitInterleaving x0,x1,s0,s1,t,over
 and \t,\x0,#0x55555555
 orr \t,\t,\t, LSR #1
 and \t,\t,#0x33333333
 orr \t,\t,\t, LSR #2
 and \t,\t,#0x0F0F0F0F
 orr \t,\t,\t, LSR #4
 and \t,\t,#0x00FF00FF
 bfi \t,\t,#8, #8
 .if \over != 0
 lsr \s0,\t, #8
 .else
 eor \s0,\s0,\t, LSR #8
 .endif
 and \t,\x1,#0x55555555
 orr \t,\t,\t, LSR #1
 and \t,\t,#0x33333333
 orr \t,\t,\t, LSR #2
 and \t,\t,#0x0F0F0F0F
 orr \t,\t,\t, LSR #4
 and \t,\t,#0x00FF00FF
 orr \t,\t,\t, LSR #8
 eor \s0,\s0,\t, LSL #16
 and \t,\x0,#0xAAAAAAAA
 orr \t,\t,\t, LSL #1
 and \t,\t,#0xCCCCCCCC
 orr \t,\t,\t, LSL #2
 and \t,\t,#0xF0F0F0F0
 orr \t,\t,\t, LSL #4
 and \t,\t,#0xFF00FF00
 orr \t,\t,\t, LSL #8
 .if \over != 0
 lsr \s1,\t, #16
 .else
 eor \s1,\s1,\t, LSR #16
 .endif
 and \t,\x1,#0xAAAAAAAA
 orr \t,\t,\t, LSL #1
 and \t,\t,#0xCCCCCCCC
 orr \t,\t,\t, LSL #2
 and \t,\t,#0xF0F0F0F0
 orr \t,\t,\t, LSL #4
 and \t,\t,#0xFF00FF00
 orr \t,\t,\t, LSL #8
 bfc \t, #0, #16
 eors \s1,\s1,\t
 .endm
 @ Credit: Henry S. Warren, Hacker's Delight, Addison-Wesley, 2002
.macro fromBitInterleaving x0, x1, t
 movs \t, \x0 @ t = x0@
 bfi \x0, \x1, #16, #16 @ x0 = (x0 & 0x0000FFFF) | (x1 << 16)@
 bfc \x1, #0, #16 @ x1 = (t >> 16) | (x1 & 0xFFFF0000)@
 orr \x1, \x1, \t, LSR #16
    eor \t, \x0, \x0, LSR #8 @ t = (x0 ^ (x0 >> 8)) & 0x0000FF00UL@ x0 = x0 ^ t ^ (t << 8)@
 and \t, #0x0000FF00
    eors \x0, \x0, \t
    eor \x0, \x0, \t, LSL #8
    eor \t, \x0, \x0, LSR #4 @ t = (x0 ^ (x0 >> 4)) & 0x00F000F0UL@ x0 = x0 ^ t ^ (t << 4)@
 and \t, #0x00F000F0
    eors \x0, \x0, \t
    eor \x0, \x0, \t, LSL #4
    eor \t, \x0, \x0, LSR #2 @ t = (x0 ^ (x0 >> 2)) & 0x0C0C0C0CUL@ x0 = x0 ^ t ^ (t << 2)@
 and \t, #0x0C0C0C0C
    eors \x0, \x0, \t
    eor \x0, \x0, \t, LSL #2
    eor \t, \x0, \x0, LSR #1 @ t = (x0 ^ (x0 >> 1)) & 0x22222222UL@ x0 = x0 ^ t ^ (t << 1)@
 and \t, #0x22222222
    eors \x0, \x0, \t
    eor \x0, \x0, \t, LSL #1
    eor \t, \x1, \x1, LSR #8 @ t = (x1 ^ (x1 >> 8)) & 0x0000FF00UL@ x1 = x1 ^ t ^ (t << 8)@
 and \t, #0x0000FF00
    eors \x1, \x1, \t
    eor \x1, \x1, \t, LSL #8
    eor \t, \x1, \x1, LSR #4 @ t = (x1 ^ (x1 >> 4)) & 0x00F000F0UL@ x1 = x1 ^ t ^ (t << 4)@
 and \t, #0x00F000F0
    eors \x1, \x1, \t
    eor \x1, \x1, \t, LSL #4
    eor \t, \x1, \x1, LSR #2 @ t = (x1 ^ (x1 >> 2)) & 0x0C0C0C0CUL@ x1 = x1 ^ t ^ (t << 2)@
 and \t, #0x0C0C0C0C
    eors \x1, \x1, \t
    eor \x1, \x1, \t, LSL #2
    eor \t, \x1, \x1, LSR #1 @ t = (x1 ^ (x1 >> 1)) & 0x22222222UL@ x1 = x1 ^ t ^ (t << 1)@
 and \t, #0x22222222
    eors \x1, \x1, \t
    eor \x1, \x1, \t, LSL #1
 .endm
@ --- offsets in state
.equ Aba0, 0*4
.equ Aba1, 1*4
.equ Abe0, 2*4
.equ Abe1, 3*4
.equ Abi0, 4*4
.equ Abi1, 5*4
.equ Abo0, 6*4
.equ Abo1, 7*4
.equ Abu0, 8*4
.equ Abu1, 9*4
.equ Aga0, 10*4
.equ Aga1, 11*4
.equ Age0, 12*4
.equ Age1, 13*4
.equ Agi0, 14*4
.equ Agi1, 15*4
.equ Ago0, 16*4
.equ Ago1, 17*4
.equ Agu0, 18*4
.equ Agu1, 19*4
.equ Aka0, 20*4
.equ Aka1, 21*4
.equ Ake0, 22*4
.equ Ake1, 23*4
.equ Aki0, 24*4
.equ Aki1, 25*4
.equ Ako0, 26*4
.equ Ako1, 27*4
.equ Aku0, 28*4
.equ Aku1, 29*4
.equ Ama0, 30*4
.equ Ama1, 31*4
.equ Ame0, 32*4
.equ Ame1, 33*4
.equ Ami0, 34*4
.equ Ami1, 35*4
.equ Amo0, 36*4
.equ Amo1, 37*4
.equ Amu0, 38*4
.equ Amu1, 39*4
.equ Asa0, 40*4
.equ Asa1, 41*4
.equ Ase0, 42*4
.equ Ase1, 43*4
.equ Asi0, 44*4
.equ Asi1, 45*4
.equ Aso0, 46*4
.equ Aso1, 47*4
.equ Asu0, 48*4
.equ Asu1, 49*4
@ --- offsets on stack
.equ mDa0, 0*4
.equ mDa1, 1*4
.equ mDo0, 2*4
.equ mDo1, 3*4
.equ mDi0, 4*4
.equ mRC , 5*4
.equ mSize, 6*4
.macro eorror dst, src1, src2, rot1, rot2
.if \rot1 >= \rot2
    eor \dst, \src1, \src2, ror \rot1-\rot2
.else
    eor \dst, \src1, \src2, ror 32+\rot1-\rot2
.endif
.endm
.macro bicror dst, src1, src2, rot1, rot2
.if \rot1 >= \rot2
    bic \dst, \src1, \src2, ror \rot1-\rot2
.else
    bic \dst, \src1, \src2, ror 32+\rot1-\rot2
.endif
.endm
.macro xor5 dst, src1, src2, src3, src4, src5, rot1, rot2, rot3, rot4, rot5
    ldr \dst, [r0, #\src1]
    ldr r1, [r0, #\src2]
    ldr r5, [r0, #\src3]
    ldr r11, [r0, #\src4]
    ldr r12, [r0, #\src5]
    eorror \dst, \dst, r1, \rot1, \rot2
    eorror \dst, \dst, r5, \rot1, \rot3
    eorror \dst, \dst, r11, \rot1, \rot4
    eorror \dst, \dst, r12, \rot1, \rot5
.endm
.macro xor5str dst, src1, src2, src3, src4, src5, rot1, rot2, rot3, rot4, rot5, strreg, stradr, strofs
    ldr \dst, [r0, #\src1]
    ldr r1, [r0, #\src2]
    ldr r5, [r0, #\src3]
    ldr r11, [r0, #\src4]
    ldr r12, [r0, #\src5]
    str \strreg, [\stradr, #\strofs]
    eorror \dst, \dst, r1, \rot1, \rot2
    eorror \dst, \dst, r5, \rot1, \rot3
    eorror \dst, \dst, r11, \rot1, \rot4
    eorror \dst, \dst, r12, \rot1, \rot5
.endm
.macro xorrol dst, src1, src2, rot
    eor \dst, \src1, \src2, ror \rot-1
.endm
.macro xandnotlazystr resofs, src1, src2, src3, rot1, rot2, rot3
    bicror r1, \src3, \src2, \rot3, \rot2
    eorror r1, r1, \src1, \rot3, \rot1
    str r1, [r0, #\resofs]
.endm
.macro xandnotlazy src1, src2, src3, rot1, rot2, rot3
    bicror r1, \src3, \src2, \rot3, \rot2
    eorror r1, r1, \src1, \rot3, \rot1
.endm
.macro xandnotstr resofs, src1, src2, src3, rot1, rot2, rot3
    bicror r1, \src3, \src2, \rot3, \rot2
    eorror r1, r1, \src1, \rot3, \rot1
.if \rot3 > 0
    ror r1, r1, #32-\rot3
.endif
    str r1, [r0, #\resofs]
.endm
.macro xandnot src1, src2, src3, rot1, rot2, rot3
    bicror r1, \src3, \src2, \rot3, \rot2
    eorror r1, r1, \src1, \rot3, \rot1
.if \rot3 > 0
    ror r1, r1, #32-\rot3
.endif
.endm
.macro xandnotiota out, rot3, rot2, rcofs, last
    bicror r5, r5, r4, \rot3, \rot2
    ldr r1, [sp, #mRC]
    ldr r4, [r1, #\rcofs]
.if \last == 1
    ldr r7, [r1, #32]!
    str r1, [sp, #mRC]
    cmp r7, #0xFF
.endif
.if \rot3 > 0
    eor r3, r3, r5, ror 32-\rot3
.else
    eor.w r3, r3, r5
.endif
    eor.w \out, r4, r3
.endm
.macro addparity par1, dly1, par2, dly2, par3, dly3, par4, dly4, par5, dly5
.if \dly1 > 0
    eor r3, \par1, r3, ror 32-\dly1
.else
    eor.w r3, \par1, r3
.endif
.if \dly2 > 0
    eor r4, \par2, r4, ror 32-\dly2
.else
    eor.w r4, \par2, r4
.endif
.if \dly3 > 0
    eor r5, \par3, r5, ror 32-\dly3
.else
    eor.w r5, \par3, r5
.endif
.if \dly4 > 0
    eor r6, \par4, r6, ror 32-\dly4
.else
    eor.w r6, \par4, r6
.endif
.if \dly5 > 0
    eor r7, \par5, r7, ror 32-\dly5
.else
    eor.w r7, \par5, r7
.endif
.endm
.macro KeccakThetaRhoPiChiIota src1, par1, dly1, src2, par2, rot2, dly2, src3, par3, rot3, dly3, src4, par4, rot4, dly4, src5, par5, rot5, dly5, ofs, last, lazy, strofs, reg
    ldr r3, [r0, #\src1]
    ldr r4, [r0, #\src2]
    ldr r5, [r0, #\src3]
    ldr r6, [r0, #\src4]
    ldr r7, [r0, #\src5]
    str r1, [r0, #\strofs]
    addparity \par1, \dly1, \par2, \dly2, \par3, \dly3, \par4, \dly4, \par5, \dly5
.if \lazy == 1
    xandnotlazystr \src2, r4, r5, r6, \rot2, \rot3, \rot4
    xandnotlazystr \src3, r5, r6, r7, \rot3, \rot4, \rot5
    xandnotlazystr \src4, r6, r7, r3, \rot4, \rot5, 0
    xandnotlazystr \src5, r7, r3, r4, \rot5, 0, \rot2
.else
    xandnotstr \src2, r4, r5, r6, \rot2, \rot3, \rot4
    xandnotstr \src3, r5, r6, r7, \rot3, \rot4, \rot5
    xandnotstr \src4, r6, r7, r3, \rot4, \rot5, 0
    xandnotstr \src5, r7, r3, r4, \rot5, 0, \rot2
.endif
    xandnotiota \reg, \rot3, \rot2, \ofs, \last
.endm
.macro KeccakThetaRhoPiChi src1, dst1, par1, rot1, dly1, src2, dst2, par2, rot2, dly2, src3, dst3, par3, rot3, dly3, src4, dst4, par4, rot4, dly4, src5, dst5, par5, rot5, dly5, lazy, strofs
    ldr r3, [r0, #\src1]
    ldr r4, [r0, #\src2]
    ldr r5, [r0, #\src3]
    ldr r6, [r0, #\src4]
    ldr r7, [r0, #\src5]
    str r1, [r0, #\strofs]
    addparity \par1, \dly1, \par2, \dly2, \par3, \dly3, \par4, \dly4, \par5, \dly5
.if \lazy == 1
    xandnotlazystr \dst1, r3, r4, r5, \rot1, \rot2, \rot3
    xandnotlazystr \dst2, r4, r5, r6, \rot2, \rot3, \rot4
    xandnotlazystr \dst3, r5, r6, r7, \rot3, \rot4, \rot5
    xandnotlazystr \dst4, r6, r7, r3, \rot4, \rot5, \rot1
    xandnotlazy r7, r3, r4, \rot5, \rot1, \rot2
.else
    xandnotstr \dst1, r3, r4, r5, \rot1, \rot2, \rot3
    xandnotstr \dst2, r4, r5, r6, \rot2, \rot3, \rot4
    xandnotstr \dst3, r5, r6, r7, \rot3, \rot4, \rot5
    xandnotstr \dst4, r6, r7, r3, \rot4, \rot5, \rot1
    xandnot r7, r3, r4, \rot5, \rot1, \rot2
.endif
.endm
.macro KeccakRound0
    xor5 r3, Abu0, Agu0, Aku0, Amu0, Asu0, 0, 0, 0, 0, 0
    xor5 r7, Abe1, Age1, Ake1, Ame1, Ase1, 0, 0, 0, 0, 0
    xorrol r6, r3, r7, 32
    xor5str r4, Abi1, Agi1, Aki1, Ami1, Asi1, 0, 0, 0, 0, 0, r6, sp, mDa0
    eor.w r6, r3, r4
    xor5str r3, Abo0, Ago0, Ako0, Amo0, Aso0, 0, 0, 0, 0, 0, r6, sp, mDo1
    eor.w r2, r7, r3
    xor5 r7, Aba0, Aga0, Aka0, Ama0, Asa0, 0, 0, 0, 0, 0
    xorrol r10, r7, r4, 32
    xor5 r4, Abo1, Ago1, Ako1, Amo1, Aso1, 0, 0, 0, 0, 0
    eor r14, r4, r7
    xor5 r7, Abe0, Age0, Ake0, Ame0, Ase0, 0, 0, 0, 0, 0
    xorrol r6, r7, r4, 32
    xor5str r4, Abu1, Agu1, Aku1, Amu1, Asu1, 0, 0, 0, 0, 0, r6, sp, mDi0
    eor.w r8, r4, r7
    xor5str r7, Abi0, Agi0, Aki0, Ami0, Asi0, 0, 0, 0, 0, 0, r8, sp, mDa1
    xorrol r9, r7, r4, 32
    xor5str r4, Aba1, Aga1, Aka1, Ama1, Asa1, 0, 0, 0, 0, 0, r9, sp, mDo0
    eor r11, r4, r7
    xorrol r12, r3, r4, 32
    KeccakThetaRhoPiChi Abo0, Aka1, r9, 14, 0, Agu0, Ame1, r12, 10, 0, Aka1, Asi1, r8, 2, 0, Ame1, Abo0, r11, 23, 0, Asi1, Agu0, r2, 31, 0, 1, Aka1
    KeccakThetaRhoPiChi Abe0, Asa1, r10, 0, 0, Agi1, Abe0, r2, 3, 0, Ako0, Agi1, r9, 12, 0, Amu1, Ako0, r14, 4, 0, Asa1, Amu1, r8, 9, 0, 1, Agu0
    ldr r8, [sp, #mDa0]
    KeccakThetaRhoPiChi Abu1, Aga0, r14, 14, 0, Aga0, Ake0, r8, 18, 0, Ake0, Ami1, r10, 5, 0, Ami1, Aso0, r2, 8, 0, Aso0, Abu1, r9, 28, 0, 1, Amu1
    KeccakThetaRhoPiChi Abi1, Ama0, r2, 31, 0, Ago0, Ase1, r9, 27, 0, Aku0, Abi1, r12, 19, 0, Ama0, Ago0, r8, 20, 0, Ase1, Aku0, r11, 1, 0, 1, Abu1
    ldr r9, [sp, #mDo1]
    KeccakThetaRhoPiChiIota Aba0, r8, 0, Age0, r10, 22, 0, Aki1, r2, 22, 0, Amo1, r9, 11, 0, Asu0, r12, 7, 0, 0, 0, 1, Aku0, r1
    ldr r2, [sp, #mDi0]
    KeccakThetaRhoPiChi Abo1, Aka0, r9, 14, 0, Agu1, Ame0, r14, 10, 0, Aka0, Asi0, r8, 1, 0, Ame0, Abo1, r10, 22, 0, Asi0, Agu1, r2, 30, 0, 1, Aba0
    KeccakThetaRhoPiChi Abe1, Asa0, r11, 1, 0, Agi0, Abe1, r2, 3, 0, Ako1, Agi0, r9, 13, 0, Amu0, Ako1, r12, 4, 0, Asa0, Amu0, r8, 9, 0, 1, Agu1
    ldr r8, [sp, #mDa1]
    KeccakThetaRhoPiChi Abu0, Aga1, r12, 13, 0, Aga1, Ake1, r8, 18, 0, Ake1, Ami0, r11, 5, 0, Ami0, Aso1, r2, 7, 0, Aso1, Abu0, r9, 28, 0, 1, Amu0
    KeccakThetaRhoPiChi Abi0, Ama1, r2, 31, 0, Ago1, Ase0, r9, 28, 0, Aku1, Abi0, r14, 20, 0, Ama1, Ago1, r8, 21, 0, Ase0, Aku1, r10, 1, 0, 1, Abu0
    ldr r9, [sp, #mDo0]
    KeccakThetaRhoPiChiIota Aba1, r8, 0, Age1, r11, 22, 0, Aki0, r2, 21, 0, Amo0, r9, 10, 0, Asu1, r14, 7, 0, 4, 0, 1, Aku1, r14
.endm
.macro KeccakRound1
    xor5str r3, Asu0, Agu0, Amu0, Abu1, Aku1, 22, 10, 3, 18, 28, r14, r0, Aba1
    xor5 r7, Age1, Ame0, Abe0, Ake1, Ase1, 10, 22, 4, 7, 20
    ror r3, 32-22
    xorrol r6, r3, r7, 32-10
    xor5str r4, Aki0, Asi0, Agi1, Ami0, Abi1, 7, 30, 9, 28, 1, r6, sp, mDa0
    eor r6, r3, r4, ror 32-7
    xor5str r3, Amo1, Abo0, Ako1, Aso0, Ago1, 0, 14, 1, 14, 31, r6, sp, mDo1
    eor r2, r3, r7, ror 32-10
    xor5 r7, Aba0, Aka1, Asa0, Aga0, Ama1, 0, 2, 13, 5, 20
    xorrol r10, r7, r4, 32-7
    xor5 r4, Amo0, Abo1, Ako0, Aso1, Ago0, 0, 14, 0, 13, 31
    eor r14, r4, r7
    xor5 r7, Age0, Ame1, Abe1, Ake0, Ase0, 11, 23, 4, 8, 21
    ror r7, 32-11
    xorrol r6, r7, r4, 32
    xor5str r4, Asu1, Agu1, Amu1, Abu0, Aku0, 22, 10, 3, 18, 27, r6, sp, mDi0
    eor r8, r7, r4, ror 32-22
    xor5str r7, Aki1, Asi1, Agi0, Ami1, Abi0, 7, 31, 9, 28, 1, r8, sp, mDa1
    ror r7, 32-7
    xorrol r9, r7, r4, 32-22
    xor5str r4, Aba1, Aka0, Asa1, Aga1, Ama0, 0, 1, 12, 5, 19, r9, sp, mDo0
    eor r11, r4, r7
    xorrol r12, r3, r4, 32
    KeccakThetaRhoPiChi Amo1, Asa1, r9, 14, 0, Agu0, Ake1, r12, 10, 10, Asa1, Abi1, r8, 2, 12, Ake1, Amo1, r11, 23, 7, Abi1, Agu0, r2, 31, 1, 1, Asa1
    KeccakThetaRhoPiChi Age0, Ama0, r10, 0, 11, Asi0, Age0, r2, 3, 30, Ako1, Asi0, r9, 12, 1, Abu0, Ako1, r14, 4, 18, Ama0, Abu0, r8, 9, 19, 1, Agu0
    ldr r8, [sp, #mDa0]
    KeccakThetaRhoPiChi Asu1, Aka1, r14, 14, 22, Aka1, Abe1, r8, 18, 2, Abe1, Ami0, r10, 5, 4, Ami0, Ago1, r2, 8, 28, Ago1, Asu1, r9, 28, 31, 1, Abu0
    KeccakThetaRhoPiChi Aki0, Aga0, r2, 31, 7, Abo0, Ase1, r9, 27, 14, Amu0, Aki0, r12, 19, 3, Aga0, Abo0, r8, 20, 5, Ase1, Amu0, r11, 1, 20, 1, Asu1
    ldr r9, [sp, #mDo1]
    KeccakThetaRhoPiChiIota Aba0, r8, 0, Ame1, r10, 22, 23, Agi1, r2, 22, 9, Aso1, r9, 11, 13, Aku1, r12, 7, 28, 8, 0, 1, Amu0, r1
    ldr r2, [sp, #mDi0]
    KeccakThetaRhoPiChi Amo0, Asa0, r9, 14, 0, Agu1, Ake0, r14, 10, 10, Asa0, Abi0, r8, 1, 13, Ake0, Amo0, r10, 22, 8, Abi0, Agu1, r2, 30, 1, 1, Aba0
    KeccakThetaRhoPiChi Age1, Ama1, r11, 1, 10, Asi1, Age1, r2, 3, 31, Ako0, Asi1, r9, 13, 0, Abu1, Ako0, r12, 4, 18, Ama1, Abu1, r8, 9, 20, 1, Agu1
    ldr r8, [sp, #mDa1]
    KeccakThetaRhoPiChi Asu0, Aka0, r12, 13, 22, Aka0, Abe0, r8, 18, 1, Abe0, Ami1, r11, 5, 4, Ami1, Ago0, r2, 7, 28, Ago0, Asu0, r9, 28, 31, 1, Abu1
    KeccakThetaRhoPiChi Aki1, Aga1, r2, 31, 7, Abo1, Ase0, r9, 28, 14, Amu1, Aki1, r14, 20, 3, Aga1, Abo1, r8, 21, 5, Ase0, Amu1, r10, 1, 21, 1, Asu0
    ldr r9, [sp, #mDo0]
    KeccakThetaRhoPiChiIota Aba1, r8, 0, Ame0, r11, 22, 22, Agi0, r2, 21, 9, Aso0, r9, 10, 14, Aku0, r14, 7, 27, 12, 0, 1, Amu1, r14
.endm
.macro KeccakRound2
    xor5str r3, Aku1, Agu0, Abu1, Asu1, Amu1, 22, 10, 3, 18, 28, r14, r0, Aba1
    xor5 r7, Ame0, Ake0, Age0, Abe0, Ase1, 10, 22, 4, 7, 20
    ror r3, 32-22
    xorrol r6, r3, r7, 32-10
    xor5str r4, Agi0, Abi0, Asi0, Ami1, Aki0, 7, 30, 9, 28, 1, r6, sp, mDa0
    eor r6, r3, r4, ror 32-7
    xor5str r3, Aso1, Amo1, Ako0, Ago1, Abo1, 0, 14, 1, 14, 31, r6, sp, mDo1
    eor r2, r3, r7, ror 32-10
    xor5 r7, Aba0, Asa1, Ama1, Aka1, Aga1, 0, 2, 13, 5, 20
    xorrol r10, r7, r4, 32-7
    xor5 r4, Aso0, Amo0, Ako1, Ago0, Abo0, 0, 14, 0, 13, 31
    eor r14, r4, r7
    xor5 r7, Ame1, Ake1, Age1, Abe1, Ase0, 11, 23, 4, 8, 21
    ror r7, 32-11
    xorrol r6, r7, r4, 32
    xor5str r4, Aku0, Agu1, Abu0, Asu0, Amu0, 22, 10, 3, 18, 27, r6, sp, mDi0
    eor r8, r7, r4, ror 32-22
    xor5str r7, Agi1, Abi1, Asi1, Ami0, Aki1, 7, 31, 9, 28, 1, r8, sp, mDa1
    ror r7, 32-7
    xorrol r9, r7, r4, 32-22
    xor5str r4, Aba1, Asa0, Ama0, Aka0, Aga0, 0, 1, 12, 5, 19, r9, sp, mDo0
    eor r11, r4, r7
    xorrol r12, r3, r4, 32
    KeccakThetaRhoPiChi Aso1, Ama0, r9, 14, 0, Agu0, Abe0, r12, 10, 10, Ama0, Aki0, r8, 2, 12, Abe0, Aso1, r11, 23, 7, Aki0, Agu0, r2, 31, 1, 1, Ama0
    KeccakThetaRhoPiChi Ame1, Aga0, r10, 0, 11, Abi0, Ame1, r2, 3, 30, Ako0, Abi0, r9, 12, 1, Asu0, Ako0, r14, 4, 18, Aga0, Asu0, r8, 9, 19, 1, Agu0
    ldr r8, [sp, #mDa0]
    KeccakThetaRhoPiChi Aku0, Asa1, r14, 14, 22, Asa1, Age1, r8, 18, 2, Age1, Ami1, r10, 5, 4, Ami1, Abo1, r2, 8, 28, Abo1, Aku0, r9, 28, 31, 1, Asu0
    KeccakThetaRhoPiChi Agi0, Aka1, r2, 31, 7, Amo1, Ase1, r9, 27, 14, Abu1, Agi0, r12, 19, 3, Aka1, Amo1, r8, 20, 5, Ase1, Abu1, r11, 1, 20, 1, Aku0
    ldr r9, [sp, #mDo1]
    KeccakThetaRhoPiChiIota Aba0, r8, 0, Ake1, r10,22, 23, Asi0, r2, 22, 9, Ago0, r9, 11, 13, Amu1, r12, 7, 28, 16, 0, 1, Abu1, r1
    ldr r2, [sp, #mDi0]
    KeccakThetaRhoPiChi Aso0, Ama1, r9, 14, 0, Agu1, Abe1, r14, 10, 10, Ama1, Aki1, r8, 1, 13, Abe1, Aso0, r10, 22, 8, Aki1, Agu1, r2, 30, 1, 1, Aba0
    KeccakThetaRhoPiChi Ame0, Aga1, r11, 1, 10, Abi1, Ame0, r2, 3, 31, Ako1, Abi1, r9, 13, 0, Asu1, Ako1, r12, 4, 18, Aga1, Asu1, r8, 9, 20, 1, Agu1
    ldr r8, [sp, #mDa1]
    KeccakThetaRhoPiChi Aku1, Asa0, r12, 13, 22, Asa0, Age0, r8, 18, 1, Age0, Ami0, r11, 5, 4, Ami0, Abo0, r2, 7, 28, Abo0, Aku1, r9, 28, 31, 1, Asu1
    KeccakThetaRhoPiChi Agi1, Aka0, r2, 31, 7, Amo0, Ase0, r9, 28, 14, Abu0, Agi1, r14, 20, 3, Aka0, Amo0, r8, 21, 5, Ase0, Abu0, r10, 1, 21, 1, Aku1
    ldr r9, [sp, #mDo0]
    KeccakThetaRhoPiChiIota Aba1, r8, 0, Ake0, r11, 22, 22, Asi1, r2, 21, 9, Ago1, r9, 10, 14, Amu0, r14, 7, 27, 20, 0, 1, Abu0, r14
.endm
.macro KeccakRound3
    xor5str r3, Amu1, Agu0, Asu1, Aku0, Abu0, 22, 10, 3, 18, 28, r14, r0, Aba1
    xor5 r7, Ake0, Abe1, Ame1, Age0, Ase1, 10, 22, 4, 7, 20
    ror r3, 32-22
    xorrol r6, r3, r7, 32-10
    xor5str r4, Asi1, Aki1, Abi0, Ami0, Agi0, 7, 30, 9, 28, 1, r6, sp, mDa0
    eor r6, r3, r4, ror 32-7
    xor5str r3, Ago0, Aso1, Ako1, Abo1, Amo0, 0, 14, 1, 14, 31, r6, sp, mDo1
    eor r2, r3, r7, ror 32-10
    xor5 r7, Aba0, Ama0, Aga1, Asa1, Aka0, 0, 2, 13, 5, 20
    xorrol r10, r7, r4, 32-7
    xor5 r4, Ago1, Aso0, Ako0, Abo0, Amo1, 0, 14, 0, 13, 31
    eor r14, r4, r7
    xor5 r7, Ake1, Abe0, Ame0, Age1, Ase0, 11, 23, 4, 8, 21
    ror r7, #32-11
    xorrol r6, r7, r4, 32
    xor5str r4, Amu0, Agu1, Asu0, Aku1, Abu1, 22, 10, 3, 18, 27, r6, sp, mDi0
    eor r8, r7, r4, ror 32-22
    xor5str r7, Asi0, Aki0, Abi1, Ami1, Agi1, 7, 31, 9, 28, 1, r8, sp, mDa1
    ror r7, 32-7
    xorrol r9, r7, r4, 32-22
    xor5str r4, Aba1, Ama1, Aga0, Asa0, Aka1, 0, 1, 12, 5, 19, r9, sp, mDo0
    eor r11, r4, r7
    xorrol r12, r3, r4, 32
    KeccakThetaRhoPiChi Ago0, Aga0, r9, 14, 0, Agu0, Age0, r12, 10, 10, Aga0, Agi0, r8, 2, 12, Age0, Ago0, r11, 23, 7, Agi0, Agu0, r2, 31, 1, 0, Aga0
    KeccakThetaRhoPiChi Ake1, Aka1, r10, 0, 11, Aki1, Ake1, r2, 3, 30, Ako1, Aki1, r9, 12, 1, Aku1, Ako1, r14, 4, 18, Aka1, Aku1, r8, 9, 19, 0, Agu0
    ldr r8, [sp, #mDa0]
    KeccakThetaRhoPiChi Amu0, Ama0, r14, 14, 22, Ama0, Ame0, r8, 18, 2, Ame0, Ami0, r10, 5, 4, Ami0, Amo0, r2, 8, 28, Amo0, Amu0, r9, 28, 31, 0, Aku1
    KeccakThetaRhoPiChi Asi1, Asa1, r2, 31, 7, Aso1, Ase1, r9, 27, 14, Asu1, Asi1, r12, 19, 3, Asa1, Aso1, r8, 20, 5, Ase1, Asu1, r11, 1, 20, 0, Amu0
    ldr r9, [sp, #mDo1]
    KeccakThetaRhoPiChiIota Aba0, r8, 0, Abe0, r10, 22, 23, Abi0, r2, 22, 9, Abo0, r9, 11, 13, Abu0, r12, 7, 28, 24, 0, 0, Asu1, r1
    ldr r2, [sp, #mDi0]
    KeccakThetaRhoPiChi Ago1, Aga1, r9, 14, 0, Agu1, Age1, r14, 10, 10, Aga1, Agi1, r8, 1, 13, Age1, Ago1, r10, 22, 8, Agi1, Agu1, r2, 30, 1, 0, Aba0
    KeccakThetaRhoPiChi Ake0, Aka0, r11, 1, 10, Aki0, Ake0, r2, 3, 31, Ako0, Aki0, r9, 13, 0, Aku0, Ako0, r12, 4, 18, Aka0, Aku0, r8, 9, 20, 0, Agu1
    ldr r8, [sp, #mDa1]
    KeccakThetaRhoPiChi Amu1, Ama1, r12, 13, 22, Ama1, Ame1, r8, 18, 1, Ame1, Ami1, r11, 5, 4, Ami1, Amo1, r2, 7, 28, Amo1, Amu1, r9, 28, 31, 0, Aku0
    KeccakThetaRhoPiChi Asi0, Asa0, r2, 31, 7, Aso0, Ase0, r9, 28, 14, Asu0, Asi0, r14, 20, 3, Asa0, Aso0, r8, 21, 5, Ase0, Asu0, r10, 1, 21, 0, Amu1
    ldr r9, [sp, #mDo0]
    KeccakThetaRhoPiChiIota Aba1, r8, 0, Abe1, r11, 22, 22, Abi1, r2, 21, 9, Abo1, r9, 10, 14, Abu1, r14, 7, 27, 28, 1, 0, Asu0, r1
    str r1, [r0, #Aba1]
.endm
@----------------------------------------------------------------------------
@
@ void KeccakF1600_Initialize( void )
@
.align 4
.global KeccakF1600_Initialize
.type KeccakF1600_Initialize, %function
KeccakF1600_Initialize:
 bx lr
@----------------------------------------------------------------------------
@
@ void KeccakF1600_StateXORBytes(void *state, const unsigned char *data, unsigned int offset, unsigned int length)
@
.align 4
.global KeccakF1600_StateXORBytes
.type KeccakF1600_StateXORBytes, %function
KeccakF1600_StateXORBytes:
 cbz r3, KeccakF1600_StateXORBytes_Exit1
 push {r4 - r8, lr} @ then
 bic r4, r2, #7 @ offset &= ~7
 adds r0, r0, r4 @ add whole lane offset to state pointer
 ands r2, r2, #7 @ offset &= 7 (part not lane aligned)
 beq KeccakF1600_StateXORBytes_CheckLanes @ .if offset != 0
 movs r4, r3 @ then, do remaining bytes in first lane
 rsb r5, r2, #8 @ max size in lane = 8 - offset
 cmp r4, r5
 ble KeccakF1600_StateXORBytes_BytesAlign
 movs r4, r5
KeccakF1600_StateXORBytes_BytesAlign:
 sub r8, r3, r4 @ size left
 movs r3, r4
 bl __KeccakF1600_StateXORBytesInLane
 mov r3, r8
KeccakF1600_StateXORBytes_CheckLanes:
 lsrs r2, r3, #3 @ .if length >= 8
 beq KeccakF1600_StateXORBytes_Bytes
 mov r8, r3
 bl __KeccakF1600_StateXORLanes
 and r3, r8, #7
KeccakF1600_StateXORBytes_Bytes:
 cbz r3, KeccakF1600_StateXORBytes_Exit
 movs r2, #0
 bl __KeccakF1600_StateXORBytesInLane
KeccakF1600_StateXORBytes_Exit:
 pop {r4 - r8, pc}
KeccakF1600_StateXORBytes_Exit1:
 bx lr
@----------------------------------------------------------------------------
@
@ __KeccakF1600_StateXORLanes
@
@ Input:
@ r0 state pointer
@ r1 data pointer
@ r2 laneCount
@
@ Output:
@ r0 state pointer next lane
@ r1 data pointer next byte to input
@
@ Changed: r2-r7
@
.align 4
__KeccakF1600_StateXORLanes:
__KeccakF1600_StateXORLanes_LoopAligned:
 ldr r4, [r1], #4
 ldr r5, [r1], #4
 ldrd r6, r7, [r0]
 toBitInterleaving r4, r5, r6, r7, r3, 0
 strd r6, r7, [r0], #8
 subs r2, r2, #1
 bne __KeccakF1600_StateXORLanes_LoopAligned
 bx lr
@----------------------------------------------------------------------------
@
@ __KeccakF1600_StateXORBytesInLane
@
@ Input:
@ r0 state pointer
@ r1 data pointer
@ r2 offset in lane
@ r3 length
@
@ Output:
@ r0 state pointer next lane
@ r1 data pointer next byte to input
@
@ Changed: r2-r7
@
.align 4
__KeccakF1600_StateXORBytesInLane:
 movs r4, #0
 movs r5, #0
 push { r4 - r5 }
 add r2, r2, sp
__KeccakF1600_StateXORBytesInLane_Loop:
 ldrb r5, [r1], #1
 strb r5, [r2], #1
 subs r3, r3, #1
 bne __KeccakF1600_StateXORBytesInLane_Loop
 pop { r4 - r5 }
 ldrd r6, r7, [r0]
 toBitInterleaving r4, r5, r6, r7, r3, 0
 strd r6, r7, [r0], #8
 bx lr
@----------------------------------------------------------------------------
@
@ void KeccakF1600_StateExtractBytes(void *state, const unsigned char *data, unsigned int offset, unsigned int length)
@
.align 4
.global KeccakF1600_StateExtractBytes
.type KeccakF1600_StateExtractBytes, %function
KeccakF1600_StateExtractBytes:
 cbz r3, KeccakF1600_StateExtractBytes_Exit1 @ .if length != 0
 push {r4 - r8, lr} @ then
 bic r4, r2, #7 @ offset &= ~7
 adds r0, r0, r4 @ add whole lane offset to state pointer
 ands r2, r2, #7 @ offset &= 7 (part not lane aligned)
 beq KeccakF1600_StateExtractBytes_CheckLanes @ .if offset != 0
 movs r4, r3 @ then, do remaining bytes in first lane
 rsb r5, r2, #8 @ max size in lane = 8 - offset
 cmp r4, r5
 ble KeccakF1600_StateExtractBytes_BytesAlign
 movs r4, r5
KeccakF1600_StateExtractBytes_BytesAlign:
 sub r8, r3, r4 @ size left
 movs r3, r4
 bl __KeccakF1600_StateExtractBytesInLane
 mov r3, r8
KeccakF1600_StateExtractBytes_CheckLanes:
 lsrs r2, r3, #3 @ .if length >= 8
 beq KeccakF1600_StateExtractBytes_Bytes
 mov r8, r3
 bl __KeccakF1600_StateExtractLanes
 and r3, r8, #7
KeccakF1600_StateExtractBytes_Bytes:
 cbz r3, KeccakF1600_StateExtractBytes_Exit
 movs r2, #0
 bl __KeccakF1600_StateExtractBytesInLane
KeccakF1600_StateExtractBytes_Exit:
 pop {r4 - r8, pc}
KeccakF1600_StateExtractBytes_Exit1:
 bx lr
@----------------------------------------------------------------------------
@
@ __KeccakF1600_StateExtractLanes
@
@ Input:
@ r0 state pointer
@ r1 data pointer
@ r2 laneCount
@
@ Output:
@ r0 state pointer next lane
@ r1 data pointer next byte to input
@
@ Changed: r2-r5
@
.align 4
__KeccakF1600_StateExtractLanes:
__KeccakF1600_StateExtractLanes_LoopAligned:
 ldrd r4, r5, [r0], #8
 fromBitInterleaving r4, r5, r3
 str r4, [r1], #4
 subs r2, r2, #1
 str r5, [r1], #4
 bne __KeccakF1600_StateExtractLanes_LoopAligned
 bx lr
@----------------------------------------------------------------------------
@
@ __KeccakF1600_StateExtractBytesInLane
@
@ Input:
@ r0 state pointer
@ r1 data pointer
@ r2 offset in lane
@ r3 length
@
@ Output:
@ r0 state pointer next lane
@ r1 data pointer next byte to input
@
@ Changed: r2-r6
@
.align 4
__KeccakF1600_StateExtractBytesInLane:
 ldrd r4, r5, [r0], #8
 fromBitInterleaving r4, r5, r6
 push {r4, r5}
 add r2, sp, r2
__KeccakF1600_StateExtractBytesInLane_Loop:
 ldrb r4, [r2], #1
 subs r3, r3, #1
 strb r4, [r1], #1
 bne __KeccakF1600_StateExtractBytesInLane_Loop
 add sp, #8
 bx lr
.align 4
KeccakF1600_StatePermute_RoundConstantsWithTerminator:
 @ 0 1
  .long 0x00000001, 0x00000000
  .long 0x00000000, 0x00000089
  .long 0x00000000, 0x8000008b
  .long 0x00000000, 0x80008080
  .long 0x00000001, 0x0000008b
  .long 0x00000001, 0x00008000
  .long 0x00000001, 0x80008088
  .long 0x00000001, 0x80000082
  .long 0x00000000, 0x0000000b
  .long 0x00000000, 0x0000000a
  .long 0x00000001, 0x00008082
  .long 0x00000000, 0x00008003
  .long 0x00000001, 0x0000808b
  .long 0x00000001, 0x8000000b
  .long 0x00000001, 0x8000008a
  .long 0x00000001, 0x80000081
  .long 0x00000000, 0x80000081
  .long 0x00000000, 0x80000008
  .long 0x00000000, 0x00000083
  .long 0x00000000, 0x80008003
  .long 0x00000001, 0x80008088
  .long 0x00000000, 0x80000088
  .long 0x00000001, 0x00008000
  .long 0x00000000, 0x80008082
  .long 0x000000FF @terminator
@----------------------------------------------------------------------------
@

.balign 16
.global KeccakF1600_StatePermute
.type KeccakF1600_StatePermute,%function
KeccakF1600_StatePermute:
movs r1,#0
b.w two
.global two34
.type two34,%function
two34:
push {r4-r12,lr}
sub sp,#128
adr.w r2,KeccakF1600_StatePermute_RoundConstantsWithTerminator
str r2,[sp,#20]
str r2,[sp,#84]
str r1,[sp,#88]
cmp r1,#0
ite eq
moveq r2,#2
movne r2,#0
str r2,[sp,#56]
adds r2,#1
str r2,[sp,#120]
movs r2,#6
str r2,[sp,#60]

.balign 4
first_0:
ldr r3, [r0, #0x20]
ldr r7, [r0, #0xc]
eor.w r6, r3, r7, ror #31
ldr r4, [r0, #0x14]
str r6, [sp]
eor.w r6, r3, r4
ldr r3, [r0, #0x18]
str r6, [sp, #0xc]
eor.w r2, r7, r3
ldr r7, [r0]
eor.w r10, r7, r4, ror #31
ldr r4, [r0, #0x1c]
eor.w lr, r4, r7
ldr r7, [r0, #0x8]
eor.w r6, r7, r4, ror #31
ldr r4, [r0, #0x24]
str r6, [sp, #0x10]
eor.w r8, r4, r7
ldr r7, [r0, #0x10]
str.w r8, [sp, #0x4]
eor.w r9, r7, r4, ror #31
ldr r4, [r0, #0x4]
str.w r9, [sp, #0x8]
eor.w r4,r4,#0x80000000
eor.w r11, r4, r7
eor.w r12, r3, r4, ror #31
ldr r3, [r0, #0x18]
mov.w r1,#0
str r1, [r0, #0x54]
eor.w r3, r9, r3
mov r4,r12
mov r5,r8
mov r6,r11
mov r7,r2
bic.w r1, r5, r4, ror #24
eor.w r1, r1, r3, ror #20
str r1, [r0, #0x54]
bic.w r1, r6, r5, ror #21
eor.w r1, r1, r4, ror #13
str.w r1, [r0, #0x84]
bic.w r1, r7, r6, ror #8
eor.w r1, r1, r5, ror #29
str.w r1, [r0, #0xb4]
bic.w r1, r3, r7, ror #15
eor.w r1, r1, r6, ror #23
str r1, [r0, #0x18]
bic.w r1, r4, r3, ror #28
eor.w r1, r1, r7, ror #11
ldr r3, [r0, #0x8]
str r1, [r0, #0x48]
eor.w r3, r10, r3
mov r4,r2
mov r5,r9
mov r6,lr
eor.w r7,r8,#0x80000000
bic.w r1, r5, r4, ror #9
eor.w r1, r1, r3, ror #12
str.w r1, [r0, #0xa4]
bic.w r1, r6, r5, ror #24
eor.w r1, r1, r4, ror #1
str r1, [r0, #0x8]
bic.w r1, r7, r6, ror #5
eor.w r1, r1, r5, ror #29
str r1, [r0, #0x3c]
bic.w r1, r3, r7, ror #23
eor.w r1, r1, r6, ror #28
str r1, [r0, #0x68]
bic.w r1, r4, r3, ror #3
eor.w r1, r1, r7, ror #26
ldr.w r8, [sp]
ldr r3, [r0, #0x24]
str.w r1, [r0, #0x9c]
eor.w r3, lr, r3
mov r4,r8
mov r5,r10
mov r6,r2
mov r7,r9
bic.w r1, r5, r4, ror #19
eor.w r1, r1, r3, ror #23
str r1, [r0, #0x28]
bic.w r1, r6, r5, ror #3
eor.w r1, r1, r4, ror #22
str r1, [r0, #0x58]
bic.w r1, r7, r6, ror #20
eor.w r1, r1, r5, ror #23
str.w r1, [r0, #0x8c]
bic.w r1, r3, r7, ror #18
eor.w r1, r1, r6, ror #6
str.w r1, [r0, #0xb8]
bic.w r1, r4, r3, ror #4
eor.w r1, r1, r7, ror #22
ldr r3, [r0, #0x14]
str r1, [r0, #0x24]
eor.w r3, r2, r3
mov r4,r9
mov r5,r12
mov r6,r8
mov r7,r11
bic.w r1, r5, r4, ror #24
eor.w r1, r1, r3, ror #20
str r1, [r0, #0x78]
bic.w r1, r6, r5, ror #1
eor.w r1, r1, r4, ror #25
str.w r1, [r0, #0xac]
bic.w r1, r7, r6, ror #13
eor.w r1, r1, r5, ror #14
str r1, [r0, #0x14]
bic.w r1, r3, r7, ror #30
eor.w r1, r1, r6, ror #11
str r1, [r0, #0x40]
bic.w r1, r4, r3, ror #28
eor.w r1, r1, r7, ror #26
ldr.w r9, [sp, #0xc]
ldr r3, [r0]
str r1, [r0, #0x70]
eor.w r3, r8, r3
mov r4,r10
mov r5,r2
mov r6,r9
mov r7,r12
bic.w r1, r6, r5, ror #21
eor.w r1, r1, r4, ror #21
str r1, [r0, #0x30]
bic.w r1, r7, r6, ror #28
eor.w r1, r1, r5, ror #17
str r1, [r0, #0x64]
bic.w r1, r3, r7, ror #25
eor.w r1, r1, r6, ror #21
str.w r1, [r0, #0x94]
bic.w r1, r4, r3, ror #22
eor.w r1, r1, r7, ror #15
str.w r1, [r0, #0xc0]
bic.w r5, r5, r4
ldr r1, [sp, #0x14]
ldr r4, [r1]
eor.w r3, r3, r5, ror #10
eor.w r1, r4, r3
ldr r3,[sp,#56]
cmp r3,#0
bne first_over_0
add sp,#24
stm.w sp,{r0,r1,r8,r9,r10,r11,r12,lr}
sub sp,#24
add sp,#64
ldr r0,[sp,#24]
b.w first_0
first_over_0:
.balign 4
first_1:
ldr r2, [sp, #0x10]
ldr r3, [r0, #0x1c]
str r1, [r0]
eor.w r3, r9, r3
mov r4,lr
mov r5,r8
mov r6,r10
mov r7,r2
bic.w r1, r5, r4, ror #23
eor.w r1, r1, r3, ror #19
str r1, [r0, #0x50]
bic.w r1, r6, r5, ror #21
eor.w r1, r1, r4, ror #12
str.w r1, [r0, #0x80]
bic.w r1, r7, r6, ror #8
eor.w r1, r1, r5, ror #29
str.w r1, [r0, #0xb0]
bic.w r1, r3, r7, ror #16
eor.w r1, r1, r6, ror #24
str r1, [r0, #0x1c]
bic.w r1, r4, r3, ror #28
eor.w r1, r1, r7, ror #12
ldr r3, [r0, #0xc]
str r1, [r0, #0x4c]
eor.w r3, r11, r3
mov r4,r2
mov r5,r9
mov r6,r12
mov r7,r8
bic.w r1, r5, r4, ror #10
eor.w r1, r1, r3, ror #12
str.w r1, [r0, #0xa0]
bic.w r1, r6, r5, ror #23
eor.w r1, r1, r4, ror #1
str r1, [r0, #0xc]
bic.w r1, r7, r6, ror #5
eor.w r1, r1, r5, ror #28
str r1, [r0, #0x38]
bic.w r1, r3, r7, ror #24
eor.w r1, r1, r6, ror #29
str r1, [r0, #0x6c]
bic.w r1, r4, r3, ror #2
eor.w r1, r1, r7, ror #26
ldr.w r8, [sp, #0x4]
ldr r3, [r0, #0x20]
str.w r1, [r0, #0x98]
eor.w r3, r12, r3
mov r4,r8
mov r5,r11
mov r6,r2
mov r7,r9
bic.w r1, r5, r4, ror #19
eor.w r1, r1, r3, ror #24
str r1, [r0, #0x2c]
bic.w r1, r6, r5, ror #2
eor.w r1, r1, r4, ror #21
str r1, [r0, #0x5c]
bic.w r1, r7, r6, ror #21
eor.w r1, r1, r5, ror #23
str.w r1, [r0, #0x88]
bic.w r1, r3, r7, ror #17
eor.w r1, r1, r6, ror #6
str.w r1, [r0, #0xbc]
bic.w r1, r4, r3, ror #5
eor.w r1, r1, r7, ror #22
ldr r3, [r0, #0x10]
str r1, [r0, #0x20]
eor.w r3, r2, r3
mov r4,r9
mov r5,lr
mov r6,r8
mov r7,r10
bic.w r1, r5, r4, ror #24
eor.w r1, r1, r3, ror #21
str r1, [r0, #0x7c]
bic.w r1, r6, r5, ror #1
eor.w r1, r1, r4, ror #25
str.w r1, [r0, #0xa8]
bic.w r1, r7, r6, ror #12
eor.w r1, r1, r5, ror #13
str r1, [r0, #0x10]
bic.w r1, r3, r7, ror #30
eor.w r1, r1, r6, ror #10
str r1, [r0, #0x44]
bic.w r1, r4, r3, ror #29
eor.w r1, r1, r7, ror #27
ldr.w r9, [sp, #0x8]
ldr r3, [r0, #0x4]
str r1, [r0, #0x74]
eor.w r3, r8, r3
mov r4,r11
mov r5,r2
mov r6,r9
mov r7,lr
bic.w r1, r6, r5, ror #21
eor.w r1, r1, r4, ror #20
str r1, [r0, #0x34]
bic.w r1, r7, r6, ror #29
eor.w r1, r1, r5, ror #18
str r1, [r0, #0x60]
bic.w r1, r3, r7, ror #25
eor.w r1, r1, r6, ror #22
str.w r1, [r0, #0x90]
bic.w r1, r4, r3, ror #22
eor.w r1, r1, r7, ror #15
str.w r1, [r0, #0xc4]
bic.w r5, r5, r4, ror #31
ldr r1, [sp, #0x14]
ldr r4, [r1, #0x4]
eor.w r3, r3, r5, ror #11
eor.w lr, r4, r3
ldr r1,[sp,#56]
cmp r1,#1
bne first_over_1
strd r0,lr,[sp,#24]
sub sp,#64
add sp,#24
ldm.w sp,{r0,r1,r8,r9,r10,r11,r12,lr}
sub sp,#24
b.w first_1
first_over_1:
b.w sector_2
.balign 4
.global two
.type two,%function
two:
push {r4-r12,lr}
sub sp,#128
adr.w r2,KeccakF1600_StatePermute_RoundConstantsWithTerminator
str r2,[sp,#20]
str r2,[sp,#84]
str r1,[sp,#88]
cmp r1,#0
ite eq
moveq r2,#2
movne r2,#0
str r2,[sp,#56]
adds r2,#1
str r2,[sp,#120]
movs r2,#6
str r2,[sp,#60]
outer:
.balign 4
sector_0:
    xor5 r3, Abu0, Agu0, Aku0, Amu0, Asu0, 0, 0, 0, 0, 0
    xor5 r7, Abe1, Age1, Ake1, Ame1, Ase1, 0, 0, 0, 0, 0
    xorrol r6, r3, r7, 32
    xor5str r4, Abi1, Agi1, Aki1, Ami1, Asi1, 0, 0, 0, 0, 0, r6, sp, mDa0
    eor.w r6, r3, r4
    xor5str r3, Abo0, Ago0, Ako0, Amo0, Aso0, 0, 0, 0, 0, 0, r6, sp, mDo1
    eor.w r2, r7, r3
    xor5 r7, Aba0, Aga0, Aka0, Ama0, Asa0, 0, 0, 0, 0, 0
    xorrol r10, r7, r4, 32
    xor5 r4, Abo1, Ago1, Ako1, Amo1, Aso1, 0, 0, 0, 0, 0
    eor r14, r4, r7
    xor5 r7, Abe0, Age0, Ake0, Ame0, Ase0, 0, 0, 0, 0, 0
    xorrol r6, r7, r4, 32
    xor5str r4, Abu1, Agu1, Aku1, Amu1, Asu1, 0, 0, 0, 0, 0, r6, sp, mDi0
    eor.w r8, r4, r7
    xor5str r7, Abi0, Agi0, Aki0, Ami0, Asi0, 0, 0, 0, 0, 0, r8, sp, mDa1
    xorrol r9, r7, r4, 32
    xor5str r4, Aba1, Aga1, Aka1, Ama1, Asa1, 0, 0, 0, 0, 0, r9, sp, mDo0
    eor r11, r4, r7
    xorrol r12, r3, r4, 32
    KeccakThetaRhoPiChi Abo0, Aka1, r9, 14, 0, Agu0, Ame1, r12, 10, 0, Aka1, Asi1, r8, 2, 0, Ame1, Abo0, r11, 23, 0, Asi1, Agu0, r2, 31, 0, 1, Aka1
    KeccakThetaRhoPiChi Abe0, Asa1, r10, 0, 0, Agi1, Abe0, r2, 3, 0, Ako0, Agi1, r9, 12, 0, Amu1, Ako0, r14, 4, 0, Asa1, Amu1, r8, 9, 0, 1, Agu0
    ldr r8, [sp, #mDa0]
    KeccakThetaRhoPiChi Abu1, Aga0, r14, 14, 0, Aga0, Ake0, r8, 18, 0, Ake0, Ami1, r10, 5, 0, Ami1, Aso0, r2, 8, 0, Aso0, Abu1, r9, 28, 0, 1, Amu1
    KeccakThetaRhoPiChi Abi1, Ama0, r2, 31, 0, Ago0, Ase1, r9, 27, 0, Aku0, Abi1, r12, 19, 0, Ama0, Ago0, r8, 20, 0, Ase1, Aku0, r11, 1, 0, 1, Abu1
    ldr r9, [sp, #mDo1]
    KeccakThetaRhoPiChiIota Aba0, r8, 0, Age0, r10, 22, 0, Aki1, r2, 22, 0, Amo1, r9, 11, 0, Asu0, r12, 7, 0, 0, 0, 1, Aku0, r1
ldr r3,[sp,#56]
cmp r3,#0
bne over_0
add sp,#24
stm.w sp,{r0,r1,r8,r9,r10,r11,r12,lr}
sub sp,#24
add sp,#64
ldr r0,[sp,#24]
b.w sector_0
over_0:
.balign 4
sector_1:
    ldr r2, [sp, #mDi0]
    KeccakThetaRhoPiChi Abo1, Aka0, r9, 14, 0, Agu1, Ame0, r14, 10, 0, Aka0, Asi0, r8, 1, 0, Ame0, Abo1, r10, 22, 0, Asi0, Agu1, r2, 30, 0, 1, Aba0
    KeccakThetaRhoPiChi Abe1, Asa0, r11, 1, 0, Agi0, Abe1, r2, 3, 0, Ako1, Agi0, r9, 13, 0, Amu0, Ako1, r12, 4, 0, Asa0, Amu0, r8, 9, 0, 1, Agu1
    ldr r8, [sp, #mDa1]
    KeccakThetaRhoPiChi Abu0, Aga1, r12, 13, 0, Aga1, Ake1, r8, 18, 0, Ake1, Ami0, r11, 5, 0, Ami0, Aso1, r2, 7, 0, Aso1, Abu0, r9, 28, 0, 1, Amu0
    KeccakThetaRhoPiChi Abi0, Ama1, r2, 31, 0, Ago1, Ase0, r9, 28, 0, Aku1, Abi0, r14, 20, 0, Ama1, Ago1, r8, 21, 0, Ase0, Aku1, r10, 1, 0, 1, Abu0
    ldr r9, [sp, #mDo0]
    KeccakThetaRhoPiChiIota Aba1, r8, 0, Age1, r11, 22, 0, Aki0, r2, 21, 0, Amo0, r9, 10, 0, Asu1, r14, 7, 0, 4, 0, 1, Aku1, r14
ldr r1,[sp,#56]
cmp r1,#1
bne over_1
strd r0,lr,[sp,#24]
sub sp,#64
add sp,#24
ldm.w sp,{r0,r1,r8,r9,r10,r11,r12,lr}
sub sp,#24
b.w sector_1
over_1:
.balign 4
sector_2:
    xor5str r3, Asu0, Agu0, Amu0, Abu1, Aku1, 22, 10, 3, 18, 28, r14, r0, Aba1
    xor5 r7, Age1, Ame0, Abe0, Ake1, Ase1, 10, 22, 4, 7, 20
    ror r3, 32-22
    xorrol r6, r3, r7, 32-10
    xor5str r4, Aki0, Asi0, Agi1, Ami0, Abi1, 7, 30, 9, 28, 1, r6, sp, mDa0
    eor r6, r3, r4, ror 32-7
    xor5str r3, Amo1, Abo0, Ako1, Aso0, Ago1, 0, 14, 1, 14, 31, r6, sp, mDo1
    eor r2, r3, r7, ror 32-10
    xor5 r7, Aba0, Aka1, Asa0, Aga0, Ama1, 0, 2, 13, 5, 20
    xorrol r10, r7, r4, 32-7
    xor5 r4, Amo0, Abo1, Ako0, Aso1, Ago0, 0, 14, 0, 13, 31
    eor r14, r4, r7
    xor5 r7, Age0, Ame1, Abe1, Ake0, Ase0, 11, 23, 4, 8, 21
    ror r7, 32-11
    xorrol r6, r7, r4, 32
    xor5str r4, Asu1, Agu1, Amu1, Abu0, Aku0, 22, 10, 3, 18, 27, r6, sp, mDi0
    eor r8, r7, r4, ror 32-22
    xor5str r7, Aki1, Asi1, Agi0, Ami1, Abi0, 7, 31, 9, 28, 1, r8, sp, mDa1
    ror r7, 32-7
    xorrol r9, r7, r4, 32-22
    xor5str r4, Aba1, Aka0, Asa1, Aga1, Ama0, 0, 1, 12, 5, 19, r9, sp, mDo0
    eor r11, r4, r7
    xorrol r12, r3, r4, 32
    KeccakThetaRhoPiChi Amo1, Asa1, r9, 14, 0, Agu0, Ake1, r12, 10, 10, Asa1, Abi1, r8, 2, 12, Ake1, Amo1, r11, 23, 7, Abi1, Agu0, r2, 31, 1, 1, Asa1
    KeccakThetaRhoPiChi Age0, Ama0, r10, 0, 11, Asi0, Age0, r2, 3, 30, Ako1, Asi0, r9, 12, 1, Abu0, Ako1, r14, 4, 18, Ama0, Abu0, r8, 9, 19, 1, Agu0
    ldr r8, [sp, #mDa0]
    KeccakThetaRhoPiChi Asu1, Aka1, r14, 14, 22, Aka1, Abe1, r8, 18, 2, Abe1, Ami0, r10, 5, 4, Ami0, Ago1, r2, 8, 28, Ago1, Asu1, r9, 28, 31, 1, Abu0
    KeccakThetaRhoPiChi Aki0, Aga0, r2, 31, 7, Abo0, Ase1, r9, 27, 14, Amu0, Aki0, r12, 19, 3, Aga0, Abo0, r8, 20, 5, Ase1, Amu0, r11, 1, 20, 1, Asu1
    ldr r9, [sp, #mDo1]
    KeccakThetaRhoPiChiIota Aba0, r8, 0, Ame1, r10, 22, 23, Agi1, r2, 22, 9, Aso1, r9, 11, 13, Aku1, r12, 7, 28, 8, 0, 1, Amu0, r1
ldr r3,[sp,#56]
cmp r3,#0
bne over_2
add sp,#24
stm.w sp,{r0,r1,r8,r9,r10,r11,r12,lr}
sub sp,#24
add sp,#64
ldrd r0,lr,[sp,#24]
b.w sector_2
over_2:
.balign 4
sector_3:
    ldr r2, [sp, #mDi0]
    KeccakThetaRhoPiChi Amo0, Asa0, r9, 14, 0, Agu1, Ake0, r14, 10, 10, Asa0, Abi0, r8, 1, 13, Ake0, Amo0, r10, 22, 8, Abi0, Agu1, r2, 30, 1, 1, Aba0
    KeccakThetaRhoPiChi Age1, Ama1, r11, 1, 10, Asi1, Age1, r2, 3, 31, Ako0, Asi1, r9, 13, 0, Abu1, Ako0, r12, 4, 18, Ama1, Abu1, r8, 9, 20, 1, Agu1
    ldr r8, [sp, #mDa1]
    KeccakThetaRhoPiChi Asu0, Aka0, r12, 13, 22, Aka0, Abe0, r8, 18, 1, Abe0, Ami1, r11, 5, 4, Ami1, Ago0, r2, 7, 28, Ago0, Asu0, r9, 28, 31, 1, Abu1
    KeccakThetaRhoPiChi Aki1, Aga1, r2, 31, 7, Abo1, Ase0, r9, 28, 14, Amu1, Aki1, r14, 20, 3, Aga1, Abo1, r8, 21, 5, Ase0, Amu1, r10, 1, 21, 1, Asu0
    ldr r9, [sp, #mDo0]
    KeccakThetaRhoPiChiIota Aba1, r8, 0, Ame0, r11, 22, 22, Agi0, r2, 21, 9, Aso0, r9, 10, 14, Aku0, r14, 7, 27, 12, 0, 1, Amu1, r14
ldr r1,[sp,#56]
cmp r1,#1
bne over_3
strd r0,lr,[sp,#24]
sub sp,#64
add sp,#24
ldm.w sp,{r0,r1,r8,r9,r10,r11,r12,lr}
sub sp,#24
b.w sector_3
over_3:
.balign 4
sector_4:
    xor5str r3, Aku1, Agu0, Abu1, Asu1, Amu1, 22, 10, 3, 18, 28, r14, r0, Aba1
    xor5 r7, Ame0, Ake0, Age0, Abe0, Ase1, 10, 22, 4, 7, 20
    ror r3, 32-22
    xorrol r6, r3, r7, 32-10
    xor5str r4, Agi0, Abi0, Asi0, Ami1, Aki0, 7, 30, 9, 28, 1, r6, sp, mDa0
    eor r6, r3, r4, ror 32-7
    xor5str r3, Aso1, Amo1, Ako0, Ago1, Abo1, 0, 14, 1, 14, 31, r6, sp, mDo1
    eor r2, r3, r7, ror 32-10
    xor5 r7, Aba0, Asa1, Ama1, Aka1, Aga1, 0, 2, 13, 5, 20
    xorrol r10, r7, r4, 32-7
    xor5 r4, Aso0, Amo0, Ako1, Ago0, Abo0, 0, 14, 0, 13, 31
    eor r14, r4, r7
    xor5 r7, Ame1, Ake1, Age1, Abe1, Ase0, 11, 23, 4, 8, 21
    ror r7, 32-11
    xorrol r6, r7, r4, 32
    xor5str r4, Aku0, Agu1, Abu0, Asu0, Amu0, 22, 10, 3, 18, 27, r6, sp, mDi0
    eor r8, r7, r4, ror 32-22
    xor5str r7, Agi1, Abi1, Asi1, Ami0, Aki1, 7, 31, 9, 28, 1, r8, sp, mDa1
    ror r7, 32-7
    xorrol r9, r7, r4, 32-22
    xor5str r4, Aba1, Asa0, Ama0, Aka0, Aga0, 0, 1, 12, 5, 19, r9, sp, mDo0
    eor r11, r4, r7
    xorrol r12, r3, r4, 32
    KeccakThetaRhoPiChi Aso1, Ama0, r9, 14, 0, Agu0, Abe0, r12, 10, 10, Ama0, Aki0, r8, 2, 12, Abe0, Aso1, r11, 23, 7, Aki0, Agu0, r2, 31, 1, 1, Ama0
    KeccakThetaRhoPiChi Ame1, Aga0, r10, 0, 11, Abi0, Ame1, r2, 3, 30, Ako0, Abi0, r9, 12, 1, Asu0, Ako0, r14, 4, 18, Aga0, Asu0, r8, 9, 19, 1, Agu0
    ldr r8, [sp, #mDa0]
    KeccakThetaRhoPiChi Aku0, Asa1, r14, 14, 22, Asa1, Age1, r8, 18, 2, Age1, Ami1, r10, 5, 4, Ami1, Abo1, r2, 8, 28, Abo1, Aku0, r9, 28, 31, 1, Asu0
    KeccakThetaRhoPiChi Agi0, Aka1, r2, 31, 7, Amo1, Ase1, r9, 27, 14, Abu1, Agi0, r12, 19, 3, Aka1, Amo1, r8, 20, 5, Ase1, Abu1, r11, 1, 20, 1, Aku0
    ldr r9, [sp, #mDo1]
    KeccakThetaRhoPiChiIota Aba0, r8, 0, Ake1, r10,22, 23, Asi0, r2, 22, 9, Ago0, r9, 11, 13, Amu1, r12, 7, 28, 16, 0, 1, Abu1, r1
ldr r3,[sp,#56]
cmp r3,#0
bne over_4
add sp,#24
stm.w sp,{r0,r1,r8,r9,r10,r11,r12,lr}
sub sp,#24
add sp,#64
ldrd r0,lr,[sp,#24]
b.w sector_4
over_4:
.balign 4
sector_5:
    ldr r2, [sp, #mDi0]
    KeccakThetaRhoPiChi Aso0, Ama1, r9, 14, 0, Agu1, Abe1, r14, 10, 10, Ama1, Aki1, r8, 1, 13, Abe1, Aso0, r10, 22, 8, Aki1, Agu1, r2, 30, 1, 1, Aba0
    KeccakThetaRhoPiChi Ame0, Aga1, r11, 1, 10, Abi1, Ame0, r2, 3, 31, Ako1, Abi1, r9, 13, 0, Asu1, Ako1, r12, 4, 18, Aga1, Asu1, r8, 9, 20, 1, Agu1
    ldr r8, [sp, #mDa1]
    KeccakThetaRhoPiChi Aku1, Asa0, r12, 13, 22, Asa0, Age0, r8, 18, 1, Age0, Ami0, r11, 5, 4, Ami0, Abo0, r2, 7, 28, Abo0, Aku1, r9, 28, 31, 1, Asu1
    KeccakThetaRhoPiChi Agi1, Aka0, r2, 31, 7, Amo0, Ase0, r9, 28, 14, Abu0, Agi1, r14, 20, 3, Aka0, Amo0, r8, 21, 5, Ase0, Abu0, r10, 1, 21, 1, Aku1
    ldr r9, [sp, #mDo0]
    KeccakThetaRhoPiChiIota Aba1, r8, 0, Ake0, r11, 22, 22, Asi1, r2, 21, 9, Ago1, r9, 10, 14, Amu0, r14, 7, 27, 20, 0, 1, Abu0, r14
ldr r1,[sp,#56]
cmp r1,#1
bne over_5
strd r0,lr,[sp,#24]
sub sp,#64
add sp,#24
ldm.w sp,{r0,r1,r8,r9,r10,r11,r12,lr}
sub sp,#24
b.w sector_5
over_5:
.balign 4
sector_6:
    xor5str r3, Amu1, Agu0, Asu1, Aku0, Abu0, 22, 10, 3, 18, 28, r14, r0, Aba1
    xor5 r7, Ake0, Abe1, Ame1, Age0, Ase1, 10, 22, 4, 7, 20
    ror r3, 32-22
    xorrol r6, r3, r7, 32-10
    xor5str r4, Asi1, Aki1, Abi0, Ami0, Agi0, 7, 30, 9, 28, 1, r6, sp, mDa0
    eor r6, r3, r4, ror 32-7
    xor5str r3, Ago0, Aso1, Ako1, Abo1, Amo0, 0, 14, 1, 14, 31, r6, sp, mDo1
    eor r2, r3, r7, ror 32-10
    xor5 r7, Aba0, Ama0, Aga1, Asa1, Aka0, 0, 2, 13, 5, 20
    xorrol r10, r7, r4, 32-7
    xor5 r4, Ago1, Aso0, Ako0, Abo0, Amo1, 0, 14, 0, 13, 31
    eor r14, r4, r7
    xor5 r7, Ake1, Abe0, Ame0, Age1, Ase0, 11, 23, 4, 8, 21
    ror r7, #32-11
    xorrol r6, r7, r4, 32
    xor5str r4, Amu0, Agu1, Asu0, Aku1, Abu1, 22, 10, 3, 18, 27, r6, sp, mDi0
    eor r8, r7, r4, ror 32-22
    xor5str r7, Asi0, Aki0, Abi1, Ami1, Agi1, 7, 31, 9, 28, 1, r8, sp, mDa1
    ror r7, 32-7
    xorrol r9, r7, r4, 32-22
    xor5str r4, Aba1, Ama1, Aga0, Asa0, Aka1, 0, 1, 12, 5, 19, r9, sp, mDo0
    eor r11, r4, r7
    xorrol r12, r3, r4, 32
    KeccakThetaRhoPiChi Ago0, Aga0, r9, 14, 0, Agu0, Age0, r12, 10, 10, Aga0, Agi0, r8, 2, 12, Age0, Ago0, r11, 23, 7, Agi0, Agu0, r2, 31, 1, 0, Aga0
    KeccakThetaRhoPiChi Ake1, Aka1, r10, 0, 11, Aki1, Ake1, r2, 3, 30, Ako1, Aki1, r9, 12, 1, Aku1, Ako1, r14, 4, 18, Aka1, Aku1, r8, 9, 19, 0, Agu0
    ldr r8, [sp, #mDa0]
    KeccakThetaRhoPiChi Amu0, Ama0, r14, 14, 22, Ama0, Ame0, r8, 18, 2, Ame0, Ami0, r10, 5, 4, Ami0, Amo0, r2, 8, 28, Amo0, Amu0, r9, 28, 31, 0, Aku1
    KeccakThetaRhoPiChi Asi1, Asa1, r2, 31, 7, Aso1, Ase1, r9, 27, 14, Asu1, Asi1, r12, 19, 3, Asa1, Aso1, r8, 20, 5, Ase1, Asu1, r11, 1, 20, 0, Amu0
    ldr r9, [sp, #mDo1]
    KeccakThetaRhoPiChiIota Aba0, r8, 0, Abe0, r10, 22, 23, Abi0, r2, 22, 9, Abo0, r9, 11, 13, Abu0, r12, 7, 28, 24, 0, 0, Asu1, r1
ldr r3,[sp,#56]
cmp r3,#0
bne over_6
add sp,#24
stm.w sp,{r0,r1,r8,r9,r10,r11,r12,lr}
sub sp,#24
add sp,#64
ldrd r0,lr,[sp,#24]
b.w sector_6
over_6:
.balign 4
sector_7:
    ldr r2, [sp, #mDi0]
    KeccakThetaRhoPiChi Ago1, Aga1, r9, 14, 0, Agu1, Age1, r14, 10, 10, Aga1, Agi1, r8, 1, 13, Age1, Ago1, r10, 22, 8, Agi1, Agu1, r2, 30, 1, 0, Aba0
    KeccakThetaRhoPiChi Ake0, Aka0, r11, 1, 10, Aki0, Ake0, r2, 3, 31, Ako0, Aki0, r9, 13, 0, Aku0, Ako0, r12, 4, 18, Aka0, Aku0, r8, 9, 20, 0, Agu1
    ldr r8, [sp, #mDa1]
    KeccakThetaRhoPiChi Amu1, Ama1, r12, 13, 22, Ama1, Ame1, r8, 18, 1, Ame1, Ami1, r11, 5, 4, Ami1, Amo1, r2, 7, 28, Amo1, Amu1, r9, 28, 31, 0, Aku0
    KeccakThetaRhoPiChi Asi0, Asa0, r2, 31, 7, Aso0, Ase0, r9, 28, 14, Asu0, Asi0, r14, 20, 3, Asa0, Aso0, r8, 21, 5, Ase0, Asu0, r10, 1, 21, 0, Amu1
    ldr r9, [sp, #mDo0]
    KeccakThetaRhoPiChiIota Aba1, r8, 0, Abe1, r11, 22, 22, Abi1, r2, 21, 9, Abo1, r9, 10, 14, Abu1, r14, 7, 27, 28, 1, 0, Asu0, r1
    str r1, [r0, #Aba1]
ldr r1,[sp,#56]
cmp r1,#1
bne over_7
str r0,[sp,#24]
sub sp,#64
add sp,#24
ldm.w sp,{r0,r1,r8,r9,r10,r11,r12,lr}
sub sp,#24
b.w sector_7
over_7:
ldr r1,[sp,#60]
subs r1,#1
str r1,[sp,#60]
bne.w outer
movs r0,#0
movs r1,#0
movs r2,#0
movs r3,#0
mov r4,sp
.rept 8
stm r4!,{r0-r3}
.endr
add sp,#128
pop {r4-r12,pc}