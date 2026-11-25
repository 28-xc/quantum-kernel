/* Fixed-rate deinterleaving for SHAKE128/256, without lookup tables for masks.
   Adapted from the public-domain Keccak teams' ARMv7-M bit-interleaving
   macros, using Henry S. Warren's successive bit exchanges. */
.syntax unified
.thumb
.cpu cortex-m4
.text
.align 2
.macro exchange x,tmp,sh,mask
    eor \tmp,\x,\x,lsr #\sh
    and \tmp,\tmp,#\mask
    eor \x,\x,\tmp
    eor \x,\x,\tmp,lsl #\sh
.endm
.macro plane x,tmp
    exchange \x,\tmp,8,0x0000ff00
    exchange \x,\tmp,4,0x00f000f0
    exchange \x,\tmp,2,0x0c0c0c0c
    exchange \x,\tmp,1,0x22222222
.endm
.macro wordpair a,b,tmp
    mov \tmp,\a
    bfi \a,\b,#16,#16
    bfc \b,#0,#16
    orr \b,\b,\tmp,lsr #16
    plane \a,\tmp
    plane \b,\tmp
.endm
.global a127_extract_words
.type a127_extract_words,%function
.thumb_func
a127_extract_words:
    /* r0 state, r1 output, r2 count=17/21. Outputs may be byte-aligned:
       normal SRAM supports their individual STR, but not an unaligned STM. */
    push.w {r4-r8,lr}
    lsrs r2,r2,#1
.Lextract_two:
    ldmia r0!,{r3-r6}
    wordpair r3,r4,r7
    wordpair r5,r6,r8
    str r3,[r1],#4
    str r4,[r1],#4
    str r5,[r1],#4
    str r6,[r1],#4
    subs r2,r2,#1
    bne .Lextract_two
    ldmia r0!,{r3,r4}
    wordpair r3,r4,r7
    str r3,[r1]
    str r4,[r1,#4]
    pop.w {r4-r8,pc}
.size a127_extract_words,.-a127_extract_words
