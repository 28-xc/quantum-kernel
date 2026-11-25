.syntax unified
.thumb
.arch armv7e-m

/* EABI unsigned 64-bit shift, r0:r1 is the low:high input/output pair.
 * Register shift counts at or above one word yield zero. Public and private
 * counts alike follow the same instruction sequence (C-defined counts 0..63). */
.section .text.__aeabi_llsl,"ax",%progbits
.global __aeabi_llsl
.type __aeabi_llsl,%function
.thumb_func
__aeabi_llsl:
    rsb.w r3,r2,#32
    lsr.w r3,r0,r3
    lsl.w r1,r1,r2
    orrs r1,r3
    sub.w r12,r2,#32
    lsl.w r3,r0,r12
    orrs r1,r3
    lsl.w r0,r0,r2
    bx lr
.size __aeabi_llsl,.-__aeabi_llsl

.section .text.__aeabi_llsr,"ax",%progbits
.global __aeabi_llsr
.type __aeabi_llsr,%function
.thumb_func
__aeabi_llsr:
    rsb.w r3,r2,#32
    lsl.w r3,r1,r3
    lsr.w r0,r0,r2
    orrs r0,r3
    sub.w r12,r2,#32
    lsr.w r3,r1,r12
    orrs r0,r3
    lsr.w r1,r1,r2
    bx lr
.size __aeabi_llsr,.-__aeabi_llsr

