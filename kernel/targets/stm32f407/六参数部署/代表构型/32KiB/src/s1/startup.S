.syntax unified
.cpu cortex-m4
.thumb
.section .vectors,"a",%progbits
.global __vectors
.balign 512
__vectors:
.word __boot_stack_top
.word Reset_Handler
.rept 14
.word Fault_Handler
.endr
.section .text.entry,"ax",%progbits
.thumb_func
.global Reset_Handler
Reset_Handler:
 cpsid i
 ldr r1,=0xe000ed88
 ldr r2,[r1]
 orr r2,r2,#0xf00000
 str r2,[r1]
 dsb
 isb
 movs r0,#0
 msr control,r0
 isb
 ldr r1,=0x40023830
 ldr r2,[r1]
 orr r2,r2,#0x100000
 str r2,[r1]
 ldr r2,[r1]
 ldr r1,=__boot_stack_top
 msr msp,r1
 ldr r1,=__stack_top
 msr psp,r1
 movs r1,#2
 msr control,r1
 isb
 ldr r1,=0xe000ed08
 ldr r2,=__vectors
 str r2,[r1]
 dsb
 isb
 ldr r1,=__data_load
 ldr r2,=__data_begin
 ldr r3,=__data_end
8: cmp r2,r3
 bhs 9f
 ldr r4,[r1],#4
 str r4,[r2],#4
 b 8b
9: ldr r1,=__bss_begin
 ldr r2,=__bss_end
1: cmp r1,r2
 bhs 2f
 str r0,[r1],#4
 b 1b
2: ldr r1,=__ccm_begin
 ldr r2,=__ccm_end
3: cmp r1,r2
 bhs 4f
 str r0,[r1],#4
 b 3b
4: ldr r1,=__stack_guard_bottom
 ldr r2,=__stack_top
 ldr r0,=0xa5a5a5a5
5: cmp r1,r2
 bhs 6f
 str r0,[r1],#4
 b 5b
6: bl board_start
.thumb_func
Fault_Handler:
 b reset_to_dfu
