.syntax unified
.cpu cortex-m4
.thumb
.section .vectors,"a",%progbits
.global vectors
vectors:
  .word __control_stack_top
  .word _start
  .rept 14
  .word target_fault
  .endr
.section .text.start,"ax",%progbits
.global _start
.thumb_func
_start:
  cpsid i
  ldr r0,=__data_load
  ldr r1,=__data_start
  ldr r2,=__data_end
1: cmp r1,r2
  bcs 2f
  ldrb r3,[r0],#1
  strb r3,[r1],#1
  b 1b
2: ldr r1,=__zero_start
  ldr r2,=__zero_end
  movs r3,#0
3: cmp r1,r2
  bcs 4f
  strb r3,[r1],#1
  b 3b
4: bl target_main
  bl target_exit
  b .
.section .text.target_call,"ax",%progbits
.global target_call
.type target_call,%function
.thumb_func
target_call:
  push {r4-r11,lr}
  sub sp,sp,#4
  mov r4,sp
  mov r2,r0
  mov r0,r1
  ldr sp,=__test_stack_top
  blx r2
  mov sp,r4
  add sp,sp,#4
  pop {r4-r11,pc}
.size target_call,.-target_call
