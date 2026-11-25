.section .text.start,"ax",@progbits
.global _start
_start:
  csrr t0,mhartid
  bnez t0,9f
  csrw mie,zero
  la t0,target_fault
  csrw mtvec,t0
  .option push
  .option norelax
  la gp,__global_pointer$
  .option pop
  la sp,__control_stack_top
  la t0,__data_load
  la t1,__data_start
  la t2,__data_end
1: bgeu t1,t2,2f
  lbu t3,0(t0)
  sb t3,0(t1)
  addi t0,t0,1
  addi t1,t1,1
  j 1b
2: la t1,__zero_start
  la t2,__zero_end
3: bgeu t1,t2,4f
  sb zero,0(t1)
  addi t1,t1,1
  j 3b
4: call target_main
  call target_exit
9: wfi
  j 9b
.section .text.target_call,"ax",@progbits
.global target_call
.type target_call,@function
target_call:
  addi sp,sp,-16
  sw ra,0(sp)
  sw s0,4(sp)
  mv s0,sp
  mv t0,a0
  mv a0,a1
  la sp,__test_stack_top
  jalr t0
  mv sp,s0
  lw ra,0(sp)
  lw s0,4(sp)
  addi sp,sp,16
  ret
.size target_call,.-target_call
