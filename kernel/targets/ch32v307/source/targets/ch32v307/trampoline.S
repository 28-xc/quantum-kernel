/* Only the isolated-stack ABI adapter from targets/rv32/start.S. */
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
