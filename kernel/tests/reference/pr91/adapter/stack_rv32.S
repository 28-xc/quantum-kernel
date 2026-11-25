/* Ordinary-return, caller-owned alternate-stack bridge for RV32 ILP32.
 * a0=job, a1=16-byte-aligned stack top, a2=int (*fn)(void *).
 * Same save/restore pattern as targets/rv32/start.S target_call, but explicit
 * top argument. gp/tp untouched. No exception/interrupt-stack contract added.
 * The C adapter validates storage and wipes it after normal/error return. */
.section .text.lc_memory_call_at,"ax",@progbits
.align 2
.global lc_memory_call_at
.type lc_memory_call_at,@function
lc_memory_call_at:
  addi sp,sp,-16
  sw ra,0(sp)
  sw s0,4(sp)
  mv s0,sp
  mv sp,a1
  jalr a2
  mv sp,s0
  lw ra,0(sp)
  lw s0,4(sp)
  addi sp,sp,16
  ret
.size lc_memory_call_at,.-lc_memory_call_at
