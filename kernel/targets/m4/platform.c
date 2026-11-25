#include "target.h"
void target_putc(char c) {
  volatile uint32_t *uart=(volatile uint32_t *)0x40004000u;
  uart[2]=1; while(uart[1]&1u) {} uart[0]=(uint32_t)(unsigned char)c;
}
void target_exit(int status) {
  /* SYS_EXIT_EXTENDED; enabled explicitly in the QEMU command. */
  uint32_t arguments[2]={0x20026u,(uint32_t)status};
  register uint32_t op __asm__("r0")=0x20u;
  register uint32_t *arg __asm__("r1")=arguments;
  __asm__ volatile("bkpt 0xab" : "+r"(op), "+r"(arg) :: "memory");
  for(;;) __asm__ volatile("wfi");
}
