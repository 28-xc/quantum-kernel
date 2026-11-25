#include "target.h"
void target_putc(char c) {
  volatile uint8_t *uart=(volatile uint8_t *)0x10000000u;
  while(!(uart[5]&0x20u)) {} uart[0]=(uint8_t)c;
}
void target_exit(int status) {
  *(volatile uint32_t *)0x100000u=status?(((uint32_t)status<<16)|0x3333u):0x5555u;
  for(;;) __asm__ volatile("wfi");
}
