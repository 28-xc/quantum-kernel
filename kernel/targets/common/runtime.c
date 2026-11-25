/* Freestanding test support, not a production entropy provider. */
#include "target.h"
#include "lc_platform.h"
#include <string.h>
void *memcpy(void *restrict d, const void *restrict s, size_t n) {
  unsigned char *a=d; const unsigned char *b=s; while(n--) *a++=*b++; return d;
}
void *memmove(void *d,const void *s,size_t n) {
  unsigned char *a=d; const unsigned char *b=s;
  if((uintptr_t)a < (uintptr_t)b) { while(n--) *a++=*b++; }
  else { a+=n; b+=n; while(n--) *--a=*--b; } return d;
}
void *memset(void *d,int c,size_t n) { unsigned char *a=d; while(n--) *a++=(unsigned char)c; return d; }
int memcmp(const void *a,const void *b,size_t n) {
  const unsigned char *x=a,*y=b; while(n--) { if(*x!=*y) return *x<*y?-1:1; x++;y++; } return 0;
}
size_t strlen(const char *s) { size_t n=0; while(s[n]) n++; return n; }
int lc_system_random(uint8_t *out,size_t n) {
  if(n && out) { volatile uint8_t *p=out; size_t k=n; while(k--) *p++=0; }
  return n ? -1 : 0;
}
void target_text(const char *s) { while(*s) target_putc(*s++); }
void target_uint(uint32_t n) { char b[10]; unsigned k=0; do { b[k++]=(char)('0'+n%10);n/=10; }while(n); while(k)target_putc(b[--k]); }
void target_int(int n) { if(n<0){target_putc('-');target_uint(0u-(uint32_t)n);}else target_uint((uint32_t)n); }
void target_fault(void) { target_text("{\"event\":\"fatal\",\"reason\":\"target_trap\"}\n"); target_exit(1); }
#if defined(__arm__)
/* EABI libc aliases emitted by some freestanding compilers. */
void __aeabi_memcpy(void *d,const void *s,size_t n){memcpy(d,s,n);}
void __aeabi_memcpy4(void *d,const void *s,size_t n){memcpy(d,s,n);}
void __aeabi_memcpy8(void *d,const void *s,size_t n){memcpy(d,s,n);}
void __aeabi_memmove(void *d,const void *s,size_t n){memmove(d,s,n);}
void __aeabi_memset(void *d,size_t n,int c){memset(d,c,n);}
void __aeabi_memset4(void *d,size_t n,int c){memset(d,c,n);}
void __aeabi_memclr(void *d,size_t n){memset(d,0,n);}
void __aeabi_memclr4(void *d,size_t n){memset(d,0,n);}
#endif
