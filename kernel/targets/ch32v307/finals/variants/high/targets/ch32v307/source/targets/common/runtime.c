/* Freestanding test support, not a production entropy provider. */
#include "target.h"
#include "lc_platform.h"
#include <string.h>
/* The compiler-specific alias type is used only after both pointers have
 * natural word alignment. Every access remains within the supplied ranges.
 * Different alignments and short inputs retain the byte path. This is a
 * conventional freestanding runtime optimization, not a cryptographic change. */
typedef uint32_t lc_alias_word __attribute__((__may_alias__));

__attribute__((aligned(4))) void *memcpy(void *restrict d,const void *restrict s,size_t n){
  unsigned char *a=d;const unsigned char *b=s;
  if(n>=8 && (((uintptr_t)a^(uintptr_t)b)&3u)==0){
    while((uintptr_t)a&3u){*a++=*b++;n--;}
    while(n>=32){
      lc_alias_word *out=(lc_alias_word *)a;const lc_alias_word *in=(const lc_alias_word *)b;
      out[0]=in[0];out[1]=in[1];out[2]=in[2];out[3]=in[3];
      out[4]=in[4];out[5]=in[5];out[6]=in[6];out[7]=in[7];
      a+=32;b+=32;n-=32;
    }
    while(n>=4){*(lc_alias_word *)a=*(const lc_alias_word *)b;a+=4;b+=4;n-=4;}
  }else if(n>=32){
    /* The first 4..7 bytes guarantee that the aligned source window begins
     * inside this object. Keep one extra word strictly inside its end. */
    size_t head=4u+((0u-(uintptr_t)a)&3u);n-=head;
    while(head--)*a++=*b++;
    unsigned offset=(uintptr_t)b&3u,shift=8u*offset;
    const lc_alias_word *in=(const lc_alias_word *)(b-offset);
    uint32_t prev=*in++;
    while(n>=20){
      uint32_t a1=in[0],a2=in[1],a3=in[2],a4=in[3];lc_alias_word *out=(lc_alias_word *)a;
      out[0]=(prev>>shift)|(a1<<(32-shift));out[1]=(a1>>shift)|(a2<<(32-shift));
      out[2]=(a2>>shift)|(a3<<(32-shift));out[3]=(a3>>shift)|(a4<<(32-shift));
      prev=a4;in+=4;a+=16;b+=16;n-=16;
    }
    while(n>=8){uint32_t next=*in++;*(lc_alias_word *)a=(prev>>shift)|(next<<(32-shift));
      prev=next;a+=4;b+=4;n-=4;}
  }
  while(n--)*a++=*b++;
  return d;
}
void *memmove(void *d,const void *s,size_t n) {
  unsigned char *a=d; const unsigned char *b=s;
  if((uintptr_t)a < (uintptr_t)b) { while(n--) *a++=*b++; }
  else { a+=n; b+=n; while(n--) *--a=*--b; } return d;
}

__attribute__((aligned(4))) void *memset(void *d,int c,size_t n){
  unsigned char *a=d;const unsigned char v=(unsigned char)c;
  if(n>=8){
    while((uintptr_t)a&3u){*a++=v;n--;}
    const uint32_t word=(uint32_t)v*0x01010101u;
    while(n>=32){lc_alias_word *w=(lc_alias_word *)a;
      w[0]=word;w[1]=word;w[2]=word;w[3]=word;w[4]=word;w[5]=word;w[6]=word;w[7]=word;
      a+=32;n-=32;}
    while(n>=4){*(lc_alias_word *)a=word;a+=4;n-=4;}
  }
  while(n--)*a++=v;
  return d;
}
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
