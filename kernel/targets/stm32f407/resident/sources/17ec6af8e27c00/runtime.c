
typedef int ptrdiff_t;
typedef unsigned int size_t;
typedef unsigned int wchar_t;
typedef struct {
  long long __clang_max_align_nonce1
      __attribute__((__aligned__(__alignof__(long long))));
  long double __clang_max_align_nonce2
      __attribute__((__aligned__(__alignof__(long double))));
} max_align_t;
typedef long long int int64_t;
typedef long long unsigned int uint64_t;
typedef int64_t int_least64_t;
typedef uint64_t uint_least64_t;
typedef int64_t int_fast64_t;
typedef uint64_t uint_fast64_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef int32_t int_least32_t;
typedef uint32_t uint_least32_t;
typedef int32_t int_fast32_t;
typedef uint32_t uint_fast32_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int16_t int_least16_t;
typedef uint16_t uint_least16_t;
typedef int16_t int_fast16_t;
typedef uint16_t uint_fast16_t;
typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef int8_t int_least8_t;
typedef uint8_t uint_least8_t;
typedef int8_t int_fast8_t;
typedef uint8_t uint_fast8_t;
typedef int intptr_t;
typedef unsigned int uintptr_t;
typedef long long int intmax_t;
typedef long long unsigned int uintmax_t;
extern unsigned char __test_stack_bottom[], __test_stack_top[];
extern unsigned char __code_start[], __code_end[], __data_start[], __data_end[];
extern unsigned char __bss_start[], __bss_end[], __arena_start[], __arena_end[];
extern unsigned char __io_start[], __io_end[], __control_stack_bottom[], __control_stack_top[];
extern unsigned char __ram_start[], __ram_end[];
int target_call(int (*fn)(void *), void *argument);
void target_putc(char c);
void target_exit(int status) __attribute__((noreturn));
void target_fault(void) __attribute__((noreturn));
void target_text(const char *text);
void target_uint(uint32_t value);
void target_int(int value);
int target_main(void);
int lc_system_random(uint8_t *out, size_t bytes);
void *memcpy(void *restrict dst, const void *restrict src, size_t n);
void *memmove(void *dst, const void *src, size_t n);
void *memset(void *dst, int value, size_t n);
int memcmp(const void *a, const void *b, size_t n);
size_t strlen(const char *s);
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
void __aeabi_memcpy(void *d,const void *s,size_t n){memcpy(d,s,n);}
void __aeabi_memcpy4(void *d,const void *s,size_t n){memcpy(d,s,n);}
void __aeabi_memcpy8(void *d,const void *s,size_t n){memcpy(d,s,n);}
void __aeabi_memmove(void *d,const void *s,size_t n){memmove(d,s,n);}
void __aeabi_memset(void *d,size_t n,int c){memset(d,c,n);}
void __aeabi_memset4(void *d,size_t n,int c){memset(d,c,n);}
void __aeabi_memclr(void *d,size_t n){memset(d,0,n);}
void __aeabi_memclr4(void *d,size_t n){memset(d,0,n);}
