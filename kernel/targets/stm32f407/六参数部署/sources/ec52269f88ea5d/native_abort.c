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
typedef int ptrdiff_t;
typedef unsigned int size_t;
typedef unsigned int wchar_t;
typedef struct {
  long long __clang_max_align_nonce1
      __attribute__((__aligned__(__alignof__(long long))));
  long double __clang_max_align_nonce2
      __attribute__((__aligned__(__alignof__(long double))));
} max_align_t;
enum { M4_HELLO=1,M4_RUN=2,M4_KAT=3,M4_BOUNDARY=4,M4_CLOCK=5,M4_RETURN_DFU=6,M4_TIMING=7,M4_POLY=8 };
typedef struct {uint32_t w[16];} m4_request;
typedef struct {uint32_t w[64];} m4_response;
void experiment(const m4_request*,m4_response*);
void hardware_info(m4_response*);
void clear_bytes(void*,size_t);
uint32_t m4_checksum(const void*,size_t);
void reset_to_dfu(void) __attribute__((noreturn));
uint32_t stack_used(void);
uint32_t cycle_stamp(void);
void board_start(void) __attribute__((noreturn));
extern uint32_t __stack_bottom[],__stack_top[];
void *malloc(size_t);
void free(void *);
void abort(void) __attribute__((noreturn));
void exit(int) __attribute__((noreturn));
void abort(void){reset_to_dfu();}
void exit(int n){(void)n;reset_to_dfu();}
