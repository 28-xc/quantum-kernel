#ifndef A127_PQC_SETJMP_H
#define A127_PQC_SETJMP_H
#include <stdint.h>
typedef uint32_t jmp_buf[10];
int setjmp(jmp_buf) __attribute__((returns_twice));
void longjmp(jmp_buf,int) __attribute__((noreturn));
#endif
