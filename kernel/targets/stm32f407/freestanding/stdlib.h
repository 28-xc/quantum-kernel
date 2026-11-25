#ifndef A127_FREESTANDING_STDLIB_H
#define A127_FREESTANDING_STDLIB_H
#include <stddef.h>
void *malloc(size_t);
void free(void *);
void abort(void) __attribute__((noreturn));
void exit(int) __attribute__((noreturn));
#endif
