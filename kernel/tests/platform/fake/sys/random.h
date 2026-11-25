#ifndef LC_TEST_SYS_RANDOM_H
#define LC_TEST_SYS_RANDOM_H
#include <stddef.h>
#include <sys/types.h>
ssize_t getrandom(void *out, size_t n, unsigned int flags);
#endif
