/* Execute the production Linux RNG branch with a scripted syscall boundary.
 * On Windows this is a branch simulation, not native Linux execution. */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#ifdef _WIN32
#undef _WIN32
#endif
#ifndef __linux__
#define __linux__ 1
#endif
#include "../../src/platform/random.c"
static int mode, calls, invalid_request;
ssize_t getrandom(void *out, size_t n, unsigned int flags) {
  calls++;
  if (!n || n > 256 || flags) invalid_request = 1;
  if (mode == 1 && calls == 1) { errno = EINTR; return -1; }
  if (mode == 2) n = 1;
  if (mode == 3 && calls == 1) n = 31;
  else if (mode == 3) { errno = EIO; return -1; }
  if (mode == 4) return 0;
  if (mode == 5) { errno = ENOSYS; return -1; }
  if (mode == 6) return (ssize_t)n + 1;
  memset(out, 0x3c, n);
  return (ssize_t)n;
}
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL %d\n",__LINE__); return 1; } } while (0)
int main(void) {
  uint8_t b[602]; int m; size_t i;
  CHECK(lc_system_random(NULL,0) == 0);
  CHECK(lc_system_random(NULL,1) == -1);
  CHECK(calls == 0);
  for (m = 0; m < 7; m++) {
    mode = m; calls = 0; invalid_request = 0; memset(b,0xa5,sizeof b);
    CHECK(lc_system_random(b+1,600) == (m < 3 ? 0 : -1));
    CHECK(b[0] == 0xa5 && b[601] == 0xa5 && !invalid_request);
    for (i = 1; i <= 600; i++) CHECK(b[i] == (m < 3 ? 0x3c : 0));
    CHECK(calls == (m == 0 ? 3 : m == 1 ? 4 : m == 2 ? 600 : m == 3 ? 2 : 1));
  }
  puts("PASS: full, EINTR, short, partial+EIO, zero, ENOSYS, oversized, null, canaries");
  return 0;
}
