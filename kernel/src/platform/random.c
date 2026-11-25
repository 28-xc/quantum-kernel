#include "lc_platform.h"

#if !defined(LC_RNG_CALLBACK_ONLY) && defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#elif !defined(LC_RNG_CALLBACK_ONLY) && defined(__linux__)
#include <sys/random.h>
#include <errno.h>
#endif

/* Do not require libc, a heap or an OS service on the callback-only path. */
static void erase_random_output(uint8_t *out, size_t bytes) {
  volatile uint8_t *p = out;
  while (bytes--) *p++ = 0;
}

int lc_system_random(uint8_t *out, size_t bytes) {
  uint8_t *start = out;
  size_t total = bytes;
  if (bytes == 0) return 0;
  if (out == NULL) return -1;
#if !defined(LC_RNG_CALLBACK_ONLY) && defined(_WIN32)
  while (bytes) {
    ULONG chunk = bytes > 0xffffffffu ? 0xffffffffu : (ULONG)bytes;
    if (BCryptGenRandom(NULL, out, chunk, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
      goto failed;
    out += chunk;
    bytes -= chunk;
  }
  return 0;
#elif !defined(LC_RNG_CALLBACK_ONLY) && defined(__linux__)
  while (bytes) {
    size_t chunk = bytes > 256 ? 256 : bytes;
    ssize_t got = getrandom(out, chunk, 0);
    if (got < 0) {
      if (errno == EINTR) continue;
      goto failed;
    }
    if (got == 0 || (size_t)got > chunk) goto failed;
    out += (size_t)got;
    bytes -= (size_t)got;
  }
  return 0;
#endif
#if !defined(LC_RNG_CALLBACK_ONLY) && (defined(_WIN32) || defined(__linux__))
failed:
#endif
  erase_random_output(start, total);
  return -1;
}
