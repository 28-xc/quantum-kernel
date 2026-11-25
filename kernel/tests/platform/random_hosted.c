#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "lc_platform.h"
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL %d\n",__LINE__); return 1; } } while (0)
int main(void) {
  const size_t lengths[] = {0,1,32,64,257,600};
  uint8_t b[602]; size_t i,j;
  CHECK(lc_system_random(NULL,0) == 0);
  CHECK(lc_system_random(NULL,1) == -1);
  for (i=0; i<sizeof lengths/sizeof lengths[0]; i++) {
    size_t n=lengths[i]; memset(b,0xa5,sizeof b);
#ifdef LC_RNG_CALLBACK_ONLY
    CHECK(lc_system_random(b+1,n) == (n ? -1 : 0));
    for(j=1;j<=n;j++) CHECK(b[j]==0);
#else
    CHECK(lc_system_random(b+1,n) == 0);
#endif
    CHECK(b[0]==0xa5);
    for(j=n+1;j<sizeof b;j++) CHECK(b[j]==0xa5);
  }
  puts("PASS: hosted/callback-only lengths, null, output bounds");
  return 0;
}
