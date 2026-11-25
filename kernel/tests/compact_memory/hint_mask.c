/* SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT */
#include <assert.h>
#include <stdio.h>
#include "rounding.h"
#include "lc_hint_mask.h"
#if defined(__GNUC__)
__attribute__((noinline))
#endif
unsigned lc_hint_probe(int32_t low,uint32_t nonzero) {return lc_make_hint_secret(low,nonzero);}
int main(void) {
  unsigned count=0;
  for(int32_t low=-2*MLDSA_GAMMA2;low<=2*MLDSA_GAMMA2;low++)for(unsigned h=0;h<2;h++) {
    assert(lc_hint_probe(low,h)==mld_make_hint(low,(int32_t)h));count++;
  }
  printf("PASS parameter=%d exhaustive_hint_cases=%u\n",MLD_CONFIG_PARAMETER_SET,count);
  return 0;
}
