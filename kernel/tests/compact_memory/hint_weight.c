/* SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "lc_hint_weight.h"

/* Keep the real production helper visible for machine-code inspection. */
#if defined(__GNUC__)
__attribute__((noinline))
#endif
unsigned lc_hint_weight_probe(const uint8_t *p, size_t rows, size_t stride,
                              unsigned omega) {
  return lc_hint_weight_exceeds(p, rows, stride, omega);
}

int main(void) {
  static const size_t strides[] = {32,608,640,672,1056};
  static const unsigned ks[] = {4,6,8}, limits[] = {80,55,75};
  uint8_t storage[8*1056+8];
  unsigned long checks=0;
  for(unsigned variant=0;variant<3;variant++) {
    const unsigned n=ks[variant]*256;
    for(unsigned s=0;s<sizeof(strides)/sizeof(strides[0]);s++) {
      for(unsigned offset=0;offset<4;offset++) {
        const size_t stride=strides[s];
        uint8_t *p=storage+offset;
        memset(storage,0xa5,sizeof(storage));
        for(unsigned k=0;k<ks[variant];k++) memset(p+k*stride,0,32);
        /* 37 is coprime to all three vector lengths. This traverses every
         * possible total weight with distributed, non-monotone positions. */
        for(unsigned weight=0;weight<=n;weight++) {
          assert(lc_hint_weight_probe(p,ks[variant],stride,limits[variant])==
                 (unsigned)(weight>limits[variant]));
          assert(lc_hint_weight_probe(p,ks[variant],stride,weight)==0);
          if(weight)assert(lc_hint_weight_probe(p,ks[variant],stride,weight-1)==1);
          checks+=2+(weight!=0);
          if(weight<n) {
            unsigned bit=(weight*37+17)%n;
            p[(bit/256)*stride+(bit%256)/8]|=(uint8_t)(1u<<(bit%8));
          }
        }
      }
    }
  }
  printf("PASS hint_weight_checks=%lu parameter_sets=3 layouts=5 alignments=4\n",checks);
  return 0;
}
