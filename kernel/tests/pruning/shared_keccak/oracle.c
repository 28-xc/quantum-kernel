/* Test-only original mldsa-native permutation oracle; upstream implementation
 * is included unchanged with its Apache-2.0 OR ISC OR MIT attribution. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "shared.h"
#include "../../../third_party/mldsa-native/mldsa/src/fips202/keccakf1600.c"

static uint64_t rng=UINT64_C(0xa127202609240901);
static uint64_t next(void){rng^=rng<<13;rng^=rng>>7;rng^=rng<<17;return rng;}
/* Independent compact byte-oriented SHAKE test composition. This is only an
 * oracle driver, not a replacement of either production SHAKE front end. */
static void shake(uint8_t *out,size_t n,const uint8_t *in,size_t bytes,unsigned rate){
  uint64_t state[25]={0};size_t pos=0;unsigned i;
  for(i=0;i<bytes;i++){state[pos/8]^=(uint64_t)in[i]<<(8*(pos%8));if(++pos==rate){lc_shared_keccakf1600(state);pos=0;}}
  state[pos/8]^=UINT64_C(0x1f)<<(8*(pos%8));state[(rate-1)/8]^=UINT64_C(0x80)<<(8*((rate-1)%8));lc_shared_keccakf1600(state);pos=0;
  while(n--){*out++=(uint8_t)(state[pos/8]>>(8*(pos%8)));if(++pos==rate&&n){lc_shared_keccakf1600(state);pos=0;}}
}
int main(void){
  unsigned i,j;uint64_t reference[25],guarded[27];uint8_t input[1024],output[400];
  for(i=0;i<10000;i++){
    guarded[0]=UINT64_C(0xdeadbeefdeadbeef);guarded[26]=UINT64_C(0xa5a5a5a5a5a5a5a5);
    for(j=0;j<25;j++)reference[j]=guarded[j+1]=(i==0?0:next());
    mld_keccakf1600_permute_c(reference);lc_shared_keccakf1600(guarded+1);
    if(memcmp(reference,guarded+1,sizeof reference)||guarded[0]!=UINT64_C(0xdeadbeefdeadbeef)||guarded[26]!=UINT64_C(0xa5a5a5a5a5a5a5a5))return 1;
  }
  puts("{\"random_state_pairs\":10000,\"guarded_25_lane_layout\":true,\"original_mldsa_C_oracle_equal\":true}");
  for(i=0;i<sizeof input;i++)input[i]=(uint8_t)(i*17+11);
  { const unsigned lengths[]={0,1,3,135,136,137,167,168,169,1024};unsigned k;
    for(k=0;k<2;k++)for(i=0;i<sizeof lengths/sizeof lengths[0];i++){
      shake(output,sizeof output,input,lengths[i],k?136:168);
      printf("{\"shake_bits\":%u,\"input_bytes\":%u,\"output_hex\":\"",k?256:128,lengths[i]);
      for(j=0;j<sizeof output;j++)printf("%02x",output[j]);puts("\"}");
    }
  }
  return 0;
}
