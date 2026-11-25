/* Exact production AVX2/NEON helpers, compared with integer specifications. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <inttypes.h>
#if defined(__aarch64__)
#include "lc_codec24_neon.h"
#define PACK lc_codec24_pack_neon
#define UNPACK lc_codec24_unpack_neon
#else
#define LC_DSA_MATRIX_STREAM_VECTOR 1
#include "lc_stream4_vector.h"
#define PACK lc_s4_pack_row
#define UNPACK lc_s4_unpack_row
#endif
#define CHECK(x) do{if(!(x)){fprintf(stderr,"line %u: %s\n",__LINE__,#x);return 1;}}while(0)
static int32_t reference_reduce(int32_t x){
  int64_t t=(int64_t)x+4194304;
  int64_t quotient=t>=0?t/8388608:-((-t+8388607)/8388608);
  return (int32_t)((int64_t)x-quotient*8380417);
}
static int row(const int32_t *p){
  int32_t decoded[256],alias[256];
  struct {uint8_t before[32],data[768],after[32];} guarded;
  uint8_t expected[768];
  for(unsigned i=0;i<256;i++){
    uint32_t v=(uint32_t)reference_reduce(p[i]);
    expected[3*i]=(uint8_t)v;expected[3*i+1]=(uint8_t)(v>>8);expected[3*i+2]=(uint8_t)(v>>16);
  }
  memset(&guarded,0xa5,sizeof guarded);PACK(guarded.data,p);
  CHECK(!memcmp(expected,guarded.data,768));
  for(unsigned i=0;i<32;i++)CHECK(guarded.before[i]==0xa5&&guarded.after[i]==0xa5);
  UNPACK(decoded,guarded.data);
  for(unsigned i=0;i<256;i++)CHECK(decoded[i]==reference_reduce(p[i]));
  memcpy(alias,p,sizeof alias);PACK((uint8_t*)alias,alias);CHECK(!memcmp(alias,expected,768));
#if defined(__aarch64__)
  UNPACK(alias,(uint8_t*)alias);
  for(unsigned i=0;i<256;i++)CHECK(alias[i]==reference_reduce(p[i]));
#endif
  return 0;
}
int main(void){
  int32_t p[256];uint64_t checked=0;
  for(int32_t base=-8388608;base<8388608;base+=256){
    for(unsigned i=0;i<256;i++)p[i]=base+(int32_t)i;
    CHECK(row(p)==0);checked+=256;
  }
  const int32_t ends[]={INT32_MIN,INT32_MIN+1,-8380417,-4194305,-4194304,-1,0,1,4194303,4194304,8380417,INT32_MAX-4194304};
  for(unsigned pos=0;pos<256;pos++)for(unsigned e=0;e<sizeof ends/sizeof ends[0];e++){
    memset(p,0,sizeof p);p[pos]=ends[e];CHECK(row(p)==0);
  }
  uint32_t random=0x20261004u;
  for(unsigned group=0;group<4096;group++){
    for(unsigned i=0;i<256;i++){
      random^=random<<13;random^=random>>17;random^=random<<5;
      int64_t value=(int64_t)INT32_MIN+(random%UINT64_C(4290772992));
      p[i]=(int32_t)value;
    }
    CHECK(row(p)==0);
  }
  printf("{\"status\":\"PASS\",\"signed24_domain_values\":%"PRIu64",\"endpoint_rows\":3072,\"fixed_seed_full_range_values\":1048576,\"alias_pack\":true,\"alias_unpack\":%s}\n",checked,
#if defined(__aarch64__)
    "true"
#else
    "false"
#endif
  );return 0;
}
