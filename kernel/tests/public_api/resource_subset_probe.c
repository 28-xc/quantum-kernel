#include "lattice_resources.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#ifndef LC_RESOURCE_OPERATION_MASK
#error Explicit selected operation mask required
#endif
#define CHECK(x) do {if(!(x)){fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);return 1;}}while(0)
int main(void) {
  const int params[]={512,768,1024,44,65,87};
  uint8_t raw[64];
  lc_resource_requirements r;lc_resource_plan plan;
  unsigned retained=0,removed=0;
  for(unsigned i=0;i<6;i++)for(unsigned op=0;op<3;op++) {
    int expected=(LC_RESOURCE_OPERATION_MASK&(1u<<(i*3+op)))?0:LC_RESOURCE_E_UNSUPPORTED;
    memset(&r,0xa5,sizeof(r));
    CHECK(lc_resource_query(params[i],(int)op,&r)==expected);
    if(expected) {
      const uint8_t *bytes=(const uint8_t *)&r;
      for(size_t n=0;n<sizeof(r);n++)CHECK(bytes[n]==0);
      CHECK(lc_resource_make_plan(params[i],(int)op,raw,sizeof(raw),&plan)==expected);
      removed++;
    } else {
      CHECK(r.minimum_workspace_bytes>0&&r.preferred_workspace_bytes>=r.minimum_workspace_bytes);
      CHECK(lc_resource_make_plan(params[i],(int)op,raw,sizeof(raw),&plan)==LC_E_WORKSPACE);
      retained++;
    }
  }
  CHECK(lc_resource_query(42,0,&r)==LC_E_ARGUMENT);
  CHECK(lc_resource_query(87,3,&r)==LC_E_ARGUMENT);
  printf("{\"status\":\"PASS\",\"retained_operations\":%u,\"removed_operations\":%u}\n",retained,removed);
  return 0;
}
