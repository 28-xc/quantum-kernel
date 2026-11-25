/* The inherited functional probe is compiled into this translation unit.
 * Its valid calls, modified-input, length, alias, RNG, OOM and guard checks
 * are reused unchanged; only the parameter loop is selected here. */
#include "latticecore_pruned.h"
#define main lc_unrestricted_probe_main
#include "../public_api/probe.c"
#undef main
#ifndef LC_SELECTED_PARAMETERS
#define LC_SELECTED_PARAMETERS 512,768,1024,44,65,87
#endif
static int selected(int p) {
  const int levels[]={LC_SELECTED_PARAMETERS};
  size_t i;
  for(i=0;i<sizeof(levels)/sizeof(levels[0]);i++)if(levels[i]==p)return 1;
  return 0;
}
int main(int argc,char **argv) {
  const int all[]={512,768,1024,44,65,87};
  unsigned n=argc>1?(unsigned)strtoul(argv[1],NULL,10):100;
  size_t i;int level=0;
  for(i=0;i<6;i++) {
    int p=all[i];level=p;
    if(selected(p)) {if(run(p,n))return 1;}
    else {
      lc_sizes z;memset(&z,0xa5,sizeof z);
      CHECK(lc_get_sizes(p,&z)==LC_E_UNSUPPORTED);CHECK(zeros((const uint8_t*)&z,sizeof z));
      CHECK(lc_keypair(NULL,p,NULL,0,NULL,0)==LC_E_UNSUPPORTED);
      CHECK(lc_encaps(NULL,p,NULL,0,NULL,0,NULL,0)==LC_E_UNSUPPORTED);
      CHECK(lc_decaps(NULL,p,NULL,0,NULL,0,NULL,0)==LC_E_UNSUPPORTED);
      CHECK(lc_sign(NULL,p,NULL,0,NULL,0,NULL,0,NULL,0)==LC_E_UNSUPPORTED);
      CHECK(lc_verify(NULL,p,NULL,0,NULL,0,NULL,0,NULL,0)==LC_E_UNSUPPORTED);
      printf("{\"parameter\":%d,\"status\":\"UNSUPPORTED_AS_CONFIGURED\",\"all_operation_entry_checks\":true}\n",p);
    }
  }
  { lc_sizes z; memset(&z,0xa5,sizeof z);
    CHECK(lc_get_sizes(999,&z)==LC_E_ARGUMENT);CHECK(zeros((const uint8_t*)&z,sizeof z));
    CHECK(lc_keypair(NULL,999,NULL,0,NULL,0)==LC_E_ARGUMENT);
    CHECK(lc_encaps(NULL,999,NULL,0,NULL,0,NULL,0)==LC_E_ARGUMENT);
    CHECK(lc_decaps(NULL,999,NULL,0,NULL,0,NULL,0)==LC_E_ARGUMENT);
    CHECK(lc_sign(NULL,999,NULL,0,NULL,0,NULL,0,NULL,0)==LC_E_ARGUMENT);
    CHECK(lc_verify(NULL,999,NULL,0,NULL,0,NULL,0,NULL,0)==LC_E_ARGUMENT);
  }
  CHECK(!strcmp(lc_error_string(LC_E_UNSUPPORTED),"unsupported parameter or operation in this build"));
  return 0;
}
