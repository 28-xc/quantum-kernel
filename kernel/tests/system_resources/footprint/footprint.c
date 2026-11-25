/* Observe the current executable's mm high water after complete operations.
 * Linux getrusage also includes the pre-exec address space in ru_maxrss; the
 * independent /proc/self/status fields below describe this executable's mm. */
#define main complete_operation_main
#include "workload.c"
#undef main
int main(int argc,char **argv){
 int rc=complete_operation_main(argc,argv);
 if(rc)return rc;
 FILE*f=fopen("/proc/self/status","r");if(!f)return 40;
 char line[256];unsigned long high=0,rss=0,vm=0;
 while(fgets(line,sizeof line,f)){
  if(sscanf(line,"VmHWM: %lu kB",&high)==1)continue;
  if(sscanf(line,"VmRSS: %lu kB",&rss)==1)continue;
  if(sscanf(line,"VmPeak: %lu kB",&vm)==1)continue;
 }
 fclose(f);if(!high||!rss||!vm)return 41;
 printf("{\"status\":\"MM_FOOTPRINT\",\"vmhwm_kib\":%lu,\"vmrss_after_cleanup_kib\":%lu,\"vmpeak_kib\":%lu}\n",high,rss,vm);
 return 0;
}
