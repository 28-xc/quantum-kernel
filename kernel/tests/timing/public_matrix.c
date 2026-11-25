/* Follow-up attribution only: every timed input is PUBLIC rho || i || j.
 * Reuse the exact archived PRNG and key/encapsulation pool construction.
 * This does not replace any original timing record or claim CT certification.
 */
#define main archived_screen_main
#include "archived_screen.c"
#undef main
#ifdef _WIN32
#define attr_alloc _aligned_malloc
#define attr_free _aligned_free
#define attr_wipe SecureZeroMemory
#define attr_symbol GetProcAddress
#define attr_close FreeLibrary
#define ATTR_UNIT "tsc_ticks"
#else
#define attr_alloc aligned_alloc_local
#define attr_free free
#define attr_wipe wipe
#define attr_symbol dlsym
#define attr_close dlclose
#define ATTR_UNIT "elapsed_ns"
#endif
#ifndef LC_ATTRIBUTION_BATCH
#define LC_ATTRIBUTION_BATCH 1
#endif
#ifndef LC_ATTRIBUTION_ROWS
#define LC_ATTRIBUTION_ROWS 0
#endif
#if LC_ATTRIBUTION_BATCH == 4
typedef void(*samplerfn)(int16_t*,int16_t*,int16_t*,int16_t*,uint8_t (*)[64]);
#else
typedef void(*samplerfn)(int16_t*,uint8_t*);
#endif
static unsigned matrix_schedule(int k,uint8_t*row,uint8_t*col){
 unsigned total=0,step_rows=LC_ATTRIBUTION_ROWS?LC_ATTRIBUTION_ROWS:(unsigned)k;
 for(unsigned first=0;first<(unsigned)k;first+=step_rows){
  unsigned rows=(unsigned)k-first;if(rows>step_rows)rows=step_rows;
  unsigned count=rows*(unsigned)k;
  for(unsigned i=0;i<count;i+=LC_ATTRIBUTION_BATCH)for(unsigned j=0;j<LC_ATTRIBUTION_BATCH;j++){
   unsigned idx=i+j;if(idx>=count)idx=count-1;
   row[total]=(uint8_t)(first+idx/(unsigned)k);col[total]=(uint8_t)(idx%(unsigned)k);total++;
  }
 }
 return total;
}
static void output_file(const char*prefix,const char*suffix,const void*p,size_t n){char path[4096];snprintf(path,sizeof path,"%s%s",prefix,suffix);FILE*f=fopen(path,"wb");if(!f||fwrite(p,1,n,f)!=n){fprintf(stderr,"output failure\n");exit(40);}fclose(f);}
int main(int argc,char**argv){
 if(argc!=8)return 2;
#ifndef _WIN32
 desired_cpu=atoi(argv[7]);
#endif
 int parameter=atoi(argv[3]),n=atoi(argv[4]),kdim=parameter==512?2:parameter==768?3:4;
 if((parameter!=512&&parameter!=768&&parameter!=1024)||n<0||n>100000||n%BATCH)return 3;
 rng_input=strtoull(argv[5],0,0);rng_class=rng_input^0x9e3779b97f4a7c15ULL;
 int core=bindcore();if(core<0)return 4;
#ifdef _WIN32
 HMODULE dll=LoadLibraryA(argv[1]);if(!dll)return 4;
 char actual[MAX_PATH],requested[MAX_PATH];
 if(!GetModuleFileNameA(dll,actual,sizeof actual)||!_fullpath(requested,argv[1],sizeof requested)||_stricmp(actual,requested))return 4;
 uintptr_t image=(uintptr_t)dll;
#else
 void*dll=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);if(!dll)return 4;
 struct link_map*map=NULL;char requested[PATH_MAX];
 if(!realpath(argv[1],requested)||dlinfo(dll,RTLD_DI_LINKMAP,&map)||!map||!realpath(map->l_name,loaded_real)||strcmp(requested,loaded_real))return 4;
 loaded_bias=(uintptr_t)map->l_addr;uintptr_t image=loaded_bias;
#endif
 samplerfn sampler=(samplerfn)(image+(uintptr_t)strtoull(argv[2],0,0));
#ifndef _WIN32
 if(!actual_module((void*)sampler))return 4;
#endif
 initfn init=(initfn)attr_symbol(dll,"lc_context_init");sizefn sizes=(sizefn)attr_symbol(dll,"lc_get_sizes");
 keyfn key=(keyfn)attr_symbol(dll,"lc_keypair");encfn enc=(encfn)attr_symbol(dll,"lc_encaps");decfn dec=(decfn)attr_symbol(dll,"lc_decaps");
 uint8_t(*pool)[3168]=attr_alloc(257*3168,32);void*work=attr_alloc(WORK,32);lc_context ctx;lc_sizes z;
 ALIGN uint8_t pk[1568],ct[1568],ss[32],expectedss[32],rho[257][32],ext[4][64];
 uint8_t schedule_row[32],schedule_col[32];unsigned lanes=matrix_schedule(kdim,schedule_row,schedule_col);
 ALIGN struct {uint8_t before[32];int16_t value[256];uint8_t after[32];} out[LC_ATTRIBUTION_BATCH];
 memset(&out,0xa7,sizeof out);if(!pool||!work||!init||!sizes||!key||!enc||!dec||sizes(parameter,&z))return 5;
 for(int i=0;i<257;i++){
  if(init(&ctx,work,WORK,random_cb,0)||key(&ctx,parameter,pk,z.public_key,pool[i],z.secret_key)||enc(&ctx,parameter,ct,z.ciphertext,expectedss,32,pk,z.public_key)||dec(&ctx,parameter,ss,32,ct,z.ciphertext,pool[i],z.secret_key)||memcmp(ss,expectedss,32))return 6;
  memcpy(rho[i],pool[i]+z.secret_key-96,32);
 }
 random_cb(0,ct,z.ciphertext); /* same draw as original key-pool screen */
 output_file(argv[6],".rhos.bin",rho,sizeof rho);
 uint64_t checksum=0,inputhash=1469598103934665603ULL;
 if(!n){
  size_t words=(size_t)257*lanes*256;int16_t*polys=malloc(words*sizeof(int16_t));if(!polys)return 7;
  for(int index=0;index<257;index++)for(unsigned g=0;g<lanes;g+=LC_ATTRIBUTION_BATCH){
   for(unsigned lane=0;lane<LC_ATTRIBUTION_BATCH;lane++){
    memcpy(ext[lane],rho[index],32);ext[lane][32]=schedule_row[g+lane];ext[lane][33]=schedule_col[g+lane];
   }
#if LC_ATTRIBUTION_BATCH == 4
   sampler(out[0].value,out[1].value,out[2].value,out[3].value,ext);
#else
   sampler(out[0].value,ext[0]);
#endif
   for(unsigned lane=0;lane<LC_ATTRIBUTION_BATCH;lane++){
    for(int j=0;j<32;j++)if(out[lane].before[j]!=0xa7||out[lane].after[j]!=0xa7)return 8;
    memcpy(polys+((size_t)index*lanes+g+lane)*256,out[lane].value,512);
   }
  }
  output_file(argv[6],".polys.bin",polys,words*sizeof(int16_t));free(polys);
  printf("{\"mode\":\"public_matrix_oracle_only\",\"parameter\":%d,\"polynomials\":%d,\"timed_samples\":0,\"cpu_logical\":%d}\n",parameter,257*(int)lanes,core);
 }else{
  uint64_t*tsc=malloc((size_t)n*sizeof(uint64_t));uint8_t*classes=malloc(n);uint16_t*keyidx=malloc((size_t)n*sizeof(uint16_t));
  if(!tsc||!classes||!keyidx)return 9;
  uint8_t cls[BATCH];uint16_t indices[BATCH];
  char path[4096];snprintf(path,sizeof path,"%s.csv",argv[6]);FILE*f=fopen(path,"wb");if(!f)return 10;
  fputs("class," ATTR_UNIT ",norm_result\n",f);fflush(f);
  for(int block=-1;block<n/BATCH;block++){
   for(int j=0;j<BATCH;j++)cls[j]=(uint8_t)(j>=BATCH/2);
   for(int j=BATCH-1;j>0;j--){int k=(int)(step(&rng_class)%(j+1));uint8_t t=cls[j];cls[j]=cls[k];cls[k]=t;}
   for(int i=0;i<BATCH;i++){unsigned index=1+next()%256;indices[i]=(uint16_t)(cls[i]?index:0);inputhash=hashbytes(inputhash,pool[indices[i]],z.secret_key);}
   for(int i=0;i<BATCH;i++){
    for(unsigned lane=0;lane<LC_ATTRIBUTION_BATCH;lane++)memcpy(ext[lane],rho[indices[i]],32);
    uint64_t t0=stamp();
    for(unsigned g=0;g<lanes;g+=LC_ATTRIBUTION_BATCH){
     for(unsigned lane=0;lane<LC_ATTRIBUTION_BATCH;lane++){ext[lane][32]=schedule_row[g+lane];ext[lane][33]=schedule_col[g+lane];}
#if LC_ATTRIBUTION_BATCH == 4
     sampler(out[0].value,out[1].value,out[2].value,out[3].value,ext);
#else
     sampler(out[0].value,ext[0]);
#endif
    }
    uint64_t t1=stamp();if(block>=0){int j=block*BATCH+i;tsc[j]=t1-t0;classes[j]=cls[i];keyidx[j]=indices[i];}checksum+=(uint16_t)out[0].value[i%256];
    if(t1<t0)return 11;
   }
   if(block>=0){for(int j=block*BATCH;j<(block+1)*BATCH;j++)fprintf(f,"%u,%llu,0\n",classes[j],(unsigned long long)tsc[j]);if(fflush(f))return 12;}
  }
  if(fclose(f))return 12;
  output_file(argv[6],".keyidx.bin",keyidx,(size_t)n*sizeof(uint16_t));free(tsc);free(classes);free(keyidx);
  printf("{\"mode\":\"PUBLIC_matrix_only\",\"parameter\":%d,\"samples\":%d,\"cpu_logical\":%d,\"input_fnv64\":\"%016llx\",\"checksum\":%llu,\"secret_input_to_timed_region\":false,\"loaded_module_path_checked\":true}\n",parameter,n,core,(unsigned long long)inputhash,(unsigned long long)checksum);
 }
 attr_wipe(pool,257*3168);attr_wipe(work,WORK);attr_free(pool);attr_free(work);attr_close(dll);return 0;
}
