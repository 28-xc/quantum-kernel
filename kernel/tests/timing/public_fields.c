/* Follow-up isolation of public ek || H(ek) in the ACTUAL full lc_decaps.
 * Original generated pools/classes are replayed; dk_PKE and z stay pool[0].
 * Constructed keys are domain-valid diagnostics, not matching key pairs.
 * The original INVESTIGATE observation is never replaced by this experiment.
 */
#define main archived_screen_main
#include "archived_screen.c"
#undef main
#ifdef _WIN32
#define pf_alloc _aligned_malloc
#define pf_free _aligned_free
#define pf_wipe SecureZeroMemory
#define pf_symbol GetProcAddress
#define pf_close FreeLibrary
#define PF_UNIT "tsc_ticks"
#else
#define pf_alloc aligned_alloc_local
#define pf_free free
#define pf_wipe wipe
#define pf_symbol dlsym
#define pf_close dlclose
#define PF_UNIT "elapsed_ns"
#endif
/* Independent scalar sponge; the loaded library is not used for H or J. */
static void pf_sponge32(uint8_t out[32],const uint8_t *a,size_t an,
                        const uint8_t *b,size_t bn,unsigned suffix){
 uint64_t s[25]={0};size_t pos=0;
 for(unsigned part=0;part<2;part++){
  const uint8_t *p=part?b:a;size_t n=part?bn:an;
  for(size_t i=0;i<n;i++){
   s[pos/8]^=(uint64_t)p[i]<<(8*(pos%8));
   if(++pos==136){keccak_ref(s);pos=0;}
  }
 }
 s[pos/8]^=(uint64_t)suffix<<(8*(pos%8));s[16]^=UINT64_C(0x8000000000000000);
 keccak_ref(s);for(unsigned i=0;i<32;i++)out[i]=(uint8_t)(s[i/8]>>(8*(i%8)));
 pf_wipe(s,sizeof s);
}
static void pf_output(const char *prefix,const char *suffix,const void *p,size_t n){
 char path[4096];if(snprintf(path,sizeof path,"%s%s",prefix,suffix)>=(int)sizeof path)exit(40);
 FILE *f=fopen(path,"wb");if(!f||fwrite(p,1,n,f)!=n||fclose(f)){fprintf(stderr,"output failure\n");exit(40);}
}
static void pf_construct(uint8_t *out,const uint8_t *fixed,const uint8_t *selected,
                         size_t skbytes,size_t prefix,size_t publicbytes){
 memcpy(out,fixed,skbytes);memcpy(out+prefix,selected+prefix,publicbytes);
}
int main(int argc,char **argv){
 /* library parameter samples seed output-prefix cpu; samples=0: oracle only */
 if(argc!=7)return 2;
 int parameter=atoi(argv[2]),n=atoi(argv[3]);
 if((parameter!=512&&parameter!=768&&parameter!=1024)||n<0||n>100000||n%BATCH)return 3;
 rng_input=strtoull(argv[4],0,0);if(!rng_input)return 3;
 rng_class=rng_input^UINT64_C(0x9e3779b97f4a7c15);
#ifndef _WIN32
 desired_cpu=atoi(argv[6]);
#endif
 int core=bindcore();if(core<0)return 4;
#ifdef _WIN32
 HMODULE dll=LoadLibraryA(argv[1]);if(!dll)return 4;
 char actual[MAX_PATH],requested[MAX_PATH];
 DWORD al=GetModuleFileNameA(dll,actual,sizeof actual);
 if(!al||al>=sizeof actual||!_fullpath(requested,argv[1],sizeof requested)||_stricmp(actual,requested))return 4;
#else
 void *dll=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);if(!dll)return 4;
 struct link_map *map=NULL;char requested[PATH_MAX];
 if(!realpath(argv[1],requested)||dlinfo(dll,RTLD_DI_LINKMAP,&map)||!map||!realpath(map->l_name,loaded_real)||strcmp(requested,loaded_real))return 4;
 loaded_bias=(uintptr_t)map->l_addr;
#endif
 initfn init=(initfn)pf_symbol(dll,"lc_context_init");sizefn sizes=(sizefn)pf_symbol(dll,"lc_get_sizes");
 keyfn key=(keyfn)pf_symbol(dll,"lc_keypair");encfn enc=(encfn)pf_symbol(dll,"lc_encaps");decfn dec=(decfn)pf_symbol(dll,"lc_decaps");
 if(!init||!sizes||!key||!enc||!dec)return 5;
#ifndef _WIN32
 if(!actual_module((void*)init)||!actual_module((void*)key)||!actual_module((void*)enc)||!actual_module((void*)dec))return 5;
#endif
 uint8_t (*pool)[3168]=pf_alloc(257*3168,32);void *work=pf_alloc(WORK,32);
 uint8_t *batch=pf_alloc(BATCH*STRIDE,32);lc_context ctx;lc_sizes sz;
 ALIGN uint8_t in[STRIDE],pk[1568],ct[1568],validct[1568],ss[32],expectedss[32],expectedj[32],digest[32];
 if(!pool||!work||!batch||sizes(parameter,&sz)||sz.secret_key>3168||sz.secret_key>STRIDE||sz.public_key>sizeof pk||sz.ciphertext>sizeof ct)return 5;
 size_t prefix=sz.secret_key-sz.public_key-64,publicbytes=sz.public_key+32;
 if(prefix!=(size_t)(parameter==512?2:parameter==768?3:4)*384)return 5;
 for(unsigned k=0;k<257;k++){
  if(init(&ctx,work,WORK,random_cb,0)||key(&ctx,parameter,pk,sz.public_key,pool[k],sz.secret_key)||
     enc(&ctx,parameter,validct,sz.ciphertext,expectedss,32,pk,sz.public_key)||
     dec(&ctx,parameter,ss,32,validct,sz.ciphertext,pool[k],sz.secret_key)||memcmp(ss,expectedss,32))return 6;
 }
 /* Same draw and position as the original DECAP_KEY screen. Do not change z. */
 random_cb(0,ct,sz.ciphertext);uint64_t state_after_pool=rng_input;
 pf_sponge32(expectedj,pool[0]+sz.secret_key-32,32,ct,sz.ciphertext,31);
 uint8_t *publicpool=malloc(257*publicbytes);if(!publicpool)return 7;
 for(unsigned k=0;k<257;k++){
  pf_construct(in,pool[0],pool[k],sz.secret_key,prefix,publicbytes);
  if(memcmp(in,pool[0],prefix)||memcmp(in+sz.secret_key-32,pool[0]+sz.secret_key-32,32))return 8;
  pf_sponge32(digest,in+prefix,sz.public_key,NULL,0,6);
  if(memcmp(digest,in+prefix+sz.public_key,32))return 9;
  if(init(&ctx,work,WORK,random_cb,0)||dec(&ctx,parameter,ss,32,ct,sz.ciphertext,in,sz.secret_key)||memcmp(ss,expectedj,32))return 10;
  if(memcmp(in,pool[0],prefix)||memcmp(in+prefix,pool[k]+prefix,publicbytes)||
     memcmp(in+sz.secret_key-32,pool[0]+sz.secret_key-32,32)||rng_input!=state_after_pool)return 11;
  memcpy(publicpool+k*publicbytes,in+prefix,publicbytes);
 }
 pf_output(argv[5],".public.bin",publicpool,257*publicbytes);pf_output(argv[5],".ct.bin",ct,sz.ciphertext);
 /* Python hashlib checks both sponge modes on PUBLIC inputs independently. */
 uint8_t spongecheck[64];pf_sponge32(spongecheck,publicpool,sz.public_key,NULL,0,6);
 pf_sponge32(spongecheck+32,ct,sz.ciphertext,NULL,0,31);pf_output(argv[5],".sponge.bin",spongecheck,sizeof spongecheck);
 uint64_t checksum=0,originalhash=UINT64_C(1469598103934665603),hybridhash=originalhash,publichash=originalhash;
 if(n){
  uint8_t cls[BATCH];uint16_t indices[BATCH];uint64_t elapsed[BATCH];
  uint16_t *allindices=malloc((size_t)n*sizeof(uint16_t));if(!allindices)return 12;
  char path[4096];if(snprintf(path,sizeof path,"%s.csv",argv[5])>=(int)sizeof path)return 12;
  FILE *f=fopen(path,"wb");if(!f)return 12;fputs("class," PF_UNIT ",norm_result\n",f);fflush(f);
  for(int block=-1;block<n/BATCH;block++){
   for(int i=0;i<BATCH;i++)cls[i]=(uint8_t)(i>=BATCH/2);
   for(int j=BATCH-1;j>0;j--){int k=(int)(step(&rng_class)%(j+1));uint8_t t=cls[j];cls[j]=cls[k];cls[k]=t;}
   for(int i=0;i<BATCH;i++){
    unsigned index=1+next()%256;indices[i]=(uint16_t)(cls[i]?index:0);uint8_t *p=batch+(size_t)i*STRIDE;
    pf_construct(p,pool[0],pool[indices[i]],sz.secret_key,prefix,publicbytes);
    originalhash=hashbytes(originalhash,pool[indices[i]],sz.secret_key);
    hybridhash=hashbytes(hybridhash,p,sz.secret_key);publichash=hashbytes(publichash,p+prefix,publicbytes);
   }
   uint64_t state_before_calls=rng_input;
   for(int i=0;i<BATCH;i++){
    memcpy(in,batch+(size_t)i*STRIDE,sz.secret_key);
    uint64_t t0=stamp();int rc=init(&ctx,work,WORK,random_cb,0);if(!rc)rc=dec(&ctx,parameter,ss,32,ct,sz.ciphertext,in,sz.secret_key);uint64_t t1=stamp();
    if(rc||t1<t0||memcmp(ss,expectedj,32)||memcmp(in,batch+(size_t)i*STRIDE,sz.secret_key)||rng_input!=state_before_calls)return 13;
    elapsed[i]=t1-t0;checksum+=ss[i%32];
   }
   if(block>=0){
    for(int i=0;i<BATCH;i++){fprintf(f,"%u,%llu,0\n",cls[i],(unsigned long long)elapsed[i]);allindices[block*BATCH+i]=indices[i];}
    if(fflush(f))return 14;
   }
  }
  if(fclose(f))return 14;pf_output(argv[5],".keyidx.bin",allindices,(size_t)n*sizeof(uint16_t));free(allindices);
 }
 printf("{\"mode\":\"decaps_public_fields_diagnostic\",\"oracle\":\"PASS\",\"parameter\":%d,\"samples\":%d,\"warmup\":%d,\"cpu_logical\":%d,\"loaded_module_path_checked\":true,\"key_pool_size\":257,\"constructed_keys_checked\":257,\"H_ek_valid\":true,\"fixed_dkPKE_and_z_checked\":true,\"independent_J_all_equal\":true,\"input_unchanged\":true,\"no_rng_during_decaps\":true,\"not_generated_matching_keypairs\":true,\"only_public_fields_vary\":true,\"secret_input_to_timed_region\":true,\"input_fnv64\":\"%016llx\",\"hybrid_input_fnv64\":\"%016llx\",\"public_segment_fnv64\":\"%016llx\",\"checksum\":%llu}\n",
 parameter,n,n?1000:0,core,(unsigned long long)originalhash,(unsigned long long)hybridhash,(unsigned long long)publichash,(unsigned long long)checksum);
 pf_wipe(in,sizeof in);pf_wipe(expectedj,sizeof expectedj);pf_wipe(ss,sizeof ss);pf_wipe(pool,257*3168);pf_wipe(batch,BATCH*STRIDE);pf_wipe(work,WORK);
 free(publicpool);pf_free(pool);pf_free(batch);pf_free(work);pf_close(dll);return 0;
}
