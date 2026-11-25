/* One input schedule and serialized operation boundary for both implementations.
 * Test entropy is NOT a production random generator. See method.md. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cpuid.h>
#else
#include <dlfcn.h>
#include <sched.h>
#include <time.h>
#include <unistd.h>
#endif
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "latticecore.h"

typedef struct {
 int (*init)(lc_context*,void*,size_t,lc_random_fn,void*);
 int (*sizes)(int,lc_sizes*);
 int (*key)(lc_context*,int,uint8_t*,size_t,uint8_t*,size_t);
 int (*enc)(lc_context*,int,uint8_t*,size_t,uint8_t*,size_t,const uint8_t*,size_t);
 int (*dec)(lc_context*,int,uint8_t*,size_t,const uint8_t*,size_t,const uint8_t*,size_t);
 int (*sign)(lc_context*,int,uint8_t*,size_t,const uint8_t*,size_t,const uint8_t*,size_t,const uint8_t*,size_t);
 int (*verify)(lc_context*,int,const uint8_t*,size_t,const uint8_t*,size_t,const uint8_t*,size_t,const uint8_t*,size_t);
 void *handle; void *raw; void *work; size_t capacity; lc_context context;
} LC;
typedef struct { OSSL_LIB_CTX *ctx; OSSL_PROVIDER *provider; EVP_SIGNATURE *signature; EVP_KEYMGMT *keymgmt; EVP_KEM *kem; const char *pct; const char *algorithm; } OS;
typedef struct { uint8_t pk[2592],sk[4896],ct[1568],sig[4627],ss[32]; } OUTPUT;
typedef struct { uint8_t pk[2592],sk[4896],ct[1568],sig[4627],ss[32],msg[16384],domain[255],coins[64]; size_t mn,dn; } TEST_INPUT;
static const char *algorithm(int p) { switch(p) {case 512:return "ML-KEM-512";case 768:return "ML-KEM-768";case 1024:return "ML-KEM-1024";case 44:return "ML-DSA-44";case 65:return "ML-DSA-65";case 87:return "ML-DSA-87";default:return NULL;} }
static uint64_t prng;
static uint8_t next_byte(void) { prng^=prng<<13;prng^=prng>>7;prng^=prng<<17;return (uint8_t)prng; }
static void fill(uint8_t *p,size_t n) { while(n--)*p++=next_byte(); }
static int supplied(void *u,uint8_t *out,size_t n) { if(n>64)return -1;memcpy(out,u,n);return 0; }
static void json_string(const char *s) { putchar('"');for(;*s;s++){unsigned c=(unsigned char)*s;if(c=='"'||c=='\\')printf("\\%c",c);else if(c<32)printf("\\u%04x",c);else putchar((int)c);}putchar('"'); }
static void hex(const uint8_t *p,size_t n,char *out) { static const char h[]="0123456789abcdef";size_t i;for(i=0;i<n;i++){out[2*i]=h[p[i]>>4];out[2*i+1]=h[p[i]&15];}out[2*n]=0; }
static int hash(OS *o,const void *p,size_t n,char out[65]) { uint8_t d[32];size_t dn=sizeof d;if(!EVP_Q_digest(o->ctx,"SHA256","provider=default",p,n,d,&dn)||dn!=32)return 0;hex(d,32,out);return 1; }

static int pin_cpu(int cpu) {
#ifdef _WIN32
 DWORD_PTR allowed,system;unsigned a,b,c,d;
 if(cpu<0||cpu>=(int)(8*sizeof(DWORD_PTR))||!GetProcessAffinityMask(GetCurrentProcess(),&allowed,&system)||!(allowed&((DWORD_PTR)1<<cpu)))return 0;
 if(!SetThreadAffinityMask(GetCurrentThread(),(DWORD_PTR)1<<cpu))return 0;
 __cpuid_count(0x1a,0,a,b,c,d);return (a>>24)==0x40;
#else
 cpu_set_t set;if(cpu<0||cpu>=CPU_SETSIZE)return 0;CPU_ZERO(&set);CPU_SET(cpu,&set);return sched_setaffinity(0,sizeof set,&set)==0;
#endif
}
static int current_cpu(void) {
#ifdef _WIN32
 return (int)GetCurrentProcessorNumber();
#else
 return sched_getcpu();
#endif
}
static uint64_t frequency(void) {
#ifdef _WIN32
 LARGE_INTEGER f;if(!QueryPerformanceFrequency(&f))return 0;return (uint64_t)f.QuadPart;
#else
 return UINT64_C(1000000000);
#endif
}
static uint64_t ticks(void) {
#ifdef _WIN32
 LARGE_INTEGER t;if(!QueryPerformanceCounter(&t))abort();return (uint64_t)t.QuadPart;
#else
 struct timespec t;if(clock_gettime(CLOCK_MONOTONIC_RAW,&t))abort();return (uint64_t)t.tv_sec*UINT64_C(1000000000)+(uint64_t)t.tv_nsec;
#endif
}
static int crypto_path(char *out,size_t n) {
#ifdef _WIN32
 /* The ordinary function address can point at the executable's import thunk.
  * Resolve the actual IAT function pointer instead of reporting our own EXE. */
 extern const char *(*__imp_OpenSSL_version)(int);
 HMODULE h;if(!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,(LPCSTR)(uintptr_t)__imp_OpenSSL_version,&h))return 0;
 return GetModuleFileNameA(h,out,(DWORD)n)>0;
#else
 Dl_info info;void *p=dlsym(RTLD_DEFAULT,"OpenSSL_version");if(!p||!dladdr(p,&info)||!info.dli_fname)return 0;
 if(strlen(info.dli_fname)>=n)return 0;
 strcpy(out,info.dli_fname);return 1;
#endif
}
static void *symbol(void *h,const char *s) {
#ifdef _WIN32
 return (void *)(uintptr_t)GetProcAddress((HMODULE)h,s);
#else
 return dlsym(h,s);
#endif
}
static int load_lc(LC *l,const char *path,size_t cap) {
#ifdef _WIN32
 l->handle=(void*)LoadLibraryA(path);
#else
 l->handle=dlopen(path,RTLD_NOW|RTLD_LOCAL);
#endif
 if(!l->handle)return 0;
#define BIND(member,name) do { void *f=symbol(l->handle,name);if(!f||sizeof(f)!=sizeof(l->member))return 0;memcpy(&l->member,&f,sizeof f); } while(0)
 BIND(init,"lc_context_init");BIND(sizes,"lc_get_sizes");BIND(key,"lc_keypair");BIND(enc,"lc_encaps");BIND(dec,"lc_decaps");BIND(sign,"lc_sign");BIND(verify,"lc_verify");
#undef BIND
 if(!symbol(l->handle,"lc_error_string"))return 0;
 l->raw=malloc(cap+128);if(!l->raw)return 0;l->work=(void*)(((uintptr_t)l->raw+63)&~(uintptr_t)31);l->capacity=cap;memset(l->raw,0xa5,cap+128);return 1;
}
static int arena_guards(const LC *l) { const uint8_t *p=l->work;for(int i=0;i<32;i++)if(p[i-32]!=0xa5||p[l->capacity+(size_t)i]!=0xa5)return 0;return 1; }
static int init_os(OS *o,int p,const char *pct) {
 const char *readback=NULL;OSSL_PARAM params[]={OSSL_PARAM_utf8_ptr(OSSL_PKEY_PARAM_ML_KEM_IMPORT_PCT_TYPE,(char**)&readback,0),OSSL_PARAM_END};
 o->algorithm=algorithm(p);o->pct=pct;o->ctx=OSSL_LIB_CTX_new();if(!o->ctx)return 0;o->provider=OSSL_PROVIDER_load(o->ctx,"default");
 if(!o->provider||!OSSL_PROVIDER_add_conf_parameter(o->provider,OSSL_PKEY_PARAM_ML_KEM_IMPORT_PCT_TYPE,pct)||!OSSL_PROVIDER_get_conf_parameters(o->provider,params)||!readback||strcmp(readback,pct))return 0;
 o->keymgmt=EVP_KEYMGMT_fetch(o->ctx,o->algorithm,"provider=default");if(!o->keymgmt||strcmp(OSSL_PROVIDER_get0_name(EVP_KEYMGMT_get0_provider(o->keymgmt)),"default"))return 0;
 if(p>100){o->kem=EVP_KEM_fetch(o->ctx,o->algorithm,"provider=default");if(!o->kem||strcmp(OSSL_PROVIDER_get0_name(EVP_KEM_get0_provider(o->kem)),"default"))return 0;}
 else {o->signature=EVP_SIGNATURE_fetch(o->ctx,o->algorithm,"provider=default");if(!o->signature||strcmp(OSSL_PROVIDER_get0_name(EVP_SIGNATURE_get0_provider(o->signature)),"default"))return 0;}
 return 1;
}
static void free_os(OS *o) { EVP_SIGNATURE_free(o->signature);EVP_KEM_free(o->kem);EVP_KEYMGMT_free(o->keymgmt);if(o->provider)OSSL_PROVIDER_unload(o->provider);OSSL_LIB_CTX_free(o->ctx);memset(o,0,sizeof *o); }
static EVP_PKEY *import_key(OS *o,int secret,const uint8_t *data,size_t n) {
 EVP_PKEY_CTX *c=EVP_PKEY_CTX_new_from_name(o->ctx,o->algorithm,"provider=default");EVP_PKEY *k=NULL;
 OSSL_PARAM params[]={OSSL_PARAM_octet_string(secret?OSSL_PKEY_PARAM_PRIV_KEY:OSSL_PKEY_PARAM_PUB_KEY,(void*)data,n),OSSL_PARAM_END};
 if(!c||EVP_PKEY_fromdata_init(c)<=0||EVP_PKEY_fromdata(c,&k,secret?EVP_PKEY_KEYPAIR:EVP_PKEY_PUBLIC_KEY,params)<=0){EVP_PKEY_free(k);k=NULL;}
 EVP_PKEY_CTX_free(c);return k;
}
/* Fresh serialized import, provider operation, serialization and destruction
 * all execute inside this function and therefore inside the sample boundary. */
static int openssl_call(OS *o,int p,int op,const lc_sizes *z,const TEST_INPUT *in,OUTPUT *out) {
 EVP_PKEY *k=NULL;EVP_PKEY_CTX *c=NULL;int ok=0,encoding=1,mu=0;size_t n=0,n2=0;
 if(op==0){
  OSSL_PARAM params[]={OSSL_PARAM_octet_string("seed",(void*)in->coins,p>100?64:32),OSSL_PARAM_END};
  c=EVP_PKEY_CTX_new_from_name(o->ctx,o->algorithm,"provider=default");
  if(c&&EVP_PKEY_keygen_init(c)>0&&EVP_PKEY_CTX_set_params(c,params)>0&&EVP_PKEY_generate(c,&k)>0&&EVP_PKEY_get_octet_string_param(k,"pub",out->pk,z->public_key,&n)>0&&n==z->public_key&&EVP_PKEY_get_octet_string_param(k,"priv",out->sk,z->secret_key,&n)>0&&n==z->secret_key)ok=1;
 }else{
  int secret=p>100?op==2:op==1;k=import_key(o,secret,secret?in->sk:in->pk,secret?z->secret_key:z->public_key);
  c=k?EVP_PKEY_CTX_new_from_pkey(o->ctx,k,"provider=default"):NULL;
  if(p>100&&op==1){
   OSSL_PARAM params[]={OSSL_PARAM_octet_string("ikme",(void*)in->coins,32),OSSL_PARAM_END};n=z->ciphertext;n2=32;
   if(c&&EVP_PKEY_encapsulate_init(c,params)>0&&EVP_PKEY_encapsulate(c,out->ct,&n,out->ss,&n2)>0&&n==z->ciphertext&&n2==32)ok=1;
  }else if(p>100){n=32;if(c&&EVP_PKEY_decapsulate_init(c,NULL)>0&&EVP_PKEY_decapsulate(c,out->ss,&n,in->ct,z->ciphertext)>0&&n==32)ok=1;
  }else{
   OSSL_PARAM params[5];params[0]=OSSL_PARAM_construct_octet_string("context-string",(void*)in->domain,in->dn);params[1]=OSSL_PARAM_construct_int("message-encoding",&encoding);params[2]=OSSL_PARAM_construct_int("mu",&mu);
   if(op==1){params[3]=OSSL_PARAM_construct_octet_string("test-entropy",(void*)in->coins,32);params[4]=OSSL_PARAM_construct_end();n=z->signature;
    if(c&&EVP_PKEY_sign_message_init(c,o->signature,params)>0&&EVP_PKEY_sign(c,out->sig,&n,in->msg,in->mn)>0&&n==z->signature)ok=1;
   }else{params[3]=OSSL_PARAM_construct_end();if(c&&EVP_PKEY_verify_message_init(c,o->signature,params)>0&&EVP_PKEY_verify(c,in->sig,z->signature,in->msg,in->mn)>0)ok=1;}
  }
 }
 EVP_PKEY_CTX_free(c);EVP_PKEY_free(k);return ok?0:LC_E_REJECT;
}
static int lattice_call(LC *l,int p,int op,const lc_sizes *z,const TEST_INPUT *in,OUTPUT *out) {
 int r=l->init(&l->context,l->work,l->capacity,supplied,(void*)in->coins);if(r)return r;
 if(op==0)return l->key(&l->context,p,out->pk,z->public_key,out->sk,z->secret_key);
 if(p>100&&op==1)return l->enc(&l->context,p,out->ct,z->ciphertext,out->ss,32,in->pk,z->public_key);
 if(p>100)return l->dec(&l->context,p,out->ss,32,in->ct,z->ciphertext,in->sk,z->secret_key);
 if(op==1)return l->sign(&l->context,p,out->sig,z->signature,in->msg,in->mn,in->domain,in->dn,in->sk,z->secret_key);
 return l->verify(&l->context,p,in->sig,z->signature,in->msg,in->mn,in->domain,in->dn,in->pk,z->public_key);
}
static int equal(int p,int op,const lc_sizes *z,const OUTPUT *a,const OUTPUT *b) {
 if(op==0)return !memcmp(a->pk,b->pk,z->public_key)&&!memcmp(a->sk,b->sk,z->secret_key);
 if(p>100)return !memcmp(a->ss,b->ss,32)&&(op==2||!memcmp(a->ct,b->ct,z->ciphertext));
 return op==2||!memcmp(a->sig,b->sig,z->signature);
}
static int transcript(LC *l,int p,const lc_sizes *z,TEST_INPUT *in) {
 OUTPUT x={0};int r=lattice_call(l,p,1,z,in,&x);
 if(!r){if(p>100){memcpy(in->ct,x.ct,z->ciphertext);memcpy(in->ss,x.ss,32);}else memcpy(in->sig,x.sig,z->signature);}
 OPENSSL_cleanse(&x,sizeof x);return r;
}
static int digest_output(EVP_MD_CTX *m,int p,int op,const lc_sizes *z,const TEST_INPUT *in,const OUTPUT *out) {
 if(op==0)return EVP_DigestUpdate(m,out->pk,z->public_key)&&EVP_DigestUpdate(m,out->sk,z->secret_key);
 if(p>100)return EVP_DigestUpdate(m,out->ss,32)&&(op==2||EVP_DigestUpdate(m,out->ct,z->ciphertext));
 return EVP_DigestUpdate(m,op==1?out->sig:in->sig,z->signature);
}
/* Configuration regression: PCT none must not disable encoded-key/hash checks.
 * An inconsistent but canonical key distinguishes random PCT from none. */
static int negatives(OS *o,LC *l,int p,const lc_sizes *z,TEST_INPUT *in) {
 OUTPUT a={0},b={0};uint8_t bad[4896]={0};EVP_PKEY *key;OS other={0};int ok=0;
 if(p>100){
  memcpy(bad,in->sk,z->secret_key);bad[z->secret_key-64]^=1;
  key=import_key(o,1,bad,z->secret_key);if(key){EVP_PKEY_free(key);goto done;}ERR_clear_error();
  memcpy(bad,in->pk,z->public_key);bad[0]=0xff;bad[1]|=15;key=import_key(o,0,bad,z->public_key);if(key){EVP_PKEY_free(key);goto done;}ERR_clear_error();
  memcpy(bad,in->sk,z->secret_key);memset(bad,0,384u*(unsigned)(p==512?2:p==768?3:4));
  key=import_key(o,1,bad,z->secret_key);if((key!=NULL)!=(strcmp(o->pct,"none")==0)){EVP_PKEY_free(key);goto done;}EVP_PKEY_free(key);ERR_clear_error();
  if(!init_os(&other,p,strcmp(o->pct,"none")==0?"random":"none"))goto done;
  key=import_key(&other,1,bad,z->secret_key);if((key!=NULL)!=(strcmp(other.pct,"none")==0)){EVP_PKEY_free(key);goto done;}EVP_PKEY_free(key);ERR_clear_error();
  in->ct[0]^=1;int r1=lattice_call(l,p,2,z,in,&a),r2=openssl_call(o,p,2,z,in,&b);in->ct[0]^=1;
  if(r1||r2||memcmp(a.ss,b.ss,32))goto done;
  OPENSSL_cleanse(bad,sizeof bad);
 }else{
  in->sig[0]^=1;int r1=lattice_call(l,p,2,z,in,&a),r2=openssl_call(o,p,2,z,in,&b);in->sig[0]^=1;
  if(r1!=LC_E_REJECT||r2!=LC_E_REJECT)goto done;
  ERR_clear_error();
 }
 ok=1;
done:free_os(&other);OPENSSL_cleanse(bad,sizeof bad);OPENSSL_cleanse(&a,sizeof a);OPENSSL_cleanse(&b,sizeof b);return ok;
}
int main(int argc,char **argv) {
 /* driver library backend parameter op samples seed output.csv capacity
    message_bytes context_bytes pct cpu mode warmups */
 if(argc!=16){fputs("usage: driver library {compare|lattice|openssl} parameter op count seed output.csv capacity message_bytes context_bytes {none|random} cpu {verify|measure} warmups expected_version\n",stderr);return 2;}
 const char *backend=argv[2],*pct=argv[11];int p=atoi(argv[3]),op=atoi(argv[4]),n=atoi(argv[5]),cpu=atoi(argv[12]),measure=!strcmp(argv[13],"measure"),warmups=atoi(argv[14]);size_t cap=(size_t)strtoull(argv[8],NULL,10),mn=(size_t)strtoull(argv[9],NULL,10),dn=(size_t)strtoull(argv[10],NULL,10);uint64_t seed=strtoull(argv[6],NULL,10),freq=frequency();
 if(!algorithm(p)||op<0||op>2||n<1||n>1000000||cap<32||cap>262144||mn>16384||dn>255||warmups<0||warmups>10000||(!measure&&strcmp(argv[13],"verify"))||(strcmp(backend,"compare")&&strcmp(backend,"lattice")&&strcmp(backend,"openssl"))||(measure&&!strcmp(backend,"compare"))||(strcmp(pct,"none")&&strcmp(pct,"random"))||!freq||!seed)return 3;
 { FILE *prior=fopen(argv[7],"rb");if(prior){fclose(prior);fputs("Refuse to overwrite raw samples\n",stderr);return 3;} }
 unsigned long expected=!strcmp(argv[15],"3.6.0")?0x30600000L:!strcmp(argv[15],"3.6.4")?0x30600040L:0;
 if(!expected||OPENSSL_VERSION_NUMBER!=expected||OpenSSL_version_num()!=expected){fprintf(stderr,"Expected OpenSSL %s headers and library, got headers %s / loaded %s\n",argv[15],OPENSSL_VERSION_TEXT,OpenSSL_version(OPENSSL_VERSION));return 4;}
 if(!pin_cpu(cpu)){fputs("Explicit CPU affinity/P-core check failed\n",stderr);return 5;}
 LC l={0};OS o={0};lc_sizes z;TEST_INPUT in={0};OUTPUT out={0},check={0};FILE *csv=NULL;EVP_MD_CTX *inputs=NULL,*outputs=NULL;EVP_MD *sha256=NULL;int rc=0,completed=0,failed=0;char crypto[4096]={0};size_t high=0;
 if(!load_lc(&l,argv[1],cap)||l.sizes(p,&z)||!init_os(&o,p,pct)||!crypto_path(crypto,sizeof crypto)){rc=6;goto done;}
 prng=seed;in.mn=mn;in.dn=dn;fill(in.coins,64);fill(in.msg,mn);fill(in.domain,dn);
 if(lattice_call(&l,p,0,&z,&in,&out)||openssl_call(&o,p,0,&z,&in,&check)||!equal(p,0,&z,&out,&check)){rc=7;goto done;}
 memcpy(in.pk,out.pk,z.public_key);memcpy(in.sk,out.sk,z.secret_key);if(transcript(&l,p,&z,&in)||!negatives(&o,&l,p,&z,&in)){rc=8;goto done;}
 sha256=EVP_MD_fetch(o.ctx,"SHA256","provider=default");inputs=EVP_MD_CTX_new();outputs=EVP_MD_CTX_new();
 if(!sha256||!inputs||!outputs||!EVP_DigestInit_ex(inputs,sha256,NULL)||!EVP_DigestInit_ex(outputs,sha256,NULL)){rc=9;goto done;}
 csv=fopen(argv[7],"wb");if(!csv){rc=10;goto done;}
 fputs("case_id,iteration,warmup,elapsed_ticks,tick_frequency,elapsed_ns,status,entropy_sha256,message_sha256,context_sha256\n",csv);
 for(int i=-warmups;i<n;i++){
  uint64_t t0=0,t1=0;int status;char eh[65],mh[65],dh[65];fill(in.coins,64);if(p<100&&op>0)fill(in.msg,mn);
  if(op==2&&transcript(&l,p,&z,&in)){rc=11;failed=1;break;}
  if(!hash(&o,in.coins,(op==0&&p>100)?64:32,eh)||!hash(&o,in.msg,mn,mh)||!hash(&o,in.domain,dn,dh)){rc=12;failed=1;break;}
  if(!EVP_DigestUpdate(inputs,eh,64)||!EVP_DigestUpdate(inputs,mh,64)||!EVP_DigestUpdate(inputs,dh,64)||!EVP_DigestUpdate(inputs,in.pk,z.public_key)||(op==2&&!EVP_DigestUpdate(inputs,p>100?in.ct:in.sig,p>100?z.ciphertext:z.signature))){rc=13;failed=1;break;}
  if(current_cpu()!=cpu){rc=14;failed=1;break;}
  if(measure)t0=ticks();
  status=!strcmp(backend,"openssl")?openssl_call(&o,p,op,&z,&in,&out):lattice_call(&l,p,op,&z,&in,&out);
  if(measure)t1=ticks();
  if(!measure){int other=!strcmp(backend,"openssl")?lattice_call(&l,p,op,&z,&in,&check):openssl_call(&o,p,op,&z,&in,&check);if(other||!equal(p,op,&z,&out,&check))status=LC_E_INTERNAL;}
  if(current_cpu()!=cpu||!arena_guards(&l))status=LC_E_INTERNAL;
  fprintf(csv,"%016" PRIx64 "-%d-%d-%d,%d,%d,",seed,p,op,i+warmups,i,i<0);
  if(measure)fprintf(csv,"%" PRIu64 ",%" PRIu64 ",%.3f,",t1-t0,freq,(double)(t1-t0)*1e9/(double)freq);else fputs(",,,",csv);
  fprintf(csv,"%d,%s,%s,%s\n",status,eh,mh,dh);fflush(csv);
  if(status){rc=15;failed=1;break;}
  if(l.context.arena_high_water>high)high=l.context.arena_high_water;
  if(!digest_output(outputs,p,op,&z,&in,&out)){rc=16;failed=1;break;}
  completed++;
 }
 if(!failed){
  /* Final measured result is independently checked outside the interval. */
  if(measure){int other=!strcmp(backend,"openssl")?lattice_call(&l,p,op,&z,&in,&check):openssl_call(&o,p,op,&z,&in,&check);if(other||!equal(p,op,&z,&out,&check)){rc=17;goto done;}}
  uint8_t a[32],b[32];unsigned an=0,bn=0;char ah[65],bh[65];
  if(!EVP_DigestFinal_ex(inputs,a,&an)||!EVP_DigestFinal_ex(outputs,b,&bn)||an!=32||bn!=32){rc=18;goto done;}hex(a,32,ah);hex(b,32,bh);
  printf("{\"status\":\"PASS\",\"backend\":");json_string(backend);printf(",\"parameter\":%d,\"operation\":%d,\"samples\":%d,\"warmups\":%d,\"raw_rows\":%d,\"mode\":",p,op,n,warmups,completed);json_string(argv[13]);printf(",\"cpu\":%d,\"timer\":",cpu);
#ifdef _WIN32
  json_string("QueryPerformanceCounter; verified P-core");
#else
  json_string("CLOCK_MONOTONIC_RAW; explicit sched_setaffinity");
#endif
  printf(",\"frequency\":%" PRIu64 ",\"seed\":%" PRIu64 ",\"message_bytes\":%zu,\"context_bytes\":%zu,\"workspace_reserved\":%zu,\"workspace_observed_test_highwater\":%zu,\"input_sequence_sha256\":\"%s\",\"output_sequence_sha256\":\"%s\",\"openssl_library\":",freq,seed,mn,dn,cap,high,ah,bh);json_string(crypto);printf(",\"openssl_version\":");json_string(OpenSSL_version(OPENSSL_VERSION));printf(",\"openssl_cflags\":");json_string(OpenSSL_version(OPENSSL_CFLAGS));printf(",\"openssl_platform\":");json_string(OpenSSL_version(OPENSSL_PLATFORM));printf(",\"provider\":\"default\",\"property_query\":\"provider=default\",\"import_pct\":");json_string(pct);printf(",\"entropy_mode\":\"supplied_test_entropy\",\"operation_entropy_bytes\":%d,\"input_transcript_preparation_entropy_bytes\":%d,\"pct_uses_extra_system_rng\":%s,\"message_encoding\":1,\"mu\":0,\"negative_checks\":true,\"fresh_serialized_key_every_call\":true,\"lattice_context_init_inside_call\":true,\"openssl_key_context_lifecycle_inside_call\":true}\n",op==2?0:op==0&&p>100?64:32,op==2?32:0,p>100&&op==2&&!strcmp(pct,"random")?"true":"false");
 }
done:
 if(rc){fprintf(stderr,"driver failed code=%d completed=%d\n",rc,completed);ERR_print_errors_fp(stderr);}
 if(csv)fclose(csv);
 EVP_MD_CTX_free(inputs);EVP_MD_CTX_free(outputs);EVP_MD_free(sha256);free_os(&o);
 OPENSSL_cleanse(&in,sizeof in);OPENSSL_cleanse(&out,sizeof out);OPENSSL_cleanse(&check,sizeof check);if(l.raw){OPENSSL_cleanse(l.raw,cap+128);free(l.raw);}
#ifdef _WIN32
 if(l.handle)FreeLibrary((HMODULE)l.handle);
#else
 if(l.handle)dlclose(l.handle);
#endif
 return rc;
}
