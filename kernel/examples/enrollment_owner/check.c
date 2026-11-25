/* SPDX-License-Identifier: Apache-2.0 */
#ifndef _WIN32
#define _GNU_SOURCE
#endif
#include "application.h"
#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifndef _WIN32
static void *_aligned_malloc(size_t n,size_t alignment){void*p=NULL;return posix_memalign(&p,alignment,n)?NULL:p;}
static void _aligned_free(void*p){free(p);}
#endif
static size_t test_workspace=9536;
static int parse_workspace(const char *text){
 if(!text||!*text)return 0;
 for(const char *p=text;*p;p++)if(*p<'0'||*p>'9')return 0;
 errno=0;char *end;unsigned long long value=strtoull(text,&end,10);
 if(errno||*end||value<32||value>1048576||value%32)return 0;
 test_workspace=(size_t)value;return 1;
}
typedef struct {uint8_t bytes[6][8192];size_t n[6];unsigned seen[6];int compare,error;} capture;
typedef struct {uint8_t *raw,*p;size_t n;} guarded;
static int load(app_api*a,const char*path){
#ifdef _WIN32
 HMODULE h=LoadLibraryA(path);if(!h)return 0;
#define BIND(f,n) do{FARPROC p=GetProcAddress(h,n);if(!p)return 0;memcpy(&a->f,&p,sizeof p);}while(0)
#else
 void*h=dlopen(path,RTLD_NOW|RTLD_LOCAL);if(!h)return 0;
#define BIND(f,n) do{void*p=dlsym(h,n);if(!p||sizeof p!=sizeof a->f)return 0;memcpy(&a->f,&p,sizeof p);}while(0)
#endif
 BIND(init,"lc_context_init");BIND(sizes,"lc_get_sizes");BIND(key,"lc_keypair");BIND(enc,"lc_encaps");BIND(dec,"lc_decaps");BIND(sign,"lc_sign");BIND(verify,"lc_verify");
#undef BIND
 return 1;
}
static guarded allocate(size_t n){guarded g;g.n=n;g.raw=_aligned_malloc(n+128,32);if(!g.raw)exit(10);memset(g.raw,0xa5,n+128);g.p=g.raw+64;return g;}
static int intact(const guarded*g){for(size_t i=0;i<64;i++)if(g->raw[i]!=0xa5||g->p[g->n+i]!=0xa5)return 0;return 1;}
static int zero(const uint8_t*p,size_t n){for(size_t i=0;i<n;i++)if(p[i])return 0;return 1;}
static void snapshot(void*u,unsigned stage,const app_state*s){
 capture*c=u;app_views v;app_get_views(s,&v);const uint8_t*p[2]={NULL,NULL};size_t n[2]={0,0};
 switch(stage){case 0:p[0]=v.spk;n[0]=s->d.public_key;p[1]=v.ssk;n[1]=s->d.secret_key;break;
 case 1:p[0]=v.kpk;n[0]=s->k.public_key;p[1]=v.ksk;n[1]=s->k.secret_key;break;
 case 2:p[0]=v.signature;n[0]=s->d.signature;break;
 case 3:p[0]=v.signature;n[0]=s->d.signature;break;
 case 4:p[0]=v.ciphertext;n[0]=s->k.ciphertext;p[1]=v.secret;n[1]=32;break;
 case 5:p[0]=v.peer_secret;n[0]=32;break;default:c->error=1;return;}
 if(n[0]+n[1]>8192){c->error=2;return;}
 if(!c->compare){c->n[stage]=n[0]+n[1];c->seen[stage]=1;for(unsigned j=0,at=0;j<2;at+=(unsigned)n[j++])if(n[j])memcpy(c->bytes[stage]+at,p[j],n[j]);}
 else {if(!c->seen[stage]||c->n[stage]!=n[0]+n[1]){c->error=3;return;}for(unsigned j=0,at=0;j<2;at+=(unsigned)n[j++])if(n[j]&&memcmp(c->bytes[stage]+at,p[j],n[j]))c->error=4;c->seen[stage]=2;}
}
static int equivalent(const app_state*a,const app_state*b,capture*c){
 if(c->error||a->rc!=b->rc||a->completed!=b->completed||a->entropy!=b->entropy||a->requests!=b->requests||a->entropy_bytes!=b->entropy_bytes||a->flows!=b->flows||a->transcript!=b->transcript||a->high!=b->high)return 0;
 for(unsigned i=0;i<6;i++)if(c->seen[i]==1)return 0;
 return app_temporaries_clear(a)&&app_temporaries_clear(b);
}
static int pair_flow(app_state*a,app_state*b,capture*c,int expected){
 memset(c,0,sizeof *c);int x=app_flow(a);c->compare=1;int y=app_flow(b);
 return x==expected&&y==expected&&equivalent(a,b,c);
}
static int one(const app_api*api,int kem,int dsa,int fresh,uint64_t seed,unsigned*flows,unsigned*faults){
 const size_t workspace=test_workspace;
 size_t sizes[2]={app_pool_bytes(api,kem,dsa,0,workspace),app_pool_bytes(api,kem,dsa,1,workspace)};
 guarded g[2]={allocate(sizes[0]),allocate(sizes[1])};capture*c=calloc(1,sizeof *c);if(!c)return 11;
 app_state*a=app_open(g[0].p,g[0].n,api,kem,dsa,0,fresh,workspace,seed),*b=app_open(g[1].p,g[1].n,api,kem,dsa,1,fresh,workspace,seed);
 if(!a||!b)return 12;
 a->observer=b->observer=snapshot;a->observer_user=b->observer_user=c;
 int x=app_prepare(a);c->compare=1;int y=app_prepare(b);
 if(x||y||c->error||a->requests!=b->requests||a->entropy!=b->entropy)return 13;
 for(unsigned i=0;i<4;i++){if(!pair_flow(a,b,c,0))return 14;(*flows)++;}
 for(int mode=APP_FAULT_RANDOM;mode<=APP_FAULT_CIPHERTEXT;mode++)for(int stage=0;stage<6;stage++){
  if(stage==0&&!fresh)continue;
  if(mode==APP_FAULT_RANDOM&&stage!=0&&stage!=1&&stage!=2&&stage!=4)continue;
  if(mode==APP_FAULT_SIGNATURE&&stage!=3)continue;
  if(mode==APP_FAULT_CIPHERTEXT&&stage!=5)continue;
  int expected=mode==APP_FAULT_RANDOM?LC_E_RANDOM:mode==APP_FAULT_CAPACITY?LC_E_WORKSPACE:mode==APP_FAULT_SIGNATURE?LC_E_REJECT:mode==APP_FAULT_CANCEL?APP_E_CANCEL:APP_E_SECRET;
  a->fault=b->fault=mode;a->fault_stage=b->fault_stage=stage;
  if(!pair_flow(a,b,c,expected)){printf("FAIL fault=%d stage=%d rc=%d/%d callback=%d\n",mode,stage,a->rc,b->rc,c->error);return 15;}(*faults)++;
  a->fault=b->fault=0;
  if(!pair_flow(a,b,c,0))return 16;
  (*flows)++;
 }
 if(!intact(&g[0])||!intact(&g[1]))return 17;
 size_t difference=a->object_bytes-b->object_bytes;
 if(difference!=a->k.public_key+a->k.ciphertext+64||g[0].n-g[1].n!=difference)return 18;
 app_finish(a);app_finish(b);
 if(!zero(a->objects,a->object_bytes)||!zero(b->objects,b->object_bytes)||!zero(a->work,a->workspace_bytes)||!zero(b->work,b->workspace_bytes)||a->entropy||b->entropy)return 21;
 app_close(a);app_close(b);if(!zero(g[0].p,g[0].n)||!zero(g[1].p,g[1].n))return 19;
 if(!intact(&g[0])||!intact(&g[1]))return 20;
 _aligned_free(g[0].raw);_aligned_free(g[1].raw);memset(c,0,sizeof *c);free(c);return 0;
}
static int protected_pool(const app_api*api,int kem,int dsa,int layout,int at_end){
#ifdef _WIN32
 SYSTEM_INFO info;GetSystemInfo(&info);size_t page=info.dwPageSize;
#else
 long queried=sysconf(_SC_PAGESIZE);if(queried<=0)return 30;size_t page=(size_t)queried;
#endif
 size_t n=app_pool_bytes(api,kem,dsa,layout,test_workspace),rw=(n+page-1)&~(page-1);
#ifdef _WIN32
 DWORD old;uint8_t*raw=VirtualAlloc(NULL,rw+2*page,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);if(!raw)return 30;
 if(!VirtualProtect(raw,page,PAGE_NOACCESS,&old)||!VirtualProtect(raw+page+rw,page,PAGE_NOACCESS,&old))return 31;
#else
 uint8_t*raw=mmap(NULL,rw+2*page,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);if(raw==MAP_FAILED)return 30;
 if(mprotect(raw+page,rw,PROT_READ|PROT_WRITE))return 31;
#endif
 uint8_t*pool=raw+page+(at_end?rw-n:0);app_state*s=app_open(pool,n,api,kem,dsa,layout,1,test_workspace,6179387);
 if(!s||app_prepare(s)||app_flow(s)||!app_temporaries_clear(s))return 32;
 app_close(s);if(!zero(pool,n))return 33;
#ifdef _WIN32
 VirtualFree(raw,0,MEM_RELEASE);
#else
 if(munmap(raw,rw+2*page))return 34;
#endif
 return 0;
}
static int production_entropy(const app_api*api,int kem,int dsa,int layout){
 size_t n=app_pool_bytes(api,kem,dsa,layout,test_workspace);guarded g=allocate(n);
 app_state*s=app_open(g.p,n,api,kem,dsa,layout,0,test_workspace,0);
 if(!s||s->context.random!=NULL||app_prepare(s))return 40;
 for(unsigned i=0;i<2;i++)if(app_flow(s)||!app_temporaries_clear(s))return 41;
 if(s->requests||s->entropy_bytes||!intact(&g))return 42;
 app_finish(s);app_close(s);if(!zero(g.p,n)||!intact(&g))return 43;_aligned_free(g.raw);return 0;
}
static int lifecycle(const app_api*api,int kem,int dsa,int layout,int fresh,unsigned*cases){
 size_t n=app_pool_bytes(api,kem,dsa,layout,test_workspace);guarded g=allocate(n);memset(g.p,0,n);
#define STATE_CHECK(test) do{if(!(test))return 50;(*cases)++;}while(0)
 STATE_CHECK(app_prepare(NULL)==LC_E_ARGUMENT&&app_flow(NULL)==LC_E_ARGUMENT);
 app_finish(NULL);app_close(NULL);
 app_state*s=(app_state*)g.p;
 STATE_CHECK(app_prepare(s)==LC_E_ARGUMENT&&app_flow(s)==LC_E_ARGUMENT);
 for(unsigned missing=0;missing<7;missing++){
  app_api bad=*api;
  switch(missing){case 0:bad.init=NULL;break;case 1:bad.sizes=NULL;break;case 2:bad.key=NULL;break;case 3:bad.enc=NULL;break;case 4:bad.dec=NULL;break;case 5:bad.sign=NULL;break;case 6:bad.verify=NULL;break;}
  STATE_CHECK(app_open(g.p,n,&bad,kem,dsa,layout,fresh,test_workspace,701)==NULL&&zero(g.p,n));
 }
 s=app_open(g.p,n,api,kem,dsa,layout,fresh,test_workspace,701);
 STATE_CHECK(s&&app_prepare(s)==0&&app_flow(s)==0&&app_temporaries_clear(s));
 app_finish(s);uint64_t requests=s->requests;
 STATE_CHECK(s->phase<0&&s->context.random==NULL&&s->context.random_user==NULL);
 STATE_CHECK(app_prepare(s)==LC_E_ARGUMENT&&app_flow(s)==LC_E_ARGUMENT&&s->requests==requests);
 app_finish(s);
 STATE_CHECK(app_flow(s)==LC_E_ARGUMENT&&zero(s->objects,s->object_bytes)&&zero(s->work,s->workspace_bytes));
 app_close(s);
 STATE_CHECK(zero(g.p,n)&&app_prepare(s)==LC_E_ARGUMENT&&app_flow(s)==LC_E_ARGUMENT);
 app_close(s);app_close(s);
 STATE_CHECK(zero(g.p,n)&&intact(&g));
 s=app_open(g.p,n,api,kem,dsa,layout,fresh,test_workspace,1709);
 STATE_CHECK(s&&app_prepare(s)==0&&app_flow(s)==0&&app_temporaries_clear(s));
 s->fault=APP_FAULT_RANDOM;s->fault_stage=1;
 STATE_CHECK(app_flow(s)==LC_E_RANDOM&&app_temporaries_clear(s));
 s->fault=APP_FAULT_NONE;
 STATE_CHECK(app_flow(s)==0&&app_temporaries_clear(s));
 /* A caller may keep the function table inside the old pool; open copies it
    before erasing the previous state and selects fresh entropy explicitly. */
 s=app_open(g.p,n,&s->api,kem,dsa,layout,fresh,test_workspace,0);
 STATE_CHECK(s&&s->context.random==NULL&&app_prepare(s)==0&&app_flow(s)==0);
 app_finish(s);app_close(s);
 STATE_CHECK(zero(g.p,n)&&app_flow(s)==LC_E_ARGUMENT&&intact(&g));
 _aligned_free(g.raw);return 0;
#undef STATE_CHECK
}
int main(int argc,char**argv){
 if((argc!=2&&argc!=3)||(argc==3&&!parse_workspace(argv[2])))return 2;
 app_api api;if(!load(&api,argv[1]))return 3;
 unsigned flows=0,faults=0,lifecycle_cases=0;int kem[3]={512,768,1024},dsa[3]={44,65,87};
 for(unsigned seed=0;seed<24;seed++)for(unsigned pair=0;pair<3;pair++)for(int fresh=0;fresh<=1;fresh++){
  int rc=one(&api,kem[pair],dsa[pair],fresh,202610034001+seed*65537+pair*101+fresh,&flows,&faults);
  if(rc){printf("FAIL pair=%u fresh=%d seed=%u code=%d\n",pair,fresh,seed,rc);return rc;}
 }
 for(unsigned pair=0;pair<3;pair++)for(int layout=0;layout<2;layout++)for(int end=0;end<2;end++){int rc=protected_pool(&api,kem[pair],dsa[pair],layout,end);if(rc)return rc;}
 for(unsigned pair=0;pair<3;pair++)for(int layout=0;layout<2;layout++){int rc=production_entropy(&api,kem[pair],dsa[pair],layout);if(rc)return rc;}
 for(unsigned pair=0;pair<3;pair++)for(int layout=0;layout<2;layout++)for(int fresh=0;fresh<2;fresh++){int rc=lifecycle(&api,kem[pair],dsa[pair],layout,fresh,&lifecycle_cases);if(rc)return rc;}
 printf("{\"status\":\"PASS\",\"lifecycle_assertions\":%u,\"lifecycle_configurations\":12,\"production_entropy_sessions\":18}\n",lifecycle_cases);
 printf("{\"status\":\"PASS\",\"ordinary_paired_flows\":%u,\"paired_failures_with_recovery\":%u,\"case_seeds\":24,\"parameter_pairs\":3,\"identity_modes\":2,\"protected_pool_placements\":12,\"workspace_bytes\":%zu,\"state_bytes\":%zu,\"full_output_comparison\":true}\n",flows,faults,test_workspace,sizeof(app_state));return 0;
}
