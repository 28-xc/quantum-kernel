/* SPDX-License-Identifier: Apache-2.0 */
/* A native loader and observer for the existing public API and application. */
#define _GNU_SOURCE
#include "application.h"
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
static void *core;
static app_api api;
static void erase(void *p,size_t n){volatile unsigned char *q=p;while(n--)*q++=0;}
int td_open(const char *path){
 if(core)return -1;core=dlopen(path,RTLD_NOW|RTLD_LOCAL);if(!core)return -2;
#define LOAD(f,n) do{void *p=dlsym(core,n);if(!p||sizeof(p)!=sizeof(api.f)){dlclose(core);core=NULL;memset(&api,0,sizeof(api));return -3;}memcpy(&api.f,&p,sizeof(p));}while(0)
 LOAD(init,"lc_context_init");LOAD(sizes,"lc_get_sizes");LOAD(key,"lc_keypair");LOAD(enc,"lc_encaps");LOAD(dec,"lc_decaps");LOAD(sign,"lc_sign");LOAD(verify,"lc_verify");
#undef LOAD
 return 0;
}
void *td_symbol(const char *name){return core?dlsym(core,name):NULL;}
const char *td_loaded_path(void){Dl_info info;void*p=td_symbol("lc_get_sizes");return p&&dladdr(p,&info)?info.dli_fname:NULL;}
void td_close(void){if(core)dlclose(core);core=NULL;memset(&api,0,sizeof(api));}
typedef struct {size_t pool,workspace,peak;unsigned observed,completed,temporary_clear,pool_clear,canaries;int rc;} td_result;
static void observe(void *u,unsigned stage,const app_state*s){td_result*r=u;if(stage<6)r->observed|=1U<<stage;if(s->high>r->peak)r->peak=s->high;}
int td_flow(const char *module,int kem,int dsa,size_t workspace,td_result *r){
 void*h=dlopen(module,RTLD_NOW|RTLD_LOCAL);if(!h)return -10;
 size_t(*pool_bytes)(const app_api*,int,int,int,size_t);
 app_state*(*open_app)(void*,size_t,const app_api*,int,int,int,int,size_t,uint64_t);
 int(*prepare)(app_state*),(*flow)(app_state*),(*clear)(const app_state*);void(*close_app)(app_state*);
#define APP(f,n) do{void*p=dlsym(h,n);if(!p||sizeof(p)!=sizeof(f)){dlclose(h);return -11;}memcpy(&f,&p,sizeof(p));}while(0)
 APP(pool_bytes,"app_pool_bytes");APP(open_app,"app_open");APP(prepare,"app_prepare");APP(flow,"app_flow");APP(clear,"app_temporaries_clear");APP(close_app,"app_close");
#undef APP
 memset(r,0,sizeof(*r));r->workspace=workspace;r->pool=pool_bytes(&api,kem,dsa,APP_SIGNATURE_REUSE,workspace);
 if(!r->pool){dlclose(h);return -12;}unsigned char*raw=NULL;if(posix_memalign((void**)&raw,32,r->pool+128)){dlclose(h);return -13;}
 memset(raw,0xa5,r->pool+128);app_state*s=open_app(raw+64,r->pool,&api,kem,dsa,APP_SIGNATURE_REUSE,0,workspace,0);
 if(!s){erase(raw,r->pool+128);free(raw);dlclose(h);return -14;}
 s->observer=observe;s->observer_user=r;r->rc=prepare(s);if(!r->rc)r->rc=flow(s);
 r->peak=s->high;r->completed=s->completed;r->temporary_clear=clear(s);close_app(s);
 r->pool_clear=1;r->canaries=1;for(size_t i=0;i<r->pool;i++)if(raw[64+i])r->pool_clear=0;
 for(size_t i=0;i<64;i++)if(raw[i]!=0xa5||raw[64+r->pool+i]!=0xa5)r->canaries=0;
 erase(raw,r->pool+128);free(raw);dlclose(h);return r->rc;
}
