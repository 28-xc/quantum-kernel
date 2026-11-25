#include "latticecore.h"
#include "lc_arena.h"
#include "lc_dsa_api.h"
#include "lc_platform.h"
#include "lc_dsa_keycheck.h"
#include <string.h>
#include <stdint.h>
extern int lc_mlk_call(int,int,unsigned char*,unsigned char*,const unsigned char*,const unsigned char*,lc_arena*);
typedef struct { const void *p; size_t n; } region;
static int kem(int p){return p==512||p==768||p==1024;}
static int dsa(int p){return p==44||p==65||p==87;}
int lc_get_sizes(int p,lc_sizes*s){
 if(!s)return LC_E_ARGUMENT;
 memset(s,0,sizeof(*s));
 switch(p){
 case 512:s->public_key=800;s->secret_key=1632;s->ciphertext=768;break;
 case 768:s->public_key=1184;s->secret_key=2400;s->ciphertext=1088;break;
 case 1024:s->public_key=1568;s->secret_key=3168;s->ciphertext=1568;break;
 case 44:s->public_key=1312;s->secret_key=2560;s->signature=2420;break;
 case 65:s->public_key=1952;s->secret_key=4032;s->signature=3309;break;
 case 87:s->public_key=2592;s->secret_key=4896;s->signature=4627;break;
 default:return LC_E_ARGUMENT;
 }
 if(kem(p))s->shared_secret=32;
 return LC_OK;
}
static int overlaps(region a,region b){
 uintptr_t x=(uintptr_t)a.p,y=(uintptr_t)b.p;
 if(!a.n||!b.n)return 0;
 /* Caller promises valid accessible objects. Arithmetic wrap is rejected
    before interval comparison; pointers are never formed out of bounds. */
 return x<=y?y-x<a.n:x-y<b.n;
}
static int validate(lc_context*c,region*r,size_t n){
 size_t i,j;
 if(!c||!c->workspace||!c->workspace_bytes)return LC_E_ARGUMENT;
 r[n++]=(region){c->workspace,c->workspace_bytes};
 r[n++]=(region){c,sizeof(*c)};
 for(i=0;i<n;i++){
  if((!r[i].p&&r[i].n)||r[i].n>UINTPTR_MAX-(uintptr_t)r[i].p)return LC_E_ARGUMENT;
  for(j=0;j<i;j++)if(overlaps(r[i],r[j]))return LC_E_ALIAS;
 }
 c->arena_high_water=c->allocations=c->allocation_failures=0;c->last_error=0;
 return LC_OK;
}
int lc_context_init(lc_context*c,void*w,size_t n,lc_random_fn f,void*u){
 if(!c||!w||!n||n>UINTPTR_MAX-(uintptr_t)w)return LC_E_ARGUMENT;
 if(overlaps((region){c,sizeof(*c)},(region){w,n}))return LC_E_ALIAS;
 memset(c,0,sizeof(*c));c->workspace=w;c->workspace_bytes=n;c->random=f;c->random_user=u;
 return 0;
}
static int random_bytes(lc_context*c,uint8_t*p,size_t n){
 int r=c->random?c->random(c->random_user,p,n):lc_system_random(p,n);
 return r?LC_E_RANDOM:LC_OK;
}
static int result(lc_context*c,int raw,lc_arena*a,lc_dsa_stats*s){
 int r;
 if(a){c->arena_high_water=a->high_water;c->allocations=a->allocations;
  c->allocation_failures=a->failed_size?1:0;
  r=a->error||a->used?LC_E_INTERNAL:a->failed_size?LC_E_WORKSPACE:raw?LC_E_REJECT:0;
 }else{c->arena_high_water=s->arena_high_water;c->allocations=s->allocations;
  c->allocation_failures=s->allocation_failures;
  r=s->lifo_errors||s->arena_remaining?LC_E_INTERNAL:s->allocation_failures?LC_E_WORKSPACE:raw?LC_E_REJECT:0;
 }
 c->last_error=r;return r;
}
int lc_keypair(lc_context*c,int p,uint8_t*pk,size_t pn,uint8_t*sk,size_t sn){
 lc_sizes z;region r[4];uint8_t seed[64];lc_arena a;lc_dsa_stats s={0};int e,raw;
 if(lc_get_sizes(p,&z))return LC_E_ARGUMENT;
 if(pn<z.public_key||sn<z.secret_key)return LC_E_LENGTH;
 r[0]=(region){pk,pn};r[1]=(region){sk,sn};if((e=validate(c,r,2)))return e;
 e=random_bytes(c,seed,kem(p)?64:32);
 if(!e){if(kem(p)){lc_arena_init(&a,c->workspace,c->workspace_bytes);raw=lc_mlk_call(p,0,pk,sk,seed,NULL,&a);e=result(c,raw,&a,NULL);}
 else {raw=lc_dsa_keypair_seed(p,pk,sk,seed,c->workspace,c->workspace_bytes,&s);e=result(c,raw,NULL,&s);}}
 lc_zero(seed,sizeof(seed));if(e){lc_zero(pk,z.public_key);lc_zero(sk,z.secret_key);c->last_error=e;}return e;
}
int lc_encaps(lc_context*c,int p,uint8_t*ct,size_t cn,uint8_t*ss,size_t sn,const uint8_t*pk,size_t pn){
 lc_sizes z;region r[5];uint8_t seed[32];lc_arena a;int e,raw;
 if(!kem(p)||lc_get_sizes(p,&z))return LC_E_ARGUMENT;
 if(cn<z.ciphertext||sn<32||pn!=z.public_key)return LC_E_LENGTH;
 r[0]=(region){ct,cn};r[1]=(region){ss,sn};r[2]=(region){pk,pn};if((e=validate(c,r,3)))return e;
 e=random_bytes(c,seed,32);
 if(!e){lc_arena_init(&a,c->workspace,c->workspace_bytes);raw=lc_mlk_call(p,1,ct,ss,pk,seed,&a);e=result(c,raw,&a,NULL);}
 lc_zero(seed,sizeof(seed));if(e){lc_zero(ct,z.ciphertext);lc_zero(ss,32);c->last_error=e;}return e;
}
int lc_decaps(lc_context*c,int p,uint8_t*ss,size_t sn,const uint8_t*ct,size_t cn,const uint8_t*sk,size_t kn){
 lc_sizes z;region r[5];lc_arena a;int e,raw;
 if(!kem(p)||lc_get_sizes(p,&z))return LC_E_ARGUMENT;
 if(sn<32||cn!=z.ciphertext||kn!=z.secret_key)return LC_E_LENGTH;
 r[0]=(region){ss,sn};r[1]=(region){ct,cn};r[2]=(region){sk,kn};if((e=validate(c,r,3)))return e;
 lc_arena_init(&a,c->workspace,c->workspace_bytes);raw=lc_mlk_call(p,2,ss,NULL,ct,sk,&a);e=result(c,raw,&a,NULL);
 if(e)lc_zero(ss,32);return e;
}
int lc_sign(lc_context*c,int p,uint8_t*sig,size_t sn,const uint8_t*m,size_t mn,const uint8_t*d,size_t dn,const uint8_t*sk,size_t kn){
 lc_sizes z;region r[6];uint8_t seed[32];lc_dsa_stats s={0};int e,raw;
 if(!dsa(p)||lc_get_sizes(p,&z))return LC_E_ARGUMENT;
 if(sn<z.signature||kn!=z.secret_key||dn>255)return LC_E_LENGTH;
 r[0]=(region){sig,sn};r[1]=(region){m,mn};r[2]=(region){d,dn};r[3]=(region){sk,kn};if((e=validate(c,r,4)))return e;
 e=lc_dsa_secret_encoding_valid(p,sk)?random_bytes(c,seed,32):LC_E_REJECT;
 if(!e){raw=lc_dsa_sign_seed(p,sig,m,mn,d,dn,seed,sk,c->workspace,c->workspace_bytes,&s);e=result(c,raw,NULL,&s);}
 lc_zero(seed,sizeof(seed));if(e){lc_zero(sig,z.signature);c->last_error=e;}return e;
}
int lc_verify(lc_context*c,int p,const uint8_t*sig,size_t sn,const uint8_t*m,size_t mn,const uint8_t*d,size_t dn,const uint8_t*pk,size_t pn){
 lc_sizes z;region r[6];lc_dsa_stats s={0};int e,raw;
 if(!dsa(p)||lc_get_sizes(p,&z))return LC_E_ARGUMENT;
 if(sn!=z.signature||pn!=z.public_key||dn>255)return LC_E_LENGTH;
 r[0]=(region){sig,sn};r[1]=(region){m,mn};r[2]=(region){d,dn};r[3]=(region){pk,pn};if((e=validate(c,r,4)))return e;
 raw=lc_dsa_verify(p,sig,sn,m,mn,d,dn,pk,c->workspace,c->workspace_bytes,&s);return result(c,raw,NULL,&s);
}
const char*lc_error_string(int e){switch(e){case LC_OK:return "success";case LC_E_ARGUMENT:return "invalid argument";
 case LC_E_LENGTH:return "invalid length";case LC_E_ALIAS:return "overlapping objects";case LC_E_RANDOM:return "random source failed";
 case LC_E_WORKSPACE:return "insufficient workspace";case LC_E_REJECT:return "operation rejected";default:return "internal invariant failure";}}

#include "a_session_public.h"
