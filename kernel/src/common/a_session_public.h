#if LC_DSA_PUBLIC_A_SESSION
#include "lattice_session.h"
#define LC_A_MAGIC UINT32_C(0x4c434131)
static int a_metadata(const lc_a_session *s) {
  size_t need;
  if(!s||s->magic!=LC_A_MAGIC||!s->cache||s->ready>1)return LC_E_ARGUMENT;
  need=lc_dsa_a_cache_bytes(s->parameter);
  if(!need||s->format_tag!=lc_dsa_a_format_tag(s->parameter)||s->cache_bytes!=need||s->capacity<need)return LC_E_ARGUMENT;
  if(((uintptr_t)s->cache&31)||s->capacity>UINTPTR_MAX-(uintptr_t)s->cache)return LC_E_ARGUMENT;
  if(sizeof(*s)>UINTPTR_MAX-(uintptr_t)s)return LC_E_ARGUMENT;
  if(overlaps((region){s,sizeof(*s)},(region){s->cache,s->capacity}))return LC_E_ALIAS;
  return 0;
}
size_t lc_a_session_cache_bytes(int p){return lc_dsa_a_cache_bytes(p);}
size_t lc_a_session_workspace_bound(int p,int op){return lc_dsa_a_workspace_bound(p,op);}
int lc_a_session_init(lc_a_session*s,int p,void*cache,size_t n) {
  size_t need=lc_dsa_a_cache_bytes(p);
  if(!s||!cache||!need||((uintptr_t)cache&31)||n>UINTPTR_MAX-(uintptr_t)cache||sizeof(*s)>UINTPTR_MAX-(uintptr_t)s)return LC_E_ARGUMENT;
  if(n<need)return LC_E_LENGTH;
  if(overlaps((region){s,sizeof(*s)},(region){cache,n}))return LC_E_ALIAS;
  memset(s,0,sizeof(*s));s->cache=cache;s->capacity=n;s->cache_bytes=need;s->parameter=p;s->format_tag=lc_dsa_a_format_tag(p);s->magic=LC_A_MAGIC;
  lc_zero(cache,n);return 0;
}
int lc_a_session_prepare(lc_context*c,lc_a_session*s,const uint8_t*pk,size_t pn) {
  region r[5];lc_sizes z;lc_dsa_stats stats={0};int e,raw;
  if((e=a_metadata(s)))return e;
  if(lc_get_sizes(s->parameter,&z))return LC_E_ARGUMENT;
  if(pn!=z.public_key)return LC_E_LENGTH;
  r[0]=(region){pk,pn};r[1]=(region){s,sizeof(*s)};r[2]=(region){s->cache,s->capacity};
  if((e=validate(c,r,3)))return e;
  /* Validation failures above do not touch any object. Once preparation
   * starts, failure leaves an empty, unusable binding rather than stale A. */
  s->ready=0;lc_zero(s->rho,sizeof(s->rho));lc_zero(s->cache,s->capacity);
  raw=lc_dsa_a_prepare(s->parameter,s->cache,pk,c->workspace,c->workspace_bytes,&stats);
  e=result(c,raw,NULL,&stats);
  if(e){lc_zero(s->cache,s->capacity);return e;}
  memcpy(s->rho,pk,32);s->ready=1;return 0;
}
int lc_a_session_sign(lc_context*c,lc_a_session*s,int p,uint8_t*sig,size_t sn,
 const uint8_t*m,size_t mn,const uint8_t*d,size_t dn,const uint8_t*sk,size_t kn) {
  lc_sizes z;region r[8];uint8_t seed[32];lc_dsa_stats stats={0};int e,raw;
  if((e=a_metadata(s)))return e;
  if(!dsa(p)||lc_get_sizes(p,&z))return LC_E_ARGUMENT;
  if(sn<z.signature||kn!=z.secret_key||dn>255)return LC_E_LENGTH;
  r[0]=(region){sig,sn};r[1]=(region){m,mn};r[2]=(region){d,dn};r[3]=(region){sk,kn};
  r[4]=(region){s,sizeof(*s)};r[5]=(region){s->cache,s->capacity};
  if((e=validate(c,r,6)))return e;
  e=(!s->ready||p!=s->parameter||memcmp(s->rho,sk,32))?LC_E_REJECT:0;
  if(!e)e=lc_dsa_secret_encoding_valid(p,sk)?random_bytes(c,seed,32):LC_E_REJECT;
  if(!e){raw=lc_dsa_a_sign_seed(p,s->cache,sig,m,mn,d,dn,seed,sk,c->workspace,c->workspace_bytes,&stats);e=result(c,raw,NULL,&stats);}
  lc_zero(seed,sizeof(seed));if(e){lc_zero(sig,z.signature);c->last_error=e;}return e;
}
int lc_a_session_verify(lc_context*c,lc_a_session*s,int p,const uint8_t*sig,size_t sn,
 const uint8_t*m,size_t mn,const uint8_t*d,size_t dn,const uint8_t*pk,size_t pn) {
  lc_sizes z;region r[8];lc_dsa_stats stats={0};int e,raw;
  if((e=a_metadata(s)))return e;
  if(!dsa(p)||lc_get_sizes(p,&z))return LC_E_ARGUMENT;
  if(sn!=z.signature||pn!=z.public_key||dn>255)return LC_E_LENGTH;
  r[0]=(region){sig,sn};r[1]=(region){m,mn};r[2]=(region){d,dn};r[3]=(region){pk,pn};
  r[4]=(region){s,sizeof(*s)};r[5]=(region){s->cache,s->capacity};
  if((e=validate(c,r,6)))return e;
  if(!s->ready||p!=s->parameter||memcmp(s->rho,pk,32)){c->last_error=LC_E_REJECT;return LC_E_REJECT;}
  raw=lc_dsa_a_verify(p,s->cache,sig,sn,m,mn,d,dn,pk,c->workspace,c->workspace_bytes,&stats);
  return result(c,raw,NULL,&stats);
}
int lc_a_session_close(lc_a_session*s) {
  int e;
  if(!s)return LC_E_ARGUMENT;
  if(!s->magic&&!s->cache&&!s->capacity&&!s->cache_bytes&&!s->ready&&!s->parameter&&!s->format_tag)return 0;
  if((e=a_metadata(s)))return e;
  lc_zero(s->cache,s->capacity);lc_zero(s,sizeof(*s));return 0;
}
#undef LC_A_MAGIC
#endif
