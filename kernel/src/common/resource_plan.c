#include "lattice_resources.h"
#include "lc_dsa_api.h"
#include <string.h>
#include <stdint.h>
#ifndef LC_RESOURCE_OPERATION_MASK
#define LC_RESOURCE_OPERATION_MASK 262143u
#endif

int lc_resource_query(int p,int op,lc_resource_requirements *r) {
  unsigned index;
  if(!r)return LC_E_ARGUMENT;
  memset(r,0,sizeof(*r));
  if(op<0||op>2)return LC_E_ARGUMENT;
  switch(p) {
  case 512:index=0;break;case 768:index=1;break;case 1024:index=2;break;
  case 44:index=3;break;case 65:index=4;break;case 87:index=5;break;
  default:return LC_E_ARGUMENT;
  }
  if(!(LC_RESOURCE_OPERATION_MASK & (1u << (index*3+(unsigned)op))))
    return LC_RESOURCE_E_UNSUPPORTED;
  r->alignment=32;r->public_context_bytes=sizeof(lc_context);
  r->caller_plan_bytes=sizeof(lc_resource_plan);
  if(p==512||p==768||p==1024) {
    /* Deliberately conservative for the compiled native ML-KEM schedule,
     * including its aligned allocator headers and optional public matrix.
     * Not advertised as the measured minimum or as adaptive sampling. */
    r->minimum_workspace_bytes=r->preferred_workspace_bytes=32768;
    return 0;
  }
  if(p!=44&&p!=65&&p!=87){memset(r,0,sizeof(*r));return LC_E_ARGUMENT;}
  if(op==0) {
    r->minimum_workspace_bytes=r->preferred_workspace_bytes=lc_dsa_runtime_keypair_workspace(p);
    r->exact_workspace_bound=1;
  } else if(op==1) {
    r->preferred_workspace_bytes=lc_dsa_runtime_sign_workspace(p,p==44?4:p==65?6:8);
    r->minimum_workspace_bytes=lc_dsa_runtime_sign_workspace(p,p==87?5:p==44?4:6);
    r->adaptive=p==87;r->exact_workspace_bound=1;
  } else {
    size_t bound=lc_dsa_workspace_bound(p,op);
    /* Existing bound includes 31 bytes of arbitrary-address front padding;
     * this interface reports an aligned workspace, padding in make_plan. */
    r->minimum_workspace_bytes=r->preferred_workspace_bytes=bound&~(size_t)31;
  }
  return 0;
}
int lc_resource_make_plan(int p,int op,const void *w,size_t bytes,lc_resource_plan *out) {
  lc_resource_requirements r;size_t pad,need;unsigned rows=0;int rc;
  if(!out)return LC_E_ARGUMENT;
  memset(out,0,sizeof(*out));
  if((rc=lc_resource_query(p,op,&r)))return rc;
  if(!w||bytes>UINTPTR_MAX-(uintptr_t)w)return LC_E_ARGUMENT;
  pad=(32-((uintptr_t)w&31))&31;
  out->workspace_bytes=bytes;out->alignment_padding=pad;
  out->usable_workspace_bytes=bytes>=pad?bytes-pad:0;
  need=r.minimum_workspace_bytes;
  if(out->usable_workspace_bytes<need)return LC_E_WORKSPACE;
  if(r.adaptive) {
    rows=lc_dsa_runtime_cache_rows(out->usable_workspace_bytes);
    need=lc_dsa_runtime_sign_workspace(p,rows);
    out->mode=rows==8?LC_RESOURCE_FULL_MATRIX:LC_RESOURCE_FIVE_ROWS;
    out->cached_rows=rows;out->cached_polynomials=7*rows;
    out->matrix_cache_bytes=7*rows*768u;
    out->saved_input_bytes=rows==5?2*1024u:0;
  }
  out->required_workspace_bytes=need;
  return 0;
}
int lc_resource_algorithm_bytes(size_t w,size_t stack,size_t other,size_t *total) {
  size_t n=w;
  if(!total)return LC_E_ARGUMENT;
  *total=0;
  if(stack>SIZE_MAX-n)return LC_E_ARGUMENT;
  n+=stack;
  if(sizeof(lc_context)>SIZE_MAX-n)return LC_E_ARGUMENT;
  n+=sizeof(lc_context);
  if(other>SIZE_MAX-n)return LC_E_ARGUMENT;
  n+=other;
  *total=n;return 0;
}
