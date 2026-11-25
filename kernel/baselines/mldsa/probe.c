#include "lc_dsa_api.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
int main(void) {
  uint8_t pk[2592],sk[4896],sig[4627],seed[32],rnd[32],msg[1024];
  uint8_t *raw=malloc(131072+64); int levels[]={44,65,87};
  if(!raw) return 1;
  memset(seed,0x17,32); memset(rnd,0x29,32); memset(msg,0x5a,sizeof(msg));
  for(int i=0;i<3;i++) {
    int l=levels[i],rc; lc_dsa_stats s;
    rc=lc_dsa_keypair_seed(l,pk,sk,seed,raw,131072,&s);
    printf("{\"level\":%d,\"operation\":\"keygen\",\"rc\":%d,\"arena_peak\":%zu,\"remaining\":%zu,\"lifo_errors\":%zu}\n",l,rc,s.arena_high_water,s.arena_remaining,s.lifo_errors);
    if(rc) return 2;
    rc=lc_dsa_sign_seed(l,sig,msg,sizeof(msg),NULL,0,rnd,sk,raw,131072,&s);
    printf("{\"level\":%d,\"operation\":\"sign\",\"rc\":%d,\"arena_peak\":%zu,\"remaining\":%zu,\"lifo_errors\":%zu}\n",l,rc,s.arena_high_water,s.arena_remaining,s.lifo_errors);
    if(rc) return 3;
    rc=lc_dsa_verify(l,sig,lc_dsa_size(l,2),msg,sizeof(msg),NULL,0,pk,raw,131072,&s);
    printf("{\"level\":%d,\"operation\":\"verify\",\"rc\":%d,\"arena_peak\":%zu,\"remaining\":%zu,\"lifo_errors\":%zu}\n",l,rc,s.arena_high_water,s.arena_remaining,s.lifo_errors);
    if(rc) return 4;
    sig[0]^=1;
    if(lc_dsa_verify(l,sig,lc_dsa_size(l,2),msg,sizeof(msg),NULL,0,pk,raw,131072,&s)!=-6) return 5;
    rc=lc_dsa_keypair_seed(l,pk,sk,seed,raw,16,&s);
    if(rc!=-2||s.lifo_errors||s.arena_remaining) return 6;
    rc=lc_dsa_keypair(l,pk,sk,raw,131072,&s); if(rc) return 7;
    rc=lc_dsa_sign(l,sig,msg,sizeof(msg),NULL,0,sk,raw,131072,&s); if(rc) return 8;
    rc=lc_dsa_verify(l,sig,lc_dsa_size(l,2),msg,sizeof(msg),NULL,0,pk,raw,131072,&s); if(rc) return 9;
  }
  free(raw); puts("{\"status\":\"PASS\",\"scope\":\"three_parameter_smoke_not_full_validation\"}"); return 0;
}
