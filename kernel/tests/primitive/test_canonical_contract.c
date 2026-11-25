#include "lc_poly.h"
#include <stdio.h>
#include <string.h>
int main(void){
 uint32_t a[256],b[256],c[256],saved[256],qs[]={0,769,UINT32_MAX};
 for(unsigned i=0;i<256;i++){a[i]=i;b[i]=255-i;c[i]=0xa127a127;}
 memcpy(saved,c,sizeof c);
 for(unsigned j=0;j<3;j++){
  uint32_t q=qs[j];
  if(lc_poly_ntt(q,c)!=-1||lc_poly_intt(q,c)!=-1||lc_poly_basemul(q,c,a,b)!=-1||lc_poly_mul(q,c,a,b)!=-1||lc_poly_add(q,c,a,b)!=-1||lc_poly_sub(q,c,a,b)!=-1)return 1;
  if(memcmp(c,saved,sizeof c))return 2;
 }
 for(unsigned j=0;j<2;j++){
  uint32_t q=j?8380417:3329;
  for(unsigned i=0;i<256;i++){a[i]=i&1?q-1:0;b[i]=i&1?0:q-1;}
  memcpy(saved,a,sizeof a);if(lc_poly_add(q,a,a,b)||lc_poly_sub(q,a,a,b)||memcmp(a,saved,sizeof a))return 3;
  if(lc_poly_ntt(q,a))return 4;
  for(unsigned i=0;i<256;i++)if(a[i]>=q)return 5;
  if(lc_poly_intt(q,a)||memcmp(a,saved,sizeof a))return 6;
 }
 puts("{\"status\":\"PASS\",\"unsupported_modulus_cases\":18,\"unsupported_output_unchanged\":true,\"canonical_range_and_inplace_add_sub\":true}");return 0;
}
