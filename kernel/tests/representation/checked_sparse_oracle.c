#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lc_sparse8_blocks.h"
#include "lc_dsa_keycheck.h"
static uint32_t rng=0x6182bc35u;
static uint32_t next(void){rng^=rng<<13;rng^=rng>>17;rng^=rng<<5;return rng;}
static unsigned count=0,canonical_count=0,noncanonical_count=0;
static void run(unsigned level,unsigned tau,unsigned eta,unsigned phase,unsigned pattern,unsigned pos,unsigned code){
 unsigned bits=eta==2?3:4;uint8_t sk[4896]={0},index[61];int secret[256];
 uint8_t *packed=sk+128;
 for(unsigned j=0;j<256;j++){
  unsigned v=pattern==0?0:pattern==1?2*eta:pattern==2?(j&1?0:2*eta):next()%(2*eta+1);
  if(j==pos)v=code;
  secret[j]=(int)eta-(int)v;
  unsigned bit=j*bits;packed[bit/8]|=(uint8_t)(v<<(bit%8));
  if(bit%8+bits>8)packed[bit/8+1]|=(uint8_t)(v>>(8-bit%8));
 }
 unsigned canon=(unsigned)lc_dsa_secret_encoding_valid((int)level,sk);
 unsigned expected=1;for(unsigned j=0;j<256;j++)expected&=(unsigned)(secret[j]>=-(int)eta&&secret[j]<=(int)eta);
 if(canon!=expected){fprintf(stderr,"encoding gate mismatch\n");exit(1);}
 index[0]=(uint8_t)(phase==0?0:phase==1?tau:tau/2);
 for(unsigned j=1;j<=tau;j++)index[j]=(uint8_t)((j*37+17)&255);
 _Alignas(32) uint8_t owner[1088];memset(owner,0xa5,sizeof(owner));
 unsigned chunk=canon?(eta==2?60:31):(eta==2?25:11);
 lc_sparse8_product_i16((int32_t*)(void*)(owner+32),packed,index,tau,chunk);
 for(unsigned j=0;j<256;j++){
  int want=0;for(unsigned k=1;k<=tau;k++){
   int n=(int)j-(int)index[k],term=secret[n&255];if(n<0)term=-term;
   want+=k<=index[0]?term:-term;
  }
  int16_t actual;memcpy(&actual,owner+32+512+2*j,2);
  if(actual!=want){fprintf(stderr,"product mismatch L%u pattern%u pos%u code%u coeff%u got%d want%d\n",level,pattern,pos,code,j,actual,want);exit(2);}
 }
 for(unsigned j=0;j<32;j++)if(owner[j]!=0xa5||owner[1056+j]!=0xa5){fprintf(stderr,"guard mismatch\n");exit(3);}
 count++;canonical_count+=canon;noncanonical_count+=1-canon;
}
int main(void){
 unsigned levels[3]={44,65,87},taus[3]={39,49,60};
 for(unsigned a=0;a<3;a++){
  unsigned eta=a==1?4:2,values=a==1?16:8;
  for(unsigned phase=0;phase<3;phase++)for(unsigned code=0;code<values;code++)for(unsigned pos=0;pos<256;pos++)
   run(levels[a],taus[a],eta,phase,(code+pos)%4,pos,code);
 }
 printf("{\"status\":\"PASS\",\"cases\":%u,\"canonical_cases\":%u,\"malformed_fallback_cases\":%u,\"coefficients\":%u}\n",count,canonical_count,noncanonical_count,count*256);return 0;
}
