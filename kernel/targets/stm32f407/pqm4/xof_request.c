#include "board.h"
#include <string.h>
extern int a127_public_xof(unsigned bits,uint8_t *out,size_t out_len,const uint8_t *input,size_t input_len,int split);
void xof_request(const m4_request*q,m4_response*r){
  uint8_t in[360],out[504];
  unsigned bits=q->w[10],ilen=q->w[11],olen=q->w[12],off=q->w[13];
  if((bits!=128&&bits!=256)||ilen>sizeof(in)||olen>353||off>olen)return;
  const uint8_t *challenge=(const uint8_t*)(q->w+4);
  for(unsigned i=0;i<ilen;i++)in[i]=(uint8_t)(7u+13u*i+challenge[i&15u]);
  if(!a127_public_xof(bits,out,olen,in,ilen,q->w[14]&1))return;
  unsigned take=olen-off;if(take>48)take=48;
  memcpy(r->w+24,out+off,take);r->w[23]=1;r->w[41]=olen;r->w[42]=off;r->w[43]=take;
  clear_bytes(out,sizeof(out));clear_bytes(in,sizeof(in));
}

