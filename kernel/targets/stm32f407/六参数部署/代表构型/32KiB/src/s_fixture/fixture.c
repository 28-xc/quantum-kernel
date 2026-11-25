/* Reconstruction of archived public ML-DSA fixtures. The production SHAKE, NTT, keygen
   and signature functions are never called by this independent reader. Integer transforms
   use standard residues and radix-2 roots, with a fixed-width reducer for the public data. */
#include "fixture_hash.c"
#define MOD 8380417
typedef struct { int32_t a[256], b[256]; unsigned char expanded[128],small[256]; } fixture_work;
static int32_t canon(int32_t a){a%=MOD;return a<0?a+MOD:a;}
/* 2^23 = 8191 mod MOD; two folds reduce 46-bit products before the final 32-bit remainder. */
static int32_t product(int32_t a,int32_t b){
 uint64_t u=(uint64_t)(unsigned)a*(unsigned)b;
 u=(u&8388607)+(u>>23)*8191;
 u=(u&8388607)+(u>>23)*8191;
 u=(u&8388607)+(u>>23)*8191;
 return (int32_t)((unsigned)u % MOD);
}
static int32_t power(int32_t a,unsigned n){int32_t b=1;for(;n;n>>=1){if(n&1)b=product(b,a);a=product(a,a);}return b;}
static unsigned rev8(unsigned a){unsigned v=0;for(unsigned i=0;i<8;i++){v=2*v+(a&1);a>>=1;}return v;}
static void transform(int32_t a[256],int inverse){
 unsigned k=inverse?256:0;
 for(unsigned layer=0;layer<8;layer++){
  unsigned len=inverse?(1u<<layer):(128u>>layer);
  for(unsigned start=0;start<256;start+=2*len){
   int32_t z=power(1753,rev8(inverse?--k:++k));if(inverse)z=MOD-z;
   for(unsigned i=start;i<start+len;i++){
    int32_t x=a[i],y=a[i+len];if(inverse){a[i]=canon(x+y);a[i+len]=product(z,canon(x-y));}
    else{int32_t t=product(z,y);a[i]=canon(x+t);a[i+len]=canon(x-t);}
   }
  }
 }
 if(inverse)for(unsigned i=0;i<256;i++)a[i]=product(a[i],8347681);
}
static unsigned getbits(const unsigned char *b,unsigned off,unsigned w){
 unsigned v=0;for(unsigned k=0;k<w;k++)v|=((b[(off+k)>>3]>>((off+k)&7))&1u)<<k;return v;
}
static void writebits(unsigned char *b,unsigned off,unsigned w,unsigned v){
 for(unsigned k=0;k<w;k++)b[(off+k)>>3]|=((v>>k)&1u)<<((off+k)&7);
}
static int shape(unsigned p,unsigned *k,unsigned *l,unsigned *eta){
 *k=p==44?4:p==65?6:8;*l=p==44?4:p==65?5:7;*eta=p==65?4:2;return *eta==4?4:3;
}
static void sample_eta(int32_t *v,const unsigned char *seed,unsigned j,unsigned eta){
 unsigned char nonce[2]={j,j>>8};fixture_xof x;xof(seed,64,nonce,2,136,&x);
 unsigned n=0;while(n<256){unsigned b=take(&x);for(int h=0;h<2 && n<256;h++,b>>=4){unsigned t=b&15;
  if(eta==2?t<15:t<9)v[n++]=eta-(int)(eta==2?t%5:t);
 }}
}
static int scalar_equal(int a,int b){return a==b;}
/* If dst is provided, materialise the whole original key for SigGen; for KeyGen,
   compare every encoded coefficient and all prefix fields directly, in their original widths. */
int a127_kat_key(unsigned p,const unsigned char *seed_or_prefix,int from_seed,unsigned char *workspace,
                 const unsigned char *pk,const unsigned char *sk,unsigned char *dst){
 fixture_work *w=(fixture_work*)workspace; unsigned k,l,eta;unsigned bits=shape(p,&k,&l,&eta),part=bits*32;
 unsigned prefix_bytes=128+(l+k)*part; const unsigned char *prefix=seed_or_prefix;
 int equal=1;unsigned char pair[2]={k,l};fixture_xof h;unsigned char *expanded=w->expanded;
 if(from_seed==1){xof(seed_or_prefix,32,pair,2,136,&h);squeeze(&h,expanded,128);equal&=!memcmp(expanded,pk,32)&&!memcmp(expanded,sk,32)&&!memcmp(expanded+96,sk+32,32);
  xof(pk,k*320+32,0,0,136,&h);squeeze(&h,w->small,64);equal&=!memcmp(w->small,sk+64,64);
 }else if(dst){
  if(from_seed<0){memcpy(dst,prefix,32);memset(dst+32,0,k*320);}
  else{memcpy(dst,prefix,prefix_bytes);memset(dst+prefix_bytes,0,k*416);}
 }
 for(unsigned row=0;row<k;row++){
  memset(w->a,0,1024);
  for(unsigned col=0;col<l;col++){
   if(from_seed==1)sample_eta(w->b,expanded+32,col,eta);
   else for(unsigned i=0;i<256;i++)w->b[i]=(int)eta-(int)getbits(prefix+(from_seed<0?32:128)+col*part,i*bits,bits);
   for(unsigned i=0;i<256;i++){
    if(from_seed==1)equal&=scalar_equal((int)getbits(sk+128+col*part,i*bits,bits),(int)eta-w->b[i]);
    w->b[i]=canon(w->b[i]);
   }
   transform(w->b,0);
   pair[0]=col;pair[1]=row;xof(from_seed==1?expanded:prefix,32,pair,2,168,&h);
   for(unsigned i=0;i<256;){unsigned a=take(&h);a|=take(&h)<<8;a|=(take(&h)&127)<<16;
    if(a<MOD){w->a[i]=canon(w->a[i]+product(a,w->b[i]));i++;}
   }
  }
  transform(w->a,1);
  if(from_seed==1)sample_eta(w->b,expanded+32,row+l,eta);
  for(unsigned i=0;i<256;i++){
   int32_t e=from_seed==1?w->b[i]:(int)eta-(int)getbits(prefix+(from_seed<0?32:128)+(l+row)*part,i*bits,bits);
   if(from_seed==1)equal&=scalar_equal((int)getbits(sk+128+(l+row)*part,i*bits,bits),(int)eta-e);
   int32_t a=canon(w->a[i]+e),high=(a+4095)>>13,low=4096-(a-(high<<13));
   if(from_seed==1){equal&=scalar_equal(getbits(pk+32+row*320,i*10,10),high);equal&=scalar_equal(getbits(sk+prefix_bytes+row*416,i*13,13),low);}
   else if(from_seed<0)writebits(dst+32+row*320,i*10,10,(unsigned)high);
   else writebits(dst+prefix_bytes+row*416,i*13,13,(unsigned)low);
  }
 }
 memset(w,0,sizeof(*w));return equal;
}
/* Recreate z using the original public KAT's committed challenge, accepted mask index,
   input secret key, message, context, and explicitly supplied randomness. Hints and
   the challenge remain physically resident. This does not search signing candidates. */
int a127_kat_sig(unsigned p,const unsigned char *rep,const unsigned char *sk,
 const unsigned char *msg,unsigned mn,const unsigned char *ctx,unsigned cn,const unsigned char *rnd,
 const unsigned char *sig,unsigned char *workspace){
 fixture_work *w=(fixture_work*)workspace; unsigned k,l,eta,bits=shape(p,&k,&l,&eta);
 unsigned cw=p==44?32:p==65?48:64,tau=p==44?39:p==65?49:60,zb=p==44?18:20;
 unsigned hint=(p==44?80:p==65?55:75)+k; int equal=!memcmp(rep+1,sig,cw)&&!memcmp(rep+1+cw,sig+cw+zb*32*l,hint);
 fixture_xof h; unsigned char context_prefix[2]={0,cn};unsigned char *mu=w->expanded,*rhoprime=w->expanded+64;
 xinit(&h,136);absorb(&h,sk+64,64);absorb(&h,context_prefix,2);absorb(&h,ctx,cn);absorb(&h,msg,mn);finish(&h,31);squeeze(&h,mu,64);
 xinit(&h,136);absorb(&h,sk+32,32);absorb(&h,rnd,32);absorb(&h,mu,64);finish(&h,31);squeeze(&h,rhoprime,64);
 xof(rep+1,cw,0,0,136,&h);unsigned char signs[8];squeeze(&h,signs,8);memset(w->small,0,256);
 for(unsigned i=256-tau;i<256;i++){
  unsigned b;do{b=take(&h);}while(b>i);w->small[i]=w->small[b];unsigned j=i-(256-tau);w->small[b]=(signs[j/8]>>(j%8)&1)?255:1;
 }
 for(unsigned col=0;col<l;col++){
  unsigned value=l*rep[0]+col;unsigned char nonce[2]={value,value>>8};xof(rhoprime,64,nonce,2,136,&h);
  for(unsigned i=0;i<256;i++)w->b[i]=(int)eta-(int)getbits(sk+128+col*bits*32,i*bits,bits);
  unsigned buf=0,available=0;
  for(unsigned i=0;i<256;i++){
   while(available<zb){buf|=take(&h)<<available;available+=8;}
   int z=(int)(buf&((1u<<zb)-1));buf>>=zb;available-=zb;
   for(unsigned j=0;j<256;j++){int v=(signed char)w->small[j];if(v)z-=(j<=i?1:-1)*v*w->b[(i-j)&255];}
   equal&=scalar_equal(z,(int)getbits(sig+cw+col*zb*32,i*zb,zb));
  }
 }
 memset(w,0,sizeof(*w));return equal;
}
/* Independent FIPS 203 KeyGen fixture reconstruction in the normal coefficient
   representation. SampleNTT data are already in the bit-reversed CRT domain. */
static int kcanon(int v){v%=3329;return v<0?v+3329:v;}
static int kpow(unsigned n){int a=17,b=1;for(;n;n>>=1){if(n&1)b=b*a%3329;a=a*a%3329;}return b;}
static void kem_forward(int32_t *a){
 unsigned k=0;for(unsigned len=128;len>=2;len>>=1)for(unsigned s=0;s<256;s+=2*len){
  int z=kpow(rev8(++k)>>1);for(unsigned j=s;j<s+len;j++){int t=z*a[j+len]%3329,u=a[j];a[j+len]=kcanon(u-t);a[j]=(u+t)%3329;}
 }
}
static void kem_noise(int32_t *a,const unsigned char *noise,unsigned eta,unsigned nonce){
 unsigned char j=nonce;fixture_xof h;xof(noise,32,&j,1,136,&h);
 unsigned buf=0,n=0;for(unsigned i=0;i<256;i++){
  while(n<2*eta){buf|=take(&h)<<n;n+=8;}int v=0;for(unsigned b=0;b<eta;b++)v+=(int)((buf>>b)&1)-(int)((buf>>(b+eta))&1);
  a[i]=kcanon(v);buf>>=2*eta;n-=2*eta;
 }kem_forward(a);
}
static void sample_matrix(int32_t *a,const unsigned char *rho,unsigned row,unsigned col){
 unsigned char j[2]={col,row};fixture_xof h;xof(rho,32,j,2,168,&h);
 for(unsigned i=0;i<256;){unsigned x=take(&h);x|=take(&h)<<8;x|=take(&h)<<16;unsigned l=x&4095,r=x>>12;
  if(l<3329)a[i++]=l;if(i<256 && r<3329)a[i++]=r;
 }
}
int a127_kat_kem_key(unsigned p,const unsigned char *coins,const unsigned char *pk,const unsigned char *sk,unsigned char *workspace){
 unsigned rank=p==512?2:p==768?3:4,eta=p==512?3:2;int32_t *a=(int32_t*)workspace,*b=a+256,*s=b+256;
 fixture_xof h;unsigned char expanded[64],tag=rank,hpk[32]; unsigned length=384*rank+32;
 xinit(&h,72);absorb(&h,coins,32);absorb(&h,&tag,1);finish(&h,6);squeeze(&h,expanded,64);
 xinit(&h,136);absorb(&h,pk,length);finish(&h,6);squeeze(&h,hpk,32);
 int ok=!memcmp(pk+384*rank,expanded,32)&&!memcmp(sk+384*rank,pk,length)&&!memcmp(sk+384*rank+length,hpk,32)&&!memcmp(sk+384*rank+length+32,coins+32,32);
 for(unsigned row=0;row<rank;row++){
  kem_noise(a,expanded+32,eta,rank+row);
  for(unsigned col=0;col<rank;col++){
   kem_noise(s,expanded+32,eta,col);sample_matrix(b,expanded,row,col);
   for(unsigned i=0;i<256;i++)ok&=scalar_equal(s[i],getbits(sk+384*col,12*i,12));
   for(unsigned i=0;i<128;i++){int z=kpow(rev8(64+i/2)>>1);if(i%2)z=3329-z;
    unsigned j=2*i;int t=(b[j+1]*s[j+1])%3329;
    a[j]=(a[j]+b[j]*s[j]+t*z)%3329;a[j+1]=(a[j+1]+b[j]*s[j+1]+b[j+1]*s[j])%3329;}
  }
  for(unsigned i=0;i<256;i++)ok&=scalar_equal(a[i],getbits(pk+384*row,12*i,12));
 }
 memset(workspace,0,3*1024);return ok;
}
