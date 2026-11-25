/* Independent, portable FIPS 202 byte-oriented test-fixture XOF. Only KAT uses this code. */
#include <stdint.h>
#include <stddef.h>
#ifdef __arm__
extern void *memset(void *,int,size_t);extern void *memcpy(void *,const void *,size_t);extern int memcmp(const void*,const void*,size_t);
#else
#include <string.h>
#endif
typedef struct { uint64_t lanes[25]; unsigned rate, pos; } fixture_xof;
static uint64_t rol(uint64_t a, unsigned n) { return (a << n) | (a >> (64-n)); }
static void keccak(fixture_xof *s) {
    static const unsigned char rotations[24]={1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44};
    static const unsigned char pi[24]={10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1};
    uint64_t *a=s->lanes, row[5]; unsigned char lfsr=1;
    for(unsigned round=0;round<24;round++) {
        for(unsigned x=0;x<5;x++)row[x]=a[x]^a[x+5]^a[x+10]^a[x+15]^a[x+20];
        for(unsigned x=0;x<5;x++) {
            uint64_t d=row[(x+4)%5]^rol(row[(x+1)%5],1);
            for(unsigned i=x;i<25;i+=5)a[i]^=d;
        }
        uint64_t cur=a[1];
        for(unsigned t=0;t<24;t++){unsigned i=pi[t];uint64_t v=a[i];a[i]=rol(cur,rotations[t]);cur=v;}
        for(unsigned y=0;y<25;y+=5){
            for(unsigned x=0;x<5;x++)row[x]=a[y+x];
            for(unsigned x=0;x<5;x++)a[y+x]=row[x]^((~row[(x+1)%5])&row[(x+2)%5]);
        }
        for(unsigned j=0;j<7;j++){
            if(lfsr&1)a[0]^=(uint64_t)1<<((1u<<j)-1);
            lfsr=(lfsr<<1)^((lfsr&0x80)?0x71:0);
        }
    }
}
static void xinit(fixture_xof *s,unsigned rate){memset(s,0,sizeof(*s));s->rate=rate;}
static void absorb(fixture_xof *s,const unsigned char *v,unsigned len) {
    unsigned char *state=(unsigned char *)s->lanes;
    while(len--){state[s->pos++]^=*v++;if(s->pos==s->rate){keccak(s);s->pos=0;}}
}
static void finish(fixture_xof *s,unsigned suffix){unsigned char *a=(unsigned char*)s->lanes;a[s->pos]^=suffix;a[s->rate-1]^=128;s->pos=s->rate;}
static unsigned take(fixture_xof *s){if(s->pos==s->rate){keccak(s);s->pos=0;}return ((unsigned char*)s->lanes)[s->pos++];}
static void squeeze(fixture_xof *s,unsigned char *out,unsigned n){while(n--)*out++=(unsigned char)take(s);}
static void xof(const unsigned char *s,unsigned n,const unsigned char *t,unsigned m,unsigned rate,fixture_xof *x){xinit(x,rate);absorb(x,s,n);absorb(x,t,m);finish(x,31);}
void a127_kat_shake(unsigned char *out,const unsigned char *in,unsigned n){fixture_xof x;xof(in,n,0,0,136,&x);squeeze(&x,out,32);}
