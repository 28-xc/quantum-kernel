#include "lc_poly.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
/* Test-only PRNG, never used for keys. */
static uint64_t state=0xa12720260923ULL;
static uint32_t rnd(void){state^=state<<13;state^=state>>7;state^=state<<17;return (uint32_t)state;}
static void oracle(uint32_t q,uint32_t c[256],const uint32_t a[256],const uint32_t b[256]) {
    int64_t acc[256]={0};unsigned i,j;
    for(i=0;i<256;i++)for(j=0;j<256;j++) {
        int64_t t=(int64_t)a[i]*b[j];
        if(i+j<256)acc[i+j]+=t;else acc[i+j-256]-=t;
    }
    for(i=0;i<256;i++){int64_t x=acc[i]%q;if(x<0)x+=q;c[i]=(uint32_t)x;}
}
int main(void){
    unsigned f,n,i;uint32_t qs[2]={3329,8380417};
    for(f=0;f<2;f++) {
        uint32_t q=qs[f],a[256],b[256],c[256],ref[256],x[256];
        for(n=0;n<10000;n++) {
            for(i=0;i<256;i++){a[i]=rnd()%q;b[i]=rnd()%q;}
            if(n==0)memset(a,0,sizeof a);
            if(n==1)for(i=0;i<256;i++)a[i]=b[i]=q-1;
            if(n==2){memset(a,0,sizeof a);memset(b,0,sizeof b);a[255]=b[1]=1;}
            memcpy(x,a,sizeof x);lc_poly_ntt(q,x);lc_poly_intt(q,x);
            if(memcmp(x,a,sizeof a)){printf("FAIL roundtrip q=%u n=%u\n",q,n);return 1;}
            lc_poly_add(q,x,a,b);lc_poly_sub(q,x,x,b);
            if(memcmp(x,a,sizeof a)){puts("FAIL add/sub");return 2;}
            if(n<2000){lc_poly_mul(q,c,a,b);oracle(q,ref,a,b);if(memcmp(c,ref,sizeof c)){printf("FAIL convolution q=%u n=%u\n",q,n);return 3;}}
        }
        printf("{\"q\":%u,\"roundtrip_cases\":10000,\"add_sub_cases\":10000,\"independent_convolution_cases\":2000,\"status\":\"PASS\"}\n",q);
    }return 0;
}
