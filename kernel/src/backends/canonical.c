#include "lc_poly.h"
#include <string.h>
#include "canonical_generated.inc"
/* Standalone component: retain volatile erasure without an arena dependency. */
static void lc_poly_erase(void *p,size_t n) {
    volatile unsigned char *b=(volatile unsigned char *)p;
    while(n--) *b++=0;
}
int lc_poly_ntt(uint32_t q,uint32_t a[256]) {
    if(q==3329) q3329_ntt(a); else if(q==8380417) q8380417_ntt(a); else return -1; return 0;
}
int lc_poly_intt(uint32_t q,uint32_t a[256]) {
    if(q==3329) q3329_intt(a); else if(q==8380417) q8380417_intt(a); else return -1; return 0;
}
int lc_poly_basemul(uint32_t q,uint32_t c[256],const uint32_t a[256],const uint32_t b[256]) {
    if(q==3329) q3329_base(c,a,b); else if(q==8380417) q8380417_base(c,a,b); else return -1; return 0;
}
int lc_poly_mul(uint32_t q,uint32_t c[256],const uint32_t a[256],const uint32_t b[256]) {
    uint32_t x[256],y[256];
    if(q!=3329 && q!=8380417) return -1;
    memcpy(x,a,sizeof x);memcpy(y,b,sizeof y);lc_poly_ntt(q,x);lc_poly_ntt(q,y);
    lc_poly_basemul(q,c,x,y);lc_poly_intt(q,c);lc_poly_erase(x,sizeof x);lc_poly_erase(y,sizeof y);return 0;
}
int lc_poly_add(uint32_t q,uint32_t c[256],const uint32_t a[256],const uint32_t b[256]) {
    unsigned i;if(q==3329)for(i=0;i<256;i++)c[i]=q3329_add(a[i],b[i]);
    else if(q==8380417)for(i=0;i<256;i++)c[i]=q8380417_add(a[i],b[i]);else return -1;
    return 0;
}
int lc_poly_sub(uint32_t q,uint32_t c[256],const uint32_t a[256],const uint32_t b[256]) {
    unsigned i;if(q==3329)for(i=0;i<256;i++)c[i]=q3329_sub(a[i],b[i]);
    else if(q==8380417)for(i=0;i<256;i++)c[i]=q8380417_sub(a[i],b[i]);else return -1;
    return 0;
}
