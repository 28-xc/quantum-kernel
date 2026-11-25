/* Baseline x86-64 host query. This file is independent of the measured cores. */
#include <stddef.h>
#include <stdint.h>
#include <cpuid.h>

__attribute__((dllexport)) int lc_host_query(uint32_t *out, size_t count)
{
    unsigned a=0,b=0,c=0,d=0;
    if (out == NULL || count != 13) return -1;
    for (size_t i=0;i<count;i++) out[i]=0;
    out[0]=1;
    unsigned maximum=__get_cpuid_max(0, NULL);
    if (maximum>=1) {
        __cpuid_count(1,0,a,b,c,d); out[1]=c;out[2]=d;
        if ((c & (1u<<27)) != 0) {
            unsigned lo,hi;
            __asm__ volatile("xgetbv" : "=a"(lo),"=d"(hi) : "c"(0));
            out[8]=lo;out[9]=hi;
        }
    }
    if (maximum>=7) {
        __cpuid_count(7,0,a,b,c,d);out[3]=b;out[4]=c;out[5]=d;
        if (a>=1) {__cpuid_count(7,1,a,b,c,d);out[6]=a;}
    }
    if (__get_cpuid_max(0x80000000u,NULL)>=0x80000001u) {
        __cpuid_count(0x80000001u,0,a,b,c,d);out[7]=c;out[11]=d;
    }
    if (maximum>=13) {__cpuid_count(13,1,a,b,c,d);out[10]=a;}
    if (maximum>=0x14) {__cpuid_count(0x14,0,a,b,c,d);out[12]=b;}
    return 0;
}
