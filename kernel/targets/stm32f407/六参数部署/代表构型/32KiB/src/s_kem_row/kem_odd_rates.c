
#include <stdint.h>
extern void *memset(void *,int,__SIZE_TYPE__);
extern void a127_rho_begin(uint32_t *,const uint8_t *);
extern void a127_matrix_begin(uint64_t *,const uint32_t *,unsigned,unsigned);
extern void four34(void *,void *,void *,void *);
extern void two34(void *,void *);
extern void two(void *,void *);
extern void four(void *,void *,void *,void *);
extern void a127_extract_words(const void *,void *,unsigned);
extern void three(void*,void*,void*);
extern void three34(void*,void*,void*);
static void permute_group(uint64_t **s,unsigned n,unsigned first){
   if(n==4){
      if(first)four34(s[0],s[1],s[2],s[3]);else four(s[0],s[1],s[2],s[3]);
   } else if(n==3){
      if(first)three34(s[0],s[1],s[2]);else three(s[0],s[1],s[2]);
   } else {
      if(n>=2){if(first)two34(s[0],s[1]);else two(s[0],s[1]);}
      if(n&1u){if(first)two34(s[n-1],0);else two(s[n-1],0);}
   }
}
static uint32_t word_at(const int16_t *a){
    uint32_t w;__asm__("ldr %0,[%1]":"=r"(w):"r"(a):"memory");return w;
}
static int16_t reduce_mont(int32_t a){
    /* q=3329, q^-1=-3327 mod 2^16. The live accumulator has at most
       four signed-halfword pair products of bounded NTT representatives. */
    int16_t t=(int16_t)((uint32_t)a*62209u);
    return (int16_t)((a-(int32_t)t*3329)>>16);
}
static inline void merge(unsigned *done,int16_t *carry,int32_t *acc,const int16_t *v,
                         const int16_t *cache,const uint8_t *block){
    int16_t words[114] __attribute__((aligned(4)));
    unsigned n=0,remaining=256u-(*done&~1u);
    if(*done&1u)words[n++]=*carry;
    for(unsigned i=0;i<168 && n<remaining;i+=3){
        unsigned x=block[i]|(unsigned)block[i+1]<<8|(unsigned)block[i+2]<<16;
        unsigned a=x&4095u,b=x>>12;
        if(a<3329u)words[n++]=(int16_t)a;
        if(b<3329u && n<remaining)words[n++]=(int16_t)b;
    }
    unsigned accepted=(*done&~1u)+n;
    unsigned start=*done>>1;
    for(unsigned j=0;j<n/2;j++){
        unsigned i=start+j;uint32_t x=word_at(words+2*j), y=word_at(v+2*i);
        uint32_t rhs;int32_t e=acc[2*i],o=acc[2*i+1];
        __asm__("pkhbt %0,%1,%2,lsl #16":"=r"(rhs):"r"(y),"r"((uint32_t)(uint16_t)cache[i]));
        __asm__("smlad %0,%1,%2,%0":"+r"(e):"r"(x),"r"(rhs));
        __asm__("smladx %0,%1,%2,%0":"+r"(o):"r"(x),"r"(y));
        acc[2*i]=e;acc[2*i+1]=o;
    }
    if(n&1u)*carry=words[n-1];
    *done=accepted;
}
void a127_kem_four_row(int16_t *out,void *scratch,const uint8_t *rho,unsigned k,unsigned row,
                       unsigned transpose,const int16_t *v,const int16_t *cache){
    int32_t *acc=scratch;
    uint64_t upper[2][25];uint8_t block[168];uint32_t rho_bits[8];
    uint64_t *states[4]={(uint64_t *)(void *)out,(uint64_t *)(void *)(out+100),upper[0],upper[1]};
    unsigned count[4]={0,0,0,0},first=1;int16_t carry[4]={0,0,0,0};
    memset(acc,0,1024);a127_rho_begin(rho_bits,rho);
    for(unsigned j=0;j<k;j++)a127_matrix_begin(states[j],rho_bits,transpose?row:j,transpose?j:row);
    for(;;){
        unsigned active[4],m=0;uint64_t *work[4];
        for(unsigned j=0;j<k;j++)if(count[j]<256){active[m]=j;work[m++]=states[j];}
        if(!m)break;
        permute_group(work,m,first);first=0;
        for(unsigned i=0;i<m;i++){
            unsigned j=active[i];a127_extract_words(states[j],block,21);
            merge(count+j,carry+j,acc,v+256*j,cache+128*j,block);
        }
    }
    for(unsigned i=0;i<256;i++)out[i]=reduce_mont(acc[i]);
    /* upper, block, and rho_bits contain public SHAKE128 outputs only.
       The secret input vector and products stay in caller-owned storage
       with its existing fixed-size clear, in both success and error paths. */
}
