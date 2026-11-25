
typedef long long int int64_t;
typedef long long unsigned int uint64_t;
typedef int64_t int_least64_t;
typedef uint64_t uint_least64_t;
typedef int64_t int_fast64_t;
typedef uint64_t uint_fast64_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef int32_t int_least32_t;
typedef uint32_t uint_least32_t;
typedef int32_t int_fast32_t;
typedef uint32_t uint_fast32_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int16_t int_least16_t;
typedef uint16_t uint_least16_t;
typedef int16_t int_fast16_t;
typedef uint16_t uint_fast16_t;
typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef int8_t int_least8_t;
typedef uint8_t uint_least8_t;
typedef int8_t int_fast8_t;
typedef uint8_t uint_fast8_t;
typedef int intptr_t;
typedef unsigned int uintptr_t;
typedef long long int intmax_t;
typedef long long unsigned int uintmax_t;
typedef int ptrdiff_t;
typedef unsigned int size_t;
typedef unsigned int wchar_t;
typedef struct {
  long long __clang_max_align_nonce1
      __attribute__((__aligned__(__alignof__(long long))));
  long double __clang_max_align_nonce2
      __attribute__((__aligned__(__alignof__(long double))));
} max_align_t;
enum { M4_HELLO=1,M4_RUN=2,M4_KAT=3,M4_BOUNDARY=4,M4_CLOCK=5,M4_RETURN_DFU=6,M4_TIMING=7,M4_POLY=8 };
typedef struct {uint32_t w[16];} m4_request;
typedef struct {uint32_t w[64];} m4_response;
void experiment(const m4_request*,m4_response*);
void hardware_info(m4_response*);
void clear_bytes(void*,size_t);
uint32_t m4_checksum(const void*,size_t);
void reset_to_dfu(void) __attribute__((noreturn));
uint32_t stack_used(void);
uint32_t cycle_stamp(void);
void board_start(void) __attribute__((noreturn));
extern uint32_t __stack_bottom[],__stack_top[];
extern const uint8_t __flash_start[], __image_bytes[];
static uint32_t ror(uint32_t x,unsigned n){return x>>n|x<<(32-n);}
static uint32_t rd(const uint8_t *b){return (uint32_t)b[0]<<24|(uint32_t)b[1]<<16|(uint32_t)b[2]<<8|b[3];}
static void wr(uint8_t *b,uint32_t x){b[0]=x>>24;b[1]=x>>16;b[2]=x>>8;b[3]=x;}
static const uint32_t k[64]={
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
static void block(uint32_t s[8],const uint8_t b[64]){
    uint32_t w[16],a=s[0],v=s[1],c=s[2],d=s[3],e=s[4],f=s[5],g=s[6],h=s[7];
    for(unsigned i=0;i<64;i++){
        unsigned j=i&15;
        if(i<16)w[j]=rd(b+4*i);
        else{uint32_t x=w[(j+1)&15],y=w[(j+14)&15];
            w[j]+=(ror(x,7)^ror(x,18)^(x>>3))+w[(j+9)&15]+(ror(y,17)^ror(y,19)^(y>>10));}
        uint32_t t=h+(ror(e,6)^ror(e,11)^ror(e,25))+((e&f)^(~e&g))+k[i]+w[j];
        uint32_t z=(ror(a,2)^ror(a,13)^ror(a,22))+((a&v)^(a&c)^(v&c));
        h=g;g=f;f=e;e=d+t;d=c;c=v;v=a;a=t+z;
    }
    s[0]+=a;s[1]+=v;s[2]+=c;s[3]+=d;s[4]+=e;s[5]+=f;s[6]+=g;s[7]+=h;
}
void unified_hash(m4_response *rsp){
    const uint8_t *data=__flash_start;
    unsigned size=(uintptr_t)__image_bytes,left=size;
    uint32_t s[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    uint8_t tail[64]={0};
    while(left>=64){block(s,data);data+=64;left-=64;}
    for(unsigned i=0;i<left;i++)tail[i]=data[i];
    tail[left]=0x80;
    if(left>=56){block(s,tail);for(unsigned i=0;i<64;i++)tail[i]=0;}
    wr(tail+60,size*8u);block(s,tail);
    for(unsigned j=0;j<8;j++)wr((uint8_t*)(rsp->w+41)+j*4,s[j]);
    rsp->w[23]=1;rsp->w[49]=(uintptr_t)__flash_start;rsp->w[50]=size;
}
