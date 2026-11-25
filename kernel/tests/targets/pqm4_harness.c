/* SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT */
#include "target.h"
#include "api.h"
#include "vectors.h"
#include <string.h>
#define GBUF(name,n) static struct {uint8_t before[32],bytes[n],after[32];} name __attribute__((section(".caller_io"),aligned(32)))
GBUF(pk,CRYPTO_PUBLICKEYBYTES);GBUF(sk,CRYPTO_SECRETKEYBYTES);GBUF(sig,CRYPTO_BYTES);
GBUF(msg,1024);GBUF(dom,255);
static const lc_target_vector *active;
static unsigned operation,generated,failed,cases,entropy_error,entropy_calls,entropy_bytes;
static size_t entropy_position,signature_length,mlen,dlen,max_stack[3];
static uint64_t rng_state=UINT64_C(0x527814289611);
int randombytes(uint8_t *out,size_t n) {
  entropy_calls++;entropy_bytes+=(unsigned)n;
  if(generated) {
    for(size_t i=0;i<n;i++) {rng_state^=rng_state<<13;rng_state^=rng_state>>7;rng_state^=rng_state<<17;out[i]=(uint8_t)rng_state;}
  } else {
    if(entropy_position>active->coins.n || n>active->coins.n-entropy_position) {entropy_error=1;return -1;}
    memcpy(out,active->coins.p+entropy_position,n);entropy_position+=n;
  }
  return 0;
}
#ifdef LC_REFERENCE_CORE
#include "latticecore.h"
static struct {uint8_t before[32],bytes[LC_COMPARISON_WORKSPACE],after[32];} work __attribute__((section(".arena"),aligned(32)));
static lc_context context;
static size_t max_workspace[3];
static int random_callback(void *u,uint8_t*out,size_t n) {(void)u;return randombytes(out,n);}
int crypto_sign_keypair(uint8_t *p,uint8_t *s) {return lc_keypair(&context,LC_PQM4_PARAMETER,p,CRYPTO_PUBLICKEYBYTES,s,CRYPTO_SECRETKEYBYTES);}
int crypto_sign_signature_ctx(uint8_t *s,size_t *sn,const uint8_t*m,size_t mn,const uint8_t*d,size_t dn,const uint8_t*k) {
  int r=lc_sign(&context,LC_PQM4_PARAMETER,s,CRYPTO_BYTES,m,mn,d,dn,k,CRYPTO_SECRETKEYBYTES);*sn=r?0:CRYPTO_BYTES;return r? -1:0;
}
int crypto_sign_verify_ctx(const uint8_t*s,size_t sn,const uint8_t*m,size_t mn,const uint8_t*d,size_t dn,const uint8_t*p) {
  return lc_verify(&context,LC_PQM4_PARAMETER,s,sn,m,mn,d,dn,p,CRYPTO_PUBLICKEYBYTES)? -1:0;
}
#endif
static int fill(const uint8_t*p,size_t n,uint8_t x) {while(n--)if(*p++!=x)return 0;return 1;}
static int guards(void) {
#define CHECK(x) if(!fill(x.before,32,0xa5)||!fill(x.after,32,0xa5))return 0
  CHECK(pk);CHECK(sk);CHECK(sig);CHECK(msg);CHECK(dom);
#ifdef LC_REFERENCE_CORE
  CHECK(work);
#endif
#undef CHECK
  return fill(__test_stack_bottom,32,0xa5);
}
static void paint(void) {memset(__test_stack_bottom,0xa5,(size_t)(__test_stack_top-__test_stack_bottom));}
static size_t watermark(void) {uint8_t*p=__test_stack_bottom;while(p<__test_stack_top&&*p==0xa5)p++;return (size_t)(__test_stack_top-p);}
static int call(void *unused) {
  (void)unused;
  if(operation==0)return crypto_sign_keypair(pk.bytes,sk.bytes);
  if(operation==1)return crypto_sign_signature_ctx(sig.bytes,&signature_length,
    generated?msg.bytes:active->message.p,generated?mlen:active->message.n,
    generated?dom.bytes:active->domain.p,generated?dlen:active->domain.n,
    generated?sk.bytes:active->sk.p);
  return crypto_sign_verify_ctx(generated?sig.bytes:active->signature.p,
    generated?signature_length:active->signature.n,
    generated?msg.bytes:active->message.p,generated?mlen:active->message.n,
    generated?dom.bytes:active->domain.p,generated?dlen:active->domain.n,
    generated?pk.bytes:active->pk.p);
}
static void one(unsigned index,const char *kind,int expected) {
  entropy_calls=entropy_bytes=0;
  paint();int rc=target_call(call,0);size_t used=watermark();int ok=(rc==expected)&&guards()&&!entropy_error;
  if(!generated&&active->accepted) {
    if(operation==0)ok=ok&&!memcmp(pk.bytes,active->expected0.p,CRYPTO_PUBLICKEYBYTES)&&!memcmp(sk.bytes,active->expected1.p,CRYPTO_SECRETKEYBYTES);
    if(operation==1)ok=ok&&signature_length==CRYPTO_BYTES&&!memcmp(sig.bytes,active->expected0.p,CRYPTO_BYTES);
    ok=ok&&entropy_position==active->coins.n;
  }
  if(used>max_stack[operation])max_stack[operation]=used;
#ifdef LC_REFERENCE_CORE
  if(context.arena_high_water>max_workspace[operation])max_workspace[operation]=context.arena_high_water;
#endif
  target_text("{\"event\":\"case\",\"parameter\":");target_uint(LC_PQM4_PARAMETER);
  target_text(",\"index\":");target_uint(index);target_text(",\"operation\":");target_uint(operation);
  target_text(",\"kind\":\"");target_text(kind);target_text("\",\"rc\":");target_int(rc);
  target_text(",\"stack_watermark_bytes\":");target_uint((uint32_t)used);
  target_text(",\"workspace_bytes\":");
#ifdef LC_REFERENCE_CORE
  target_uint((uint32_t)context.arena_high_water);
#else
  target_uint(0);
#endif
  target_text(",\"entropy_requests\":");target_uint(entropy_calls);target_text(",\"entropy_bytes\":");target_uint(entropy_bytes);
  target_text(",\"public_output_hex\":\"");
  if(generated&&operation<2) {
    const uint8_t *p=operation==0?pk.bytes:sig.bytes;size_t n=operation==0?CRYPTO_PUBLICKEYBYTES:CRYPTO_BYTES;
    const char *hex="0123456789abcdef";
    for(size_t i=0;i<n;i++){target_putc(hex[p[i]>>4]);target_putc(hex[p[i]&15]);}
  }
  target_text("\",\"ok\":");target_text(ok?"true":"false");target_text("}\n");
  cases++;if(!ok)failed++;
}
int target_main(void) {
  /* M4F upstream code uses FP registers as integer storage. Enable CP10/11
   * without changing its arithmetic or its function calling convention. */
  *(volatile uint32_t*)0xe000ed88u|=0x00f00000u;
  __asm__ volatile("dsb\nisb":::"memory");
  memset(&pk,0xa5,sizeof(pk));memset(&sk,0xa5,sizeof(sk));memset(&sig,0xa5,sizeof(sig));
  memset(&msg,0xa5,sizeof(msg));memset(&dom,0xa5,sizeof(dom));
  target_text("{\"event\":\"begin\",\"implementation\":\"");
#ifdef LC_REFERENCE_CORE
  memset(&work,0xa5,sizeof(work));
  if(lc_context_init(&context,work.bytes,sizeof(work.bytes),random_callback,NULL))return 1;
  target_text(LC_COMPARISON_PROFILE);
#else
  target_text("pqm4-m4fstack");
#endif
  target_text("\",\"parameter\":");target_uint(LC_PQM4_PARAMETER);
  target_text(",\"pointer_bits\":32,\"timing_collected\":false}\n");
  paint();__test_stack_bottom[64]=0;
  int control=watermark()==(size_t)(__test_stack_top-__test_stack_bottom)-64;
  target_text("{\"event\":\"watermark_positive_control\",\"ok\":");target_text(control?"true":"false");target_text("}\n");if(!control)failed++;
  for(unsigned i=0;i<LC_TARGET_VECTOR_COUNT;i++)if(target_vectors[i].parameter==LC_PQM4_PARAMETER) {
    active=&target_vectors[i];operation=active->operation;generated=0;entropy_position=0;entropy_error=0;
    one(i,active->accepted?"acvp_positive":"acvp_negative",active->accepted?0:-1);
  }
  for(unsigned i=0;i<24;i++) {
    generated=1;entropy_error=0;mlen=i%4==0?0:i%4==1?1:i%4==2?32:1024;
    dlen=i%4==0?0:i%4==1?1:i%4==2?32:255;
    memset(msg.bytes,(int)(i+1),sizeof(msg.bytes));memset(dom.bytes,(int)(i+11),sizeof(dom.bytes));
    for(operation=0;operation<3;operation++)one(i,"fixed_seed_roundtrip",0);
  }
  target_text("{\"event\":\"summary\",\"cases\":");target_uint(cases);target_text(",\"failures\":");target_uint(failed);
  target_text(",\"operation_stack_watermarks\":[");for(unsigned i=0;i<3;i++){if(i)target_text(",");target_uint((uint32_t)max_stack[i]);}
  target_text("],\"operation_workspace_peaks\":[");for(unsigned i=0;i<3;i++) {if(i)target_text(",");
#ifdef LC_REFERENCE_CORE
    target_uint((uint32_t)max_workspace[i]);
#else
    target_uint(0);
#endif
  }
  target_text("],\"timing_collected\":false}\n");return failed?1:0;
}
