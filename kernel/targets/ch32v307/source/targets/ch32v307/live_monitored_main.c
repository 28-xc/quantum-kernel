/* Isolated CH32V307 UART flow harness. Crypto sources are unchanged. */
#include "ch32v30x.h"
#include "target.h"
#include "latticecore.h"
#include "live_build_id.h"
#include <string.h>

#ifndef LC_LIVE_PAYLOAD_BYTES
#define LC_LIVE_PAYLOAD_BYTES 1391
#endif
#ifndef LC_LIVE_MAX_MESSAGE
#define LC_LIVE_MAX_MESSAGE 1024
#endif
#ifndef LC_LIVE_MAX_CONTEXT
#define LC_LIVE_MAX_CONTEXT 255
#endif
#ifndef LC_LIVE_SHARE_OUTPUT
#define LC_LIVE_SHARE_OUTPUT 1
#endif
#if LC_LIVE_PAYLOAD_BYTES < 112 || LC_LIVE_PAYLOAD_BYTES > 4096 || LC_LIVE_MAX_MESSAGE < 0 || LC_LIVE_MAX_CONTEXT < 0 || LC_LIVE_MAX_MESSAGE > LC_LIVE_PAYLOAD_BYTES-112 || LC_LIVE_MAX_CONTEXT > 255
#error Unsupported live payload capability
#endif
#if LC_LIVE_SHARE_OUTPUT != 0 && LC_LIVE_SHARE_OUTPUT != 1
#error Output sharing must be zero or one
#endif
#define MAX_PAYLOAD ((unsigned)LC_LIVE_PAYLOAD_BYTES)
#define GUARD_BYTES 32u
#define NOT_RUN (-127)
#define OWNER(name,n,sec) static struct { uint8_t pre[32],bytes[n],post[32]; } name __attribute__((section(sec),aligned(32)))
OWNER(pk,2592,".caller_io"); OWNER(sk,4896,".caller_io");
/* KEM ciphertext and DSA signature are mutually exclusive in every FLOW.
 * No public API call receives both. All aliases retain the same guards/wipe. */
#if LC_LIVE_SHARE_OUTPUT
OWNER(output,4627,".caller_io");
#define ct output
#define sig output
#else
OWNER(ct,1568,".caller_io"); OWNER(sig,4627,".caller_io");
#endif
OWNER(ss1,32,".caller_io"); OWNER(ss2,32,".caller_io");
OWNER(work,LC_TARGET_WORKSPACE,".arena");
OWNER(rx,MAX_PAYLOAD,".caller_io");
static uint8_t response[256], request_header[20];
static lc_context context;
static lc_sizes sizes;
static uint32_t parameter,message_n,domain_n,active_operation;
static uint64_t session_nonce;
static uint32_t last_flow_seq,run_seq;
static struct { const uint8_t *bytes; size_t n,pos; } entropy;
static uint64_t operation_ticks;
volatile uint32_t live_state,live_fault_cause,live_fault_pc,live_fault_value;

/* Informational raw checks for the hardware owner, deliberately outside wire. */
volatile struct {
  uint32_t magic,version,pass_mask,final_ctlr;
  uint64_t carry_written,carry_read,monotonic_first,monotonic_last;
  uint32_t monotonic_failures,monotonic_reads;
  uint64_t empty_read_ticks[8];
  uint64_t hclk_start,hclk_end,div8_start,div8_end;
  uint32_t nop_iterations,reserved;
} timer_selftest;
_Static_assert(sizeof(timer_selftest)==160,"Timer self-test RAM contract");

/* Actual shared scalar KEM helper, no separate digest implementation. */
extern void lc_base_mlk_sha3_256(uint8_t *,const uint8_t *,size_t);

static void erase(void *v,size_t n) {
  volatile uint8_t *p=(volatile uint8_t *)v;
  while(n--) *p++=0;
  __asm__ volatile("" ::: "memory");
}
static int filled(const void *v,size_t n,uint8_t value) {
  const volatile uint8_t *p=(const volatile uint8_t *)v;
  uint8_t different=0;
  while(n--) different|=(uint8_t)(*p++^value);
  return different==0;
}
/* Startup paints before any C call. This scanner never writes stack bytes. */
extern uint8_t __control_stack_bottom[], __control_stack_top[];
volatile struct {
  uint32_t magic,version,observations,current_bytes,maximum_bytes,guard_ok,sticky_failure;
} control_stack_observation;
_Static_assert(sizeof(control_stack_observation)==28,"Control stack RAM contract");
static __attribute__((noinline)) int control_stack_update(void) {
  const volatile uint8_t *p=__control_stack_bottom;
  uint32_t used;unsigned i;uint8_t damaged=0;
  for(i=0;i<32;i++)damaged|=(uint8_t)(p[i]^0xa5u);
  while(p<__control_stack_top && *p==0xa5u)p++;
  used=(uint32_t)(__control_stack_top-p);
  control_stack_observation.magic=0x4353544bu;control_stack_observation.version=1;
  control_stack_observation.observations++;
  control_stack_observation.current_bytes=used;
  if(used>control_stack_observation.maximum_bytes)control_stack_observation.maximum_bytes=used;
  control_stack_observation.guard_ok=damaged==0;
  if(damaged)control_stack_observation.sticky_failure=1;
  return !control_stack_observation.sticky_failure;
}
static int same_shared_secret(const uint8_t *a,const uint8_t *b) {
  unsigned i;uint8_t different=0;
  for(i=0;i<32;i++)different|=(uint8_t)(a[i]^b[i]);
  return different==0;
}
static uint32_t rd32(const uint8_t *p) {
  return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);
}
static uint64_t rd64(const uint8_t *p) {return (uint64_t)rd32(p)|((uint64_t)rd32(p+4)<<32);}
static void wr32(uint8_t *p,uint32_t v) { unsigned i;for(i=0;i<4;i++){p[i]=(uint8_t)v;v>>=8;} }
static void wr64(uint8_t *p,uint64_t v) {wr32(p,(uint32_t)v);wr32(p+4,(uint32_t)(v>>32));}

static uint64_t ticks(void) {
  volatile uint32_t *counter=(volatile uint32_t *)0xe000f008u;
  uint32_t high0,low,high1;
  __asm__ volatile("" ::: "memory");
  do { high0=counter[1];low=counter[0];high1=counter[1]; } while(high0!=high1);
  __asm__ volatile("" ::: "memory");
  return ((uint64_t)high1<<32)|low;
}
static void timer_start(uint32_t ctl,uint64_t initial) {
  volatile uint32_t *counter=(volatile uint32_t *)0xe000f008u;
  SysTick->CTLR=0;
  counter[0]=(uint32_t)initial;counter[1]=(uint32_t)(initial>>32);
  SysTick->SR=0;
  SysTick->CMP=UINT64_MAX;
  SysTick->CTLR=ctl;
  __asm__ volatile("fence rw,rw" ::: "memory");
}
static void fixed_nops(void) {
  unsigned i;
  for(i=0;i<1024;i++) __asm__ volatile("nop; nop; nop; nop" ::: "memory");
}
static void test_timer(void) {
  uint64_t first,last,now,start,full,div8;unsigned i;uint32_t mask=0,bad=0;
  timer_selftest.magic=0x5354494du;timer_selftest.version=1;
  timer_selftest.carry_written=UINT64_C(0xfffffff0);
  timer_start(5,UINT64_C(0xfffffff0));
  for(i=0;i<64;i++)__asm__ volatile("nop" ::: "memory");
  now=ticks();timer_selftest.carry_read=now;
  if(now>=UINT64_C(0x100000000)&&now<UINT64_C(0x100010000))mask|=1;
  first=last=ticks();
  for(i=0;i<128;i++){now=ticks();if(now<last)bad++;last=now;}
  timer_selftest.monotonic_first=first;timer_selftest.monotonic_last=last;
  timer_selftest.monotonic_failures=bad;timer_selftest.monotonic_reads=128;
  if(!bad&&last>first)mask|=2;
  for(i=0;i<8;i++){start=ticks();now=ticks();timer_selftest.empty_read_ticks[i]=now-start;}
  timer_start(5,0);start=ticks();fixed_nops();now=ticks();
  timer_selftest.hclk_start=start;timer_selftest.hclk_end=now;full=now-start;
  timer_start(1,0);start=ticks();fixed_nops();now=ticks();
  timer_selftest.div8_start=start;timer_selftest.div8_end=now;div8=now-start;
  if(div8&&full>div8*6&&full<div8*10)mask|=4;
  timer_selftest.nop_iterations=1024;
  timer_start(5,0);timer_selftest.final_ctlr=SysTick->CTLR;
  if(SysTick->CTLR==5)mask|=8;
  timer_selftest.pass_mask=mask;
}

static void init_uart(void) {
  GPIO_InitTypeDef gpio;
  USART_InitTypeDef uart;
  RCC_APB2PeriphClockCmd(RCC_APB2Periph_USART1|RCC_APB2Periph_GPIOA,ENABLE);
  gpio.GPIO_Pin=GPIO_Pin_9;gpio.GPIO_Speed=GPIO_Speed_50MHz;gpio.GPIO_Mode=GPIO_Mode_AF_PP;GPIO_Init(GPIOA,&gpio);
  gpio.GPIO_Pin=GPIO_Pin_10;gpio.GPIO_Mode=GPIO_Mode_IN_FLOATING;GPIO_Init(GPIOA,&gpio);
  USART_StructInit(&uart);uart.USART_BaudRate=115200;uart.USART_Mode=USART_Mode_Rx|USART_Mode_Tx;
  USART_Init(USART1,&uart);USART_Cmd(USART1,ENABLE);
}
static int receive_byte(uint8_t *out,int wait_first) {
  uint64_t start=ticks();uint16_t flags,data;
  for(;;){
    flags=USART1->STATR;
    if(flags&0x0fu){data=USART1->DATAR;(void)data;return -109;}
    if(flags&USART_FLAG_RXNE){*out=(uint8_t)USART1->DATAR;return 0;}
    if(!wait_first&&ticks()-start>(uint64_t)SystemCoreClock/2u)return -109;
  }
}
static void discard_to_idle(void) {
  uint64_t last=ticks();uint16_t flags,data;
  while(ticks()-last<(uint64_t)SystemCoreClock/10u){
    flags=USART1->STATR;
    if(flags&(USART_FLAG_RXNE|0x0fu)){data=USART1->DATAR;(void)data;last=ticks();}
  }
}
static void send_byte(uint8_t b) {
  while(!(USART1->STATR&USART_FLAG_TXE)){}
  USART1->DATAR=b;
}
static uint32_t crc_part(uint32_t crc,const uint8_t *p,size_t n) {
  unsigned j;while(n--){crc^=*p++;for(j=0;j<8;j++)crc=(crc>>1)^(0xedb88320u&(0u-(crc&1u)));}return crc;
}
static void send_response(uint32_t cmd,uint32_t seq,uint32_t length) {
  uint8_t h[20];uint32_t crc;unsigned i;
  memcpy(h,"PQCR",4);wr32(h+4,cmd);wr32(h+8,seq);wr32(h+12,length);
  if(!control_stack_update()){
    wr32(response+4,(uint32_t)-106);
    if(length==256)wr32(response+48,rd32(response+48)&~16u);
  }
  crc=crc_part(crc_part(UINT32_MAX,h,16),response,length)^UINT32_MAX;wr32(h+16,crc);
  for(i=0;i<20;i++)send_byte(h[i]);
  for(i=0;i<length;i++)send_byte(response[i]);
  while(!(USART1->STATR&USART_FLAG_TC)){}
  erase(h,sizeof(h));erase(response,sizeof(response));
}

static void paint_owners(void) {
#define PAINT(x) memset(&x,0xa5,sizeof(x));memset(x.bytes,0,sizeof(x.bytes))
  PAINT(pk);PAINT(sk);PAINT(ct);PAINT(sig);PAINT(ss1);PAINT(ss2);PAINT(work);
#undef PAINT
}
static int guards_ok(void) {
#define CHECK(x) if(!filled(x.pre,32,0xa5)||!filled(x.post,32,0xa5))return 0
  CHECK(pk);CHECK(sk);CHECK(ct);CHECK(sig);CHECK(ss1);CHECK(ss2);CHECK(work);CHECK(rx);
#undef CHECK
  return filled(__test_stack_bottom,32,0xa5)&&control_stack_update();
}
static size_t stack_used(void) {
  uint8_t *p=__test_stack_bottom;while(p<__test_stack_top&&*p==0xa5)p++;return (size_t)(__test_stack_top-p);
}
static uint32_t cleanup_owners(void) {
  int w,other;
  erase(work.bytes,sizeof(work.bytes));w=filled(work.bytes,sizeof(work.bytes),0);
  erase(pk.bytes,sizeof(pk.bytes));erase(sk.bytes,sizeof(sk.bytes));erase(ct.bytes,sizeof(ct.bytes));erase(sig.bytes,sizeof(sig.bytes));
  erase(ss1.bytes,sizeof(ss1.bytes));erase(ss2.bytes,sizeof(ss2.bytes));erase(rx.bytes,sizeof(rx.bytes));
  erase(__test_stack_bottom,(size_t)(__test_stack_top-__test_stack_bottom));
  erase(&entropy,sizeof(entropy));erase(&context,sizeof(context));erase(&sizes,sizeof(sizes));
  other=filled(pk.bytes,sizeof(pk.bytes),0)&&filled(sk.bytes,sizeof(sk.bytes),0)&&filled(ct.bytes,sizeof(ct.bytes),0)&&
    filled(sig.bytes,sizeof(sig.bytes),0)&&filled(ss1.bytes,sizeof(ss1.bytes),0)&&filled(ss2.bytes,sizeof(ss2.bytes),0)&&
    filled(rx.bytes,sizeof(rx.bytes),0)&&filled(__test_stack_bottom,(size_t)(__test_stack_top-__test_stack_bottom),0)&&
    filled(&entropy,sizeof(entropy),0)&&filled(&context,sizeof(context),0)&&filled(&sizes,sizeof(sizes),0);
  return (w?32u:0u)|(other?64u:0u);
}
static int supplied(void *unused,uint8_t *out,size_t n) {
  (void)unused;
  if(entropy.pos>entropy.n||n>entropy.n-entropy.pos)return -1;
  memcpy(out,entropy.bytes+entropy.pos,n);entropy.pos+=n;return 0;
}
static int timed_api(void *unused) {
  int rc;uint64_t start,end;(void)unused;
  const uint8_t *message=rx.bytes+112,*domain=message+message_n;
  switch(active_operation){
  case 0:
    start=ticks();rc=lc_keypair(&context,(int)parameter,pk.bytes,sizeof(pk.bytes),sk.bytes,sizeof(sk.bytes));end=ticks();break;
  case 1:
    if(parameter>100){start=ticks();rc=lc_encaps(&context,(int)parameter,ct.bytes,sizeof(ct.bytes),ss1.bytes,32,pk.bytes,sizes.public_key);end=ticks();}
    else {start=ticks();rc=lc_sign(&context,(int)parameter,sig.bytes,sizeof(sig.bytes),message,message_n,domain,domain_n,sk.bytes,sizes.secret_key);end=ticks();}break;
  default:
    if(parameter>100){start=ticks();rc=lc_decaps(&context,(int)parameter,ss2.bytes,32,ct.bytes,sizes.ciphertext,sk.bytes,sizes.secret_key);end=ticks();}
    else {start=ticks();rc=lc_verify(&context,(int)parameter,sig.bytes,sizes.signature,message,message_n,domain,domain_n,pk.bytes,sizes.public_key);end=ticks();}break;
  }
  operation_ticks=end-start;return rc;
}
static void prefix(uint32_t seq,int status,uint32_t detail,uint32_t erased) {
  if(!control_stack_update())status=-106;
  wr32(response,1);wr32(response+4,(uint32_t)status);wr32(response+8,seq);wr32(response+12,run_seq);
  wr64(response+16,session_nonce);wr32(response+24,(SysTick->CTLR==5?1u:0u)|(erased==96?2u:0u));wr32(response+28,detail);
}
static uint32_t hello(uint32_t seq,uint32_t n) {
  uint32_t erased;
  if(n!=8||rd64(rx.bytes)==0){erased=cleanup_owners();prefix(seq,n!=8?-101:-104,0,erased);return 32;}
  session_nonce=rd64(rx.bytes);last_flow_seq=0;
  wr32(response+32,SystemCoreClock);wr32(response+36,SysTick->CTLR);wr32(response+40,196608);wr32(response+44,131072);
  wr32(response+48,(uint32_t)(__code_end-__code_start));wr32(response+52,(uint32_t)(__ram_end-__ram_start));
  wr32(response+56,sizeof(work.bytes));wr32(response+60,(uint32_t)(__test_stack_top-__test_stack_bottom));
  wr32(response+64,(uint32_t)(__control_stack_top-__control_stack_bottom));wr32(response+68,(uint32_t)(__io_end-__io_start));
  wr32(response+72,MAX_PAYLOAD);wr32(response+76,LC_LIVE_MAX_MESSAGE);wr32(response+80,LC_LIVE_MAX_CONTEXT);wr32(response+84,0x3ffff);
  wr32(response+88,96);wr32(response+92,64);memcpy(response+96,pqc_live_build_id,32);
  wr32(response+128,RCC->CTLR);wr32(response+132,RCC->CFGR0);wr64(response+136,ticks());
  wr32(response+144,GPIOA->CFGHR);wr32(response+148,USART1->BRR);
  erased=cleanup_owners();prefix(seq,erased==96?0:-106,0,erased);return 152;
}
static uint32_t flow(uint32_t seq,uint32_t n) {
  uint32_t i,passed=0,peak_arena=0,peak_stack=0,erased,used_entropy=0;int rc,status=0,guard=1,expected;size_t stack;
  if(!session_nonce){status=-107;goto rejected;}
  if(!seq||seq<=last_flow_seq||run_seq==UINT32_MAX){status=-108;goto rejected;}
  if(n<112){status=-101;goto rejected;}
  parameter=rd32(rx.bytes);message_n=rd32(rx.bytes+4);domain_n=rd32(rx.bytes+8);entropy.n=rd32(rx.bytes+12);
  if(lc_get_sizes((int)parameter,&sizes)||message_n>LC_LIVE_MAX_MESSAGE||domain_n>LC_LIVE_MAX_CONTEXT||message_n+domain_n>MAX_PAYLOAD-112||n!=112+message_n+domain_n){status=-104;goto rejected;}
  if(parameter>100){if(message_n||domain_n||entropy.n!=96){status=-104;goto rejected;}}
  else if(entropy.n!=64||!filled(rx.bytes+80,32,0)){status=-104;goto rejected;}
  if(SysTick->CTLR!=5||timer_selftest.pass_mask!=15){status=-106;goto rejected;}
  entropy.bytes=rx.bytes+16;entropy.pos=0;
  paint_owners();
  if(lc_context_init(&context,work.bytes,sizeof(work.bytes),supplied,0)!=LC_OK){status=-105;goto rejected;}
  last_flow_seq=seq;run_seq++;
  wr32(response+32,parameter);wr32(response+36,message_n);wr32(response+40,domain_n);wr32(response+60,4);
  for(i=0;i<4;i++){wr32(response+128+32*i,i);wr32(response+132+32*i,(uint32_t)NOT_RUN);}
  for(i=0;i<4;i++){
    active_operation=i;
    if(i==3){if(parameter>100)ct.bytes[0]^=1;else sig.bytes[0]^=1;}
    memset(__test_stack_bottom,0xa5,(size_t)(__test_stack_top-__test_stack_bottom));
    rc=target_call(timed_api,0);stack=stack_used();
    if(!guards_ok())guard=0;
    wr32(response+132+32*i,(uint32_t)rc);wr64(response+136+32*i,operation_ticks);
    wr32(response+144+32*i,(uint32_t)context.arena_high_water);wr32(response+148+32*i,(uint32_t)stack);
    wr32(response+152+32*i,(uint32_t)context.allocations);wr32(response+156+32*i,(uint32_t)context.allocation_failures);
    if(context.arena_high_water>peak_arena)peak_arena=(uint32_t)context.arena_high_water;
    if(stack>peak_stack)peak_stack=(uint32_t)stack;
    erase(__test_stack_bottom,(size_t)(__test_stack_top-__test_stack_bottom));
    expected=(i==3&&parameter<100)?LC_E_REJECT:LC_OK;
    if(rc!=expected){status=-105;break;}
    if(parameter>100&&i==2&&!same_shared_secret(ss1.bytes,ss2.bytes)){status=-105;break;}
    if(parameter>100&&i==3&&same_shared_secret(ss1.bytes,ss2.bytes)){status=-105;break;}
    passed|=1u<<i;
    if(i==0)lc_base_mlk_sha3_256(response+64,pk.bytes,sizes.public_key);
    if(i==1)lc_base_mlk_sha3_256(response+96,parameter>100?ct.bytes:sig.bytes,parameter>100?sizes.ciphertext:sizes.signature);
    if(!guard){status=-106;break;}
  }
  if(guard)passed|=16;
  used_entropy=(uint32_t)entropy.pos;if(entropy.pos==entropy.n)passed|=128;
  erased=cleanup_owners();passed|=erased;
  if((passed&112)!=112)status=-106;else if(passed!=255&&!status)status=-105;
  wr32(response+44,used_entropy);wr32(response+48,passed);wr32(response+52,peak_arena);wr32(response+56,peak_stack);
  prefix(seq,status,0,erased);return 256;
rejected:
  erased=cleanup_owners();prefix(seq,status,0,erased);return 32;
}

void target_putc(char c){(void)c;}
void target_exit(int status){live_state=0x100u+(uint32_t)status;for(;;)__asm__ volatile("nop");}
void NMI_Handler(void) __attribute__((interrupt("WCH-Interrupt-fast")));
void HardFault_Handler(void) __attribute__((interrupt("WCH-Interrupt-fast")));
void NMI_Handler(void){live_state=0x201;for(;;)__asm__ volatile("nop");}
void HardFault_Handler(void){
  __asm__ volatile("csrr %0,mcause":"=r"(live_fault_cause));
  __asm__ volatile("csrr %0,mepc":"=r"(live_fault_pc));
  __asm__ volatile("csrr %0,mtval":"=r"(live_fault_value));
  live_state=0x202;for(;;)__asm__ volatile("nop");
}
int main(void) {
  uint32_t i,n,cmd,seq,crc,out_n,erased;int error;
  __disable_irq();SystemCoreClockUpdate();test_timer();init_uart();control_stack_update();live_state=1;
  for(;;){
    memset(rx.pre,0xa5,32);memset(rx.post,0xa5,32);erase(response,sizeof(response));erase(request_header,sizeof(request_header));
    cmd=seq=0;error=0;
    for(i=0;i<20;i++){error=receive_byte(request_header+i,i==0);if(error)break;}
    if(!error){cmd=rd32(request_header+4);seq=rd32(request_header+8);n=rd32(request_header+12);
      if(memcmp(request_header,"PQC1",4))error=-100;else if(n>MAX_PAYLOAD)error=-101;
      else {for(i=0;i<n;i++){error=receive_byte(rx.bytes+i,0);if(error)break;}
        if(!error){crc=crc_part(crc_part(UINT32_MAX,request_header,16),rx.bytes,n)^UINT32_MAX;
          if(crc!=rd32(request_header+16))error=-102;else if(!seq)error=-108;else if(cmd!=1&&cmd!=2)error=-103;}
      }
    }
    if(error){discard_to_idle();erased=cleanup_owners();prefix(seq,error,0,erased);out_n=32;}
    else {live_state=2;out_n=cmd==1?hello(seq,n):flow(seq,n);}
    erase(request_header,sizeof(request_header));send_response(cmd,seq,out_n);control_stack_update();live_state=1;
  }
}
