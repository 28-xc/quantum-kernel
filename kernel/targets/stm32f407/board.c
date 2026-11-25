#include "board.h"
#include "build_tag.h"
#include <string.h>
#include <libopencm3/usb/usbd.h>
#include <libopencm3/usb/cdc.h>
#include <libopencm3/stm32/rcc.h>
/* 1209:0001 is the pid.codes private-prototyping PID, not an assigned product ID.
   Set USB_VENDOR/USB_PRODUCT to authorized values when distributing hardware. */
#ifndef USB_VENDOR
#define USB_VENDOR 0x1209
#define USB_PRODUCT 0x0001
#endif
#define RCC 0x40023800u
#define GPIOA 0x40020000u
#define OTG 0x50000000u
#define BIT(n) (1u<<(n))
static usbd_device *usb;
static m4_request rx;
static m4_response tx;
static unsigned received,sent;
static int configured,ready,reset_after_tx,in_flight;
volatile uint32_t usb_diagnostics[16] __attribute__((used,section(".usb_diag")));
static const uint32_t tag[4]=BUILD_TAG;
static char serial_no[25];
static const char *strings[]={"A127","A127 STM32F407",serial_no};
static const struct usb_device_descriptor device={
 .bLength=USB_DT_DEVICE_SIZE,.bDescriptorType=USB_DT_DEVICE,.bcdUSB=0x0200,
 .bDeviceClass=2,.bDeviceSubClass=2,.bDeviceProtocol=0,.bMaxPacketSize0=64,
 .idVendor=USB_VENDOR,.idProduct=USB_PRODUCT,.bcdDevice=0x0100,
 .iManufacturer=1,.iProduct=2,.iSerialNumber=3,.bNumConfigurations=1};
static const struct usb_endpoint_descriptor intr[]={
 {.bLength=7,.bDescriptorType=5,.bEndpointAddress=0x83,.bmAttributes=3,.wMaxPacketSize=16,.bInterval=16}};
static const struct usb_endpoint_descriptor data_ep[]={
 {.bLength=7,.bDescriptorType=5,.bEndpointAddress=0x01,.bmAttributes=2,.wMaxPacketSize=64,.bInterval=0},
 {.bLength=7,.bDescriptorType=5,.bEndpointAddress=0x82,.bmAttributes=2,.wMaxPacketSize=64,.bInterval=0}};
static const uint8_t cdc_extra[]={5,0x24,0,0x10,1,5,0x24,1,0,1,4,0x24,2,2,5,0x24,6,0,1};
static const struct usb_interface_descriptor control_iface={
 .bLength=9,.bDescriptorType=4,.bInterfaceNumber=0,.bNumEndpoints=1,.bInterfaceClass=2,.bInterfaceSubClass=2,.bInterfaceProtocol=1,
 .endpoint=intr,.extra=cdc_extra,.extralen=sizeof(cdc_extra)};
static const struct usb_interface_descriptor data_iface={
 .bLength=9,.bDescriptorType=4,.bInterfaceNumber=1,.bNumEndpoints=2,.bInterfaceClass=10,.endpoint=data_ep};
static const struct usb_interface interfaces[]={{.num_altsetting=1,.altsetting=&control_iface},{.num_altsetting=1,.altsetting=&data_iface}};
static const struct usb_config_descriptor config={.bLength=9,.bDescriptorType=2,.bNumInterfaces=2,.bConfigurationValue=1,.bmAttributes=0x80,.bMaxPower=50,.interface=interfaces};
static uint8_t ctrl[160] __attribute__((aligned(4)));
static uint8_t linecoding[7]={0x00,0xc2,0x01,0x00,0,0,8};
static uint32_t last_host_activity;
extern uint8_t __image_bytes[],__reserved_ram[];
static void delay(uint32_t n){while(n--)__asm__ volatile("nop");}
void clear_bytes(void*p,size_t n){volatile uint8_t *b=p;while(n--)*b++=0;}
uint32_t m4_checksum(const void*p,size_t n){const uint8_t *b=p;uint32_t h=2166136261u;while(n--)h=(h^*b++)*16777619u;return h;}
uint32_t cycle_stamp(void){__asm__ volatile("dsb;isb":::"memory");return REG(0xe0001004);}
uint32_t stack_used(void){uint8_t*p=(uint8_t*)__stack_bottom;while(p<(uint8_t*)__stack_top&&*p==0xa5)p++;return (uint32_t)((uint8_t*)__stack_top-p);}
void reset_to_dfu(void){
 /* Windows may still be tearing down usbser when the mask ROM attaches
    WinUSB to the same physical port. Hold a real disconnect before reset. */
 if((REG(RCC+0x34)&BIT(7))!=0){
   REG(OTG+0x804)|=BIT(1);__asm__ volatile("dsb");
   if((REG(0xe000edfc)&BIT(24))&&(REG(0xe0001000)&1u)){
     uint32_t start=cycle_stamp();
     while((uint32_t)(cycle_stamp()-start)<100800000u){}
   }else delay(18000000u);
   REG(RCC+0x14)|=BIT(7);__asm__ volatile("dsb");
   REG(RCC+0x14)&=~BIT(7);REG(RCC+0x34)&=~BIT(7);
 }
 REG(RCC)|=1u;
 for(unsigned i=0;i<1000000u && !(REG(RCC)&BIT(1));i++){}
 if(REG(RCC)&BIT(1)){
   REG(RCC+8)&=~3u;
   for(unsigned i=0;i<1000000u && (REG(RCC+8)&12u);i++){}
   if(!(REG(RCC+8)&12u)){REG(RCC)&=~(BIT(24)|BIT(16));delay(500000u);}
 }
 __asm__ volatile("dsb");REG(0xe000ed0c)=0x05fa0004u;__asm__ volatile("dsb");for(;;){}
}
static int wait_bits(uint32_t a,uint32_t mask,uint32_t val){for(uint32_t n=0;n<8000000;n++){if((REG(a)&mask)==val)return 1;}return 0;}
static void clocks(void){
 /* Detach and reset the FS core left by the ROM before issuing a new device configuration. */
 REG(RCC+0x34)|=BIT(7);(void)REG(RCC+0x34);REG(OTG+0x804)|=BIT(1);delay(900000);
 REG(RCC+0x14)|=BIT(7);REG(RCC+0x14)&=~BIT(7);
 REG(RCC)|=1u;if(!wait_bits(RCC,3,3))reset_to_dfu();
 REG(RCC+8)&=~3u;if(!wait_bits(RCC+8,12,0))reset_to_dfu();
 REG(RCC)&=~BIT(24);if(!wait_bits(RCC,BIT(25),0))reset_to_dfu();
 REG(RCC)|=BIT(16);if(!wait_bits(RCC,BIT(17),BIT(17)))reset_to_dfu();
 REG(RCC+0x40)|=BIT(28);(void)REG(RCC+0x40);REG(0x40007000)|=BIT(14);
 REG(0x40023c00)=BIT(8)|BIT(9)|BIT(10)|5;
 REG(RCC+4)=8u|(336u<<6)|BIT(22)|(7u<<24);
 REG(RCC+8)=(REG(RCC+8)&~0x0000fcf3u)|(5u<<10)|(4u<<13);
 REG(RCC)|=BIT(24);if(!wait_bits(RCC,BIT(25),BIT(25)))reset_to_dfu();
 REG(RCC+8)=(REG(RCC+8)&~3u)|2u;if(!wait_bits(RCC+8,12,8))reset_to_dfu();
 REG(RCC+0x30)|=1u;(void)REG(RCC+0x30);
 REG(GPIOA)=(REG(GPIOA)&~(15u<<22))|(10u<<22);
 REG(GPIOA+8)|=15u<<22;REG(GPIOA+12)&=~(15u<<22);REG(GPIOA+4)&=~(3u<<11);
 REG(GPIOA+0x24)=(REG(GPIOA+0x24)&~(0xffu<<12))|(0xaau<<12);
 REG(0xe000edfc)|=BIT(24);REG(0xe0001000)|=1;REG(0xe0001004)=0;
}
void hardware_info(m4_response *r){
 r->w[0]=RSP_MAGIC;r->w[1]=1;memcpy(r->w+8,tag,16);r->w[12]=PARAM;r->w[13]=PROFILE;
 r->w[14]=REG(0xe000ed00);r->w[15]=REG(0xe0042000);
 for(int j=0;j<3;j++)r->w[16+j]=REG(0x1fff7a10u+4u*j);
 r->w[19]=168000000u;r->w[20]=REG(RCC+8);r->w[21]=REG(RCC+4);
 r->w[22]=(REG(0xe0001000)&1u);r->w[36]=stack_used();r->w[37]=(uint32_t)((uint8_t*)__stack_top-(uint8_t*)__stack_bottom);
 r->w[38]=ARENA_BYTES;r->w[39]=(uint32_t)(uintptr_t)__image_bytes;
 r->w[40]=(uint32_t)(uintptr_t)__reserved_ram;
 r->w[55]=REG(RCC);r->w[56]=*(volatile uint16_t*)0x1fff7a22u;
}
static enum usbd_request_return_codes control(usbd_device*d,struct usb_setup_data*q,uint8_t**b,uint16_t*n,void(**complete)(usbd_device*,struct usb_setup_data*)){
 (void)d;(void)complete;
 if(q->wIndex)return USBD_REQ_NOTSUPP;
 if(q->bRequest==USB_CDC_REQ_SET_CONTROL_LINE_STATE)return USBD_REQ_HANDLED;
 if(q->bRequest==USB_CDC_REQ_SET_LINE_CODING&&*n==7){memcpy(linecoding,*b,7);return USBD_REQ_HANDLED;}
 if(q->bRequest==USB_CDC_REQ_GET_LINE_CODING){*b=linecoding;*n=7;return USBD_REQ_HANDLED;}
 return USBD_REQ_NOTSUPP;
}
static void incoming(usbd_device*d,uint8_t ep){
 uint8_t pkt[64];int n=usbd_ep_read_packet(d,ep,pkt,sizeof(pkt));last_host_activity=cycle_stamp();
 usb_diagnostics[3]++;usb_diagnostics[4]=n;
 if(ready||sent<sizeof(tx))return;
 for(int i=0;i<n;i++){
  ((uint8_t*)&rx)[received++]=pkt[i];
  if(received==4&&rx.w[0]!=REQ_MAGIC){memmove(&rx,((uint8_t*)&rx)+1,3);received=3;}
  if(received==sizeof(rx)){ready=1;received=0;break;}
 }
}
static void completed(usbd_device*d,uint8_t ep){(void)d;(void)ep;in_flight=0;usb_diagnostics[7]++;}
static void cfg(usbd_device*d,uint16_t index){
 configured=index==1;ready=0;received=0;sent=sizeof(tx);reset_after_tx=0;in_flight=0;usb_diagnostics[2]++;
 if(!configured)return;
 usbd_ep_setup(d,0x01,USB_ENDPOINT_ATTR_BULK,64,incoming);usbd_ep_setup(d,0x82,USB_ENDPOINT_ATTR_BULK,64,completed);usbd_ep_setup(d,0x83,USB_ENDPOINT_ATTR_INTERRUPT,16,0);
 usbd_register_control_callback(d,0x21,0x7f,control);last_host_activity=cycle_stamp();
}
static void bus_reset(void){configured=0;ready=0;received=0;sent=sizeof(tx);reset_after_tx=0;in_flight=0;clear_bytes(&rx,sizeof(rx));clear_bytes(&tx,sizeof(tx));usb_diagnostics[1]++;}
static void clock_sample(m4_response *r){
 /* Full-speed host frames give an independent one millisecond reference. */
 uint32_t initial=(REG(OTG+0x808)>>8)&0x7ffu;
 uint32_t deadline=cycle_stamp(),last=initial,start=0,frames=0;
 while((uint32_t)(cycle_stamp()-deadline)<16800000u){
   uint32_t frame=(REG(OTG+0x808)>>8)&0x7ffu;
   if(frame==last)continue;
   uint32_t now=cycle_stamp();
   if(!start)start=now;
   else frames+=(frame-last)&0x7ffu;
   last=frame;
   if(frames>=32){
     uint32_t elapsed=now-start;
     uint32_t hz=(elapsed/frames)*1000u+((elapsed%frames)*1000u+frames/2u)/frames;
     r->w[41]=frames;r->w[42]=elapsed;r->w[43]=hz;
     r->w[23]=hz>=166320000u&&hz<=169680000u;return;
   }
 }
}
void board_start(void){
 clocks();memset((void*)usb_diagnostics,0,sizeof(usb_diagnostics));usb_diagnostics[0]=0x31474244;
 const char chars[]="0123456789ABCDEF";
 for(unsigned a=0;a<12;a++){uint8_t v=*(volatile uint8_t*)(0x1fff7a10u+a);serial_no[2*a]=chars[v>>4];serial_no[2*a+1]=chars[v&15];}
 usb=usbd_init(&otgfs_usb_driver,&device,&config,strings,3,ctrl,sizeof(ctrl));
 /* This board wires D+/D- but not VBUS sense to PA9. */
 REG(OTG+0x38)=(REG(OTG+0x38)&~(BIT(18)|BIT(19)))|BIT(21)|BIT(16);
 usbd_register_set_config_callback(usb,cfg);usbd_register_reset_callback(usb,bus_reset);
 uint32_t previous=cycle_stamp(),seen_activity=last_host_activity;uint64_t idle_ticks=0;
 /* BOOT0 remains asserted. Inactivity returns the user to the ROM loader. */
 for(;;){
   usbd_poll(usb);
   uint32_t now=cycle_stamp();idle_ticks+=(uint32_t)(now-previous);previous=now;
   if(last_host_activity!=seen_activity){seen_activity=last_host_activity;idle_ticks=0;}
   if(idle_ticks>=168000000ull*90ull){usb_diagnostics[9]=1;reset_to_dfu();}
   if(ready){
     ready=0;usb_diagnostics[5]++;memset(&tx,0,sizeof(tx));hardware_info(&tx);tx.w[2]=rx.w[2];tx.w[3]=rx.w[3];memcpy(tx.w+4,rx.w+4,16);
     if(rx.w[0]!=REQ_MAGIC||rx.w[1]!=1||m4_checksum(&rx,60)!=rx.w[15])tx.w[23]=0;
     else if(rx.w[2]==M4_HELLO)tx.w[23]=1;
     else if(rx.w[2]==M4_CLOCK)clock_sample(&tx);
     else if(rx.w[2]==M4_RETURN_DFU){tx.w[23]=1;reset_after_tx=1;}
     else experiment(&rx,&tx);
     tx.w[36]=stack_used();tx.w[63]=m4_checksum(&tx,252);clear_bytes(&rx,sizeof(rx));sent=0;
   }
   if(configured&&!in_flight&&sent<sizeof(tx)){
    unsigned n=sizeof(tx)-sent;if(n>60)n=60;
    unsigned k=usbd_ep_write_packet(usb,0x82,(uint8_t*)&tx+sent,n);
    if(k){in_flight=1;sent+=k;usb_diagnostics[6]++;usb_diagnostics[8]=sent;}
   }
   if(sent==sizeof(tx)&&!in_flight&&reset_after_tx){delay(900000);reset_to_dfu();}
 }
}

