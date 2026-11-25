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
enum { LC_OK=0, LC_E_ARGUMENT=-1, LC_E_LENGTH=-2, LC_E_ALIAS=-3,
       LC_E_RANDOM=-4, LC_E_WORKSPACE=-5, LC_E_REJECT=-6, LC_E_INTERNAL=-7 };
typedef int (*lc_random_fn)(void *user,uint8_t *out,size_t bytes);
typedef struct {
  void *workspace;
  size_t workspace_bytes;
  lc_random_fn random;
  void *random_user;
  size_t arena_high_water, allocations, allocation_failures;
  int last_error;
} lc_context;
typedef struct { size_t public_key,secret_key,ciphertext,shared_secret,signature; } lc_sizes;
__attribute__((externally_visible)) int lc_get_sizes(int parameter,lc_sizes *sizes);
__attribute__((externally_visible)) int lc_context_init(lc_context *ctx,void *workspace,size_t bytes,
                    lc_random_fn random,void *random_user);
__attribute__((externally_visible)) int lc_keypair(lc_context *ctx,int parameter,uint8_t *pk,size_t pk_capacity,
               uint8_t *sk,size_t sk_capacity);
__attribute__((externally_visible)) int lc_encaps(lc_context *ctx,int parameter,uint8_t *ct,size_t ct_capacity,
              uint8_t *ss,size_t ss_capacity,const uint8_t *pk,size_t pk_bytes);
__attribute__((externally_visible)) int lc_decaps(lc_context *ctx,int parameter,uint8_t *ss,size_t ss_capacity,
              const uint8_t *ct,size_t ct_bytes,const uint8_t *sk,size_t sk_bytes);
__attribute__((externally_visible)) int lc_sign(lc_context *ctx,int parameter,uint8_t *sig,size_t sig_capacity,
            const uint8_t *message,size_t message_bytes,const uint8_t *domain,
            size_t domain_bytes,const uint8_t *sk,size_t sk_bytes);
__attribute__((externally_visible)) int lc_verify(lc_context *ctx,int parameter,const uint8_t *sig,size_t sig_bytes,
              const uint8_t *message,size_t message_bytes,const uint8_t *domain,
              size_t domain_bytes,const uint8_t *pk,size_t pk_bytes);
__attribute__((externally_visible)) const char *lc_error_string(int status);
typedef struct {uint32_t state[4]; int source; const uint8_t *fixed; size_t left;} entropy_source;
struct io_512 {uint8_t pk[800], sk[1632], ct[768], ss[32], ss2[32], sig[1], message[256], context[256];};
struct io_768 {uint8_t pk[1184], sk[2400], ct[1088], ss[32], ss2[32], sig[1], message[256], context[256];};
struct io_1024 {uint8_t pk[1568], sk[3168], ct[1568], ss[32], ss2[32], sig[1], message[256], context[256];};
struct io_44 {uint8_t pk[1312], sk[2560], ct[1], ss[32], ss2[32], sig[2420], message[256], context[256];};
struct io_65 {uint8_t pk[1952], sk[4032], ct[1], ss[32], ss2[32], sig[3309], message[256], context[256];};
struct io_87 {uint8_t pk[2592], sk[4896], ct[1], ss[32], ss2[32], sig[4627], message[256], context[256];};
union transaction_views {
 struct {struct {uint8_t before[32],data[5120],after[32];} guarded; uint8_t io_lower[16];struct io_512 io;uint8_t io_upper[16];} c512_compact;
 struct {struct {uint8_t before[32],data[5120],after[32];} guarded; uint8_t io_lower[16];struct io_512 io;uint8_t io_upper[16];} c512_cached;
 struct {struct {uint8_t before[32],data[6656],after[32];} guarded; uint8_t io_lower[16];struct io_768 io;uint8_t io_upper[16];} c768_compact;
 struct {struct {uint8_t before[32],data[6656],after[32];} guarded; uint8_t io_lower[16];struct io_768 io;uint8_t io_upper[16];} c768_cached;
 struct {struct {uint8_t before[32],data[8448],after[32];} guarded; uint8_t io_lower[16];struct io_1024 io;uint8_t io_upper[16];} c1024_compact;
 struct {struct {uint8_t before[32],data[8448],after[32];} guarded; uint8_t io_lower[16];struct io_1024 io;uint8_t io_upper[16];} c1024_cached;
 struct {struct {uint8_t before[32],data[11424],after[32];} guarded; uint8_t io_lower[16];struct io_44 io;uint8_t io_upper[16];} c44_compact;
 struct {struct {uint8_t before[32],data[11424],after[32];} guarded; uint8_t io_lower[16];struct io_44 io;uint8_t io_upper[16];} c44_cached;
 struct {struct {uint8_t before[32],data[9792],after[32];} guarded; uint8_t io_lower[16];struct io_65 io;uint8_t io_upper[16];} c65_compact;
 struct {struct {uint8_t before[32],data[9792],after[32];} guarded; uint8_t io_lower[16];struct io_65 io;uint8_t io_upper[16];} c65_cached;
 struct {struct {uint8_t before[32],data[7712],after[32];} guarded; uint8_t io_lower[16];struct io_87 io;uint8_t io_upper[16];} c87_compact;
 struct {struct {uint8_t before[32],data[7712],after[32];} guarded; uint8_t io_lower[16];struct io_87 io;uint8_t io_upper[16];} c87_cached;
};
extern union transaction_views combined_storage;
extern lc_context active_context;
extern entropy_source active_entropy;
void unified_hello(m4_response*);
void unified_hash(m4_response*);
int unified_select(const m4_request*,m4_response*);
void unified_idle(void);
void selected_layout(const m4_request*,m4_response*);
void *memcpy(void *restrict dst, const void *restrict src, size_t n);
void *memmove(void *dst, const void *src, size_t n);
void *memset(void *dst, int value, size_t n);
int memcmp(const void *a, const void *b, size_t n);
size_t strlen(const char *s);
struct usb_setup_data {
 uint8_t bmRequestType;
 uint8_t bRequest;
 uint16_t wValue;
 uint16_t wIndex;
 uint16_t wLength;
} __attribute__((packed));
struct usb_device_descriptor {
 uint8_t bLength;
 uint8_t bDescriptorType;
 uint16_t bcdUSB;
 uint8_t bDeviceClass;
 uint8_t bDeviceSubClass;
 uint8_t bDeviceProtocol;
 uint8_t bMaxPacketSize0;
 uint16_t idVendor;
 uint16_t idProduct;
 uint16_t bcdDevice;
 uint8_t iManufacturer;
 uint8_t iProduct;
 uint8_t iSerialNumber;
 uint8_t bNumConfigurations;
} __attribute__((packed));
struct usb_device_qualifier_descriptor {
 uint8_t bLength;
 uint8_t bDescriptorType;
 uint16_t bcdUSB;
 uint8_t bDeviceClass;
 uint8_t bDeviceSubClass;
 uint8_t bDeviceProtocol;
 uint8_t bMaxPacketSize0;
 uint8_t bNumConfigurations;
 uint8_t bReserved;
} __attribute__((packed));
struct usb_interface {
 uint8_t *cur_altsetting;
 uint8_t num_altsetting;
 const struct usb_iface_assoc_descriptor *iface_assoc;
 const struct usb_interface_descriptor *altsetting;
};
struct usb_config_descriptor {
 uint8_t bLength;
 uint8_t bDescriptorType;
 uint16_t wTotalLength;
 uint8_t bNumInterfaces;
 uint8_t bConfigurationValue;
 uint8_t iConfiguration;
 uint8_t bmAttributes;
 uint8_t bMaxPower;
 const struct usb_interface *interface;
} __attribute__((packed));
struct usb_interface_descriptor {
 uint8_t bLength;
 uint8_t bDescriptorType;
 uint8_t bInterfaceNumber;
 uint8_t bAlternateSetting;
 uint8_t bNumEndpoints;
 uint8_t bInterfaceClass;
 uint8_t bInterfaceSubClass;
 uint8_t bInterfaceProtocol;
 uint8_t iInterface;
 const struct usb_endpoint_descriptor *endpoint;
 const void *extra;
 int extralen;
} __attribute__((packed));
struct usb_endpoint_descriptor {
 uint8_t bLength;
 uint8_t bDescriptorType;
 uint8_t bEndpointAddress;
 uint8_t bmAttributes;
 uint16_t wMaxPacketSize;
 uint8_t bInterval;
 const void *extra;
 int extralen;
} __attribute__((packed));
struct usb_string_descriptor {
 uint8_t bLength;
 uint8_t bDescriptorType;
 uint16_t wData[];
} __attribute__((packed));
struct usb_iface_assoc_descriptor {
 uint8_t bLength;
 uint8_t bDescriptorType;
 uint8_t bFirstInterface;
 uint8_t bInterfaceCount;
 uint8_t bFunctionClass;
 uint8_t bFunctionSubClass;
 uint8_t bFunctionProtocol;
 uint8_t iFunction;
} __attribute__((packed));
enum usb_language_id {
 USB_LANGID_ENGLISH_US = 0x409,
};
enum usbd_request_return_codes {
 USBD_REQ_NOTSUPP = 0,
 USBD_REQ_HANDLED = 1,
 USBD_REQ_NEXT_CALLBACK = 2,
};
typedef struct _usbd_driver usbd_driver;
typedef struct _usbd_device usbd_device;
extern const usbd_driver st_usbfs_v1_usb_driver;
extern const usbd_driver stm32f107_usb_driver;
extern const usbd_driver stm32f207_usb_driver;
extern const usbd_driver stm32u5_usb_driver;
extern const usbd_driver stm32h7_usb_driver;
extern const usbd_driver st_usbfs_v2_usb_driver;
extern const usbd_driver efm32lg_usb_driver;
extern const usbd_driver efm32hg_usb_driver;
extern const usbd_driver lm4f_usb_driver;
extern usbd_device *usbd_init(const usbd_driver *driver, const struct usb_device_descriptor *dev,
 const struct usb_config_descriptor *conf, const char *const *strings, int num_strings, uint8_t *control_buffer,
 uint16_t control_buffer_size);
extern void usbd_register_reset_callback(usbd_device *usbd_dev, void (*callback)(void));
extern void usbd_register_suspend_callback(usbd_device *usbd_dev, void (*callback)(void));
extern void usbd_register_resume_callback(usbd_device *usbd_dev, void (*callback)(void));
extern void usbd_register_sof_callback(usbd_device *usbd_dev, void (*callback)(void));
typedef void (*usbd_control_complete_callback)(usbd_device *usbd_dev, struct usb_setup_data *req);
typedef enum usbd_request_return_codes (*usbd_control_callback)(usbd_device *usbd_dev, struct usb_setup_data *req,
 uint8_t **buf, uint16_t *len, usbd_control_complete_callback *complete);
typedef void (*usbd_set_config_callback)(usbd_device *usbd_dev, uint16_t wValue);
typedef enum usbd_request_return_codes (*usbd_microsoft_os_req_callback)(
 usbd_device *usbd_dev, struct usb_setup_data *req, uint8_t **buf, uint16_t *len);
typedef void (*usbd_set_altsetting_callback)(usbd_device *usbd_dev, uint16_t wIndex, uint16_t wValue);
typedef void (*usbd_endpoint_callback)(usbd_device *usbd_dev, uint8_t ep);
extern int usbd_register_control_callback(
 usbd_device *usbd_dev, uint8_t type, uint8_t type_mask, usbd_control_callback callback);
extern int usbd_register_set_config_callback(usbd_device *usbd_dev, usbd_set_config_callback callback);
extern void usbd_register_set_altsetting_callback(usbd_device *usbd_dev, usbd_set_altsetting_callback callback);
extern void usbd_register_extra_string(usbd_device *usbd_dev, int index, const char *string);
extern void usbd_poll(usbd_device *usbd_dev);
extern void usbd_disconnect(usbd_device *usbd_dev, _Bool disconnected);
extern void usbd_ep_setup(
 usbd_device *usbd_dev, uint8_t addr, uint8_t type, uint16_t max_size, usbd_endpoint_callback callback);
extern uint16_t usbd_ep_write_packet(usbd_device *usbd_dev, uint8_t addr, const void *buf, uint16_t len);
extern uint16_t usbd_ep_read_packet(usbd_device *usbd_dev, uint8_t addr, void *buf, uint16_t len);
extern void usbd_ep_stall_set(usbd_device *usbd_dev, uint8_t addr, uint8_t stall);
extern uint8_t usbd_ep_stall_get(usbd_device *usbd_dev, uint8_t addr);
extern void usbd_ep_nak_set(usbd_device *usbd_dev, uint8_t addr, uint8_t nak);
struct usb_cdc_header_descriptor {
 uint8_t bFunctionLength;
 uint8_t bDescriptorType;
 uint8_t bDescriptorSubtype;
 uint16_t bcdCDC;
} __attribute__((packed));
struct usb_cdc_union_descriptor {
 uint8_t bFunctionLength;
 uint8_t bDescriptorType;
 uint8_t bDescriptorSubtype;
 uint8_t bControlInterface;
 uint8_t bSubordinateInterface0;
} __attribute__((packed));
struct usb_cdc_call_management_descriptor {
 uint8_t bFunctionLength;
 uint8_t bDescriptorType;
 uint8_t bDescriptorSubtype;
 uint8_t bmCapabilities;
 uint8_t bDataInterface;
} __attribute__((packed));
struct usb_cdc_acm_descriptor {
 uint8_t bFunctionLength;
 uint8_t bDescriptorType;
 uint8_t bDescriptorSubtype;
 uint8_t bmCapabilities;
} __attribute__((packed));
struct usb_cdc_line_coding {
 uint32_t dwDTERate;
 uint8_t bCharFormat;
 uint8_t bParityType;
 uint8_t bDataBits;
} __attribute__((packed));
enum usb_cdc_line_coding_bCharFormat {
 USB_CDC_1_STOP_BITS = 0,
 USB_CDC_1_5_STOP_BITS = 1,
 USB_CDC_2_STOP_BITS = 2,
};
enum usb_cdc_line_coding_bParityType {
 USB_CDC_NO_PARITY = 0,
 USB_CDC_ODD_PARITY = 1,
 USB_CDC_EVEN_PARITY = 2,
 USB_CDC_MARK_PARITY = 3,
 USB_CDC_SPACE_PARITY = 4,
};
struct usb_cdc_notification {
 uint8_t bmRequestType;
 uint8_t bNotification;
 uint16_t wValue;
 uint16_t wIndex;
 uint16_t wLength;
} __attribute__((packed));
void pwr_disable_backup_domain_write_protect(void);
void pwr_enable_backup_domain_write_protect(void);
void pwr_enable_power_voltage_detect(uint32_t pvd_level);
void pwr_disable_power_voltage_detect(void);
void pwr_clear_standby_flag(void);
void pwr_clear_wakeup_flag(void);
void pwr_set_standby_mode(void);
void pwr_set_stop_mode(void);
void pwr_voltage_regulator_on_in_stop(void);
void pwr_voltage_regulator_low_power_in_stop(void);
void pwr_enable_wakeup_pin(void);
void pwr_disable_wakeup_pin(void);
_Bool pwr_voltage_high(void);
_Bool pwr_get_standby_flag(void);
_Bool pwr_get_wakeup_flag(void);
enum pwr_vos_scale {
 PWR_SCALE1 = 0x3,
 PWR_SCALE2 = 0x2,
 PWR_SCALE3 = 0x1,
};
void pwr_set_vos_scale(enum pwr_vos_scale scale);
extern uint32_t rcc_ahb_frequency;
extern uint32_t rcc_apb1_frequency;
extern uint32_t rcc_apb2_frequency;
enum rcc_clock_3v3 {
 RCC_CLOCK_3V3_84MHZ,
 RCC_CLOCK_3V3_96MHZ,
 RCC_CLOCK_3V3_168MHZ,
 RCC_CLOCK_3V3_180MHZ,
 RCC_CLOCK_3V3_END
};
struct rcc_clock_scale {
 uint8_t pllm;
 uint16_t plln;
 uint8_t pllp;
 uint8_t pllq;
 uint8_t pllr;
 uint8_t pll_source;
 uint32_t flash_config;
 uint8_t hpre;
 uint8_t ppre1;
 uint8_t ppre2;
 enum pwr_vos_scale voltage_scale;
 uint32_t ahb_frequency;
 uint32_t apb1_frequency;
 uint32_t apb2_frequency;
};
extern const struct rcc_clock_scale rcc_hsi_configs[RCC_CLOCK_3V3_END];
extern const struct rcc_clock_scale rcc_hse_8mhz_3v3[RCC_CLOCK_3V3_END];
extern const struct rcc_clock_scale rcc_hse_12mhz_3v3[RCC_CLOCK_3V3_END];
extern const struct rcc_clock_scale rcc_hse_16mhz_3v3[RCC_CLOCK_3V3_END];
extern const struct rcc_clock_scale rcc_hse_25mhz_3v3[RCC_CLOCK_3V3_END];
enum rcc_osc {
 RCC_PLL,
 RCC_PLLSAI,
 RCC_PLLI2S,
 RCC_HSE,
 RCC_HSI,
 RCC_LSE,
 RCC_LSI
};
enum rcc_periph_clken {
 RCC_GPIOA = (((0x30) << 5) + (0)),
 RCC_GPIOB = (((0x30) << 5) + (1)),
 RCC_GPIOC = (((0x30) << 5) + (2)),
 RCC_GPIOD = (((0x30) << 5) + (3)),
 RCC_GPIOE = (((0x30) << 5) + (4)),
 RCC_GPIOF = (((0x30) << 5) + (5)),
 RCC_GPIOG = (((0x30) << 5) + (6)),
 RCC_GPIOH = (((0x30) << 5) + (7)),
 RCC_GPIOI = (((0x30) << 5) + (8)),
 RCC_GPIOJ = (((0x30) << 5) + (9)),
 RCC_GPIOK = (((0x30) << 5) + (10)),
 RCC_CRC = (((0x30) << 5) + (12)),
 RCC_BKPSRAM = (((0x30) << 5) + (18)),
 RCC_CCMDATARAM = (((0x30) << 5) + (20)),
 RCC_DMA1 = (((0x30) << 5) + (21)),
 RCC_DMA2 = (((0x30) << 5) + (22)),
 RCC_DMA2D = (((0x30) << 5) + (23)),
 RCC_ETHMAC = (((0x30) << 5) + (25)),
 RCC_ETHMACTX = (((0x30) << 5) + (26)),
 RCC_ETHMACRX = (((0x30) << 5) + (27)),
 RCC_ETHMACPTP = (((0x30) << 5) + (28)),
 RCC_OTGHS = (((0x30) << 5) + (29)),
 RCC_OTGHSULPI = (((0x30) << 5) + (30)),
 RCC_DCMI = (((0x34) << 5) + (0)),
 RCC_CRYP = (((0x34) << 5) + (4)),
 RCC_HASH = (((0x34) << 5) + (5)),
 RCC_RNG = (((0x34) << 5) + (6)),
 RCC_OTGFS = (((0x34) << 5) + (7)),
 RCC_FSMC = (((0x38) << 5) + (0)),
 RCC_FMC = (((0x38) << 5) + (0)),
 RCC_QUADSPI = (((0x38) << 5) + (1)),
 RCC_TIM2 = (((0x40) << 5) + (0)),
 RCC_TIM3 = (((0x40) << 5) + (1)),
 RCC_TIM4 = (((0x40) << 5) + (2)),
 RCC_TIM5 = (((0x40) << 5) + (3)),
 RCC_TIM6 = (((0x40) << 5) + (4)),
 RCC_TIM7 = (((0x40) << 5) + (5)),
 RCC_TIM12 = (((0x40) << 5) + (6)),
 RCC_TIM13 = (((0x40) << 5) + (7)),
 RCC_TIM14 = (((0x40) << 5) + (8)),
 RCC_WWDG = (((0x40) << 5) + (11)),
 RCC_SPI2 = (((0x40) << 5) + (14)),
 RCC_SPI3 = (((0x40) << 5) + (15)),
 RCC_USART2 = (((0x40) << 5) + (17)),
 RCC_USART3 = (((0x40) << 5) + (18)),
 RCC_UART4 = (((0x40) << 5) + (19)),
 RCC_UART5 = (((0x40) << 5) + (20)),
 RCC_I2C1 = (((0x40) << 5) + (21)),
 RCC_I2C2 = (((0x40) << 5) + (22)),
 RCC_I2C3 = (((0x40) << 5) + (23)),
 RCC_CAN1 = (((0x40) << 5) + (25)),
 RCC_CAN2 = (((0x40) << 5) + (26)),
 RCC_PWR = (((0x40) << 5) + (28)),
 RCC_DAC = (((0x40) << 5) + (29)),
 RCC_UART7 = (((0x40) << 5) + (30)),
 RCC_UART8 = (((0x40) << 5) + (31)),
 RCC_TIM1 = (((0x44) << 5) + (0)),
 RCC_TIM8 = (((0x44) << 5) + (1)),
 RCC_USART1 = (((0x44) << 5) + (4)),
 RCC_USART6 = (((0x44) << 5) + (5)),
 RCC_ADC1 = (((0x44) << 5) + (8)),
 RCC_ADC2 = (((0x44) << 5) + (9)),
 RCC_ADC3 = (((0x44) << 5) + (10)),
 RCC_SDIO = (((0x44) << 5) + (11)),
 RCC_SPI1 = (((0x44) << 5) + (12)),
 RCC_SPI4 = (((0x44) << 5) + (13)),
 RCC_SYSCFG = (((0x44) << 5) + (14)),
 RCC_TIM9 = (((0x44) << 5) + (16)),
 RCC_TIM10 = (((0x44) << 5) + (17)),
 RCC_TIM11 = (((0x44) << 5) + (18)),
 RCC_SPI5 = (((0x44) << 5) + (20)),
 RCC_SPI6 = (((0x44) << 5) + (21)),
 RCC_SAI1EN = (((0x44) << 5) + (22)),
 RCC_LTDC = (((0x44) << 5) + (26)),
 RCC_DSI = (((0x44) << 5) + (27)),
 RCC_RTC = (((0x70) << 5) + (15)),
 SCC_GPIOA = (((0x50) << 5) + (0)),
 SCC_GPIOB = (((0x50) << 5) + (1)),
 SCC_GPIOC = (((0x50) << 5) + (2)),
 SCC_GPIOD = (((0x50) << 5) + (3)),
 SCC_GPIOE = (((0x50) << 5) + (4)),
 SCC_GPIOF = (((0x50) << 5) + (5)),
 SCC_GPIOG = (((0x50) << 5) + (6)),
 SCC_GPIOH = (((0x50) << 5) + (7)),
 SCC_GPIOI = (((0x50) << 5) + (8)),
 SCC_GPIOJ = (((0x50) << 5) + (9)),
 SCC_GPIOK = (((0x50) << 5) + (10)),
 SCC_CRC = (((0x50) << 5) + (12)),
 SCC_FLTIF = (((0x50) << 5) + (15)),
 SCC_SRAM1 = (((0x50) << 5) + (16)),
 SCC_SRAM2 = (((0x50) << 5) + (17)),
 SCC_BKPSRAM = (((0x50) << 5) + (18)),
 SCC_SRAM3 = (((0x50) << 5) + (19)),
 SCC_DMA1 = (((0x50) << 5) + (21)),
 SCC_DMA2 = (((0x50) << 5) + (22)),
 SCC_DMA2D = (((0x50) << 5) + (23)),
 SCC_ETHMAC = (((0x50) << 5) + (25)),
 SCC_ETHMACTX = (((0x50) << 5) + (26)),
 SCC_ETHMACRX = (((0x50) << 5) + (27)),
 SCC_ETHMACPTP = (((0x50) << 5) + (28)),
 SCC_OTGHS = (((0x50) << 5) + (29)),
 SCC_OTGHSULPI = (((0x50) << 5) + (30)),
 SCC_DCMI = (((0x54) << 5) + (0)),
 SCC_CRYP = (((0x54) << 5) + (4)),
 SCC_HASH = (((0x54) << 5) + (5)),
 SCC_RNG = (((0x54) << 5) + (6)),
 SCC_OTGFS = (((0x54) << 5) + (7)),
 SCC_QSPIC = (((0x58) << 5) + (1)),
 SCC_FMC = (((0x58) << 5) + (0)),
 SCC_FSMC = (((0x58) << 5) + (0)),
 SCC_TIM2 = (((0x60) << 5) + (0)),
 SCC_TIM3 = (((0x60) << 5) + (1)),
 SCC_TIM4 = (((0x60) << 5) + (2)),
 SCC_TIM5 = (((0x60) << 5) + (3)),
 SCC_TIM6 = (((0x60) << 5) + (4)),
 SCC_TIM7 = (((0x60) << 5) + (5)),
 SCC_TIM12 = (((0x60) << 5) + (6)),
 SCC_TIM13 = (((0x60) << 5) + (7)),
 SCC_TIM14 = (((0x60) << 5) + (8)),
 SCC_WWDG = (((0x60) << 5) + (11)),
 SCC_SPI2 = (((0x60) << 5) + (14)),
 SCC_SPI3 = (((0x60) << 5) + (15)),
 SCC_USART2 = (((0x60) << 5) + (17)),
 SCC_USART3 = (((0x60) << 5) + (18)),
 SCC_UART4 = (((0x60) << 5) + (19)),
 SCC_UART5 = (((0x60) << 5) + (20)),
 SCC_I2C1 = (((0x60) << 5) + (21)),
 SCC_I2C2 = (((0x60) << 5) + (22)),
 SCC_I2C3 = (((0x60) << 5) + (23)),
 SCC_CAN1 = (((0x60) << 5) + (25)),
 SCC_CAN2 = (((0x60) << 5) + (26)),
 SCC_PWR = (((0x60) << 5) + (28)),
 SCC_DAC = (((0x60) << 5) + (29)),
 SCC_UART7 = (((0x60) << 5) + (30)),
 SCC_UART8 = (((0x60) << 5) + (31)),
 SCC_TIM1 = (((0x64) << 5) + (0)),
 SCC_TIM8 = (((0x64) << 5) + (1)),
 SCC_USART1 = (((0x64) << 5) + (4)),
 SCC_USART6 = (((0x64) << 5) + (5)),
 SCC_ADC1 = (((0x64) << 5) + (8)),
 SCC_ADC2 = (((0x64) << 5) + (9)),
 SCC_ADC3 = (((0x64) << 5) + (10)),
 SCC_SDIO = (((0x64) << 5) + (11)),
 SCC_SPI1 = (((0x64) << 5) + (12)),
 SCC_SPI4 = (((0x64) << 5) + (13)),
 SCC_SYSCFG = (((0x64) << 5) + (14)),
 SCC_TIM9 = (((0x64) << 5) + (16)),
 SCC_TIM10 = (((0x64) << 5) + (17)),
 SCC_TIM11 = (((0x64) << 5) + (18)),
 SCC_SPI5 = (((0x64) << 5) + (20)),
 SCC_SPI6 = (((0x64) << 5) + (21)),
 SCC_SAI1 = (((0x64) << 5) + (22)),
 SCC_LTDC = (((0x64) << 5) + (26)),
 SCC_DSI = (((0x64) << 5) + (27)),
};
enum rcc_periph_rst {
 RST_GPIOA = (((0x10) << 5) + (0)),
 RST_GPIOB = (((0x10) << 5) + (1)),
 RST_GPIOC = (((0x10) << 5) + (2)),
 RST_GPIOD = (((0x10) << 5) + (3)),
 RST_GPIOE = (((0x10) << 5) + (4)),
 RST_GPIOF = (((0x10) << 5) + (5)),
 RST_GPIOG = (((0x10) << 5) + (6)),
 RST_GPIOH = (((0x10) << 5) + (7)),
 RST_GPIOI = (((0x10) << 5) + (8)),
 RST_GPIOJ = (((0x10) << 5) + (9)),
 RST_GPIOK = (((0x10) << 5) + (10)),
 RST_CRC = (((0x10) << 5) + (12)),
 RST_DMA1 = (((0x10) << 5) + (21)),
 RST_DMA2 = (((0x10) << 5) + (22)),
 RST_DMA2D = (((0x10) << 5) + (23)),
 RST_ETHMAC = (((0x10) << 5) + (25)),
 RST_OTGHS = (((0x10) << 5) + (29)),
 RST_DCMI = (((0x14) << 5) + (0)),
 RST_CRYP = (((0x14) << 5) + (4)),
 RST_HASH = (((0x14) << 5) + (5)),
 RST_RNG = (((0x14) << 5) + (6)),
 RST_OTGFS = (((0x14) << 5) + (7)),
 RST_QSPI = (((0x18) << 5) + (1)),
 RST_FSMC = (((0x18) << 5) + (0)),
 RST_FMC = (((0x18) << 5) + (0)),
 RST_TIM2 = (((0x20) << 5) + (0)),
 RST_TIM3 = (((0x20) << 5) + (1)),
 RST_TIM4 = (((0x20) << 5) + (2)),
 RST_TIM5 = (((0x20) << 5) + (3)),
 RST_TIM6 = (((0x20) << 5) + (4)),
 RST_TIM7 = (((0x20) << 5) + (5)),
 RST_TIM12 = (((0x20) << 5) + (6)),
 RST_TIM13 = (((0x20) << 5) + (7)),
 RST_TIM14 = (((0x20) << 5) + (8)),
 RST_WWDG = (((0x20) << 5) + (11)),
 RST_SPI2 = (((0x20) << 5) + (14)),
 RST_SPI3 = (((0x20) << 5) + (15)),
 RST_USART2 = (((0x20) << 5) + (17)),
 RST_USART3 = (((0x20) << 5) + (18)),
 RST_UART4 = (((0x20) << 5) + (19)),
 RST_UART5 = (((0x20) << 5) + (20)),
 RST_I2C1 = (((0x20) << 5) + (21)),
 RST_I2C2 = (((0x20) << 5) + (22)),
 RST_I2C3 = (((0x20) << 5) + (23)),
 RST_CAN1 = (((0x20) << 5) + (25)),
 RST_CAN2 = (((0x20) << 5) + (26)),
 RST_PWR = (((0x20) << 5) + (28)),
 RST_DAC = (((0x20) << 5) + (29)),
 RST_UART7 = (((0x20) << 5) + (30)),
 RST_UART8 = (((0x20) << 5) + (31)),
 RST_TIM1 = (((0x24) << 5) + (0)),
 RST_TIM8 = (((0x24) << 5) + (1)),
 RST_USART1 = (((0x24) << 5) + (4)),
 RST_USART6 = (((0x24) << 5) + (5)),
 RST_ADC = (((0x24) << 5) + (8)),
 RST_SDIO = (((0x24) << 5) + (11)),
 RST_SPI1 = (((0x24) << 5) + (12)),
 RST_SPI4 = (((0x24) << 5) + (13)),
 RST_SYSCFG = (((0x24) << 5) + (14)),
 RST_TIM9 = (((0x24) << 5) + (16)),
 RST_TIM10 = (((0x24) << 5) + (17)),
 RST_TIM11 = (((0x24) << 5) + (18)),
 RST_SPI5 = (((0x24) << 5) + (20)),
 RST_SPI6 = (((0x24) << 5) + (21)),
 RST_SAI1RST = (((0x24) << 5) + (22)),
 RST_LTDC = (((0x24) << 5) + (26)),
 RST_DSI = (((0x24) << 5) + (27)),
 RST_BDCR = (((0x70) << 5) + (16)),
};
void rcc_peripheral_enable_clock(volatile uint32_t *reg, uint32_t en);
void rcc_peripheral_disable_clock(volatile uint32_t *reg, uint32_t en);
void rcc_peripheral_reset(volatile uint32_t *reg, uint32_t reset);
void rcc_peripheral_clear_reset(volatile uint32_t *reg, uint32_t clear_reset);
void rcc_periph_clock_enable(enum rcc_periph_clken clken);
void rcc_periph_clock_disable(enum rcc_periph_clken clken);
void rcc_periph_reset_pulse(enum rcc_periph_rst rst);
void rcc_periph_reset_hold(enum rcc_periph_rst rst);
void rcc_periph_reset_release(enum rcc_periph_rst rst);
void rcc_set_mco(uint32_t mcosrc);
void rcc_osc_bypass_enable(enum rcc_osc osc);
void rcc_osc_bypass_disable(enum rcc_osc osc);
_Bool rcc_is_osc_ready(enum rcc_osc osc);
void rcc_wait_for_osc_ready(enum rcc_osc osc);
uint16_t rcc_get_div_from_hpre(uint8_t div_val);
void rcc_osc_ready_int_clear(enum rcc_osc osc);
void rcc_osc_ready_int_enable(enum rcc_osc osc);
void rcc_osc_ready_int_disable(enum rcc_osc osc);
int rcc_osc_ready_int_flag(enum rcc_osc osc);
void rcc_css_int_clear(void);
int rcc_css_int_flag(void);
void rcc_wait_for_sysclk_status(enum rcc_osc osc);
void rcc_osc_on(enum rcc_osc osc);
void rcc_osc_off(enum rcc_osc osc);
void rcc_css_enable(void);
void rcc_css_disable(void);
void rcc_plli2s_config(uint16_t n, uint8_t r);
void rcc_pllsai_config(uint16_t n, uint16_t p, uint16_t q, uint16_t r);
void rcc_pllsai_postscalers(uint8_t q, uint8_t r);
void rcc_set_sysclk_source(uint32_t clk);
void rcc_set_pll_source(uint32_t pllsrc);
void rcc_set_ppre2(uint32_t ppre2);
void rcc_set_ppre1(uint32_t ppre1);
void rcc_set_hpre(uint32_t hpre);
void rcc_set_rtcpre(uint32_t rtcpre);
void rcc_set_main_pll_hsi(uint32_t pllm, uint32_t plln, uint32_t pllp,
     uint32_t pllq, uint32_t pllr);
void rcc_set_main_pll_hse(uint32_t pllm, uint32_t plln, uint32_t pllp,
     uint32_t pllq, uint32_t pllr);
uint32_t rcc_system_clock_source(void);
void rcc_clock_setup_pll(const struct rcc_clock_scale *clock);
void __attribute__((deprecated("Use rcc_clock_setup_pll as direct replacement"))) rcc_clock_setup_hse_3v3(const struct rcc_clock_scale *clock);
uint32_t rcc_get_usart_clk_freq(uint32_t usart);
uint32_t rcc_get_timer_clk_freq(uint32_t timer);
uint32_t rcc_get_i2c_clk_freq(uint32_t i2c);
uint32_t rcc_get_spi_clk_freq(uint32_t spi);
static usbd_device *usb;
static m4_request rx;
static m4_response tx;
static unsigned received,sent;
static int configured,ready,reset_after_tx,in_flight;
volatile uint32_t usb_diagnostics[16] __attribute__((used,section(".usb_diag")));
static const uint32_t tag[4]={0x514a842du,0x166e90eeu,0x2717439cu,0xad3e7e3u};
static char serial_no[25];
static const char *strings[]={"A127","A127 STM32F407",serial_no};
static const struct usb_device_descriptor device={
 .bLength=sizeof(struct usb_device_descriptor),.bDescriptorType=1,.bcdUSB=0x0200,
 .bDeviceClass=2,.bDeviceSubClass=2,.bDeviceProtocol=0,.bMaxPacketSize0=64,
 .idVendor=0x1209,.idProduct=0x0001,.bcdDevice=0x0100,
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
uint32_t cycle_stamp(void){__asm__ volatile("dsb;isb":::"memory");return (*(volatile uint32_t *)(uintptr_t)(0xe0001004));}
uint32_t stack_used(void){uint8_t*p=(uint8_t*)__stack_bottom;while(p<(uint8_t*)__stack_top&&*p==0xa5)p++;return (uint32_t)((uint8_t*)__stack_top-p);}
void reset_to_dfu(void){
 if(((*(volatile uint32_t *)(uintptr_t)(0x40023800u +0x34))&(1u<<(7)))!=0){
   (*(volatile uint32_t *)(uintptr_t)(0x50000000u +0x804))|=(1u<<(1));__asm__ volatile("dsb");
   if(((*(volatile uint32_t *)(uintptr_t)(0xe000edfc))&(1u<<(24)))&&((*(volatile uint32_t *)(uintptr_t)(0xe0001000))&1u)){
     uint32_t start=cycle_stamp();
     while((uint32_t)(cycle_stamp()-start)<100800000u){}
   }else delay(18000000u);
   (*(volatile uint32_t *)(uintptr_t)(0x40023800u +0x14))|=(1u<<(7));__asm__ volatile("dsb");
   (*(volatile uint32_t *)(uintptr_t)(0x40023800u +0x14))&=~(1u<<(7));(*(volatile uint32_t *)(uintptr_t)(0x40023800u +0x34))&=~(1u<<(7));
 }
 (*(volatile uint32_t *)(uintptr_t)(0x40023800u))|=1u;
 for(unsigned i=0;i<1000000u && !((*(volatile uint32_t *)(uintptr_t)(0x40023800u))&(1u<<(1)));i++){}
 if((*(volatile uint32_t *)(uintptr_t)(0x40023800u))&(1u<<(1))){
   (*(volatile uint32_t *)(uintptr_t)(0x40023800u +8))&=~3u;
   for(unsigned i=0;i<1000000u && ((*(volatile uint32_t *)(uintptr_t)(0x40023800u +8))&12u);i++){}
   if(!((*(volatile uint32_t *)(uintptr_t)(0x40023800u +8))&12u)){(*(volatile uint32_t *)(uintptr_t)(0x40023800u))&=~((1u<<(24))|(1u<<(16)));delay(500000u);}
 }
 __asm__ volatile("dsb");(*(volatile uint32_t *)(uintptr_t)(0xe000ed0c))=0x05fa0004u;__asm__ volatile("dsb");for(;;){}
}
static int wait_bits(uint32_t a,uint32_t mask,uint32_t val){for(uint32_t n=0;n<8000000;n++){if(((*(volatile uint32_t *)(uintptr_t)(a))&mask)==val)return 1;}return 0;}
static void clocks(void){
 (*(volatile uint32_t *)(uintptr_t)(0x40023800u +0x34))|=(1u<<(7));(void)(*(volatile uint32_t *)(uintptr_t)(0x40023800u +0x34));(*(volatile uint32_t *)(uintptr_t)(0x50000000u +0x804))|=(1u<<(1));delay(900000);
 (*(volatile uint32_t *)(uintptr_t)(0x40023800u +0x14))|=(1u<<(7));(*(volatile uint32_t *)(uintptr_t)(0x40023800u +0x14))&=~(1u<<(7));
 (*(volatile uint32_t *)(uintptr_t)(0x40023800u))|=1u;if(!wait_bits(0x40023800u,3,3))reset_to_dfu();
 (*(volatile uint32_t *)(uintptr_t)(0x40023800u +8))&=~3u;if(!wait_bits(0x40023800u +8,12,0))reset_to_dfu();
 (*(volatile uint32_t *)(uintptr_t)(0x40023800u))&=~(1u<<(24));if(!wait_bits(0x40023800u,(1u<<(25)),0))reset_to_dfu();
 (*(volatile uint32_t *)(uintptr_t)(0x40023800u))|=(1u<<(16));if(!wait_bits(0x40023800u,(1u<<(17)),(1u<<(17))))reset_to_dfu();
 (*(volatile uint32_t *)(uintptr_t)(0x40023800u +0x40))|=(1u<<(28));(void)(*(volatile uint32_t *)(uintptr_t)(0x40023800u +0x40));(*(volatile uint32_t *)(uintptr_t)(0x40007000))|=(1u<<(14));
 (*(volatile uint32_t *)(uintptr_t)(0x40023c00))=(1u<<(8))|(1u<<(9))|(1u<<(10))|5;
 (*(volatile uint32_t *)(uintptr_t)(0x40023800u +4))=8u|(336u<<6)|(1u<<(22))|(7u<<24);
 (*(volatile uint32_t *)(uintptr_t)(0x40023800u +8))=((*(volatile uint32_t *)(uintptr_t)(0x40023800u +8))&~0x0000fcf3u)|(5u<<10)|(4u<<13);
 (*(volatile uint32_t *)(uintptr_t)(0x40023800u))|=(1u<<(24));if(!wait_bits(0x40023800u,(1u<<(25)),(1u<<(25))))reset_to_dfu();
 (*(volatile uint32_t *)(uintptr_t)(0x40023800u +8))=((*(volatile uint32_t *)(uintptr_t)(0x40023800u +8))&~3u)|2u;if(!wait_bits(0x40023800u +8,12,8))reset_to_dfu();
 (*(volatile uint32_t *)(uintptr_t)(0x40023800u +0x30))|=1u;(void)(*(volatile uint32_t *)(uintptr_t)(0x40023800u +0x30));
 (*(volatile uint32_t *)(uintptr_t)(0x40020000u))=((*(volatile uint32_t *)(uintptr_t)(0x40020000u))&~(15u<<22))|(10u<<22);
 (*(volatile uint32_t *)(uintptr_t)(0x40020000u +8))|=15u<<22;(*(volatile uint32_t *)(uintptr_t)(0x40020000u +12))&=~(15u<<22);(*(volatile uint32_t *)(uintptr_t)(0x40020000u +4))&=~(3u<<11);
 (*(volatile uint32_t *)(uintptr_t)(0x40020000u +0x24))=((*(volatile uint32_t *)(uintptr_t)(0x40020000u +0x24))&~(0xffu<<12))|(0xaau<<12);
 (*(volatile uint32_t *)(uintptr_t)(0xe000edfc))|=(1u<<(24));(*(volatile uint32_t *)(uintptr_t)(0xe0001000))|=1;(*(volatile uint32_t *)(uintptr_t)(0xe0001004))=0;
}
void hardware_info(m4_response *r){
 r->w[0]=0x524d3441u;r->w[1]=1;memcpy(r->w+8,tag,16);r->w[12]=0;r->w[13]=240;
 r->w[14]=(*(volatile uint32_t *)(uintptr_t)(0xe000ed00));r->w[15]=(*(volatile uint32_t *)(uintptr_t)(0xe0042000));
 for(int j=0;j<3;j++)r->w[16+j]=(*(volatile uint32_t *)(uintptr_t)(0x1fff7a10u+4u*j));
 r->w[19]=168000000u;r->w[20]=(*(volatile uint32_t *)(uintptr_t)(0x40023800u +8));r->w[21]=(*(volatile uint32_t *)(uintptr_t)(0x40023800u +4));
 r->w[22]=((*(volatile uint32_t *)(uintptr_t)(0xe0001000))&1u);r->w[36]=stack_used();r->w[37]=(uint32_t)((uint8_t*)__stack_top-(uint8_t*)__stack_bottom);
 r->w[38]=17024;r->w[39]=(uint32_t)(uintptr_t)__image_bytes;
 r->w[40]=(uint32_t)(uintptr_t)__reserved_ram;
 r->w[55]=(*(volatile uint32_t *)(uintptr_t)(0x40023800u));r->w[56]=*(volatile uint16_t*)0x1fff7a22u;
}
static enum usbd_request_return_codes control(usbd_device*d,struct usb_setup_data*q,uint8_t**b,uint16_t*n,void(**complete)(usbd_device*,struct usb_setup_data*)){
 (void)d;(void)complete;
 if(q->wIndex)return USBD_REQ_NOTSUPP;
 if(q->bRequest==0x22)return USBD_REQ_HANDLED;
 if(q->bRequest==0x20&&*n==7){memcpy(linecoding,*b,7);return USBD_REQ_HANDLED;}
 if(q->bRequest==0x21){*b=linecoding;*n=7;return USBD_REQ_HANDLED;}
 return USBD_REQ_NOTSUPP;
}
static void incoming(usbd_device*d,uint8_t ep){
 uint8_t pkt[64];int n=usbd_ep_read_packet(d,ep,pkt,sizeof(pkt));last_host_activity=cycle_stamp();
 usb_diagnostics[3]++;usb_diagnostics[4]=n;
 if(ready||sent<sizeof(tx))return;
 for(int i=0;i<n;i++){
  ((uint8_t*)&rx)[received++]=pkt[i];
  if(received==4&&rx.w[0]!=0x514d3441u){memmove(&rx,((uint8_t*)&rx)+1,3);received=3;}
  if(received==sizeof(rx)){ready=1;received=0;break;}
 }
}
static void completed(usbd_device*d,uint8_t ep){(void)d;(void)ep;in_flight=0;usb_diagnostics[7]++;}
static void cfg(usbd_device*d,uint16_t index){
 configured=index==1;ready=0;received=0;sent=sizeof(tx);reset_after_tx=0;in_flight=0;usb_diagnostics[2]++;
 if(!configured)return;
 usbd_ep_setup(d,0x01,0x02,64,incoming);usbd_ep_setup(d,0x82,0x02,64,completed);usbd_ep_setup(d,0x83,0x03,16,0);
 usbd_register_control_callback(d,0x21,0x7f,control);last_host_activity=cycle_stamp();
}
static void bus_reset(void){configured=0;ready=0;received=0;sent=sizeof(tx);reset_after_tx=0;in_flight=0;clear_bytes(&rx,sizeof(rx));clear_bytes(&tx,sizeof(tx));usb_diagnostics[1]++;}
static void clock_sample(m4_response *r){
 uint32_t initial=((*(volatile uint32_t *)(uintptr_t)(0x50000000u +0x808))>>8)&0x7ffu;
 uint32_t deadline=cycle_stamp(),last=initial,start=0,frames=0;
 while((uint32_t)(cycle_stamp()-deadline)<16800000u){
   uint32_t frame=((*(volatile uint32_t *)(uintptr_t)(0x50000000u +0x808))>>8)&0x7ffu;
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

extern void a127_repaint_dead_stack(void);
__asm__(".pushsection .text.a127_repaint_dead_stack,\"ax\",%progbits\n"
        ".thumb\n.type a127_repaint_dead_stack,%function\n"
        ".global a127_repaint_dead_stack\n.thumb_func\na127_repaint_dead_stack:\n"
        "ldr r0,=__stack_bottom\n mov r1,sp\n mov.w r2,#0xa5a5a5a5\n"
        "cmp r0,r1\n bhs 2f\n"
        "1: str r2,[r0],#4\n cmp r0,r1\n blo 1b\n"
        "2: dsb\n bx lr\n.size a127_repaint_dead_stack,.-a127_repaint_dead_stack\n"
        ".ltorg\n.popsection\n");

void board_start(void){
 clocks();memset((void*)usb_diagnostics,0,sizeof(usb_diagnostics));usb_diagnostics[0]=0x31474244;
 const char chars[]="0123456789ABCDEF";
 for(unsigned a=0;a<12;a++){uint8_t v=*(volatile uint8_t*)(0x1fff7a10u+a);serial_no[2*a]=chars[v>>4];serial_no[2*a+1]=chars[v&15];}
 usb=usbd_init(&stm32f107_usb_driver,&device,&config,strings,3,ctrl,sizeof(ctrl));
 (*(volatile uint32_t *)(uintptr_t)(0x50000000u +0x38))=((*(volatile uint32_t *)(uintptr_t)(0x50000000u +0x38))&~((1u<<(18))|(1u<<(19))))|(1u<<(21))|(1u<<(16));
 usbd_register_set_config_callback(usb,cfg);usbd_register_reset_callback(usb,bus_reset);
 uint32_t previous=cycle_stamp(),seen_activity=last_host_activity;uint64_t idle_ticks=0;
 for(;;){
   usbd_poll(usb);
   uint32_t now=cycle_stamp();idle_ticks+=(uint32_t)(now-previous);previous=now;
   if(last_host_activity!=seen_activity){seen_activity=last_host_activity;idle_ticks=0;}
   if(idle_ticks>=168000000ull*90ull){usb_diagnostics[9]++;unified_idle();idle_ticks=0;}
   if(ready){
     ready=0;usb_diagnostics[5]++;memset(&tx,0,sizeof(tx));hardware_info(&tx);tx.w[2]=rx.w[2];tx.w[3]=rx.w[3];memcpy(tx.w+4,rx.w+4,16);
     if(rx.w[0]!=0x514d3441u||rx.w[1]!=1||m4_checksum(&rx,60)!=rx.w[15])tx.w[23]=0;
     else if(rx.w[2]==M4_HELLO)unified_hello(&tx);
     else if(rx.w[2]==11)unified_hash(&tx);
     else if(rx.w[2]==12)selected_layout(&rx,&tx);
     else if(rx.w[2]==M4_CLOCK){if(unified_select(&rx,&tx))clock_sample(&tx);}
     else if(rx.w[2]==M4_RETURN_DFU){tx.w[23]=1;reset_after_tx=1;}
     else experiment(&rx,&tx);
     tx.w[36]=stack_used();tx.w[63]=m4_checksum(&tx,252);clear_bytes(&rx,sizeof(rx));a127_repaint_dead_stack();sent=0;
   }
   if(configured&&!in_flight&&sent<sizeof(tx)){
    unsigned n=sizeof(tx)-sent;if(n>60)n=60;
    unsigned k=usbd_ep_write_packet(usb,0x82,(uint8_t*)&tx+sent,n);
    if(k){in_flight=1;sent+=k;usb_diagnostics[6]++;usb_diagnostics[8]=sent;}
   }
   if(sent==sizeof(tx)&&!in_flight&&reset_after_tx){delay(900000);reset_to_dfu();}
 }
}
