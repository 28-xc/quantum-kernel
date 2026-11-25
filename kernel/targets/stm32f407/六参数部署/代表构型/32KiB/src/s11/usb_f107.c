typedef int ptrdiff_t;
typedef unsigned int size_t;
typedef unsigned int wchar_t;
typedef struct {
  long long __clang_max_align_nonce1
      __attribute__((__aligned__(__alignof__(long long))));
  long double __clang_max_align_nonce2
      __attribute__((__aligned__(__alignof__(long double))));
} max_align_t;
void *memcpy(void *restrict dst, const void *restrict src, size_t n);
void *memmove(void *dst, const void *src, size_t n);
void *memset(void *dst, int value, size_t n);
int memcmp(const void *a, const void *b, size_t n);
size_t strlen(const char *s);
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
typedef struct __attribute__((packed)) usb_bos_descriptor {
 uint8_t bLength;
 uint8_t bDescriptorType;
 uint16_t wTotalLength;
 uint8_t bNumDeviceCaps;
 const void *device_capability_descriptors;
} usb_bos_descriptor;
typedef struct __attribute__((packed)) usb_bos_uuid {
 uint32_t a;
 uint16_t b;
 uint16_t c;
 uint16_t d;
 uint8_t e[6];
} usb_bos_uuid;
typedef struct usb_device_capability_descriptor {
 uint8_t bLength;
 uint8_t bDescriptorType;
 uint8_t bDevCapabilityType;
} usb_device_capability_descriptor;
typedef struct __attribute__((packed)) usb_usb2_extension_descriptor {
 usb_device_capability_descriptor device_capability_descriptor;
 uint32_t bmAttributes;
} usb_usb2_extension_descriptor;
typedef struct __attribute__((packed)) usb_superspeeed_device_capability_descriptor {
 usb_device_capability_descriptor device_capability_descriptor;
 uint8_t bmAttributes;
 uint16_t wSpeedsSupported;
 uint8_t bFunctionalitySupport;
 uint8_t bU1DevExitLat;
 uint16_t wU2DevExitLat;
} usb_superspeeed_device_capability_descriptor;
typedef struct usb_superspeed_endpoint_companion_descriptor {
 uint8_t bLength;
 uint8_t bDescriptorType;
 uint8_t bMaxBurst;
 uint8_t bmAttributes;
 uint16_t wBytesPerInterval;
} usb_superspeed_endpoint_companion_descriptor;
typedef struct __attribute__((packed)) usb_platform_device_capability_descriptor {
 usb_device_capability_descriptor device_capability_descriptor;
 uint8_t bReserved;
 usb_bos_uuid PlatformCapabilityUUID;
 const void *CapabilityData;
} usb_platform_device_capability_descriptor;
void usbd_register_bos_descriptor(usbd_device *usbd_dev, const usb_bos_descriptor *bos);
struct _usbd_device {
 const struct usb_device_descriptor *desc;
 const struct usb_config_descriptor *config;
 const usb_bos_descriptor *bos;
 const char *const *strings;
 int num_strings;
 uint8_t *ctrl_buf;
 uint16_t ctrl_buf_len;
 uint8_t current_address;
 uint8_t current_config;
 uint16_t pm_top;
 void (*user_callback_reset)(void);
 void (*user_callback_suspend)(void);
 void (*user_callback_resume)(void);
 void (*user_callback_sof)(void);
 struct usb_control_state {
  enum {
   IDLE,
   STALLED,
   DATA_IN,
   LAST_DATA_IN,
   STATUS_IN,
   DATA_OUT,
   LAST_DATA_OUT,
   STATUS_OUT,
  } state;
  struct usb_setup_data req __attribute__((aligned(4)));
  uint8_t *ctrl_buf;
  uint16_t ctrl_len;
  usbd_control_complete_callback complete;
  _Bool needs_zlp;
 } control_state;
 usbd_microsoft_os_req_callback microsoft_os_req_callback;
 const void *microsoft_os_descriptor_sets;
 uint8_t num_microsoft_os_descriptor_sets;
 struct user_control_callback {
  usbd_control_callback cb;
  uint8_t type;
  uint8_t type_mask;
 } user_control_callback[4U];
 usbd_endpoint_callback user_callback_ctr[8][3];
 usbd_set_config_callback user_callback_set_config[4U];
 usbd_set_altsetting_callback user_callback_set_altsetting;
 const struct _usbd_driver *driver;
 int extra_string_idx;
 const char *extra_string;
 uint16_t fifo_mem_top;
 uint16_t fifo_mem_top_ep0;
 uint8_t force_nak[4U];
 uint32_t doeptsiz[4U];
 uint16_t rxbcnt;
};
enum _usbd_transaction {
 USB_TRANSACTION_IN,
 USB_TRANSACTION_OUT,
 USB_TRANSACTION_SETUP,
};
void _usbd_control_in(usbd_device *usbd_dev, uint8_t ea);
void _usbd_control_out(usbd_device *usbd_dev, uint8_t ea);
void _usbd_control_setup(usbd_device *usbd_dev, uint8_t ea);
enum usbd_request_return_codes _usbd_standard_request_device(
 usbd_device *usbd_dev, struct usb_setup_data *req, uint8_t **buf, uint16_t *len);
enum usbd_request_return_codes _usbd_standard_request_interface(
 usbd_device *usbd_dev, struct usb_setup_data *req, uint8_t **buf, uint16_t *len);
enum usbd_request_return_codes _usbd_standard_request_endpoint(
 usbd_device *usbd_dev, struct usb_setup_data *req, uint8_t **buf, uint16_t *len);
enum usbd_request_return_codes _usbd_standard_request(
 usbd_device *usbd_dev, struct usb_setup_data *req, uint8_t **buf, uint16_t *len);
void _usbd_reset(usbd_device *usbd_dev);
struct _usbd_driver {
 usbd_device *(*init)(void);
 void (*set_address)(usbd_device *usbd_dev, uint8_t addr);
 void (*ep_setup)(usbd_device *usbd_dev, uint8_t addr, uint8_t type, uint16_t max_size, usbd_endpoint_callback cb);
 void (*ep_reset)(usbd_device *usbd_dev);
 void (*ep_stall_set)(usbd_device *usbd_dev, uint8_t addr, uint8_t stall);
 void (*ep_nak_set)(usbd_device *usbd_dev, uint8_t addr, uint8_t nak);
 uint8_t (*ep_stall_get)(usbd_device *usbd_dev, uint8_t addr);
 uint16_t (*ep_write_packet)(usbd_device *usbd_dev, uint8_t addr, const void *buf, uint16_t len);
 uint16_t (*ep_read_packet)(usbd_device *usbd_dev, uint8_t addr, void *buf, uint16_t len);
 void (*poll)(usbd_device *usbd_dev);
 void (*disconnect)(usbd_device *usbd_dev, _Bool disconnected);
 void (*enable_sof)(usbd_device *usbd_dev);
 uint32_t base_address;
 _Bool set_address_before_status;
 uint16_t rx_fifo_size;
};
void dwc_set_address(usbd_device *usbd_dev, uint8_t addr);
void dwc_ep_setup(usbd_device *usbd_dev, uint8_t addr, uint8_t type, uint16_t max_size,
 void (*callback)(usbd_device *usbd_dev, uint8_t ep));
void dwc_endpoints_reset(usbd_device *usbd_dev);
void dwc_ep_stall_set(usbd_device *usbd_dev, uint8_t addr, uint8_t stall);
uint8_t dwc_ep_stall_get(usbd_device *usbd_dev, uint8_t addr);
void dwc_ep_nak_set(usbd_device *usbd_dev, uint8_t addr, uint8_t nak);
uint16_t dwc_ep_write_packet(usbd_device *usbd_dev, uint8_t addr, const void *buf, uint16_t len);
uint16_t dwc_ep_read_packet(usbd_device *usbd_dev, uint8_t addr, void *buf, uint16_t len);
void dwc_poll(usbd_device *usbd_dev);
void dwc_disconnect(usbd_device *usbd_dev, _Bool disconnected);
void dwc_enable_sof(usbd_device *usbd_dev);
static usbd_device *stm32f107_usbd_init(void);
static struct _usbd_device usbd_dev;
const struct _usbd_driver stm32f107_usb_driver = {
 .init = stm32f107_usbd_init,
 .set_address = dwc_set_address,
 .ep_setup = dwc_ep_setup,
 .ep_reset = dwc_endpoints_reset,
 .ep_stall_set = dwc_ep_stall_set,
 .ep_stall_get = dwc_ep_stall_get,
 .ep_nak_set = dwc_ep_nak_set,
 .ep_write_packet = dwc_ep_write_packet,
 .ep_read_packet = dwc_ep_read_packet,
 .poll = dwc_poll,
 .disconnect = dwc_disconnect,
 .base_address = (0x50000000U + 0x00000),
 .set_address_before_status = 1,
 .rx_fifo_size = 38U,
};
static usbd_device *stm32f107_usbd_init(void)
{
 rcc_periph_clock_enable(RCC_OTGFS);
 (*(volatile uint32_t *)((0x50000000U + 0x00000) + 0x00CU)) |= (1U << 6U);
 while (((*(volatile uint32_t *)((0x50000000U + 0x00000) + 0x010U)) & (1U << 31U)) == 0U)
  continue;
 (*(volatile uint32_t *)((0x50000000U + 0x00000) + 0x010U)) |= (1U << 0U);
 while (((*(volatile uint32_t *)((0x50000000U + 0x00000) + 0x010U)) & (1U << 0U)) != 0U)
  continue;
 if ((*(volatile uint32_t *)((0x50000000U + 0x00000) + 0x03CU)) >= 0x00002000U) {
  (*(volatile uint32_t *)((0x50000000U + 0x00000) + 0x038U)) |= (1U << 21U) | (1U << 16U);
 } else {
  (*(volatile uint32_t *)((0x50000000U + 0x00000) + 0x038U)) |= (1U << 19U) | (1U << 16U);
 }
 (*(volatile uint32_t *)((0x50000000U + 0x00000) + 0x804U)) &= ~(1U << 1U);
 (*(volatile uint32_t *)((0x50000000U + 0x00000) + 0x00CU)) |= (1U << 30U) | (0xfU << 10U);
 (*(volatile uint32_t *)((0x50000000U + 0x00000) + 0x014U)) = (1U << 1U);
 (*(volatile uint32_t *)((0x50000000U + 0x00000) + 0x800U)) |= 0x00000003U;
 (*(volatile uint32_t *)((0x50000000U + 0x00000) + 0xE00U)) = 0;
 (*(volatile uint32_t *)((0x50000000U + 0x00000) + 0x008U)) |= (1U << 0U);
 (*(volatile uint32_t *)((0x50000000U + 0x00000) + 0x018U)) = (1U << 4U) | (1U << 11U) | (1U << 12U) | (1U << 13U) |
  (1U << 18U) | (1U << 19U) | (1U << 31U);
 (*(volatile uint32_t *)((0x50000000U + 0x00000) + 0x81CU)) = 0x000f000fU;
 (*(volatile uint32_t *)((0x50000000U + 0x00000) + 0x810U)) = (1U << 0U);
 (*(volatile uint32_t *)((0x50000000U + 0x00000) + 0x814U)) = (1U << 3U) | (1U << 0U);
 return &usbd_dev;
}
