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
static void dwc_flush_txfifo(usbd_device *usbd_dev, uint8_t ep);
void dwc_set_address(usbd_device *const usbd_dev, const uint8_t address)
{
 (*(volatile uint32_t *)((0x800U) + ((usbd_dev->driver->base_address)))) = ((*(volatile uint32_t *)((0x800U) + ((usbd_dev->driver->base_address)))) & ~0x000007F0U) | ((address << 4U) & 0x000007F0U);
}
void dwc_ep_setup(usbd_device *const usbd_dev, const uint8_t endpoint_address, const uint8_t type,
 const uint16_t max_packet_length, void (*const callback)(usbd_device *usbd_dev, uint8_t ep))
{
 const uint8_t ep = endpoint_address & 0x7fU;
 const uint8_t dir = endpoint_address & 0x80U;
 const uint16_t packet_length = max_packet_length / 4U;
 if (ep == 0U) {
  (*(volatile uint32_t *)((0x024U) + ((usbd_dev->driver->base_address)))) = usbd_dev->driver->rx_fifo_size;
  (*(volatile uint32_t *)((0x028U) + ((usbd_dev->driver->base_address)))) = (packet_length << 16U) | usbd_dev->driver->rx_fifo_size;
  usbd_dev->fifo_mem_top_ep0 = usbd_dev->driver->rx_fifo_size + packet_length;
  usbd_dev->fifo_mem_top = usbd_dev->fifo_mem_top_ep0;
  if (max_packet_length >= 64U)
   (*(volatile uint32_t *)((0x900U) + ((usbd_dev->driver->base_address)))) = (0x0U << 0U);
  else if (max_packet_length >= 32U)
   (*(volatile uint32_t *)((0x900U) + ((usbd_dev->driver->base_address)))) = (0x1U << 0U);
  else if (max_packet_length >= 16U)
   (*(volatile uint32_t *)((0x900U) + ((usbd_dev->driver->base_address)))) = (0x2U << 0U);
  else
   (*(volatile uint32_t *)((0x900U) + ((usbd_dev->driver->base_address)))) = (0x3U << 0U);
  (*(volatile uint32_t *)((0x900U) + ((usbd_dev->driver->base_address)))) |= (1U << 27U) | (1U << 15U);
  usbd_dev->doeptsiz[0U] =
   (0x1U << 29U) | (1U << 19U) | (max_packet_length & (0x0000007fU));
  (*(volatile uint32_t *)((0xB10U) + ((usbd_dev->driver->base_address)))) = usbd_dev->doeptsiz[0U];
  (*(volatile uint32_t *)((0xB00U) + ((usbd_dev->driver->base_address)))) = (1U << 31U) | (1U << 27U) | (1U << 15U);
 } else {
  if (dir == 0U) {
   usbd_dev->doeptsiz[ep] = (((1U) << (19U)) & (0x1ff80000U)) | (max_packet_length & (0x0007ffffU));
   (*(volatile uint32_t *)(((0xB10U + 0x20*(ep))) + ((usbd_dev->driver->base_address)))) = usbd_dev->doeptsiz[ep];
   (*(volatile uint32_t *)(((0xB00U + 0x20*(ep))) + ((usbd_dev->driver->base_address)))) = (1U << 31U) | (1U << 26U) | (1U << 15U) |
    (1U << 28U) | (type << 18U) |
    (max_packet_length & (0x000007ffU));
   usbd_dev->user_callback_ctr[ep][USB_TRANSACTION_OUT] = callback;
  } else {
   (*(volatile uint32_t *)(((0x104U + 4*((ep)-1))) + ((usbd_dev->driver->base_address)))) = (packet_length << 16U) | usbd_dev->fifo_mem_top;
   usbd_dev->fifo_mem_top += packet_length;
   (*(volatile uint32_t *)(((0x910U + 0x20*(ep))) + ((usbd_dev->driver->base_address)))) = 0U;
   (*(volatile uint32_t *)(((0x900U + 0x20*(ep))) + ((usbd_dev->driver->base_address)))) = (1U << 27U) | (1U << 15U) | (1U << 28U) |
    (ep << 22U) | (type << 18U) |
    (max_packet_length & (0x000007ffU));
   usbd_dev->user_callback_ctr[ep][USB_TRANSACTION_IN] = callback;
  }
 }
}
void dwc_endpoints_reset(usbd_device *const usbd_dev)
{
 usbd_dev->fifo_mem_top = usbd_dev->fifo_mem_top_ep0;
 for (size_t i = 1U; i < 4U; i++) {
  if ((*(volatile uint32_t *)(((0xB00U + 0x20*(i))) + ((usbd_dev->driver->base_address)))) & (1U << 31U)) {
   (*(volatile uint32_t *)(((0xB00U + 0x20*(i))) + ((usbd_dev->driver->base_address)))) |= (1U << 27U) | (1U << 30U);
  }
  if ((*(volatile uint32_t *)(((0x900U + 0x20*(i))) + ((usbd_dev->driver->base_address)))) & (1U << 31U)) {
   (*(volatile uint32_t *)(((0x900U + 0x20*(i))) + ((usbd_dev->driver->base_address)))) |= (1U << 27U) | (1U << 30U);
  }
 }
 (*(volatile uint32_t *)((0x010U) + ((usbd_dev->driver->base_address)))) = (0x10U << 6U) | (1U << 5U) | (1U << 4U);
 while (((*(volatile uint32_t *)((0x010U) + ((usbd_dev->driver->base_address)))) & ((1U << 5U) | (1U << 4U))) != 0U) {
 }
 (*(volatile uint32_t *)((0x010U) + ((usbd_dev->driver->base_address)))) &= ~(0x1fU << 6U);
 for (size_t i = 1U; i < 4U; i++) {
  (*(volatile uint32_t *)(((0xB08U + 0x20*(i))) + ((usbd_dev->driver->base_address)))) = (1U << 1U);
  (*(volatile uint32_t *)(((0x908U + 0x20*(i))) + ((usbd_dev->driver->base_address)))) = (1U << 1U);
 }
}
void dwc_ep_stall_set(usbd_device *const usbd_dev, const uint8_t endpoint_address, const uint8_t stall)
{
 const uint8_t ep = endpoint_address & 0x7fU;
 const uint8_t dir = endpoint_address & 0x80U;
 if (ep == 0U) {
  if (stall) {
   (*(volatile uint32_t *)(((0x900U + 0x20*(ep))) + ((usbd_dev->driver->base_address)))) |= (1U << 21U);
  } else {
   (*(volatile uint32_t *)(((0x900U + 0x20*(ep))) + ((usbd_dev->driver->base_address)))) &= ~(1U << 21U);
  }
 } else {
  if (dir == 0U) {
   if (stall) {
    (*(volatile uint32_t *)(((0xB00U + 0x20*(ep))) + ((usbd_dev->driver->base_address)))) |= (1U << 21U);
   } else {
    (*(volatile uint32_t *)(((0xB00U + 0x20*(ep))) + ((usbd_dev->driver->base_address)))) &= ~(1U << 21U);
   }
   (*(volatile uint32_t *)(((0xB00U + 0x20*(ep))) + ((usbd_dev->driver->base_address)))) |= (1U << 28U);
  } else {
   if (stall) {
    (*(volatile uint32_t *)(((0x900U + 0x20*(ep))) + ((usbd_dev->driver->base_address)))) |= (1U << 21U);
   } else {
    (*(volatile uint32_t *)(((0x900U + 0x20*(ep))) + ((usbd_dev->driver->base_address)))) &= ~(1U << 21U);
   }
   (*(volatile uint32_t *)(((0x900U + 0x20*(ep))) + ((usbd_dev->driver->base_address)))) |= (1U << 28U);
  }
 }
}
uint8_t dwc_ep_stall_get(usbd_device *const usbd_dev, const uint8_t endpoint_address)
{
 const uint8_t ep = endpoint_address & 0x7fU;
 const uint8_t dir = endpoint_address & 0x80U;
 if (dir == 0U) {
  return ((*(volatile uint32_t *)(((0xB00U + 0x20*(ep))) + ((usbd_dev->driver->base_address)))) & (1U << 21U)) ? 1 : 0;
 }
 return ((*(volatile uint32_t *)(((0x900U + 0x20*(ep))) + ((usbd_dev->driver->base_address)))) & (1U << 21U)) ? 1 : 0;
}
void dwc_ep_nak_set(usbd_device *const usbd_dev, const uint8_t endpoint_address, const uint8_t nak)
{
 const uint8_t ep = endpoint_address & 0x7fU;
 const uint8_t dir = endpoint_address & 0x80U;
 if (dir != 0U) {
  return;
 }
 usbd_dev->force_nak[ep] = nak;
 if (nak) {
  (*(volatile uint32_t *)(((0xB00U + 0x20*(ep))) + ((usbd_dev->driver->base_address)))) |= (1U << 27U);
 } else {
  (*(volatile uint32_t *)(((0xB00U + 0x20*(ep))) + ((usbd_dev->driver->base_address)))) |= (1U << 26U);
 }
}
uint16_t dwc_ep_write_packet(
 usbd_device *const usbd_dev, const uint8_t endpoint_address, const void *const buffer, const uint16_t length)
{
 const uint8_t ep = endpoint_address & 0x7fU;
 if (((*(volatile uint32_t *)(((0x900U + 0x20*(ep))) + ((usbd_dev->driver->base_address)))) & ((1U << 31U) | (1U << 30U) | (1U << 17U))) ==
  (1U << 31U)) {
  return 0U;
 }
 if (((*(volatile uint32_t *)(((0x900U + 0x20*(ep))) + ((usbd_dev->driver->base_address)))) & (1U << 31U)) != 0U) {
  dwc_flush_txfifo(usbd_dev, ep);
  (*(volatile uint32_t *)(((0x900U + 0x20*(ep))) + ((usbd_dev->driver->base_address)))) |= (1U << 30U);
  while (((*(volatile uint32_t *)(((0x908U + 0x20*(ep))) + ((usbd_dev->driver->base_address)))) & (1U << 1U)) == 0U)
   continue;
  (*(volatile uint32_t *)(((0x908U + 0x20*(ep))) + ((usbd_dev->driver->base_address)))) = (1U << 1U);
 }
 if (ep == 0U)
  (*(volatile uint32_t *)((0x910U) + ((usbd_dev->driver->base_address)))) = (1U << 19U) | (length & (0x0000007fU));
 else
  (*(volatile uint32_t *)(((0x910U + 0x20*(ep))) + ((usbd_dev->driver->base_address)))) = (0x1U << 29U) | (((1) << (19U)) & (0x1ff80000U)) | (length & (0x0007ffffU));
 (*(volatile uint32_t *)(((0x900U + 0x20*(ep))) + ((usbd_dev->driver->base_address)))) |= (1U << 31U) | (1U << 26U);
 const size_t aligned_length = length & ~3U;
  for (size_t offset = 0U; offset < aligned_length; offset += 4U)
   (*(volatile uint32_t *)(((((uintptr_t)(ep) + 1U) << 12U)) + ((usbd_dev->driver->base_address)))) = ((const uint32_t *)buffer)[offset >> 2U];
 if (length - aligned_length) {
  uint32_t data = 0U;
  memcpy(&data, (const uint8_t *)buffer + aligned_length, length - aligned_length);
  (*(volatile uint32_t *)(((((uintptr_t)(ep) + 1U) << 12U)) + ((usbd_dev->driver->base_address)))) = data;
 }
 return length;
}
uint16_t dwc_ep_read_packet(
 usbd_device *const usbd_dev, const uint8_t endpoint_address, void *const buffer, const uint16_t length)
{
 (void)endpoint_address;
 const size_t count = ((length) < (usbd_dev->rxbcnt) ? (length) : (usbd_dev->rxbcnt));
 const size_t aligned_count = count & ~3U;
  for (size_t offset = 0U; offset < aligned_count; offset += 4U)
   ((uint32_t *)buffer)[offset >> 2U] = (*(volatile uint32_t *)(((((uintptr_t)(0U) + 1U) << 12U)) + ((usbd_dev->driver->base_address))));
 if (count - aligned_count) {
  const uint32_t data = (*(volatile uint32_t *)(((((uintptr_t)(0U) + 1U) << 12U)) + ((usbd_dev->driver->base_address))));
  memcpy((uint8_t *)buffer + aligned_count, &data, count - aligned_count);
  if (usbd_dev->rxbcnt <= aligned_count + 4U)
   usbd_dev->rxbcnt = 0U;
  else
   usbd_dev->rxbcnt -= count + 4U;
 } else
  usbd_dev->rxbcnt -= count;
 return count;
}
static void dwc_flush_txfifo(usbd_device *const usbd_dev, const uint8_t ep)
{
 (*(volatile uint32_t *)(((0x900U + 0x20*(ep))) + ((usbd_dev->driver->base_address)))) |= (1U << 27U);
 while (((*(volatile uint32_t *)(((0x908U + 0x20*(ep))) + ((usbd_dev->driver->base_address)))) & (1U << 6U)) == 0U && ((*(volatile uint32_t *)(((0x900U + 0x20*(ep))) + ((usbd_dev->driver->base_address)))) & (1U << 17U)) == 0U) {
 }
 const uint32_t fifo = ((*(volatile uint32_t *)(((0x900U + 0x20*(ep))) + ((usbd_dev->driver->base_address)))) & (0xfU << 22U)) >> 22;
 while (((*(volatile uint32_t *)((0x010U) + ((usbd_dev->driver->base_address)))) & (1U << 31U)) == 0U) {
 }
 (*(volatile uint32_t *)((0x010U) + ((usbd_dev->driver->base_address)))) = (fifo << 6U) | (1U << 5U);
 while (((*(volatile uint32_t *)((0x010U) + ((usbd_dev->driver->base_address)))) & (1U << 5U)) != 0U) {
 }
 (*(volatile uint32_t *)(((0x910U + 0x20*(ep))) + ((usbd_dev->driver->base_address)))) = 0U;
}
void dwc_poll(usbd_device *const usbd_dev)
{
 const uint32_t status = (*(volatile uint32_t *)((0x014U) + ((usbd_dev->driver->base_address)))) & (*(volatile uint32_t *)((0x018U) + ((usbd_dev->driver->base_address))));
 if (status & (1U << 12U)) {
  dwc_endpoints_reset(usbd_dev);
  _usbd_reset(usbd_dev);
  (*(volatile uint32_t *)((0x014U) + ((usbd_dev->driver->base_address)))) = (1U << 12U);
  return;
 }
 if (status & (1U << 13U)) {
  (*(volatile uint32_t *)((0x014U) + ((usbd_dev->driver->base_address)))) = (1U << 13U);
  return;
 }
 if (status & (1U << 18U)) {
  for (size_t ep = 0U; ep < 4U; ++ep) {
   if ((*(volatile uint32_t *)(((0x908U + 0x20*(ep))) + ((usbd_dev->driver->base_address)))) & (1U << 0U)) {
    (*(volatile uint32_t *)(((0x900U + 0x20*(ep))) + ((usbd_dev->driver->base_address)))) |= (1U << 27U);
    if (usbd_dev->user_callback_ctr[ep][USB_TRANSACTION_IN]) {
     usbd_dev->user_callback_ctr[ep][USB_TRANSACTION_IN](usbd_dev, ep);
    }
   }
   (*(volatile uint32_t *)(((0x908U + 0x20*(ep))) + ((usbd_dev->driver->base_address)))) = (*(volatile uint32_t *)(((0x908U + 0x20*(ep))) + ((usbd_dev->driver->base_address))));
  }
 }
 while ((*(volatile uint32_t *)((0x014U) + ((usbd_dev->driver->base_address)))) & (1U << 4U)) {
  const uint32_t rx_status = (*(volatile uint32_t *)((0x020U) + ((usbd_dev->driver->base_address))));
  const uint32_t phase = rx_status & (0xfU << 17U);
  const uint8_t ep = rx_status & (0xfU << 0U);
  usbd_dev->rxbcnt = (rx_status & (0x7ffU << 4U)) >> 4U;
  switch (phase) {
  case (0x4U << 17U):
   usbd_dev->user_callback_ctr[ep][USB_TRANSACTION_SETUP](usbd_dev, ep);
   break;
  case (0x6U << 17U):
   if (((*(volatile uint32_t *)(((0x910U + 0x20*(ep))) + ((usbd_dev->driver->base_address)))) & (1U << 19U)) != 0U) {
    dwc_flush_txfifo(usbd_dev, ep);
   }
   dwc_ep_read_packet(usbd_dev, ep, &usbd_dev->control_state.req, sizeof(usbd_dev->control_state.req));
   break;
  case (0x2U << 17U):
   if (usbd_dev->user_callback_ctr[ep][USB_TRANSACTION_OUT]) {
    usbd_dev->user_callback_ctr[ep][USB_TRANSACTION_OUT](usbd_dev, ep);
   }
   break;
  default:
   break;
  }
  for (size_t offset = 0; offset < usbd_dev->rxbcnt; offset += 4U) {
   (void)(*(volatile uint32_t *)(((((uintptr_t)(0) + 1U) << 12U)) + ((usbd_dev->driver->base_address))));
  }
  usbd_dev->rxbcnt = 0U;
  if (phase == (0x4U << 17U) || phase == (0x3U << 17U)) {
   (*(volatile uint32_t *)(((0xB10U + 0x20*(ep))) + ((usbd_dev->driver->base_address)))) = usbd_dev->doeptsiz[ep];
   (*(volatile uint32_t *)(((0xB00U + 0x20*(ep))) + ((usbd_dev->driver->base_address)))) |=
    (1U << 31U) | (usbd_dev->force_nak[ep] ? (1U << 27U) : (1U << 26U));
  }
 }
 const uint32_t endpoints_status = (*(volatile uint32_t *)((0x818U) + ((usbd_dev->driver->base_address)))) & (*(volatile uint32_t *)((0x81CU) + ((usbd_dev->driver->base_address))));
 if (status & (1U << 19U)) {
  uint16_t endpoints_mask = (uint16_t)(endpoints_status >> 16U);
  uint8_t ep = 0U;
  while (endpoints_mask != 0U) {
   if (endpoints_mask & 1U) {
    (*(volatile uint32_t *)(((0xB08U + 0x20*(ep))) + ((usbd_dev->driver->base_address)))) = (*(volatile uint32_t *)(((0xB08U + 0x20*(ep))) + ((usbd_dev->driver->base_address))));
   }
   endpoints_mask >>= 1U;
   ++ep;
  }
 }
 if (status & (1U << 11U)) {
  if (usbd_dev->user_callback_suspend) {
   usbd_dev->user_callback_suspend();
  }
  (*(volatile uint32_t *)((0x014U) + ((usbd_dev->driver->base_address)))) = (1U << 11U);
 }
 if (status & (1U << 31U)) {
  if (usbd_dev->user_callback_resume) {
   usbd_dev->user_callback_resume();
  }
  (*(volatile uint32_t *)((0x014U) + ((usbd_dev->driver->base_address)))) = (1U << 31U);
 }
 if (status & (1U << 3U)) {
  if (usbd_dev->user_callback_sof) {
   usbd_dev->user_callback_sof();
  }
  (*(volatile uint32_t *)((0x014U) + ((usbd_dev->driver->base_address)))) = (1U << 3U);
 }
 if (usbd_dev->user_callback_sof) {
  (*(volatile uint32_t *)((0x018U) + ((usbd_dev->driver->base_address)))) |= (1U << 3U);
 } else {
  (*(volatile uint32_t *)((0x018U) + ((usbd_dev->driver->base_address)))) &= ~(1U << 3U);
 }
}
void dwc_disconnect(usbd_device *const usbd_dev, const _Bool disconnected)
{
 if (disconnected) {
  (*(volatile uint32_t *)((0x804U) + ((usbd_dev->driver->base_address)))) |= (1U << 1U);
 } else {
  (*(volatile uint32_t *)((0x804U) + ((usbd_dev->driver->base_address)))) &= ~(1U << 1U);
 }
}
void dwc_enable_sof(usbd_device *const usbd_dev)
{
 if (usbd_dev->user_callback_sof) {
  (*(volatile uint32_t *)((0x018U) + ((usbd_dev->driver->base_address)))) |= (1U << 3U);
 } else {
  (*(volatile uint32_t *)((0x018U) + ((usbd_dev->driver->base_address)))) &= ~(1U << 3U);
 }
}
