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
typedef uint16_t usb_char16_t;
enum microsoft_req {
 MICROSOFT_GET_DESCRIPTOR_SET = 7,
 MICROSOFT_SET_ALTERNATE_ENUM = 8,
};
enum microsoft_os_descriptor_types {
 MICROSOFT_OS_SET_HEADER = 0,
 MICROSOFT_OS_SUBSET_HEADER_CONFIGURATION = 1,
 MICROSOFT_OS_SUBSET_HEADER_FUNCTION = 2,
 MICROSOFT_OS_FEATURE_COMPATIBLE_ID = 3,
 MICROSOFT_OS_FEATURE_REG_PROPERTY = 4,
 MICROSOFT_OS_FEATURE_MIN_RESUME_TIME = 5,
 MICROSOFT_OS_FEATURE_MODEL_ID = 6,
 MICROSOFT_OS_FEATURE_CCGP_DEVICE = 7,
 MICROSOFT_OS_FEATURE_VENDOR_REVISION = 8,
};
enum microsoft_registry_types {
 REG_SZ = 1,
 REG_EXPAND_SZ = 2,
 REG_BINARY = 3,
 REG_DWORD_LITTLE_ENDIAN = 4,
 REG_DWORD_BIG_ENDIAN = 5,
 REG_LINK = 6,
 REG_MULTI_SZ = 7,
};
typedef struct __attribute__((packed)) microsoft_os_descriptor_set_information {
 uint32_t dwWindowsVersion;
 uint16_t wMSOSDescriptorSetTotalLength;
 uint8_t bMS_VendorCode;
 uint8_t bAltEnumCode;
} microsoft_os_descriptor_set_information;
typedef struct microsoft_os_feature_descriptor {
 uint16_t wLength;
 uint16_t wDescriptorType;
} microsoft_os_feature_descriptor;
typedef struct microsoft_os_feature_compatible_id_descriptor {
 microsoft_os_feature_descriptor header;
 char compatible_id[8];
 char sub_compatible_id[8];
} microsoft_os_feature_compatible_id_descriptor;
typedef struct microsoft_os_feature_registry_property_descriptor {
 microsoft_os_feature_descriptor header;
 uint16_t wPropertyDataType;
 uint16_t wPropertyNameLength;
 const usb_char16_t *PropertyName;
 uint16_t wPropertyDataLength;
 const void *PropertyData;
} microsoft_os_feature_registry_property_descriptor;
typedef struct microsoft_os_feature_min_recovery_time_descriptor {
 microsoft_os_feature_descriptor header;
 uint8_t bResumeRecoveryTime;
 uint8_t bResumeSignalingTime;
} microsoft_os_feature_min_recovery_time_descriptor;
typedef struct microsoft_os_feature_model_id_descriptor {
 microsoft_os_feature_descriptor header;
 usb_bos_uuid ModelID;
} microsoft_os_feature_model_id_descriptor;
typedef struct microsoft_os_feature_descriptor microsoft_os_feature_ccgp_device_descriptor;
typedef struct microsoft_os_feature_vendor_revision_descriptor {
 microsoft_os_feature_descriptor header;
 uint16_t VendorRevision;
} microsoft_os_feature_vendor_revision_descriptor;
typedef struct microsoft_os_descriptor_function_subset_header {
 uint16_t wLength;
 uint16_t wDescriptorType;
 uint8_t bFirstInterface;
 uint8_t bReserved;
 uint16_t wTotalLength;
 const void *feature_descriptors;
 uint8_t num_feature_descriptors;
} microsoft_os_descriptor_function_subset_header;
typedef struct microsoft_os_descriptor_config_subset_header {
 uint16_t wLength;
 uint16_t wDescriptorType;
 uint8_t bConfigurationValue;
 uint8_t bReserved;
 uint16_t wTotalLength;
 const microsoft_os_descriptor_function_subset_header *function_subset_headers;
 uint8_t num_function_subset_headers;
} microsoft_os_descriptor_config_subset_header;
typedef struct microsoft_os_descriptor_set_header {
 uint16_t wLength;
 uint16_t wDescriptorType;
 uint32_t dwWindowsVersion;
 uint16_t wTotalLength;
 uint8_t vendor_code;
 uint8_t num_config_subset_headers;
 const microsoft_os_descriptor_config_subset_header *config_subset_headers;
} microsoft_os_descriptor_set_header;
extern void microsoft_os_register_descriptor_sets(usbd_device *dev,
 const microsoft_os_descriptor_set_header *sets, uint8_t num_sets);
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

static const usb_bos_uuid microsoft_os_descriptor_platform_capability_id =
 { 0xd8dd60dfU, 0x4589U, 0x4cc7U, 0xd29cU, {0x65U, 0x9dU, 0x9eU, 0x64U, 0x8aU, 0x9fU}, };
int usbd_register_set_config_callback(usbd_device *usbd_dev, usbd_set_config_callback callback)
{
 for (size_t i = 0; i < 4U; i++) {
  if (usbd_dev->user_callback_set_config[i]) {
   if (usbd_dev->user_callback_set_config[i] == callback) {
    return 0;
   }
   continue;
  }
  usbd_dev->user_callback_set_config[i] = callback;
  return 0;
 }
 return -1;
}
void usbd_register_set_altsetting_callback(usbd_device *usbd_dev, usbd_set_altsetting_callback callback)
{
 usbd_dev->user_callback_set_altsetting = callback;
}
static uint16_t build_config_descriptor(usbd_device *usbd_dev, uint8_t index, uint8_t *buf, uint16_t len)
{
 uint8_t *tmpbuf = buf;
 const struct usb_config_descriptor *cfg = &usbd_dev->config[index];
 uint16_t count, total = 0, totallen = 0;
 uint16_t i, j, k;
 memcpy(buf, cfg, count = ((len) < (cfg->bLength) ? (len) : (cfg->bLength)));
 buf += count;
 len -= count;
 total += count;
 totallen += cfg->bLength;
 for (i = 0; i < cfg->bNumInterfaces; i++) {
  if (cfg->interface[i].iface_assoc) {
   const struct usb_iface_assoc_descriptor *assoc = cfg->interface[i].iface_assoc;
   memcpy(buf, assoc, count = ((len) < (assoc->bLength) ? (len) : (assoc->bLength)));
   buf += count;
   len -= count;
   total += count;
   totallen += assoc->bLength;
  }
  for (j = 0; j < cfg->interface[i].num_altsetting; j++) {
   const struct usb_interface_descriptor *iface = &cfg->interface[i].altsetting[j];
   memcpy(buf, iface, count = ((len) < (iface->bLength) ? (len) : (iface->bLength)));
   buf += count;
   len -= count;
   total += count;
   totallen += iface->bLength;
   if (iface->extra) {
    memcpy(buf, iface->extra, count = ((len) < (iface->extralen) ? (len) : (iface->extralen)));
    buf += count;
    len -= count;
    total += count;
    totallen += iface->extralen;
   }
   for (k = 0; k < iface->bNumEndpoints; k++) {
    const struct usb_endpoint_descriptor *ep = &iface->endpoint[k];
    memcpy(buf, ep, count = ((len) < (ep->bLength) ? (len) : (ep->bLength)));
    buf += count;
    len -= count;
    total += count;
    totallen += ep->bLength;
    if (ep->extra) {
     memcpy(buf, ep->extra, count = ((len) < (ep->extralen) ? (len) : (ep->extralen)));
     buf += count;
     len -= count;
     total += count;
     totallen += ep->extralen;
    }
   }
  }
 }
 memcpy((tmpbuf + 2), &totallen, sizeof(uint16_t));
 return total;
}
static uint16_t build_devcap_platform(
 const usb_platform_device_capability_descriptor *const plat, uint8_t *const buf, uint16_t len)
{
 uint16_t count = ((len) < (20U) ? (len) : (20U));
 memcpy(buf, plat, count);
 len -= count;
 const uint16_t total = count;
 if (!memcmp(&plat->PlatformCapabilityUUID, &microsoft_os_descriptor_platform_capability_id, sizeof(usb_bos_uuid))) {
  const microsoft_os_descriptor_set_information *info = plat->CapabilityData;
  count = ((len) < (sizeof(microsoft_os_descriptor_set_information)) ? (len) : (sizeof(microsoft_os_descriptor_set_information)));
  memcpy(buf + total, info, count);
  return total + count;
 }
 return 0;
}
static uint16_t build_bos_descriptor(usbd_device *usbd_dev, uint8_t *const buf, uint16_t len)
{
 const usb_bos_descriptor *const bos = usbd_dev->bos;
 uint16_t count = ((len) < (bos->bLength) ? (len) : (bos->bLength));
 memcpy(buf, bos, count);
 len -= count;
 uint16_t total = count;
 uint16_t total_length = bos->bLength;
 size_t offset = 0;
 for (uint8_t i = 0; i < bos->bNumDeviceCaps; ++i) {
  const usb_device_capability_descriptor *const dev_cap =
   (const usb_device_capability_descriptor *)(((const uint8_t *)bos->device_capability_descriptors) + offset);
  switch (dev_cap->bDevCapabilityType) {
  case 5:
   count = build_devcap_platform((const usb_platform_device_capability_descriptor *)dev_cap, buf + total, len);
   total_length += dev_cap->bLength;
   offset += sizeof(usb_platform_device_capability_descriptor) + sizeof(microsoft_os_descriptor_set_information);
   break;
  default:
   return 0;
  }
  if (!count && len)
   return 0;
  len -= count;
  total += count;
 }
 ((usb_bos_descriptor *)buf)->wTotalLength = total_length;
 return total;
}
static int usb_descriptor_type(uint16_t wValue)
{
 return wValue >> 8;
}
static int usb_descriptor_index(uint16_t wValue)
{
 return wValue & 0xFF;
}
static enum usbd_request_return_codes usb_standard_get_descriptor(
 usbd_device *usbd_dev, struct usb_setup_data *req, uint8_t **buf, uint16_t *len)
{
 int i, array_idx, descr_idx;
 struct usb_string_descriptor *sd;
 descr_idx = usb_descriptor_index(req->wValue);
 switch (usb_descriptor_type(req->wValue)) {
 case 1:
  *buf = (uint8_t *)usbd_dev->desc;
  *len = ((*len) < (usbd_dev->desc->bLength) ? (*len) : (usbd_dev->desc->bLength));
  return USBD_REQ_HANDLED;
 case 2:
  *buf = usbd_dev->ctrl_buf;
  *len = build_config_descriptor(usbd_dev, descr_idx, *buf, *len);
  return USBD_REQ_HANDLED;
 case 15:
  if (!usbd_dev->bos || descr_idx != 0)
   return USBD_REQ_NOTSUPP;
  *buf = usbd_dev->ctrl_buf;
  *len = build_bos_descriptor(usbd_dev, *buf, *len);
  return *len ? USBD_REQ_HANDLED : USBD_REQ_NOTSUPP;
 case 3:
  sd = (struct usb_string_descriptor *)usbd_dev->ctrl_buf;
  if (descr_idx == 0) {
   sd->wData[0] = USB_LANGID_ENGLISH_US;
   sd->bLength = sizeof(sd->bLength) + sizeof(sd->bDescriptorType) + sizeof(sd->wData[0]);
   *len = ((*len) < (sd->bLength) ? (*len) : (sd->bLength));
  } else if (descr_idx == usbd_dev->extra_string_idx) {
   sd->bLength = strlen(usbd_dev->extra_string) * 2 + sizeof(sd->bLength) + sizeof(sd->bDescriptorType);
   *len = ((*len) < (sd->bLength) ? (*len) : (sd->bLength));
   for (i = 0; i < (*len / 2) - 1; i++) {
    sd->wData[i] = usbd_dev->extra_string[i];
   }
  } else {
   array_idx = descr_idx - 1;
   if (!usbd_dev->strings) {
    return USBD_REQ_NOTSUPP;
   }
   if (array_idx >= usbd_dev->num_strings) {
    return USBD_REQ_NOTSUPP;
   }
   if (req->wIndex != USB_LANGID_ENGLISH_US) {
    return USBD_REQ_NOTSUPP;
   }
   sd->bLength = strlen(usbd_dev->strings[array_idx]) * 2 + sizeof(sd->bLength) + sizeof(sd->bDescriptorType);
   *len = ((*len) < (sd->bLength) ? (*len) : (sd->bLength));
   for (i = 0; i < (*len / 2) - 1; i++) {
    sd->wData[i] = usbd_dev->strings[array_idx][i];
   }
  }
  sd->bDescriptorType = 3;
  *buf = (uint8_t *)sd;
  return USBD_REQ_HANDLED;
 }
 return USBD_REQ_NOTSUPP;
}
static enum usbd_request_return_codes usb_standard_set_address(
 usbd_device *usbd_dev, struct usb_setup_data *req, uint8_t **buf, uint16_t *len)
{
 (void)buf;
 (void)len;
 if (req->bmRequestType != 0 || req->wValue >= 128) {
  return USBD_REQ_NOTSUPP;
 }
 usbd_dev->current_address = req->wValue;
 if (usbd_dev->driver->set_address_before_status) {
  usbd_dev->driver->set_address(usbd_dev, req->wValue);
 }
 return USBD_REQ_HANDLED;
}
static enum usbd_request_return_codes usb_standard_set_configuration(
 usbd_device *usbd_dev, struct usb_setup_data *req, uint8_t **buf, uint16_t *len)
{
 unsigned i;
 int found_index = -1;
 const struct usb_config_descriptor *cfg;
 (void)buf;
 (void)len;
 if (req->wValue > 0) {
  for (i = 0; i < usbd_dev->desc->bNumConfigurations; i++) {
   if (req->wValue == usbd_dev->config[i].bConfigurationValue) {
    found_index = i;
    break;
   }
  }
  if (found_index < 0) {
   return USBD_REQ_NOTSUPP;
  }
 }
 usbd_dev->current_config = found_index + 1;
 if (usbd_dev->current_config > 0) {
  cfg = &usbd_dev->config[usbd_dev->current_config - 1];
  for (i = 0; i < cfg->bNumInterfaces; i++) {
   if (cfg->interface[i].cur_altsetting) {
    *cfg->interface[i].cur_altsetting = 0;
   }
  }
 }
 usbd_dev->driver->ep_reset(usbd_dev);
 if (usbd_dev->user_callback_set_config[0]) {
  for (i = 0; i < 4U; i++) {
   usbd_dev->user_control_callback[i].cb = ((void*)0);
  }
  for (i = 0; i < 4U; i++) {
   if (usbd_dev->user_callback_set_config[i]) {
    usbd_dev->user_callback_set_config[i](usbd_dev, req->wValue);
   }
  }
 }
 return USBD_REQ_HANDLED;
}
static enum usbd_request_return_codes usb_standard_get_configuration(
 usbd_device *usbd_dev, struct usb_setup_data *req, uint8_t **buf, uint16_t *len)
{
 (void)req;
 if (*len > 1) {
  *len = 1;
 }
 if (usbd_dev->current_config > 0) {
  const struct usb_config_descriptor *cfg = &usbd_dev->config[usbd_dev->current_config - 1];
  (*buf)[0] = cfg->bConfigurationValue;
 } else {
  (*buf)[0] = 0;
 }
 return USBD_REQ_HANDLED;
}
static enum usbd_request_return_codes usb_standard_set_interface(
 usbd_device *usbd_dev, struct usb_setup_data *req, uint8_t **buf, uint16_t *len)
{
 const struct usb_config_descriptor *cfx = &usbd_dev->config[usbd_dev->current_config - 1];
 const struct usb_interface *iface;
 (void)buf;
 if (req->wIndex >= cfx->bNumInterfaces) {
  return USBD_REQ_NOTSUPP;
 }
 iface = &cfx->interface[req->wIndex];
 if (req->wValue >= iface->num_altsetting) {
  return USBD_REQ_NOTSUPP;
 }
 if (iface->cur_altsetting) {
  *iface->cur_altsetting = req->wValue;
 } else if (req->wValue > 0) {
  return USBD_REQ_NOTSUPP;
 }
 if (usbd_dev->user_callback_set_altsetting) {
  usbd_dev->user_callback_set_altsetting(usbd_dev, req->wIndex, req->wValue);
 }
 *len = 0;
 return USBD_REQ_HANDLED;
}
static enum usbd_request_return_codes usb_standard_get_interface(
 usbd_device *usbd_dev, struct usb_setup_data *req, uint8_t **buf, uint16_t *len)
{
 uint8_t *cur_altsetting;
 const struct usb_config_descriptor *cfx = &usbd_dev->config[usbd_dev->current_config - 1];
 if (req->wIndex >= cfx->bNumInterfaces) {
  return USBD_REQ_NOTSUPP;
 }
 *len = 1;
 cur_altsetting = cfx->interface[req->wIndex].cur_altsetting;
 (*buf)[0] = (cur_altsetting) ? *cur_altsetting : 0;
 return USBD_REQ_HANDLED;
}
static enum usbd_request_return_codes usb_standard_device_get_status(
 usbd_device *usbd_dev, struct usb_setup_data *req, uint8_t **buf, uint16_t *len)
{
 (void)usbd_dev;
 (void)req;
 if (*len > 2) {
  *len = 2;
 }
 (*buf)[0] = 0;
 (*buf)[1] = 0;
 return USBD_REQ_HANDLED;
}
static enum usbd_request_return_codes usb_standard_interface_get_status(
 usbd_device *usbd_dev, struct usb_setup_data *req, uint8_t **buf, uint16_t *len)
{
 (void)usbd_dev;
 (void)req;
 if (*len > 2) {
  *len = 2;
 }
 (*buf)[0] = 0;
 (*buf)[1] = 0;
 return USBD_REQ_HANDLED;
}
static enum usbd_request_return_codes usb_standard_endpoint_get_status(
 usbd_device *usbd_dev, struct usb_setup_data *req, uint8_t **buf, uint16_t *len)
{
 (void)req;
 if (*len > 2) {
  *len = 2;
 }
 (*buf)[0] = usbd_ep_stall_get(usbd_dev, req->wIndex) ? 1 : 0;
 (*buf)[1] = 0;
 return USBD_REQ_HANDLED;
}
static enum usbd_request_return_codes usb_standard_endpoint_stall(
 usbd_device *usbd_dev, struct usb_setup_data *req, uint8_t **buf, uint16_t *len)
{
 (void)buf;
 (void)len;
 usbd_ep_stall_set(usbd_dev, req->wIndex, 1);
 return USBD_REQ_HANDLED;
}
static enum usbd_request_return_codes usb_standard_endpoint_unstall(
 usbd_device *usbd_dev, struct usb_setup_data *req, uint8_t **buf, uint16_t *len)
{
 (void)buf;
 (void)len;
 usbd_ep_stall_set(usbd_dev, req->wIndex, 0);
 return USBD_REQ_HANDLED;
}
enum usbd_request_return_codes _usbd_standard_request_device(
 usbd_device *usbd_dev, struct usb_setup_data *req, uint8_t **buf, uint16_t *len)
{
 enum usbd_request_return_codes (*command)(
  usbd_device *usbd_dev, struct usb_setup_data *req, uint8_t **buf, uint16_t *len) = ((void*)0);
 switch (req->bRequest) {
 case 1:
 case 3:
  if (req->wValue == 1) {
  }
  if (req->wValue == 2) {
  }
  break;
 case 5:
  command = usb_standard_set_address;
  break;
 case 9:
  command = usb_standard_set_configuration;
  break;
 case 8:
  command = usb_standard_get_configuration;
  break;
 case 6:
  command = usb_standard_get_descriptor;
  break;
 case 0:
  command = usb_standard_device_get_status;
  break;
 case 7:
  break;
 }
 if (!command) {
  return USBD_REQ_NOTSUPP;
 }
 return command(usbd_dev, req, buf, len);
}
enum usbd_request_return_codes _usbd_standard_request_interface(
 usbd_device *usbd_dev, struct usb_setup_data *req, uint8_t **buf, uint16_t *len)
{
 enum usbd_request_return_codes (*command)(
  usbd_device *usbd_dev, struct usb_setup_data *req, uint8_t **buf, uint16_t *len) = ((void*)0);
 switch (req->bRequest) {
 case 1:
 case 3:
  break;
 case 10:
  command = usb_standard_get_interface;
  break;
 case 11:
  command = usb_standard_set_interface;
  break;
 case 0:
  command = usb_standard_interface_get_status;
  break;
 }
 if (!command) {
  return USBD_REQ_NOTSUPP;
 }
 return command(usbd_dev, req, buf, len);
}
enum usbd_request_return_codes _usbd_standard_request_endpoint(
 usbd_device *usbd_dev, struct usb_setup_data *req, uint8_t **buf, uint16_t *len)
{
 enum usbd_request_return_codes (*command)(
  usbd_device *usbd_dev, struct usb_setup_data *req, uint8_t **buf, uint16_t *len) = ((void*)0);
 switch (req->bRequest) {
 case 1:
  if (req->wValue == 0) {
   command = usb_standard_endpoint_unstall;
  }
  break;
 case 3:
  if (req->wValue == 0) {
   command = usb_standard_endpoint_stall;
  }
  break;
 case 0:
  command = usb_standard_endpoint_get_status;
  break;
 case 12:
  break;
 }
 if (!command) {
  return USBD_REQ_NOTSUPP;
 }
 return command(usbd_dev, req, buf, len);
}
enum usbd_request_return_codes _usbd_standard_request(
 usbd_device *usbd_dev, struct usb_setup_data *req, uint8_t **buf, uint16_t *len)
{
 if ((req->bmRequestType & 0x60) != 0x00) {
  return USBD_REQ_NOTSUPP;
 }
 switch (req->bmRequestType & 0x1F) {
 case 0x00:
  return _usbd_standard_request_device(usbd_dev, req, buf, len);
 case 0x01:
  return _usbd_standard_request_interface(usbd_dev, req, buf, len);
 case 0x02:
  return _usbd_standard_request_endpoint(usbd_dev, req, buf, len);
 default:
  return USBD_REQ_NOTSUPP;
 }
}
