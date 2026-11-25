#ifndef LC_PLATFORM_H
#define LC_PLATFORM_H
#include <stddef.h>
#include <stdint.h>
/* Internal platform service, not an additional public API export.
 * Zero bytes succeed. Other failures erase the complete requested output.
 * LC_RNG_CALLBACK_ONLY disables OS entropy, including on hosted targets. */
int lc_system_random(uint8_t *out, size_t bytes);
#endif
