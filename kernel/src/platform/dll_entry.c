/* SPDX-License-Identifier: Apache-2.0
 * The hosted C core stores mutable operation state in explicit caller contexts.
 * Windows initializes image data and imported providers before this entry.
 * This translation unit has no TLS, constructors, global destructors or FP state.
 */
#include <windows.h>
#if defined(__GNUC__)
__attribute__((used,externally_visible))
#endif
BOOL WINAPI lc_dll_entry(HINSTANCE module,DWORD event,LPVOID reserved) {
    (void)module;(void)event;(void)reserved;
    return TRUE;
}
