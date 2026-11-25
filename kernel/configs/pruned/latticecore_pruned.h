#ifndef LC_PRUNED_API_H
#define LC_PRUNED_API_H
#include "latticecore.h"
/* Restricted builds retain the eight public function signatures. Any valid
 * parameter omitted at link time returns this explicit status before reading
 * operation buffers. lc_get_sizes clears a non-null result on this status.
 * Calling an operation of the wrong family for a retained parameter still
 * returns LC_E_ARGUMENT, as in the unrestricted API. */
enum { LC_E_UNSUPPORTED = -8 };
#endif
