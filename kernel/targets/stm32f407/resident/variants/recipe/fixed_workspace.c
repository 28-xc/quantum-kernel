#include "latticecore.h"
#include "configuration.h"

size_t lc_f407_aligned_workspace(int parameter, int operation) {
    static const size_t aligned[3] = LC_F407_BOUNDS;
    if (parameter != LC_F407_PARAM || (unsigned)operation >= 3) return 0;
    return aligned[operation];
}

size_t lc_f407_usable_requirement(int parameter, int operation, size_t front_padding) {
    size_t aligned = lc_f407_aligned_workspace(parameter, operation);
    /* KEM places its size_t LIFO header before the first 32-aligned object.
       From a 32-aligned starting pointer that consumes one 32-byte slot.
       If caller front padding already fits that header, no further slot is needed. */
    if (LC_F407_PARAM > 100 && aligned && front_padding >= sizeof(size_t))
        return aligned - 32;
    return aligned;
}

int lc_f407_fits(int parameter, int operation, const void *workspace, size_t bytes) {
    uintptr_t addr = (uintptr_t)workspace;
    size_t padding = (0u - addr) & 31u;
    size_t required = lc_f407_usable_requirement(parameter, operation, padding);
    return required && workspace && bytes <= UINTPTR_MAX - addr &&
           bytes >= padding && bytes-padding >= required;
}

/* This older internal DSA interface promises a bound valid for any address. */
size_t lc_dsa_workspace_bound(int parameter, int operation) {
    size_t bytes = lc_f407_aligned_workspace(parameter, operation);
    return LC_F407_PARAM < 100 && bytes ? bytes + 31 : 0;
}
