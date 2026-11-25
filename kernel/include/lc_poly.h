#ifndef LC_POLY_H
#define LC_POLY_H
#include <stdint.h>
/* Canonical coefficients [0,q); bit-reversed FIPS transform layout.
 * ML-KEM: 7 layers, paired components. ML-DSA: 8 layers, scalar components.
 * Inverse returns the coefficient domain without a Montgomery scale.
 * In-place transforms; multiplication output must not alias its inputs.
 */
int lc_poly_ntt(uint32_t q, uint32_t a[256]);
int lc_poly_intt(uint32_t q, uint32_t a[256]);
int lc_poly_basemul(uint32_t q, uint32_t c[256],const uint32_t a[256],const uint32_t b[256]);
int lc_poly_mul(uint32_t q,uint32_t c[256],const uint32_t a[256],const uint32_t b[256]);
int lc_poly_add(uint32_t q,uint32_t c[256],const uint32_t a[256],const uint32_t b[256]);
int lc_poly_sub(uint32_t q,uint32_t c[256],const uint32_t a[256],const uint32_t b[256]);
#endif
