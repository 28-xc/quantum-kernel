#include <stdint.h>
#include <string.h>
#include "src/poly.h"
#include "src/poly_kl.h"

#if defined(_WIN32)
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif
#define JOIN_(a, b) a##b
#define JOIN(a, b) JOIN_(a, b)

EXPORT int JOIN(lc_demo_dsa, MLD_CONFIG_PARAMETER_SET)(
    int operation, int32_t coefficients[256], uint8_t bytes[384],
    const uint8_t seed[64], uint32_t index, uint32_t row, uint32_t column)
{
    mld_poly poly;
    switch (operation) {
    case 0: {
        uint8_t extended[34];
        if (row > 255 || column > 255) return -1;
        memcpy(extended, seed, 32);
        extended[32] = (uint8_t)column;
        extended[33] = (uint8_t)row;
        mld_poly_uniform(&poly, extended);
        break;
    }
    case 1:
        if (index > 255) return -1;
        mld_poly_uniform_eta(&poly, seed, (uint8_t)index);
        break;
    case 2:
        if (index > 65535) return -1;
        mld_poly_uniform_gamma1(&poly, seed, (uint16_t)index);
        break;
    case 3:
        mld_poly_challenge(&poly, seed);
        break;
    case 4:
        for (size_t i = 0; i < 256; ++i) {
            if (coefficients[i] < -MLDSA_ETA || coefficients[i] > MLDSA_ETA) return -1;
            poly.coeffs[i] = coefficients[i];
        }
        mld_polyeta_pack(bytes, &poly);
        return 0;
    case 5:
        mld_polyeta_unpack(&poly, bytes);
        break;
    case 8:
        for (size_t i = 0; i < 256; ++i) {
            if (coefficients[i] > INT32_MAX - (1 << 22)) return -1;
            poly.coeffs[i] = coefficients[i];
        }
        mld_poly_reduce(&poly);
        break;
    default:
        return -1;
    }
    memcpy(coefficients, poly.coeffs, sizeof(poly.coeffs));
    return 0;
}
