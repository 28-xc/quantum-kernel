#include <stdint.h>
#include <string.h>
#include "src/sampling.h"
#include "src/compress.h"
#include "src/poly_k.h"

#if defined(_WIN32)
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif

typedef void noise_fn(mlk_poly *, mlk_poly *, mlk_poly *, mlk_poly *,
                      const uint8_t *, uint8_t, uint8_t, uint8_t, uint8_t);
extern noise_fn lc_base_mlk768_poly_getnoise_eta1_4x;
extern noise_fn lc_base_mlk1024_poly_getnoise_eta1_4x;

EXPORT int lc_demo_kem(int parameter, int operation, int32_t coefficients[256],
                       uint8_t bytes[384], const uint8_t seed[64], uint32_t index,
                       uint32_t row, uint32_t column, uint32_t width)
{
    mlk_poly poly;
    if (parameter != 512 && parameter != 768 && parameter != 1024) return -1;

    if (operation == 0) {
        uint8_t extended[34];
        if (row > 255 || column > 255) return -1;
        memcpy(extended, seed, 32);
        extended[32] = (uint8_t)column;
        extended[33] = (uint8_t)row;
        mlk_poly_rej_uniform(&poly, extended);
    } else if (operation == 1) {
        mlk_poly discard[3];
        noise_fn *sample = mlk_poly_getnoise_eta1_4x;
        if (index > 255) return -1;
        if (parameter == 768) sample = lc_base_mlk768_poly_getnoise_eta1_4x;
        if (parameter == 1024) sample = lc_base_mlk1024_poly_getnoise_eta1_4x;
        sample(&poly, &discard[0], &discard[1], &discard[2], seed,
               (uint8_t)index, (uint8_t)(index + 1),
               (uint8_t)(index + 2), (uint8_t)(index + 3));
    } else if (operation == 4 || operation == 6 || operation == 8) {
        for (size_t i = 0; i < 256; ++i) {
            int32_t value = coefficients[i];
            if (operation == 8) {
                if (value < INT16_MIN || value > INT16_MAX) return -1;
            } else if (value < 0 || value >= 3329) {
                return -1;
            }
            poly.coeffs[i] = (int16_t)value;
        }
        if (operation == 4) {
            mlk_poly_tobytes(bytes, &poly);
            return 0;
        }
        if (operation == 6) {
            switch (width) {
            case 4: mlk_poly_compress_d4(bytes, &poly); break;
            case 5: mlk_poly_compress_d5(bytes, &poly); break;
            case 10: mlk_poly_compress_d10(bytes, &poly); break;
            case 11: mlk_poly_compress_d11(bytes, &poly); break;
            default: return -1;
            }
            return 0;
        }
        mlk_poly_reduce(&poly);
    } else if (operation == 5) {
        mlk_poly_frombytes(&poly, bytes);
    } else if (operation == 7) {
        switch (width) {
        case 4: mlk_poly_decompress_d4(&poly, bytes); break;
        case 5: mlk_poly_decompress_d5(&poly, bytes); break;
        case 10: mlk_poly_decompress_d10(&poly, bytes); break;
        case 11: mlk_poly_decompress_d11(&poly, bytes); break;
        default: return -1;
        }
    } else {
        return -1;
    }

    for (size_t i = 0; i < 256; ++i) coefficients[i] = poly.coeffs[i];
    return 0;
}
