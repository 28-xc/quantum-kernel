#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t cookie, parameter, operation, index, row, column, width;
    int32_t coefficients[256];
    uint8_t octets[384], seed[64];
} primitive_input;

typedef int (*dsa_binding)(int, int32_t *, uint8_t *, const uint8_t *, uint32_t, uint32_t, uint32_t);
extern int lc_demo_kem(int, int, int32_t *, uint8_t *, const uint8_t *, uint32_t, uint32_t, uint32_t, uint32_t);
extern int lc_demo_dsa44(int, int32_t *, uint8_t *, const uint8_t *, uint32_t, uint32_t, uint32_t);
extern int lc_demo_dsa65(int, int32_t *, uint8_t *, const uint8_t *, uint32_t, uint32_t, uint32_t);
extern int lc_demo_dsa87(int, int32_t *, uint8_t *, const uint8_t *, uint32_t, uint32_t, uint32_t);

static int run_primitive(primitive_input *work) {
    if (work->operation > 8) return -1;
    if (work->parameter == 512 || work->parameter == 768 || work->parameter == 1024)
        return lc_demo_kem(work->parameter,work->operation,work->coefficients,work->octets,work->seed,
                           work->index,work->row,work->column,work->width);
    dsa_binding fn;
    switch (work->parameter) {
    case 44: fn = lc_demo_dsa44; break;
    case 65: fn = lc_demo_dsa65; break;
    case 87: fn = lc_demo_dsa87; break;
    default: return -1;
    }
    return fn(work->operation,work->coefficients,work->octets,work->seed,work->index,work->row,work->column);
}
