
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
typedef struct {
    int16_t coeffs[256];
} poly;
void poly_compress(unsigned char *r, const poly *a);
void poly_decompress(poly *r, const unsigned char *a);
void poly_packcompress(unsigned char *r, poly *a, int i);
void poly_unpackdecompress(poly *r, const unsigned char *a, int i);
int cmp_poly_compress(const unsigned char *r, poly *a);
int cmp_poly_packcompress(const unsigned char *r, poly *a, int i);
void poly_tobytes(unsigned char *r, poly *a);
void poly_frombytes(poly *r, const unsigned char *a);
void poly_frombytes_mul_16_32(int32_t *r_tmp, const poly *b, const unsigned char *a);
void poly_frombytes_mul_32_32(int32_t *r_tmp, const poly *b, const unsigned char *a);
void poly_frombytes_mul_32_16(poly *r, const poly* b, const unsigned char *a, const int32_t *r_tmp);
void poly_frommsg(poly *r, const unsigned char msg[32]);
void poly_tomsg(unsigned char msg[32], poly *a);
void poly_noise_eta1(poly *r, const unsigned char *seed, unsigned char nonce, int add);
void poly_noise_eta2(poly *r, const unsigned char *seed, unsigned char nonce, int add);
void poly_ntt(poly *r);
void poly_invntt(poly *r);
void poly_basemul_opt_16_32(int32_t *r, const poly *a, const poly *b, const poly *a_prime);
void poly_basemul_acc_opt_32_32(int32_t *r, const poly *a, const poly *b, const poly *a_prime);
void poly_basemul_acc_opt_32_16(poly *r, const poly *a, const poly *b, const poly *a_prime, const int32_t * r_tmp);
void poly_fromplantt(poly *r);
void poly_reduce(poly *r);
void poly_add(poly *r, const poly *a, const poly *b);
void poly_sub(poly *r, const poly *a, const poly *b);
void poly_zeroize(poly *p);

void cbd_eta1(poly *r, const unsigned char *buf, int add);
void cbd_eta2(poly *r, const unsigned char *buf, int add);
static uint32_t load32_littleendian(const unsigned char *x) {
    uint32_t r;
    r = (uint32_t)x[0];
    r |= (uint32_t)x[1] << 8;
    r |= (uint32_t)x[2] << 16;
    r |= (uint32_t)x[3] << 24;
    return r;
}
static uint32_t load24_littleendian(const uint8_t x[3])
{
  uint32_t r;
  r = (uint32_t)x[0];
  r |= (uint32_t)x[1] << 8;
  r |= (uint32_t)x[2] << 16;
  return r;
}
void cbd_eta1(poly *r, const unsigned char *buf, int add) {
  unsigned int i,j;
  uint32_t t,d;
  int16_t a,b;
  for(i=0;i<256/4;i++) {
    t = load24_littleendian(buf+3*i);
    d = t & 0x00249249;
    d += (t>>1) & 0x00249249;
    d += (t>>2) & 0x00249249;
    for(j=0;j<4;j++) {
      a = (d >> (6*j+0)) & 0x7;
      b = (d >> (6*j+3)) & 0x7;
      if (!add)
        r->coeffs[4 * i + j] = 0;
      r->coeffs[4 * i + j] = r->coeffs[4 * i + j] + (a - b);
    }
  }
}
void cbd_eta2(poly *r, const unsigned char *buf, int add) {
    uint32_t d, t;
    int16_t a, b;
    int i, j;
    for (i = 0; i < 256 / 8; i++) {
        t = load32_littleendian(buf + 4 * i);
        d = t & 0x55555555;
        d += (t >> 1) & 0x55555555;
        for (j = 0; j < 8; j++) {
            a = (d >> 4 * j) & 0x3;
            b = (d >> (4 * j + 2)) & 0x3;
            if (!add)
              r->coeffs[8 * i + j] = 0;
            r->coeffs[8 * i + j] = r->coeffs[8 * i + j] + (a - b);
        }
    }
}
