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
void poly_noise(poly *r, const unsigned char *seed, unsigned char nonce, int add);
void poly_ntt(poly *r);
void poly_invntt(poly *r);
void poly_basemul_opt_16_32(int32_t *r, const poly *a, const poly *b, const poly *a_prime);
void poly_basemul_acc_opt_32_32(int32_t *r_tmp, const poly *a, const poly *b, const poly *a_prime);
void poly_basemul_acc_opt_32_16(poly *r, const poly *a, const poly *b, const poly *a_prime, const int32_t * r_tmp);
void poly_fromplant(poly *r);
void poly_reduce(poly *r);
void poly_add(poly *r, const poly *a, const poly *b);
void poly_sub(poly *r, const poly *a, const poly *b);
void poly_zeroize(poly *p);

typedef struct {
    poly vec[3];
} polyvec;
void polyvec_compress(unsigned char *r, const polyvec *a);
void polyvec_decompress(polyvec *r, const unsigned char *a);
void polyvec_tobytes(unsigned char *r, polyvec *a);
void polyvec_frombytes(polyvec *r, const unsigned char *a);
void polyvec_ntt(polyvec *r);
void polyvec_invntt(polyvec *r);
void polyvec_reduce(polyvec *r);
void polyvec_add(polyvec *r, const polyvec *a, const polyvec *b);
void polyvec_compress(unsigned char *r, const polyvec *a)
{
  unsigned int i,j,k;
  uint64_t d0;
  uint16_t t[4];
  for(i=0;i<3;i++) {
    for(j=0;j<256/4;j++) {
      for(k=0;k<4;k++) {
        t[k] = a->vec[i].coeffs[4*j+k];
        t[k] += ((int16_t)t[k] >> 15) & 3329;
        d0 = t[k];
        d0 <<= 10;
        d0 += 1665;
        d0 *= 1290167;
        d0 >>= 32;
        t[k] = d0 & 0x3ff;
      }
      r[0] = (t[0] >> 0);
      r[1] = (t[0] >> 8) | (t[1] << 2);
      r[2] = (t[1] >> 6) | (t[2] << 4);
      r[3] = (t[2] >> 4) | (t[3] << 6);
      r[4] = (t[3] >> 2);
      r += 5;
    }
  }
}
void polyvec_decompress(polyvec *r, const unsigned char *a)
{
  int i,j;
  for(i=0;i<3;i++)
  {
    for(j=0;j<256/4;j++)
    {
      r->vec[i].coeffs[4*j+0] = (((a[5*j+ 0] | (((uint32_t)a[5*j+ 1] & 0x03) << 8)) * 3329) + 512) >> 10;
      r->vec[i].coeffs[4*j+1] = ((((a[5*j+ 1] >> 2) | (((uint32_t)a[5*j+ 2] & 0x0f) << 6)) * 3329) + 512) >> 10;
      r->vec[i].coeffs[4*j+2] = ((((a[5*j+ 2] >> 4) | (((uint32_t)a[5*j+ 3] & 0x3f) << 4)) * 3329) + 512) >> 10;
      r->vec[i].coeffs[4*j+3] = ((((a[5*j+ 3] >> 6) | (((uint32_t)a[5*j+ 4] & 0xff) << 2)) * 3329) + 512) >> 10;
    }
    a += 320;
  }
}
void polyvec_tobytes(unsigned char *r, polyvec *a)
{
  int i;
  for(i=0;i<3;i++)
    poly_tobytes(r+i*384, &a->vec[i]);
}
void polyvec_frombytes(polyvec *r, const unsigned char *a)
{
  int i;
  for(i=0;i<3;i++)
    poly_frombytes(&r->vec[i], a+i*384);
}
void polyvec_ntt(polyvec *r)
{
  int i;
  for(i=0;i<3;i++)
    poly_ntt(&r->vec[i]);
}
void polyvec_invntt(polyvec *r)
{
  int i;
  for(i=0;i<3;i++)
    poly_invntt(&r->vec[i]);
}
void polyvec_reduce(polyvec *r)
{
  int i;
  for(i=0;i<3;i++)
    poly_reduce(&r->vec[i]);
}
void polyvec_add(polyvec *r, const polyvec *a, const polyvec *b)
{
  int i;
  for(i=0;i<3;i++)
    poly_add(&r->vec[i], &a->vec[i], &b->vec[i]);
}
