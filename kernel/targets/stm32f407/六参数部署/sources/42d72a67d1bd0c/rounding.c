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
int32_t pqcrystals_dilithium_power2round(int32_t *a0, int32_t a);
int32_t pqcrystals_dilithium_decompose(int32_t *a0, int32_t a);
unsigned int pqcrystals_dilithium_make_hint(int32_t a0, int32_t a1);
int32_t pqcrystals_dilithium_use_hint(int32_t a, unsigned int hint);
int32_t pqcrystals_dilithium_power2round(int32_t *a0, int32_t a) {
  int32_t a1;
  a1 = (a + (1 << (13 -1)) - 1) >> 13;
  *a0 = a - (a1 << 13);
  return a1;
}
int32_t pqcrystals_dilithium_decompose(int32_t *a0, int32_t a) {
  int32_t a1;
  a1 = (a + 127) >> 7;
  a1 = (a1*1025 + (1 << 21)) >> 22;
  a1 &= 15;
  *a0 = a - a1*2*((8380417 -1)/32);
  *a0 -= (((8380417 -1)/2 - *a0) >> 31) & 8380417;
  return a1;
}
unsigned int pqcrystals_dilithium_make_hint(int32_t a0, int32_t a1) {
  if(a0 > ((8380417 -1)/32) || a0 < -((8380417 -1)/32) || (a0 == -((8380417 -1)/32) && a1 != 0))
    return 1;
  return 0;
}
int32_t pqcrystals_dilithium_use_hint(int32_t a, unsigned int hint) {
  int32_t a0, a1;
  a1 = pqcrystals_dilithium_decompose(&a0, a);
  if(hint == 0)
    return a1;
  if(a0 > 0)
    return (a1 + 1) & 15;
  else
    return (a1 - 1) & 15;
}
