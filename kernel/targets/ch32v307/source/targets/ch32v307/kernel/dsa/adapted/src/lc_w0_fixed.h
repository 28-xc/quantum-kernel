/* Fixed groups read all source coefficients before their overlapping output
 * bytes are written. Unpacking requires a separate aligned polynomial.
 * These are internal signed representations; FIPS encodings are unchanged. */
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if LC_W0_BITS == 18
static void lc_pack_w0_row(uint8_t *out,const mld_poly *poly) {
  for(unsigned g=0;g<MLDSA_N;g+=4) {
    uint32_t a=(uint32_t)poly->coeffs[g]&262143u,b=(uint32_t)poly->coeffs[g+1]&262143u;
    uint32_t c=(uint32_t)poly->coeffs[g+2]&262143u,d=(uint32_t)poly->coeffs[g+3]&262143u;
    out[0]=(uint8_t)a;out[1]=(uint8_t)(a>>8);out[2]=(uint8_t)((a>>16)|(b<<2));
    out[3]=(uint8_t)(b>>6);out[4]=(uint8_t)((b>>14)|(c<<4));out[5]=(uint8_t)(c>>4);
    out[6]=(uint8_t)((c>>12)|(d<<6));out[7]=(uint8_t)(d>>2);out[8]=(uint8_t)(d>>10);out+=9;
  }
}
static void lc_unpack_w0_row(mld_poly *poly,const uint8_t *in) {
  for(unsigned g=0;g<MLDSA_N;g+=4) {
    uint32_t a=((uint32_t)in[0]|((uint32_t)in[1]<<8)|((uint32_t)in[2]<<16))&262143u;
    uint32_t b=(((uint32_t)in[2]>>2)|((uint32_t)in[3]<<6)|((uint32_t)in[4]<<14))&262143u;
    uint32_t c=(((uint32_t)in[4]>>4)|((uint32_t)in[5]<<4)|((uint32_t)in[6]<<12))&262143u;
    uint32_t d=((uint32_t)in[6]>>6)|((uint32_t)in[7]<<2)|((uint32_t)in[8]<<10);
    poly->coeffs[g]=(int32_t)(a&131071u)-(int32_t)(a&131072u);poly->coeffs[g+1]=(int32_t)(b&131071u)-(int32_t)(b&131072u);
    poly->coeffs[g+2]=(int32_t)(c&131071u)-(int32_t)(c&131072u);poly->coeffs[g+3]=(int32_t)(d&131071u)-(int32_t)(d&131072u);in+=9;
  }
}
#elif LC_W0_BITS == 24
static void lc_pack_w0_row(uint8_t *out,const mld_poly *poly) {
  for(unsigned i=0;i<MLDSA_N;i++) {
    uint32_t u=(uint32_t)poly->coeffs[i]&0xffffffu;
    out[3*i]=(uint8_t)u;out[3*i+1]=(uint8_t)(u>>8);out[3*i+2]=(uint8_t)(u>>16);
  }
}
static void lc_unpack_w0_row(mld_poly *poly,const uint8_t *in) {
  for(unsigned i=0;i<MLDSA_N;i++) {
    uint32_t u=(uint32_t)in[3*i]|((uint32_t)in[3*i+1]<<8)|((uint32_t)in[3*i+2]<<16);
    poly->coeffs[i]=(int32_t)(u&0x7fffffu)-(int32_t)(u&0x800000u);
  }
}
#else
#if LC_W0_BITS == 19
static void lc_pack_w0_row(uint8_t *out, const mld_poly *poly) {
  const int32_t *p=poly->coeffs;

  for (unsigned g=0; g<256; g+=8) {
    const uint32_t u0=(uint32_t)p[g+0] & 524287u;
    const uint32_t u1=(uint32_t)p[g+1] & 524287u;
    const uint32_t u2=(uint32_t)p[g+2] & 524287u;
    const uint32_t u3=(uint32_t)p[g+3] & 524287u;
    const uint32_t u4=(uint32_t)p[g+4] & 524287u;
    const uint32_t u5=(uint32_t)p[g+5] & 524287u;
    const uint32_t u6=(uint32_t)p[g+6] & 524287u;
    const uint32_t u7=(uint32_t)p[g+7] & 524287u;
    out[0]=(uint8_t)(u0);
    out[1]=(uint8_t)((u0 >> 8));
    out[2]=(uint8_t)((u0 >> 16) | (u1 << 3));
    out[3]=(uint8_t)((u1 >> 5));
    out[4]=(uint8_t)((u1 >> 13) | (u2 << 6));
    out[5]=(uint8_t)((u2 >> 2));
    out[6]=(uint8_t)((u2 >> 10));
    out[7]=(uint8_t)((u2 >> 18) | (u3 << 1));
    out[8]=(uint8_t)((u3 >> 7));
    out[9]=(uint8_t)((u3 >> 15) | (u4 << 4));
    out[10]=(uint8_t)((u4 >> 4));
    out[11]=(uint8_t)((u4 >> 12) | (u5 << 7));
    out[12]=(uint8_t)((u5 >> 1));
    out[13]=(uint8_t)((u5 >> 9));
    out[14]=(uint8_t)((u5 >> 17) | (u6 << 2));
    out[15]=(uint8_t)((u6 >> 6));
    out[16]=(uint8_t)((u6 >> 14) | (u7 << 5));
    out[17]=(uint8_t)((u7 >> 3));
    out[18]=(uint8_t)((u7 >> 11));
    out+=19;
  }

}
#else
static void lc_pack_w0_row(uint8_t *out, const mld_poly *poly) {
  const int32_t *p=poly->coeffs;

  for (unsigned g=0; g<256; g+=2) {
    const uint32_t u0=(uint32_t)p[g+0] & 1048575u;
    const uint32_t u1=(uint32_t)p[g+1] & 1048575u;
    out[0]=(uint8_t)(u0);
    out[1]=(uint8_t)((u0 >> 8));
    out[2]=(uint8_t)((u0 >> 16) | (u1 << 4));
    out[3]=(uint8_t)((u1 >> 4));
    out[4]=(uint8_t)((u1 >> 12));
    out+=5;
  }

}
#endif
#if LC_W0_BITS == 19
static void lc_unpack_w0_row(mld_poly *poly, const uint8_t *in) {
  int32_t *p=poly->coeffs;

  for (unsigned g=0; g<256; g+=8) {
    const uint32_t u0=((((uint32_t)in[0] << 0) | ((uint32_t)in[1] << 8) | ((uint32_t)in[2] << 16)) >> 0) & 524287u;
    p[g+0]=(int32_t)(u0&262143u)-(int32_t)(u0&262144u);
    const uint32_t u1=((((uint32_t)in[2] << 0) | ((uint32_t)in[3] << 8) | ((uint32_t)in[4] << 16)) >> 3) & 524287u;
    p[g+1]=(int32_t)(u1&262143u)-(int32_t)(u1&262144u);
    const uint32_t u2=((((uint32_t)in[4] << 0) | ((uint32_t)in[5] << 8) | ((uint32_t)in[6] << 16) | ((uint32_t)in[7] << 24)) >> 6) & 524287u;
    p[g+2]=(int32_t)(u2&262143u)-(int32_t)(u2&262144u);
    const uint32_t u3=((((uint32_t)in[7] << 0) | ((uint32_t)in[8] << 8) | ((uint32_t)in[9] << 16)) >> 1) & 524287u;
    p[g+3]=(int32_t)(u3&262143u)-(int32_t)(u3&262144u);
    const uint32_t u4=((((uint32_t)in[9] << 0) | ((uint32_t)in[10] << 8) | ((uint32_t)in[11] << 16)) >> 4) & 524287u;
    p[g+4]=(int32_t)(u4&262143u)-(int32_t)(u4&262144u);
    const uint32_t u5=((((uint32_t)in[11] << 0) | ((uint32_t)in[12] << 8) | ((uint32_t)in[13] << 16) | ((uint32_t)in[14] << 24)) >> 7) & 524287u;
    p[g+5]=(int32_t)(u5&262143u)-(int32_t)(u5&262144u);
    const uint32_t u6=((((uint32_t)in[14] << 0) | ((uint32_t)in[15] << 8) | ((uint32_t)in[16] << 16)) >> 2) & 524287u;
    p[g+6]=(int32_t)(u6&262143u)-(int32_t)(u6&262144u);
    const uint32_t u7=((((uint32_t)in[16] << 0) | ((uint32_t)in[17] << 8) | ((uint32_t)in[18] << 16)) >> 5) & 524287u;
    p[g+7]=(int32_t)(u7&262143u)-(int32_t)(u7&262144u);
    in+=19;
  }

}
#else
static void lc_unpack_w0_row(mld_poly *poly, const uint8_t *in) {
  int32_t *p=poly->coeffs;

  for (unsigned g=0; g<256; g+=2) {
    const uint32_t u0=((((uint32_t)in[0] << 0) | ((uint32_t)in[1] << 8) | ((uint32_t)in[2] << 16)) >> 0) & 1048575u;
    p[g+0]=(int32_t)(u0&524287u)-(int32_t)(u0&524288u);
    const uint32_t u1=((((uint32_t)in[2] << 0) | ((uint32_t)in[3] << 8) | ((uint32_t)in[4] << 16)) >> 4) & 1048575u;
    p[g+1]=(int32_t)(u1&524287u)-(int32_t)(u1&524288u);
    in+=5;
  }

}
#endif
#endif
#else
#if LC_W0_BITS == 24
static void lc_pack_w0_row(uint8_t *out,const mld_poly *poly) {
  for(unsigned i=0;i<MLDSA_N;i++) {
    uint32_t u=(uint32_t)poly->coeffs[i]&0xffffffu;
    out[3*i]=(uint8_t)u;out[3*i+1]=(uint8_t)(u>>8);out[3*i+2]=(uint8_t)(u>>16);
  }
}
static void lc_unpack_w0_row(mld_poly *poly,const uint8_t *in) {
  for(unsigned i=0;i<MLDSA_N;i++) {
    uint32_t u=(uint32_t)in[3*i]|((uint32_t)in[3*i+1]<<8)|((uint32_t)in[3*i+2]<<16);
    poly->coeffs[i]=(int32_t)(u&0x7fffffu)-(int32_t)(u&0x800000u);
  }
}
#else
#if LC_W0_BITS == 19
static void lc_pack_w0_row(uint8_t *out, const mld_poly *poly) {
  const int32_t *p=poly->coeffs;

  for (unsigned g=0; g<256; g+=8) {
    const uint32_t u0=(uint32_t)p[g+0] & 524287u;
    const uint32_t u1=(uint32_t)p[g+1] & 524287u;
    const uint32_t u2=(uint32_t)p[g+2] & 524287u;
    const uint32_t u3=(uint32_t)p[g+3] & 524287u;
    const uint32_t u4=(uint32_t)p[g+4] & 524287u;
    const uint32_t u5=(uint32_t)p[g+5] & 524287u;
    const uint32_t u6=(uint32_t)p[g+6] & 524287u;
    const uint32_t u7=(uint32_t)p[g+7] & 524287u;
    out[0]=(uint8_t)(u0);
    out[1]=(uint8_t)((u0 >> 8));
    out[2]=(uint8_t)((u0 >> 16) | (u1 << 3));
    out[3]=(uint8_t)((u1 >> 5));
    out[4]=(uint8_t)((u1 >> 13) | (u2 << 6));
    out[5]=(uint8_t)((u2 >> 2));
    out[6]=(uint8_t)((u2 >> 10));
    out[7]=(uint8_t)((u2 >> 18) | (u3 << 1));
    out[8]=(uint8_t)((u3 >> 7));
    out[9]=(uint8_t)((u3 >> 15) | (u4 << 4));
    out[10]=(uint8_t)((u4 >> 4));
    out[11]=(uint8_t)((u4 >> 12) | (u5 << 7));
    out[12]=(uint8_t)((u5 >> 1));
    out[13]=(uint8_t)((u5 >> 9));
    out[14]=(uint8_t)((u5 >> 17) | (u6 << 2));
    out[15]=(uint8_t)((u6 >> 6));
    out[16]=(uint8_t)((u6 >> 14) | (u7 << 5));
    out[17]=(uint8_t)((u7 >> 3));
    out[18]=(uint8_t)((u7 >> 11));
    out+=19;
  }

}
#else
static void lc_pack_w0_row(uint8_t *out, const mld_poly *poly) {
  const int32_t *p=poly->coeffs;

  for (unsigned g=0; g<256; g+=2) {
    const uint32_t u0=(uint32_t)p[g+0] & 1048575u;
    const uint32_t u1=(uint32_t)p[g+1] & 1048575u;
    out[0]=(uint8_t)(u0);
    out[1]=(uint8_t)((u0 >> 8));
    out[2]=(uint8_t)((u0 >> 16) | (u1 << 4));
    out[3]=(uint8_t)((u1 >> 4));
    out[4]=(uint8_t)((u1 >> 12));
    out+=5;
  }

}
#endif
#if LC_W0_BITS == 19
static void lc_unpack_w0_row(mld_poly *poly, const uint8_t *in) {
  int32_t *p=poly->coeffs;

  for (unsigned g=0; g<256; g+=8) {
    const uint32_t u0=((((uint32_t)in[0] << 0) | ((uint32_t)in[1] << 8) | ((uint32_t)in[2] << 16)) >> 0) & 524287u;
    p[g+0]=(int32_t)(u0&262143u)-(int32_t)(u0&262144u);
    const uint32_t u1=((((uint32_t)in[2] << 0) | ((uint32_t)in[3] << 8) | ((uint32_t)in[4] << 16)) >> 3) & 524287u;
    p[g+1]=(int32_t)(u1&262143u)-(int32_t)(u1&262144u);
    const uint32_t u2=((((uint32_t)in[4] << 0) | ((uint32_t)in[5] << 8) | ((uint32_t)in[6] << 16) | ((uint32_t)in[7] << 24)) >> 6) & 524287u;
    p[g+2]=(int32_t)(u2&262143u)-(int32_t)(u2&262144u);
    const uint32_t u3=((((uint32_t)in[7] << 0) | ((uint32_t)in[8] << 8) | ((uint32_t)in[9] << 16)) >> 1) & 524287u;
    p[g+3]=(int32_t)(u3&262143u)-(int32_t)(u3&262144u);
    const uint32_t u4=((((uint32_t)in[9] << 0) | ((uint32_t)in[10] << 8) | ((uint32_t)in[11] << 16)) >> 4) & 524287u;
    p[g+4]=(int32_t)(u4&262143u)-(int32_t)(u4&262144u);
    const uint32_t u5=((((uint32_t)in[11] << 0) | ((uint32_t)in[12] << 8) | ((uint32_t)in[13] << 16) | ((uint32_t)in[14] << 24)) >> 7) & 524287u;
    p[g+5]=(int32_t)(u5&262143u)-(int32_t)(u5&262144u);
    const uint32_t u6=((((uint32_t)in[14] << 0) | ((uint32_t)in[15] << 8) | ((uint32_t)in[16] << 16)) >> 2) & 524287u;
    p[g+6]=(int32_t)(u6&262143u)-(int32_t)(u6&262144u);
    const uint32_t u7=((((uint32_t)in[16] << 0) | ((uint32_t)in[17] << 8) | ((uint32_t)in[18] << 16)) >> 5) & 524287u;
    p[g+7]=(int32_t)(u7&262143u)-(int32_t)(u7&262144u);
    in+=19;
  }

}
#else
static void lc_unpack_w0_row(mld_poly *poly, const uint8_t *in) {
  int32_t *p=poly->coeffs;

  for (unsigned g=0; g<256; g+=2) {
    const uint32_t u0=((((uint32_t)in[0] << 0) | ((uint32_t)in[1] << 8) | ((uint32_t)in[2] << 16)) >> 0) & 1048575u;
    p[g+0]=(int32_t)(u0&524287u)-(int32_t)(u0&524288u);
    const uint32_t u1=((((uint32_t)in[2] << 0) | ((uint32_t)in[3] << 8) | ((uint32_t)in[4] << 16)) >> 4) & 1048575u;
    p[g+1]=(int32_t)(u1&524287u)-(int32_t)(u1&524288u);
    in+=5;
  }

}
#endif
#endif
#endif
