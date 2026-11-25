/* Integration of mlkem-native and its project-derived variants. Upstream licenses retained. */
#define MLK_CONFIG_MULTILEVEL_WITH_SHARED
#define MLK_CONFIG_MONOBUILD_KEEP_SHARED_HEADERS
#define MLK_CONFIG_PARAMETER_SET 512
#include "mlkem_native.c"
#undef MLK_CONFIG_PARAMETER_SET
#undef MLK_CONFIG_MULTILEVEL_WITH_SHARED
#define MLK_CONFIG_MULTILEVEL_NO_SHARED
#define MLK_CONFIG_PARAMETER_SET 768
#include "mlkem_native.c"
#undef MLK_CONFIG_PARAMETER_SET
#undef MLK_CONFIG_MONOBUILD_KEEP_SHARED_HEADERS
#define MLK_CONFIG_PARAMETER_SET 1024
#include "mlkem_native.c"
#undef MLK_CONFIG_PARAMETER_SET

int lc_mlk_call(int level, int op, unsigned char *out1, unsigned char *out2,
    const unsigned char *in1, const unsigned char *in2, lc_arena *arena) {
    #define LC_CASE(P) case P: switch(op) { \
      case 0: return lc_base_mlk##P##_keypair_derand(out1,out2,in1,arena); \
      case 1: return lc_base_mlk##P##_enc_derand(out1,out2,in1,in2,arena); \
      case 2: return lc_base_mlk##P##_dec(out1,in1,in2,arena); \
      case 3: return lc_base_mlk##P##_check_pk(in1,arena); \
      case 4: return lc_base_mlk##P##_check_sk(in1,arena); } break
    switch(level) { LC_CASE(512); LC_CASE(768); LC_CASE(1024); }
    return -99;
    #undef LC_CASE
}
