/* Compile beside the actual SCU types and macros, with its exact feature flags. */
#include <stdio.h>
int main(void){
#if LC_DSA_PACK_W0
 printf("{\"parameter\":%d,\"k\":%d,\"l\":%d,\"poly_bytes\":%zu,\"hash_bytes\":%zu,\"hash_alignment\":%zu,\"storage_bytes\":%zu,\"storage_alignment\":%zu,\"matrix_bytes\":%zu,\"low_bits\":%d,\"low_row_bytes\":%d,\"flag_bytes\":%d,\"stride_bytes\":%d,\"encoded_high_bytes\":%d,\"packed_accumulator\":%d,\"recompute\":%d,\"retain_high\":%d",
 MLD_CONFIG_PARAMETER_SET,MLDSA_K,MLDSA_L,sizeof(mld_poly),sizeof(mld_shake256ctx),_Alignof(mld_shake256ctx),sizeof(lc_sign_w0_storage),_Alignof(lc_sign_w0_storage),sizeof(mld_polymat),LC_W0_BITS,LC_W0_ROW_BYTES,LC_W1_FLAG_BYTES,LC_W0_FLAG_STRIDE,MLDSA_POLYW1_PACKEDBYTES,LC_DSA_PACKED_ACCUM,LC_DSA_STREAM_RECOMPUTE,LC_DSA_RETAIN_FULL_HIGH);
#if LC_DSA_PACKED_ACCUM
 printf(",\"temporary_offset\":%d,\"hash_offset\":%d,\"last_row_offset\":%d",LC_SIGN_T_OFFSET,LC_SIGN_HASH_OFFSET,LC_SIGN_LAST_NTT_OFFSET);
#else
 printf(",\"temporary_offset\":%zu,\"hash_offset\":%zu,\"last_row_offset\":%zu",(MLDSA_K-1)*sizeof(mld_poly),(MLDSA_K-1)*sizeof(mld_poly),(MLDSA_K-1)*sizeof(mld_poly));
#endif
 printf("}\n");return 0;
#else
 return 2;
#endif
}
