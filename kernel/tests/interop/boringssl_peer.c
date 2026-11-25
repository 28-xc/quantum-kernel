/* Thin test-only binding of BoringSSL's documented serialized-object APIs. */
#include <openssl/bytestring.h>
#include <openssl/mem.h>
#include <openssl/mlkem.h>
#include <openssl/mldsa.h>
#include <stdint.h>
#include <stddef.h>
#define KEM(P) \
int b_key_##P(const uint8_t *seed,uint8_t *out) { \
 struct MLKEM##P##_private_key sk;struct MLKEM##P##_public_key pk;CBB c; \
 if(!MLKEM##P##_private_key_from_seed(&sk,seed,64))return 0; \
 MLKEM##P##_public_from_private(&pk,&sk);CBB_init_fixed(&c,out,MLKEM##P##_PUBLIC_KEY_BYTES); \
 int ok=MLKEM##P##_marshal_public_key(&c,&pk)&&CBB_len(&c)==MLKEM##P##_PUBLIC_KEY_BYTES; \
 CBB_cleanup(&c);OPENSSL_cleanse(&sk,sizeof(sk));return ok; } \
int b_enc_##P(const uint8_t *pk,uint8_t *ct,uint8_t *ss) { \
 struct MLKEM##P##_public_key key;CBS c;CBS_init(&c,pk,MLKEM##P##_PUBLIC_KEY_BYTES); \
 if(!MLKEM##P##_parse_public_key(&key,&c))return 0;MLKEM##P##_encap(ct,ss,&key);return 1; } \
int b_dec_##P(const uint8_t *seed,const uint8_t *ct,uint8_t *ss) { \
 struct MLKEM##P##_private_key key;if(!MLKEM##P##_private_key_from_seed(&key,seed,64))return 0; \
 int ok=MLKEM##P##_decap(ss,ct,MLKEM##P##_CIPHERTEXT_BYTES,&key);OPENSSL_cleanse(&key,sizeof(key));return ok; }
#define DSA(P) \
int b_key_##P(const uint8_t *seed,uint8_t *out) { \
 struct MLDSA##P##_private_key sk;struct MLDSA##P##_public_key pk;CBB c; \
 if(!MLDSA##P##_private_key_from_seed(&sk,seed,32))return 0; \
 int ok=MLDSA##P##_public_from_private(&pk,&sk);CBB_init_fixed(&c,out,MLDSA##P##_PUBLIC_KEY_BYTES); \
 ok=ok&&MLDSA##P##_marshal_public_key(&c,&pk)&&CBB_len(&c)==MLDSA##P##_PUBLIC_KEY_BYTES; \
 CBB_cleanup(&c);OPENSSL_cleanse(&sk,sizeof(sk));return ok; } \
int b_sign_##P(const uint8_t *seed,const uint8_t *m,size_t n,const uint8_t *ctx,size_t cn,uint8_t *sig) { \
 struct MLDSA##P##_private_key key;if(!MLDSA##P##_private_key_from_seed(&key,seed,32))return 0; \
 int ok=MLDSA##P##_sign(sig,&key,m,n,ctx,cn);OPENSSL_cleanse(&key,sizeof(key));return ok; } \
int b_verify_##P(const uint8_t *pk,const uint8_t *m,size_t n,const uint8_t *ctx,size_t cn,const uint8_t *sig) { \
 struct MLDSA##P##_public_key key;CBS c;CBS_init(&c,pk,MLDSA##P##_PUBLIC_KEY_BYTES); \
 if(!MLDSA##P##_parse_public_key(&key,&c))return 0;return MLDSA##P##_verify(&key,sig,MLDSA##P##_SIGNATURE_BYTES,m,n,ctx,cn); }
KEM(768)
KEM(1024)
DSA(44)
DSA(65)
DSA(87)
