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
typedef int ptrdiff_t;
typedef unsigned int size_t;
typedef unsigned int wchar_t;
typedef struct {
  long long __clang_max_align_nonce1
      __attribute__((__aligned__(__alignof__(long long))));
  long double __clang_max_align_nonce2
      __attribute__((__aligned__(__alignof__(long double))));
} max_align_t;
int crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
int crypto_sign_signature_ctx(uint8_t *sig, size_t *siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *ctx, size_t ctxlen,
        const uint8_t *sk);
int crypto_sign_ctx(uint8_t *sm, size_t *smlen,
        const uint8_t *m, size_t mlen,
        const uint8_t *ctx, size_t ctxlen,
        const uint8_t *sk);
int crypto_sign_verify_ctx(const uint8_t *sig, size_t siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *ctx, size_t ctxlen,
        const uint8_t *pk);
int crypto_sign_open_ctx(uint8_t *m, size_t *mlen,
        const uint8_t *sm, size_t smlen,
        const uint8_t *ctx, size_t ctxlen,
        const uint8_t *pk);
typedef struct {
  int32_t coeffs[256];
} poly;
void pqcrystals_dilithium_poly_reduce(poly *a);
void pqcrystals_dilithium_poly_caddq(poly *a);
void pqcrystals_dilithium_poly_freeze(poly *a);
void pqcrystals_dilithium_poly_add(poly *c, const poly *a, const poly *b);
void pqcrystals_dilithium_poly_sub(poly *c, const poly *a, const poly *b);
void pqcrystals_dilithium_poly_shiftl(poly *a);
void pqcrystals_dilithium_poly_ntt(poly *a);
void pqcrystals_dilithium_poly_invntt_tomont(poly *a);
void pqcrystals_dilithium_poly_pointwise_montgomery(poly *c, const poly *a, const poly *b);
void pqcrystals_dilithium_poly_pointwise_acc_montgomery(poly *c, const poly *a, const poly *b);
void pqcrystals_dilithium_poly_power2round(poly *a1, poly *a0, const poly *a);
void pqcrystals_dilithium_poly_decompose(poly *a1, poly *a0, const poly *a);
unsigned int pqcrystals_dilithium_poly_make_hint(poly *h, const poly *a0, const poly *a1);
void pqcrystals_dilithium_poly_use_hint(poly *b, const poly *a, const poly *h);
int pqcrystals_dilithium_poly_chknorm(const poly *a, int32_t B);
void pqcrystals_dilithium_poly_uniform(poly *a,
                  const uint8_t seed[32],
                  uint16_t nonce);
void pqcrystals_dilithium_poly_uniform_eta(poly *a,
                      const uint8_t seed[64],
                      uint16_t nonce);
void pqcrystals_dilithium_poly_uniform_gamma1(poly *a,
                         const uint8_t seed[64],
                         uint16_t nonce);
void pqcrystals_dilithium_poly_challenge(poly *c, const uint8_t seed[64]);
void pqcrystals_dilithium_polyeta_pack(uint8_t *r, const poly *a);
void pqcrystals_dilithium_polyt1_pack(uint8_t *r, const poly *a);
void pqcrystals_dilithium_polyt1_unpack(poly *r, const uint8_t *a);
void pqcrystals_dilithium_polyt0_pack(uint8_t *r, const poly *a);
void pqcrystals_dilithium_polyt0_unpack(poly *r, const uint8_t *a);
void pqcrystals_dilithium_polyz_pack(uint8_t *r, const poly *a);
void pqcrystals_dilithium_polyz_unpack(poly *r, const uint8_t *a);
void pqcrystals_dilithium_polyw1_pack(uint8_t *r, const poly *a);
typedef struct {
  poly vec[7];
} polyvecl;
void pqcrystals_dilithium_polyvecl_uniform_eta(polyvecl *v, const uint8_t seed[64], uint16_t nonce);
void pqcrystals_dilithium_polyvecl_uniform_gamma1(polyvecl *v, const uint8_t seed[64], uint16_t nonce);
void pqcrystals_dilithium_polyvecl_reduce(polyvecl *v);
void pqcrystals_dilithium_polyvecl_freeze(polyvecl *v);
void pqcrystals_dilithium_polyvecl_add(polyvecl *w, const polyvecl *u, const polyvecl *v);
void pqcrystals_dilithium_polyvecl_ntt(polyvecl *v);
void pqcrystals_dilithium_polyvecl_invntt_tomont(polyvecl *v);
void pqcrystals_dilithium_polyvecl_pointwise_poly_montgomery(polyvecl *r, const poly *a, const polyvecl *v);
void pqcrystals_dilithium_polyvecl_pointwise_acc_montgomery(poly *w,
                                       const polyvecl *u,
                                       const polyvecl *v);
int pqcrystals_dilithium_polyvecl_chknorm(const polyvecl *v, int32_t B);
typedef struct {
  poly vec[8];
} polyveck;
void pqcrystals_dilithium_polyveck_uniform_eta(polyveck *v, const uint8_t seed[64], uint16_t nonce);
void pqcrystals_dilithium_polyveck_reduce(polyveck *v);
void pqcrystals_dilithium_polyveck_caddq(polyveck *v);
void pqcrystals_dilithium_polyveck_freeze(polyveck *v);
void pqcrystals_dilithium_polyveck_add(polyveck *w, const polyveck *u, const polyveck *v);
void pqcrystals_dilithium_polyveck_sub(polyveck *w, const polyveck *u, const polyveck *v);
void pqcrystals_dilithium_polyveck_shiftl(polyveck *v);
void pqcrystals_dilithium_polyveck_ntt(polyveck *v);
void pqcrystals_dilithium_polyveck_invntt_tomont(polyveck *v);
void pqcrystals_dilithium_polyveck_pointwise_poly_montgomery(polyveck *r, const poly *a, const polyveck *v);
int pqcrystals_dilithium_polyveck_chknorm(const polyveck *v, int32_t B);
void pqcrystals_dilithium_polyveck_power2round(polyveck *v1, polyveck *v0, const polyveck *v);
void pqcrystals_dilithium_polyveck_decompose(polyveck *v1, polyveck *v0, const polyveck *v);
unsigned int pqcrystals_dilithium_polyveck_make_hint(polyveck *h,
                                const polyveck *v0,
                                const polyveck *v1);
void pqcrystals_dilithium_polyveck_use_hint(polyveck *w, const polyveck *v, const polyveck *h);
void pqcrystals_dilithium_polyveck_pack_w1(uint8_t r[8*128], const polyveck *w1);
void pqcrystals_dilithium_polyvec_matrix_expand(polyvecl mat[8], const uint8_t rho[32]);
void pqcrystals_dilithium_polyvec_matrix_pointwise_montgomery(polyveck *t, const polyvecl mat[8], const polyvecl *v);
typedef struct {
    int16_t coeffs[256];
} smallpoly;
typedef smallpoly smallhalfpoly;
void poly_small_ntt_copy(smallpoly*, poly*);
void polyvecl_small_ntt(smallpoly v[7]);
void polyveck_small_ntt(smallpoly v[8]);
void polyvecl_small_basemul_invntt(polyvecl *r, const smallpoly *a, const smallpoly b[7]);
void poly_small_basemul_invntt(poly *r, const smallpoly *a, const smallpoly *b);
void small_polyeta_unpack(smallpoly *r, const uint8_t *a);
void pqcrystals_dilithium_pack_pk(uint8_t pk[(32 + 8*320)], const uint8_t rho[32], const polyveck *t1);
void pqcrystals_dilithium_pack_sk(uint8_t sk[(2*32 + 64 + 7*96 + 8*96 + 8*416)],
             const uint8_t rho[32],
             const uint8_t tr[64],
             const uint8_t key[32],
             const polyveck *t0,
             const polyvecl *s1,
             const polyveck *s2);
void pqcrystals_dilithium_pack_sig(uint8_t sig[(64 + 7*640 + (75 + 8))], const uint8_t c[64], const polyvecl *z, const polyveck *h);
void pqcrystals_dilithium_unpack_pk(uint8_t rho[32], polyveck *t1, const uint8_t pk[(32 + 8*320)]);
void pqcrystals_dilithium_unpack_pk_t1(poly *t1, size_t idx, const unsigned char pk[(32 + 8*320)]);
void pqcrystals_dilithium_unpack_sk(uint8_t rho[32],
               uint8_t tr[64],
               uint8_t key[32],
               polyveck *t0,
               smallpoly s1[7],
               smallpoly s2[8],
               const uint8_t sk[(2*32 + 64 + 7*96 + 8*96 + 8*416)]);
int pqcrystals_dilithium_unpack_sig(uint8_t c[64], polyvecl *z, polyveck *h, const uint8_t sig[(64 + 7*640 + (75 + 8))]);
int pqcrystals_dilithium_unpack_sig_z(polyvecl *z, const unsigned char sig[(64 + 7*640 + (75 + 8))]);
int pqcrystals_dilithium_unpack_sig_h(poly *h, size_t idx, const unsigned char sig[(64 + 7*640 + (75 + 8))]);
int pqcrystals_dilithium_unpack_sig_c(uint8_t c[64], const unsigned char sig[(64 + 7*640 + (75 + 8))]);
void pqcrystals_dilithium_pack_sig_c(uint8_t sig[(64 + 7*640 + (75 + 8))], const uint8_t c[64]);
void pqcrystals_dilithium_pack_sig_z(uint8_t sig[(64 + 7*640 + (75 + 8))], const polyvecl *z);
void pqcrystals_dilithium_pack_sig_h(unsigned char sig[(64 + 7*640 + (75 + 8))],
                const poly *h_elem,
                const unsigned int idx,
                unsigned int *hints_written);
void pqcrystals_dilithium_pack_sig_h_zero(unsigned char sig[(64 + 7*640 + (75 + 8))],
                unsigned int *hints_written);

int randombytes(uint8_t*,size_t);
typedef struct {
    uint64_t ctx[26];
} shake128incctx;
typedef struct {
    uint64_t ctx[25];
} shake128ctx;
typedef struct {
    uint64_t ctx[26];
} shake256incctx;
typedef struct {
    uint64_t ctx[25];
} shake256ctx;
typedef struct {
    uint64_t ctx[26];
} sha3_256incctx;
typedef struct {
    uint64_t ctx[26];
} sha3_384incctx;
typedef struct {
    uint64_t ctx[26];
} sha3_512incctx;
void shake128_absorb(shake128ctx *state, const uint8_t *input, size_t inlen);
void shake128_squeezeblocks(uint8_t *output, size_t nblocks, shake128ctx *state);
void shake128_ctx_release(shake128ctx *state);
void shake128_ctx_clone(shake128ctx *dest, const shake128ctx *src);
void cshake128_simple_absorb(shake128ctx *state, uint16_t cstm, const uint8_t *input, size_t inlen);
void cshake128_simple_squeezeblocks(uint8_t *output, size_t nblocks, shake128ctx *state);
void cshake128_simple(uint8_t *output, size_t outlen, uint16_t cstm, const uint8_t *input, size_t inlen);
void shake128_inc_init(shake128incctx *state);
void shake128_inc_absorb(shake128incctx *state, const uint8_t *input, size_t inlen);
void shake128_inc_finalize(shake128incctx *state);
void shake128_inc_squeeze(uint8_t *output, size_t outlen, shake128incctx *state);
void shake128_inc_ctx_clone(shake128incctx* dest, const shake128incctx *src);
void shake128_inc_ctx_release(shake128incctx *state);
void shake256_absorb(shake256ctx *state, const uint8_t *input, size_t inlen);
void shake256_squeezeblocks(uint8_t *output, size_t nblocks, shake256ctx *state);
void shake256_ctx_release(shake256ctx *state);
void shake256_ctx_clone(shake256ctx *dest, const shake256ctx *src);
void cshake256_simple_absorb(shake256ctx *state, uint16_t cstm, const uint8_t *input, size_t inlen);
void cshake256_simple_squeezeblocks(uint8_t *output, size_t nblocks, shake256ctx *state);
void cshake256_simple(uint8_t *output, size_t outlen, uint16_t cstm, const uint8_t *input, size_t inlen);
void shake256_inc_init(shake256incctx *state);
void shake256_inc_absorb(shake256incctx *state, const uint8_t *input, size_t inlen);
void shake256_inc_finalize(shake256incctx *state);
void shake256_inc_squeeze(uint8_t *output, size_t outlen, shake256incctx *state);
void shake256_inc_ctx_clone(shake256incctx* dest, const shake256incctx *src);
void shake256_inc_ctx_release(shake256incctx *state);
void shake128(uint8_t *output, size_t outlen,
              const uint8_t *input, size_t inlen);
void shake256(uint8_t *output, size_t outlen,
              const uint8_t *input, size_t inlen);
void sha3_256_inc_init(sha3_256incctx *state);
void sha3_256_inc_absorb(sha3_256incctx *state, const uint8_t *input, size_t inlen);
void sha3_256_inc_finalize(uint8_t *output, sha3_256incctx *state);
void sha3_256_inc_ctx_clone(sha3_256incctx *dest, const sha3_256incctx *src);
void sha3_256_inc_ctx_release(sha3_256incctx *state);
void sha3_256(uint8_t *output, const uint8_t *input, size_t inlen);
void sha3_384_inc_init(sha3_384incctx *state);
void sha3_384_inc_absorb(sha3_384incctx *state, const uint8_t *input, size_t inlen);
void sha3_384_inc_finalize(uint8_t *output, sha3_384incctx *state);
void sha3_384_inc_ctx_clone(sha3_384incctx *dest, const sha3_384incctx *src);
void sha3_384_inc_ctx_release(sha3_384incctx *state);
void sha3_384(uint8_t *output, const uint8_t *input, size_t inlen);
void sha3_512_inc_init(sha3_512incctx *state);
void sha3_512_inc_absorb(sha3_512incctx *state, const uint8_t *input, size_t inlen);
void sha3_512_inc_finalize(uint8_t *output, sha3_512incctx *state);
void sha3_512_inc_ctx_clone(sha3_512incctx *dest, const sha3_512incctx *src);
void sha3_512_inc_ctx_release(sha3_512incctx *state);
void sha3_512(uint8_t *output, const uint8_t *input, size_t inlen);
typedef shake128incctx stream128_state;
typedef shake256incctx stream256_state;
void pqcrystals_dilithium_dilithium_shake128_stream_init(stream128_state *state,
                                    const uint8_t seed[32],
                                    uint16_t nonce);
void pqcrystals_dilithium_dilithium_shake256_stream_init(stream256_state *state,
                                    const uint8_t seed[64],
                                    uint16_t nonce);

void poly_challenge_compress(uint8_t c[68], const poly *cp);
void poly_challenge_decompress(poly *cp, const uint8_t c[68]);
void poly_schoolbook(poly *c, const uint8_t ccomp[68], const uint8_t *t0);
void poly_schoolbook_t1(poly *c, const uint8_t ccomp[68], const uint8_t *t1);
void polyw_pack(uint8_t buf[3*256], poly *w);
void polyw_unpack(poly *w, const uint8_t buf[3*256]);
void polyw_add(uint8_t buf[3*256], poly *p);
void polyw_sub(poly* c, uint8_t buf[3*256], poly *a);
void poly_highbits(poly *a1, const poly *a);
void poly_lowbits(poly *a0, const poly *a);
void unpack_sk_s1(smallpoly *a, const uint8_t *sk, size_t idx);
void unpack_sk_s2(smallpoly *a, const uint8_t *sk, size_t idx);
void poly_uniform_pointwise_montgomery_polywadd_stack(uint8_t wcomp[3*256], poly *b, const uint8_t seed[32], uint16_t nonce, shake128incctx *state);
void poly_uniform_gamma1_stack(poly *a, const uint8_t seed[64], uint16_t nonce, shake256incctx *state);
void poly_uniform_gamma1_add_stack(poly *a, poly *b, const uint8_t seed[64], uint16_t nonce, shake256incctx *state);
void poly_challenge_stack(poly *c, const uint8_t seed[64]);
size_t poly_make_hint_stack(poly *a, poly *t, uint8_t w[768]);
int unpack_sig_h_indices(uint8_t h_i[75], unsigned int * number_of_hints, unsigned int idx, const unsigned char sig[(64 + 7*640 + (75 + 8))]);
void poly_use_hint_stack(poly *b, const poly *a, uint8_t h_i[75], unsigned int number_of_hints);
void pack_pk_rho(unsigned char pk[(32 + 8*320)],
                 const unsigned char rho[32]);
void pack_pk_t1(unsigned char pk[(32 + 8*320)],
             const poly *t1,
             const unsigned int idx);
void pack_sk_s1(unsigned char sk[(2*32 + 64 + 7*96 + 8*96 + 8*416)],
                const poly *s1_elem,
                const unsigned int idx);
void pack_sk_s2(unsigned char sk[(2*32 + 64 + 7*96 + 8*96 + 8*416)],
                const poly *s2_elem,
                const unsigned int idx);
void pack_sk_t0(unsigned char sk[(2*32 + 64 + 7*96 + 8*96 + 8*416)],
                const poly *t0_elem,
                const unsigned int idx);
void pack_sk_rho(unsigned char sk[(2*32 + 64 + 7*96 + 8*96 + 8*416)],
                 const unsigned char rho[32]);
void pack_sk_key(unsigned char sk[(2*32 + 64 + 7*96 + 8*96 + 8*416)],
                 const unsigned char key[32]);
void pack_sk_tr(unsigned char sk[(2*32 + 64 + 7*96 + 8*96 + 8*416)],
                const unsigned char tr[64]);

static const int32_t zetas_769[64] = {
 3138844760, 1334846793, 999738812, 1854264165, 1681125041, 1150537404, 2820492178, 3071823164, 726067294, 2066499220, 3272887953, 1055590142, 4255871365, 1871019564, 2731130050, 1826338500, 513832239, 1792827701, 3373420347, 2993631302, 1161707670, 3306398751, 3518633806, 3406931146, 1586177780, 3853741788, 3317569017, 3825816122, 971813147, 122872927, 217820188, 619949766, 3753209393, 770748358, 4099487641, 765163225, 3630336467, 1742561504, 3479537875, 982983413, 2809321912, 2379266669, 703726762, 681386230, 4110657907, 1457719720, 1217559000, 2474213930, 1195218468, 1089100940, 564098436, 614364633, 3635921600, 2088839752, 3702943196, 1949211426, 2569161192, 374203913, 3982199847, 2083254619, 1513571050, 3647091866, 413299844, 4149753838};
static const int32_t zetas_asm_769[128] = {
 346278248, 223405321, 966228013, 759578091, -150798592, 318352582, -1736976371, 1697880440, -2105595150, -804259156, 1675539907, -1016494210, 1401868389, -2005062756, 240160720, 474736307, -1200803600, -1435379187, -1156122536, 1334846793, 999738811, 1854264164, -631120032, -787503756, -1580592646, 1681125040, 1150537403, -1474475119, -1223144132, 1809583100, -100532394, -1938041160, 726067293, 2066499219, -1022079344, 1055590142, 525002504, 273671518, -212235055, -39095931, 1871019563, -1563837247, 1826338499, 139628326, 27925665, 1731391238, 513832238, 1792827701, -921546949, -1301335995, 67021596, 1117026605, 536172770, 1161707669, -988568545, -776333490, -888036151, 1290165729, -497076839, -753992958, 1586177779, -441225509, -977398279, -469151174, -1614103444, 1591762912, -94947261, 971813146, 122872927, 217820188, 619949766, -1709050706, 1010909077, -1748146637, -541757903, 770748357, -195479656, 765163224, 1413038655, 1781657435, -1206388733, -664630830, 1742561504, -815429422, 982983412, 357448514, 44681064, -1524741316, -1485645385, -1915700627, 703726761, 681386229, 686971362, 1787242568, -860110486, -184309390, 1457719719, 1217558999, -1820753366, -502661972, -1921285760, 1139367137, 1195218467, 1089100940, 564098435, 614364633, -1100271206, 457980908, -1669954774, -659045697, 2088839751, -592024101, 1949211426, 1368357591, 698141628, 335107981, -1725806105, 374203913, -312767449, 2083254618, -1061175275, -2139105948, 519417371, 1513571050, -647875431, 413299844, -145213459, 0};
static const int32_t zetas_inv_asm_769[256] = {
 5585134, 5585134, -346278248, 5585134, -966228013, -346278248, -223405321, 5585134, 1736976371, -966228013, 150798592, -346278248, -318352582, -223405321, -759578091,
 5585134, -346278248, 5585134, -966228013, -346278248, -223405321, 636705165, 446810642, 1519156183, 11170266, -821014555, -1932456027, 301597183, -692556495, -240160720, 1061175275, -1368357591, -519417371, -335107981, 2139105948, -698141628, -625534899, -1267825197, 843355087, 290426917, 128458060, 1295750862, -748407825, -826599688, 1736976371, -240160720, 2005062756, 1061175275, 1100271206, -1368357591, 502661972, 915961816, 1396283256, 452395775, -1038834743, -955057747, -670215963, 2016233022, -16755399, -1675539907, 1614103444, -1290165729, 94947261, 753992958, -1591762912, 497076839, -1954796559, 1943626293, -1122611738, -1239899531, 938302348, -245745853, 882451018, -435640376, -966228013, 1736976371, -318352582, -240160720, -1401868389, 2005062756, 1016494210, 714897027, -1005323944, 876865885, 2122350549, -1373942724, -2094424884, 1468889985, 1558252114, -1401868389, -686971362, -357448514, 860110486, 1524741316, -1787242568, -44681064, 1407453522, -368618780, 1323676527, -653460564, -1362772458, 1379527857, -463566041, 1859849297, 150798592, -1675539907, 804259156, 1614103444, -67021596, -1290165729, -139628326, -2060914086, -994153678, 55851330, 189894523, -1072345541, 1507985917, 832184821, 1111441472, 2105595150, -525002504, -1809583100, 212235055, 1938041160, -273671518, 100532394, -2044158687, -78191862, 1452134586, 642290298, -2111180283, 552928169, 161968858, -1167292802, -346278248, -966228013, -223405321, 1736976371, 150798592, -318352582, -759578091, -1608518311, -2032988421, -899206417, -480321440, 943887481, 1491230518, -83776995, -284841784, 2005062756, 1100271206, 502661972, 1669954774, -1139367137, -457980908, 1921285760, 1128196871, -1318091394, -1904530361, 396544445, -1228729265, 117287794, 2116765416, 1184048201, -318352582, -1401868389, 1016494210, -686971362, -1413038655, -357448514, 1709050706, -731652426, 89362128, 2021818155, 1720220972, -1882189829, -1245484665, -798674023, 720482160, 804259156, -67021596, -139628326, -536172770, -1731391238, -1117026605, -27925665, -1843093898, -1971551958, 1027664477, 1776072302, -1692295306, 1977137091, 709311894, 1552666981, -223405321, 150798592, -759578091, -1675539907, 2105595150, 804259156, -1697880440, -675801096, 279256651, 949472614, -1066760408, -1050005009, -134043193, 1262240064, 1714635839, 1016494210, -1413038655, 1709050706, 1206388733, 1748146637, -1781657435, -1010909077, -390959312, -1329261660, -1083515807, -1965966825, -1530326449, 809844289, -1541496715, 1630858843, -759578091, 2105595150, -1697880440, -525002504, 631120032, -1809583100, -474736307, -1575007513, -201064789, 1893360095, 424470110, -1133782004, -418884977, -1424208921, -547343036, -1697880440, 631120032, -474736307, 1580592646, 1435379187, 787503756, 1200803600, 1999477623, -932717215, 1982722224, -1848679031, 586438968, 1993892490, 1625273710, -1346017059, 0};
void small_ntt_asm_769(int16_t a[256], const int32_t * zetas);
void small_invntt_asm_769(int16_t a[256], const int32_t * zetas);
void small_basemul_asm_769(int16_t *c, const int16_t *a, const int16_t *b, const int32_t *zetas);
int crypto_sign_keypair(uint8_t *pk, uint8_t *sk) {
  unsigned int i, j;
  uint8_t seedbuf[2*32 + 64];
  const uint8_t *rho, *rhoprime, *key;
  poly tA, tB;
  union {
    uint8_t tr[64];
    shake256incctx s256;
    poly tC;
  } data;
  shake256incctx *s256 = &data.s256;
  uint8_t *tr = &data.tr[0];
  poly *tC = &data.tC;
  randombytes(seedbuf, 32);
  seedbuf[32 + 0] = 8;
  seedbuf[32 + 1] = 7;
  shake256_inc_init(s256);
  shake256_inc_absorb(s256, seedbuf, 32 + 2);
  shake256_inc_finalize(s256);
  shake256_inc_squeeze(seedbuf, 2*32 + 64, s256);
  rho = seedbuf;
  rhoprime = rho + 32;
  key = rhoprime + 64;
  pack_sk_rho(sk, rho);
  pack_sk_key(sk, key);
  pack_pk_rho(pk, rho);
  for (i = 0; i < 8; i++)
  {
    pqcrystals_dilithium_poly_uniform_eta(tC, rhoprime, 0);
    if (i == 0)
    {
      pack_sk_s1(sk, tC, 0);
    }
    pqcrystals_dilithium_poly_ntt(tC);
    pqcrystals_dilithium_poly_uniform(&tB, rho, (i << 8) + 0);
    pqcrystals_dilithium_poly_pointwise_montgomery(&tA, &tB, tC);
    for(j = 1; j < 7; j++)
    {
      pqcrystals_dilithium_poly_uniform_eta(tC, rhoprime, j);
      if (i == 0)
      {
        pack_sk_s1(sk, tC, j);
      }
      pqcrystals_dilithium_poly_ntt(tC);
      pqcrystals_dilithium_poly_uniform(&tB, rho, (i << 8) + j);
      pqcrystals_dilithium_poly_pointwise_acc_montgomery(&tA, &tB, tC);
    }
    pqcrystals_dilithium_poly_reduce(&tA);
    pqcrystals_dilithium_poly_invntt_tomont(&tA);
    pqcrystals_dilithium_poly_uniform_eta(&tB, rhoprime, 7 + i);
    pack_sk_s2(sk, &tB, i);
    pqcrystals_dilithium_poly_add(&tA, &tA, &tB);
    pqcrystals_dilithium_poly_caddq(&tA);
    pqcrystals_dilithium_poly_power2round(tC, &tB, &tA);
    pack_sk_t0(sk, &tB, i);
    pack_pk_t1(pk, tC, i);
  }
  shake256(tr, 64, pk, (32 + 8*320));
  pack_sk_tr(sk, tr);
  return 0;
}
int crypto_sign_signature_ctx(uint8_t *sig,
                          size_t *siglen,
                          const uint8_t *m,
                          size_t mlen,
                          const uint8_t *ctx,
                          size_t ctxlen,
                          const uint8_t *sk) {
  uint8_t buf[2 * 64];
  uint8_t *mu, *rhoprime, *rnd;
  const uint8_t *rho, *tr, *key;
  uint16_t nonce = 0;
  uint8_t wcomp[8][768];
  uint8_t ccomp[68];
  union {
    shake128incctx s128;
    shake256incctx s256;
  } state;
  union {
    poly full;
    struct {
      smallpoly stmp0;
      smallpoly stmp1;
    } small;
  } polybuffer;
  poly *tmp0 = &polybuffer.full;
  smallpoly *stmp0 = &polybuffer.small.stmp0;
  smallpoly *scp = &polybuffer.small.stmp1;
  rho = sk;
  tr = sk + 32*2;
  key = sk + 32;
  mu = buf;
  rnd = mu + 64;
  rhoprime = mu + 64;
  if (ctxlen > 255) {
    return -1;
  }
  mu[0] = 0;
  mu[1] = (uint8_t)ctxlen;
  shake256_inc_init(&state.s256);
  shake256_inc_absorb(&state.s256, tr, 64);
  shake256_inc_absorb(&state.s256, mu, 2);
  shake256_inc_absorb(&state.s256, ctx, ctxlen);
  shake256_inc_absorb(&state.s256, m, mlen);
  shake256_inc_finalize(&state.s256);
  shake256_inc_squeeze(mu, 64, &state.s256);
  randombytes(rnd, 32);
  shake256_inc_init(&state.s256);
  shake256_inc_absorb(&state.s256, key, 32);
  shake256_inc_absorb(&state.s256, rnd, 32);
  shake256_inc_absorb(&state.s256, mu, 64);
  shake256_inc_finalize(&state.s256);
  shake256_inc_squeeze(rhoprime, 64, &state.s256);
rej:
    for (size_t k_idx = 0; k_idx < 8; k_idx++) {
      for(size_t i=0;i<768;i++){
        wcomp[k_idx][i] = 0;
      }
    }
      for (size_t l_idx = 0; l_idx < 7; l_idx++) {
        poly_uniform_gamma1_stack(tmp0, rhoprime, 7*nonce + l_idx, &state.s256);
        pqcrystals_dilithium_poly_ntt(tmp0);
        for (size_t k_idx = 0; k_idx < 8; k_idx++) {
          poly_uniform_pointwise_montgomery_polywadd_stack(wcomp[k_idx], tmp0, rho, (k_idx << 8) + l_idx, &state.s128);
        }
      }
      nonce++;
      for (size_t k_idx = 0; k_idx < 8; k_idx++) {
        polyw_unpack(tmp0, wcomp[k_idx]);
        pqcrystals_dilithium_poly_invntt_tomont(tmp0);
        pqcrystals_dilithium_poly_caddq(tmp0);
        polyw_pack(wcomp[k_idx], tmp0);
        poly_highbits(tmp0, tmp0);
        pqcrystals_dilithium_polyw1_pack(&sig[k_idx*128], tmp0);
      }
  shake256_inc_init(&state.s256);
  shake256_inc_absorb(&state.s256, mu, 64);
  shake256_inc_absorb(&state.s256, sig, 8*128);
  shake256_inc_finalize(&state.s256);
  shake256_inc_squeeze(sig, 64, &state.s256);
  pqcrystals_dilithium_poly_challenge(tmp0, sig);
  poly_challenge_compress(ccomp, tmp0);
    for(size_t l_idx=0;l_idx < 7; l_idx++){
    if(l_idx != 0){
      poly_challenge_decompress(tmp0, ccomp);
    }
      poly_small_ntt_copy(scp, tmp0);
      unpack_sk_s1(stmp0, sk, l_idx);
      small_ntt_asm_769(stmp0->coeffs, zetas_asm_769);
      poly_small_basemul_invntt(tmp0, scp, stmp0);
      poly_uniform_gamma1_add_stack(tmp0, tmp0, rhoprime, 7*(nonce-1) + l_idx, &state.s256);
      pqcrystals_dilithium_poly_reduce(tmp0);
      if(pqcrystals_dilithium_poly_chknorm(tmp0, (1 << 19) - 120))
        goto rej;
      pqcrystals_dilithium_polyz_pack(sig + 64 + l_idx*640, tmp0);
  }
  unsigned int hint_n = 0;
  unsigned int hints_written = 0;
  for(unsigned int k_idx = 0; k_idx < 8; ++k_idx) {
    poly_challenge_decompress(tmp0, ccomp);
    poly_small_ntt_copy(scp, tmp0);
    unpack_sk_s2(stmp0, sk, k_idx);
    small_ntt_asm_769(stmp0->coeffs, zetas_asm_769);
    poly_small_basemul_invntt(tmp0, scp, stmp0);
    polyw_sub(tmp0, wcomp[k_idx], tmp0);
    pqcrystals_dilithium_poly_reduce(tmp0);
    polyw_pack(wcomp[k_idx], tmp0);
    poly_lowbits(tmp0, tmp0);
    pqcrystals_dilithium_poly_reduce(tmp0);
    if(pqcrystals_dilithium_poly_chknorm(tmp0, ((8380417 -1)/32) - 120)){
      goto rej;
    }
    poly_schoolbook(tmp0, ccomp, sk + 32 + 64 + 32 +
      7*96 + 8*96 + k_idx*416);
    if(pqcrystals_dilithium_poly_chknorm(tmp0, ((8380417 -1)/32))) {
      goto rej;
    }
    hint_n += poly_make_hint_stack(tmp0, tmp0, wcomp[k_idx]);
    if (hint_n > 75) {
      goto rej;
    }
    pqcrystals_dilithium_pack_sig_h(sig, tmp0, k_idx, &hints_written);
  }
  pqcrystals_dilithium_pack_sig_h_zero(sig, &hints_written);
  *siglen = (64 + 7*640 + (75 + 8));
  return 0;
}
int crypto_sign_ctx(uint8_t *sm,
                size_t *smlen,
                const uint8_t *m,
                size_t mlen,
                const uint8_t *ctx,
                size_t ctxlen,
                const uint8_t *sk)
{
  int ret;
  size_t i;
  for(i = 0; i < mlen; ++i) {
    sm[(64 + 7*640 + (75 + 8)) + mlen - 1 - i] = m[mlen - 1 - i];
  }
  ret = crypto_sign_signature_ctx(sm, smlen, sm + (64 + 7*640 + (75 + 8)), mlen, ctx, ctxlen, sk);
  *smlen += mlen;
  return ret;
}
int crypto_sign_verify_ctx(const uint8_t *sig,
                       size_t siglen,
                       const uint8_t *m,
                       size_t mlen,
                       const uint8_t *ctx,
                       size_t ctxlen,
                       const uint8_t *pk)
{
  unsigned int i;
  poly p;
  union {
    uint8_t w1_packed[128];
    uint8_t wcomp[768];
  } w1_packed_comp;
  uint8_t *w1_packed = &w1_packed_comp.w1_packed[0];
  uint8_t *wcomp = &w1_packed_comp.wcomp[0];
  union {
    uint8_t ccomp[68];
    uint8_t mu[64];
  } ccomp_mu;
  uint8_t *ccomp = &ccomp_mu.ccomp[0];
  uint8_t *mu = &ccomp_mu.mu[0];
  shake256incctx s256;
  union {
    uint8_t hint_ones[75];
    shake128incctx s128;
    uint8_t c2[64];
  } shake_hint;
  uint8_t *hint_ones = &shake_hint.hint_ones[0];
  shake128incctx *s128 = &shake_hint.s128;
  uint8_t *c2 = &shake_hint.c2[0];
  if (ctxlen > 255 || siglen != (64 + 7*640 + (75 + 8))) {
      return -1;
  }
  shake256_inc_init(&s256);
  shake256_inc_absorb(&s256, pk, (32 + 8*320));
  shake256_inc_finalize(&s256);
  shake256_inc_squeeze(mu, 64, &s256);
  shake256_inc_init(&s256);
  shake256_inc_absorb(&s256, mu, 64);
  mu[0] = 0;
  mu[1] = (uint8_t)ctxlen;
  shake256_inc_absorb(&s256, mu, 2);
  shake256_inc_absorb(&s256, ctx, ctxlen);
  shake256_inc_absorb(&s256, m, mlen);
  shake256_inc_finalize(&s256);
  shake256_inc_squeeze(mu, 64, &s256);
  shake256_inc_init(&s256);
  shake256_inc_absorb(&s256, mu, 64);
  poly_challenge_stack(&p, sig);
  poly_challenge_compress(ccomp, &p);
  for (size_t k_idx = 0; k_idx < 8; k_idx++) {
    for(size_t widx=0;widx<768;widx++){
        wcomp[widx] = 0;
    }
    pqcrystals_dilithium_polyz_unpack(&p, sig + 64);
    if(pqcrystals_dilithium_poly_chknorm(&p, (1 << 19) - 120))
      return -1;
    pqcrystals_dilithium_poly_ntt(&p);
    poly_uniform_pointwise_montgomery_polywadd_stack(wcomp, &p, pk, (k_idx << 8) + 0, s128);
    for (size_t l_idx = 1; l_idx < 7; l_idx++) {
      pqcrystals_dilithium_polyz_unpack(&p, sig + 64 + l_idx*640);
      if(pqcrystals_dilithium_poly_chknorm(&p, (1 << 19) - 120))
        return -1;
      pqcrystals_dilithium_poly_ntt(&p);
      poly_uniform_pointwise_montgomery_polywadd_stack(wcomp, &p, pk, (k_idx << 8) + l_idx, s128);
    }
    polyw_unpack(&p, wcomp);
    pqcrystals_dilithium_poly_reduce(&p);
    pqcrystals_dilithium_poly_invntt_tomont(&p);
    polyw_pack(wcomp, &p);
    poly_schoolbook_t1(&p, ccomp, pk + 32 + k_idx*320);
    polyw_sub(&p, wcomp, &p);
    pqcrystals_dilithium_poly_reduce(&p);
    pqcrystals_dilithium_poly_caddq(&p);
    if (unpack_sig_h_indices(hint_ones, &i, k_idx, sig) != 0)
    {
      return -1;
    }
    poly_use_hint_stack(&p, &p, hint_ones, i);
    pqcrystals_dilithium_polyw1_pack(w1_packed, &p);
    shake256_inc_absorb(&s256, w1_packed, 128);
  }
  shake256_inc_finalize(&s256);
  shake256_inc_squeeze(c2, 64, &s256);
  for (i = 0; i < 64; ++i) {
    if (sig[i] != c2[i])
      return -1;
  }
  return 0;
}
int crypto_sign_open_ctx(uint8_t *m,
                     size_t *mlen,
                     const uint8_t *sm,
                     size_t smlen,
                     const uint8_t *ctx,
                     size_t ctxlen,
                     const uint8_t *pk)
{
  size_t i;
  if(smlen < (64 + 7*640 + (75 + 8)))
    goto badsig;
  *mlen = smlen - (64 + 7*640 + (75 + 8));
  if(crypto_sign_verify_ctx(sm, (64 + 7*640 + (75 + 8)), sm + (64 + 7*640 + (75 + 8)), *mlen, ctx, ctxlen, pk))
    goto badsig;
  else {
    for (i = 0; i < *mlen; ++i) {
      m[i] = sm[(64 + 7*640 + (75 + 8)) + i];
    }
    return 0;
  }
badsig:
  *mlen = 0;
  for (i = 0; i < smlen; ++i) {
    m[i] = 0;
  }
  return -1;
}
