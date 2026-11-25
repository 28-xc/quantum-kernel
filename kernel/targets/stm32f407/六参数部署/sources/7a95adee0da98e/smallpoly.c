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
void pqcrystals_dilithium_poly_challenge(poly *c, const uint8_t seed[48]);
void pqcrystals_dilithium_polyeta_pack(uint8_t *r, const poly *a);
void pqcrystals_dilithium_polyt1_pack(uint8_t *r, const poly *a);
void pqcrystals_dilithium_polyt1_unpack(poly *r, const uint8_t *a);
void pqcrystals_dilithium_polyt0_pack(uint8_t *r, const poly *a);
void pqcrystals_dilithium_polyt0_unpack(poly *r, const uint8_t *a);
void pqcrystals_dilithium_polyz_pack(uint8_t *r, const poly *a);
void pqcrystals_dilithium_polyz_unpack(poly *r, const uint8_t *a);
void pqcrystals_dilithium_polyw1_pack(uint8_t *r, const poly *a);
typedef struct {
  poly vec[5];
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
  poly vec[6];
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
void pqcrystals_dilithium_polyveck_pack_w1(uint8_t r[6*128], const polyveck *w1);
void pqcrystals_dilithium_polyvec_matrix_expand(polyvecl mat[6], const uint8_t rho[32]);
void pqcrystals_dilithium_polyvec_matrix_pointwise_montgomery(polyveck *t, const polyvecl mat[6], const polyvecl *v);
typedef struct {
    int16_t coeffs[256];
} smallpoly;
typedef smallpoly smallhalfpoly;
void poly_small_ntt_copy(smallpoly*, poly*);
void polyvecl_small_ntt(smallpoly v[5]);
void polyveck_small_ntt(smallpoly v[6]);
void polyvecl_small_basemul_invntt(polyvecl *r, const smallpoly *a, const smallpoly b[5]);
void poly_small_basemul_invntt(poly *r, const smallpoly *a, const smallpoly *b);
void small_polyeta_unpack(smallpoly *r, const uint8_t *a);
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

void poly_small_ntt_copy(smallpoly *out, poly *in) {
  for (int i = 256 - 1; i >= 0; i--)
  {
    out->coeffs[i] = in->coeffs[i];
  }
  small_ntt_asm_769(out->coeffs, zetas_asm_769);
}
void polyvecl_small_ntt(smallpoly v[5]) {
  unsigned int i;
  for(i = 0; i < 5; ++i)
    small_ntt_asm_769(v[i].coeffs, zetas_asm_769);
}
void polyveck_small_ntt(smallpoly v[6]) {
  unsigned int i;
  for(i = 0; i < 6; ++i)
    small_ntt_asm_769(v[i].coeffs, zetas_asm_769);
}
void poly_small_basemul_invntt(poly *r, const smallpoly *a, const smallpoly *b){
    smallpoly *tmp = (smallpoly *)r;
    small_basemul_asm_769(tmp->coeffs, a->coeffs, b->coeffs, zetas_769);
    small_invntt_asm_769(tmp->coeffs, zetas_inv_asm_769);
    int j;
    for(j=256 -1;j>=0;j--){
        r->coeffs[j] = tmp->coeffs[j];
    }
}
void polyvecl_small_basemul_invntt(polyvecl *r, const smallpoly *a, const smallpoly b[5]){
    unsigned int i;
    for(i=0;i<5;i++){
        poly_small_basemul_invntt(&r->vec[i], a, &b[i]);
    }
}
void small_polyeta_unpack(smallpoly *r, const uint8_t *a) {
  unsigned int i;
  for(i = 0; i < 256/2; ++i) {
    r->coeffs[2*i+0] = a[i] & 0x0F;
    r->coeffs[2*i+1] = a[i] >> 4;
    r->coeffs[2*i+0] = 4 - r->coeffs[2*i+0];
    r->coeffs[2*i+1] = 4 - r->coeffs[2*i+1];
  }
}
