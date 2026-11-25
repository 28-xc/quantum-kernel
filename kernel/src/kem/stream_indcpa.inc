/* LatticeCore generated-schedule primitives. FIPS 203 semantics are unchanged.
 * This file replaces only keygen/encrypt scheduling in the attributed upstream
 * adapter. Public LC_KEM_ACTIVE_ROWS/BATCH/NOISE_CACHE select a fixed schedule.
 */
#ifndef LC_KEM_ARM_HJ_PREFIX
#define LC_KEM_ARM_HJ_PREFIX 0
#endif
#if LC_KEM_ARM_HJ_PREFIX && (!defined(LC_BUILD_ARM_PROFILE) || !LC_BUILD_ARM_PROFILE)
#error "ARM hash/matrix schedule requires AArch64"
#endif
#if LC_KEM_ARM_HJ_PREFIX < 0 || LC_KEM_ARM_HJ_PREFIX > 2
#error "ARM hash/matrix schedule selects zero, one or two retained rows"
#endif
#define LC_KEM_ARM_HJ_ROWS ((MLKEM_K==2)?2:LC_KEM_ARM_HJ_PREFIX)
#ifndef LC_KEM_K2_ROWS2
#define LC_KEM_K2_ROWS2 0
#endif
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if LC_KEM_K2_ROWS2
#define LC_KEM_ACTIVE_ROWS ((MLKEM_K==2)?2:LC_KEM_ROWS)
_Static_assert(LC_KEM_ROWS==1 && LC_KEM_BATCH==4,"Rank-two coalescing uses a one-row four-lane parent");
#else
#define LC_KEM_ACTIVE_ROWS LC_KEM_ROWS
#endif
#else
#if LC_KEM_K2_ROWS2
#define LC_KEM_ACTIVE_ROWS ((MLKEM_K==2)?2:LC_KEM_ROWS)
_Static_assert(LC_KEM_ROWS==1 && LC_KEM_BATCH==4,"Rank-two coalescing uses a one-row four-lane parent");
#else
#define LC_KEM_ACTIVE_ROWS LC_KEM_ROWS
#endif
#ifndef LC_KEM_CBD_AVX2
#define LC_KEM_CBD_AVX2 0
#endif
#if LC_KEM_CBD_AVX2
#include "lc_cbd_avx2.h"
#endif
#ifndef LC_KEM_LINEAR_K3
#define LC_KEM_LINEAR_K3 0
#endif
#ifndef LC_KEM_MATRIX_INTERLEAVED
#define LC_KEM_MATRIX_INTERLEAVED 0
#endif
#if LC_KEM_MATRIX_INTERLEAVED
#if !defined(__AVX2__)
#error "The shared interleaved matrix backend requires AVX2"
#endif
#include "lc_kem_interleaved.h"
#endif
#ifndef LC_KEM_REJECT_DIRECT
#define LC_KEM_REJECT_DIRECT 0
#endif
#if LC_KEM_REJECT_DIRECT
#if !defined(__AVX2__)
#error "Direct public rejection requires the x86_64 AVX2 backend"
#endif
#include "lc_kem_rejection8.h"
#endif
#ifndef LC_KEM_DIRECT_STATE
#define LC_KEM_DIRECT_STATE 0
#endif
#if LC_KEM_DIRECT_STATE
#if !LC_KEM_REJECT_DIRECT || !LC_KEM_MATRIX_INTERLEAVED || !defined(__AVX2__)
#error "Direct matrix-state consumption requires the shared AVX2 rejection path"
#endif
#include "lc_kem_direct_state.h"
#endif
#ifndef LC_KEM_ENC_HYBRID
#define LC_KEM_ENC_HYBRID 0
#endif
#if LC_KEM_ENC_HYBRID
#if !defined(__AVX2__) || !LC_KEM_REJECT_DIRECT || !LC_KEM_MATRIX_INTERLEAVED || !LC_KEM_DECAPS_TMP_REUSE
#error "Encapsulation hybrid schedule requires the qualified native shared backend"
#endif
#include "lc_kem_enc_hybrid.h"
#endif
#if LC_KEM_HJ_PREFIX
#if !LC_KEM_REJECT_DIRECT || !LC_KEM_MATRIX_INTERLEAVED || !LC_KEM_DECAPS_TMP_REUSE
#error "Mixed H/J prefix requires the qualified direct interleaved backend"
#endif
#include "lc_kem_hj_prefix.h"
#endif
#endif
#define lc_kem_tile MLK_ADD_PARAM_SET(lc_kem_tile)
#define lc_kem_noise MLK_ADD_PARAM_SET(lc_kem_noise)
#ifndef LC_KEM_TILE_BORROW
#define LC_KEM_TILE_BORROW 0
#endif
#ifndef LC_KEM_RETAIN_MULCACHE
#define LC_KEM_RETAIN_MULCACHE 0
#endif
#if LC_KEM_RETAIN_MULCACHE && (!defined(LC_BUILD_ARM_PROFILE) || !LC_BUILD_ARM_PROFILE || !LC_KEM_TILE_BORROW)
#error "Retained product cache requires the ARM borrowed-state schedule"
#endif
#define LC_KEM_USE_RETAINED_CACHE (LC_KEM_RETAIN_MULCACHE && MLKEM_K == 4)
#ifndef LC_KEM_RATE_NATIVE_STAGE
#define LC_KEM_RATE_NATIVE_STAGE 0
#endif
#ifndef LC_KEM_MATRIX_INITIAL3
#define LC_KEM_MATRIX_INITIAL3 0
#endif
#if LC_KEM_MATRIX_INITIAL3 && !LC_KEM_RATE_NATIVE_STAGE
#error "Initial-block matrix staging requires the decoded scratch"
#endif
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#ifndef LC_KEM_NOISE_RAW
#define LC_KEM_NOISE_RAW 0
#endif
#else
#ifndef LC_KEM_NOISE_INTERLEAVED
#define LC_KEM_NOISE_INTERLEAVED 0
#endif
#if LC_KEM_NOISE_INTERLEAVED && !LC_KEM_MATRIX_INTERLEAVED
#error "Noise uses the existing shared interleaved permutation provider"
#endif
#ifndef LC_KEM_NOISE_RAW
#define LC_KEM_NOISE_RAW 0
#endif
#ifndef LC_KEM_NOISE_REUSE_E2
#define LC_KEM_NOISE_REUSE_E2 0
#endif
#if LC_KEM_NOISE_RAW && !LC_KEM_CBD_AVX2
#error "This candidate uses the verified AVX2 decoder"
#endif
#if LC_KEM_NOISE_REUSE_E2 && !LC_KEM_NOISE_RAW
#error "Final-error reuse requires raw PRF storage"
#endif
#endif
#ifndef LC_KEM_COMPACT_NOISE4
#define LC_KEM_COMPACT_NOISE4 0
#endif
#if LC_KEM_COMPACT_NOISE4
#include "lc_noise_compact.h"
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#define LC_KEM_NOISE_BYTES (LC_KEM_NOISE_RAW ? (64*MLKEM_ETA1) : 96)
#else
#define LC_KEY_NOISE_BYTES (LC_KEM_NOISE_RAW ? 64*MLKEM_ETA1 : 96)
#define LC_ENC_NOISE_BYTES (LC_KEM_NOISE_RAW ? 64*MLKEM_ETA2 : 96)
#define LC_ENC_NOISE_COUNT (MLKEM_K+((LC_KEM_NOISE_REUSE_E2 && MLKEM_K==3)?1:0))
#endif
#if !LC_KEM_TILE_BORROW
#error "Compact four-way noise requires the borrowed x4 state"
#endif
#endif
#if LC_KEM_TILE_BORROW
#if LC_KEM_BATCH != 4 || LC_KEM_NOISE_CACHE || defined(MLK_CONFIG_SERIAL_FIPS202_ONLY)
#error "Borrowed four-lane scratch requires scalar noise scheduling and x4 SHAKE"
#endif
#define lc_kem_cache_union MLK_ADD_PARAM_SET(lc_kem_cache_union)
#define lc_kem_work_union MLK_ADD_PARAM_SET(lc_kem_work_union)
#define lc_kem_reject_rate MLK_ADD_PARAM_SET(lc_kem_reject_rate)
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#else
#if LC_KEM_ENC_HYBRID
#define lc_kem_secret_union MLK_ADD_PARAM_SET(lc_kem_secret_union)
typedef union {mlk_polyvec secret;uint64_t hybrid_states[125];} lc_kem_secret_union;
_Static_assert(sizeof(lc_kem_secret_union)==sizeof(mlk_polyvec),"Public prehash fits the existing secret-vector owner");
#endif
#endif
typedef union {
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#else
#if LC_KEM_ENC_HYBRID
    uint64_t hybrid_aux[25];
#endif
#endif
    mlk_polyvec_mulcache product;
    mlk_xof_x4_ctx xof;
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#else
#if LC_KEM_LINEAR_K3 && MLKEM_K==3
    mlk_xof_ctx single;
#endif
#endif
} lc_kem_cache_union;
typedef union {
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#else
#if LC_KEM_ENC_HYBRID
    int16_t hybrid_decoded[256];
    mlk_poly enc_noise_poly[2];
    uint8_t enc_noise_raw[4][192];
#endif
#endif
    struct {mlk_poly row,temporary;} polynomials;
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#else
#if LC_KEM_LINEAR_K3 && MLKEM_K==3
    struct {mlk_poly partial; MLK_ALIGN uint8_t rate[192]; MLK_ALIGN int16_t decoded[MLKEM_N];} linear;
#endif
#endif
    struct {
        MLK_ALIGN uint8_t rate[4][MLK_ALIGN_UP(MLK_XOF_RATE)];
#if LC_KEM_RATE_NATIVE_STAGE
        MLK_ALIGN int16_t decoded[MLKEM_N];
#endif
    } sampling;
} lc_kem_work_union;
_Static_assert(sizeof(lc_kem_work_union)<=2*sizeof(mlk_poly)+256*LC_KEM_RATE_NATIVE_STAGE,"Rate scratch growth is bounded by 256 bytes");
/* Same 12-bit public-seed rejection rule as upstream sampling.c; the
 * continuation keeps its exact coefficient offset across rate blocks. */
static unsigned lc_kem_reject_rate(int16_t *out,unsigned count,const uint8_t *bytes,unsigned length) {
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if defined(MLK_USE_NATIVE_REJ_UNIFORM)
    if(count==0) {
        int n=mlk_rej_uniform_native(out,MLKEM_N,bytes,length);
        if(n!=MLK_NATIVE_FUNC_FALLBACK)return (unsigned)n;
    }
#endif
    for(unsigned pos=0;count<MLKEM_N && pos+3<=length;pos+=3) {
        uint16_t a=((uint16_t)bytes[pos]|((uint16_t)bytes[pos+1]<<8))&4095u;
        uint16_t b=((uint16_t)bytes[pos+1]>>4)|((uint16_t)bytes[pos+2]<<4);
        if(a<MLKEM_Q)out[count++]=(int16_t)a;
        if(count<MLKEM_N && b<MLKEM_Q)out[count++]=(int16_t)b;
    }
    return count;
#else
#if LC_KEM_REJECT_DIRECT
    return lc_kem_reject8(out,count,bytes,length);
#else
#if defined(MLK_USE_NATIVE_REJ_UNIFORM)
    if(count==0) {
        int n=mlk_rej_uniform_native(out,MLKEM_N,bytes,length);
        if(n!=MLK_NATIVE_FUNC_FALLBACK)return (unsigned)n;
    }
#endif
    for(unsigned pos=0;count<MLKEM_N && pos+3<=length;pos+=3) {
        uint16_t a=((uint16_t)bytes[pos]|((uint16_t)bytes[pos+1]<<8))&4095u;
        uint16_t b=((uint16_t)bytes[pos+1]>>4)|((uint16_t)bytes[pos+2]<<4);
        if(a<MLKEM_Q)out[count++]=(int16_t)a;
        if(count<MLKEM_N && b<MLKEM_Q)out[count++]=(int16_t)b;
    }
    return count;
#endif
#endif
}
#endif

#if LC_KEM_ARM_HJ_PREFIX
#if LC_KEM_ROWS != 1 || LC_KEM_BATCH != 4 || !LC_KEM_TILE_BORROW
#error "ARM hash/matrix prefix requires the one-row borrowed four-lane schedule"
#endif
#if !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "Canonical ARM hash/matrix lanes require little-endian AArch64"
#endif
#include "lc_kem_hj_arm.h"
#endif

#if LC_KEM_COMPACT_NOISE4
#define lc_kem_noise4_compact MLK_ADD_PARAM_SET(lc_kem_noise4_compact)
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
static void lc_kem_noise4_compact(mlk_poly *a,mlk_poly *b,mlk_poly *c,mlk_poly *d,
#else
static void lc_kem_noise4_compact(void *a,void *b,void *c,void *d,
#endif
 const uint8_t seed[32],uint8_t first,unsigned eta_low,unsigned eta_high,
 unsigned expand_mask,lc_kem_cache_union *owner) {
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
    uint8_t nonce[4]={first,(uint8_t)(first+1),(uint8_t)(first+2),(uint8_t)(first+3)};
    uint8_t pad=0x1f,end=0x80;uint64_t *state=owner->xof.ctx;
    unsigned blocks=(eta_low==3||eta_high==3)?2:1;
    mlk_zeroize(state,sizeof owner->xof.ctx);
    mlk_keccakf1600x4_xor_bytes(state,seed,seed,seed,seed,0,32);
    mlk_keccakf1600x4_xor_bytes(state,nonce,nonce+1,nonce+2,nonce+3,32,1);
    mlk_keccakf1600x4_xor_bytes(state,&pad,&pad,&pad,&pad,33,1);
    mlk_keccakf1600x4_xor_bytes(state,&end,&end,&end,&end,135,1);
    for(unsigned block=0;block<blocks;block++) {
        mlk_keccakf1600x4_permute(state);
        mlk_keccakf1600x4_extract_bytes(state,(uint8_t*)a+block*136,(uint8_t*)b+block*136,
         (uint8_t*)c+block*136,(uint8_t*)d+block*136,0,136);
    }
#else
#if LC_KEM_NOISE_INTERLEAVED
    uint64_t *state=owner->xof.ctx;
    unsigned blocks=(eta_low==3||eta_high==3)?2:1;
    lc_kem_noise_interleaved_init(state,seed,first);
    for(unsigned block=0;block<blocks;block++) {
        lc_kem_interleaved_permute(state);
        lc_kem_noise_interleaved_extract((uint8_t*)a+block*136,(uint8_t*)b+block*136,
         (uint8_t*)c+block*136,(uint8_t*)d+block*136,state);
    }
#else
    uint8_t nonce[4]={first,(uint8_t)(first+1),(uint8_t)(first+2),(uint8_t)(first+3)};
    uint8_t pad=0x1f,end=0x80;uint64_t *state=owner->xof.ctx;
    unsigned blocks=(eta_low==3||eta_high==3)?2:1;
    mlk_zeroize(state,sizeof owner->xof.ctx);
    mlk_keccakf1600x4_xor_bytes(state,seed,seed,seed,seed,0,32);
    mlk_keccakf1600x4_xor_bytes(state,nonce,nonce+1,nonce+2,nonce+3,32,1);
    mlk_keccakf1600x4_xor_bytes(state,&pad,&pad,&pad,&pad,33,1);
    mlk_keccakf1600x4_xor_bytes(state,&end,&end,&end,&end,135,1);
    for(unsigned block=0;block<blocks;block++) {
        mlk_keccakf1600x4_permute(state);
        mlk_keccakf1600x4_extract_bytes(state,(uint8_t*)a+block*136,(uint8_t*)b+block*136,
         (uint8_t*)c+block*136,(uint8_t*)d+block*136,0,136);
    }
#endif
#endif
    mlk_zeroize(state,sizeof owner->xof.ctx);
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
    if(expand_mask&1)lc_cbd_reverse(a->coeffs,eta_low);
    if(expand_mask&2)lc_cbd_reverse(b->coeffs,eta_low);
    if(expand_mask&4)lc_cbd_reverse(c->coeffs,eta_high);
    if(expand_mask&8)lc_cbd_reverse(d->coeffs,eta_high);
#else
    if(expand_mask&1){if(eta_low==2)lc_cbd2_avx2((int16_t*)a,(const uint8_t*)a);else lc_cbd3_avx2((int16_t*)a,(const uint8_t*)a);}
    if(expand_mask&2){if(eta_low==2)lc_cbd2_avx2((int16_t*)b,(const uint8_t*)b);else lc_cbd3_avx2((int16_t*)b,(const uint8_t*)b);}
    if(expand_mask&4){if(eta_high==2)lc_cbd2_avx2((int16_t*)c,(const uint8_t*)c);else lc_cbd3_avx2((int16_t*)c,(const uint8_t*)c);}
    if(expand_mask&8){if(eta_high==2)lc_cbd2_avx2((int16_t*)d,(const uint8_t*)d);else lc_cbd3_avx2((int16_t*)d,(const uint8_t*)d);}
#endif
}
#endif

#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if LC_KEM_SHARED_SAMPLE4 && LC_KEM_MATRIX_INITIAL3 && LC_KEM_COMPACT_NOISE4 && LC_KEM_NOISE_RAW && MLKEM_K==3 && LC_KEM_ACTIVE_ROWS==1
#define LC_KEM_KEYGEN_MIXED3 1
#else
#define LC_KEM_KEYGEN_MIXED3 0
#endif
#endif
#define LC_TILE_POLYS ((LC_KEM_BATCH==4)?((((LC_KEM_ACTIVE_ROWS<MLKEM_K)?LC_KEM_ACTIVE_ROWS:MLKEM_K)*MLKEM_K+3)/4*4):(((LC_KEM_ACTIVE_ROWS<MLKEM_K)?LC_KEM_ACTIVE_ROWS:MLKEM_K)*MLKEM_K))
static void lc_kem_noise(mlk_poly *p,const uint8_t seed[32],uint8_t nonce,unsigned eta) {
    uint8_t input[33],bytes[192];
    mlk_memcpy(input,seed,32); input[32]=nonce;
    mlk_prf_eta(eta,bytes,input);
    /* Public eta dispatch, using the attributed upstream SWAR CBD decoder. */
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
    if(eta==2)mlk_poly_cbd2(p,bytes);else mlk_poly_cbd3(p,bytes);
#else
#if LC_KEM_CBD_AVX2
    if(eta==2)lc_cbd2_avx2(p->coeffs,bytes);else lc_cbd3_avx2(p->coeffs,bytes);
#else
    if(eta==2)mlk_poly_cbd2(p,bytes);else mlk_poly_cbd3(p,bytes);
#endif
#endif
    mlk_zeroize(input,sizeof input);mlk_zeroize(bytes,sizeof bytes);
}
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if LC_KEM_SHARED_SAMPLE4
#if !LC_KEM_TILE_BORROW || !LC_KEM_RATE_NATIVE_STAGE || LC_KEM_BATCH != 4
#error "Shared sampler requires the fixed four-lane borrowed scratch path"
#endif
__attribute__((noipa,visibility("hidden")))
void lc_kem_sample4_shared(mlk_poly *tile,
 const uint8_t ext[4][MLK_ALIGN_UP(34)],mlk_xof_x4_ctx *state,
 uint8_t rate[4][MLK_ALIGN_UP(MLK_XOF_RATE)],int16_t decoded[MLKEM_N],unsigned initial3);
#if !defined(MLK_CONFIG_MULTILEVEL_NO_SHARED)
_Static_assert(MLKEM_N==256 && MLKEM_Q==3329 && sizeof(mlk_poly)==512,
               "Shared sampler has one fixed ring and polynomial representation");
__attribute__((noipa,visibility("hidden")))
void lc_kem_sample4_shared(mlk_poly *tile,
 const uint8_t ext[4][MLK_ALIGN_UP(34)],mlk_xof_x4_ctx *state,
 uint8_t rate[4][MLK_ALIGN_UP(MLK_XOF_RATE)],int16_t decoded[MLKEM_N],unsigned initial3)
{
        /* Bit1 selects a public three-A/one-noise schedule. The fourth
         * state is canonical SHAKE256(sigma || nonce), independent of A. */
        unsigned active=(initial3&2)?3:4;
        unsigned count[4]={0,0,0,(initial3&2)?MLKEM_N:0};
        mlk_xof_x4_init(state);mlk_xof_x4_absorb(state,ext,MLKEM_SYMBYTES+2);
        if(initial3&2) {
            uint8_t *noise=(uint8_t*)(state->ctx+75);
            noise[33]=0x1f;noise[34]=0;noise[135]=0x80;noise[167]=0;
        }
        if(initial3&1) {
        /* Each dead 512-byte polynomial holds its first 504 XOF bytes.
         * Rejection writes to disjoint decoded scratch before copying back. */
        for(unsigned block=0;block<3;block++) {
            mlk_keccakf1600x4_permute(state->ctx);
            mlk_keccakf1600x4_extract_bytes(state->ctx,
              (uint8_t*)(tile+0)+block*MLK_XOF_RATE,
              (uint8_t*)(tile+1)+block*MLK_XOF_RATE,
              (uint8_t*)(tile+2)+block*MLK_XOF_RATE,
              (uint8_t*)(tile+3)+block*MLK_XOF_RATE,0,MLK_XOF_RATE);
        }
        for(unsigned lane=0;lane<active;lane++) {
            count[lane]=lc_kem_reject_rate(decoded,0,(const uint8_t*)(tile+lane),3*MLK_XOF_RATE);
            mlk_memcpy((tile+lane)->coeffs,decoded,count[lane]*sizeof(int16_t));
        }
        }
        while(count[0]<MLKEM_N||count[1]<MLKEM_N||count[2]<MLKEM_N||count[3]<MLKEM_N) {
            mlk_xof_x4_squeezeblocks(rate,1,state);
            for(unsigned lane=0;lane<active;lane++) {
#if LC_KEM_RATE_NATIVE_STAGE && defined(MLK_USE_NATIVE_REJ_UNIFORM)
                /* Upstream native rejection receives its full 256-coefficient
                 * destination. Only the public remaining prefix is appended. */
                int produced=mlk_rej_uniform_native(decoded,MLKEM_N,rate[lane],MLK_XOF_RATE);
                if(produced!=MLK_NATIVE_FUNC_FALLBACK) {
                    unsigned take=(unsigned)produced;
                    if(take>MLKEM_N-count[lane])take=MLKEM_N-count[lane];
                    mlk_memcpy((tile+lane)->coeffs+count[lane],decoded,take*sizeof(int16_t));
                    count[lane]+=take;
                } else
#endif
                count[lane]=lc_kem_reject_rate((tile+lane)->coeffs,count[lane],rate[lane],MLK_XOF_RATE);
            }
        }
        mlk_xof_x4_release(state);mlk_zeroize(state,sizeof(*state));mlk_zeroize(rate,4*MLK_ALIGN_UP(MLK_XOF_RATE));
}
#endif
#endif

#else
#endif
static void lc_kem_tile(mlk_poly *tile,const uint8_t seed[32],unsigned first,unsigned rows,int transpose
#if LC_KEM_TILE_BORROW
 ,lc_kem_cache_union *cache_owner,lc_kem_work_union *work
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
 ,const uint8_t *noise_seed
#endif
#endif
) {
    MLK_ALIGN uint8_t ext[4][MLK_ALIGN_UP(34)];
    unsigned n=rows*MLKEM_K,i,j;
    for(j=0;j<4;j++)mlk_memcpy(ext[j],seed,32);
    for(i=0;i<n;i+=LC_KEM_BATCH) {
        for(j=0;j<LC_KEM_BATCH;j++) {
            unsigned idx=i+j;
            /* Unused final SIMD lanes repeat a PUBLIC index and are discarded. */
            if(idx>=n)idx=n-1;
            unsigned row=first+idx/MLKEM_K,col=idx%MLKEM_K;
            ext[j][32]=(uint8_t)(transpose?row:col);
            ext[j][33]=(uint8_t)(transpose?col:row);
        }
#if LC_KEM_BATCH == 4
#if LC_KEM_TILE_BORROW
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if LC_KEM_SHARED_SAMPLE4
        if(noise_seed) {
            mlk_memcpy(ext[3],noise_seed,32);
            ext[3][32]=(uint8_t)(MLKEM_K+first);ext[3][33]=0;
        }
        lc_kem_sample4_shared(tile+i,ext,&cache_owner->xof,
                              work->sampling.rate,work->sampling.decoded,
                              LC_KEM_MATRIX_INITIAL3|(noise_seed?2:0));
#else
        unsigned count[4]={0,0,0,0};
        mlk_xof_x4_ctx *state=&cache_owner->xof;
        mlk_xof_x4_init(state);mlk_xof_x4_absorb(state,ext,MLKEM_SYMBYTES+2);
#if LC_KEM_MATRIX_INITIAL3
        /* Each dead 512-byte polynomial holds its first 504 XOF bytes.
         * Rejection writes to disjoint decoded scratch before copying back. */
        for(unsigned block=0;block<3;block++) {
            mlk_keccakf1600x4_permute(state->ctx);
            mlk_keccakf1600x4_extract_bytes(state->ctx,
              (uint8_t*)(tile+i+0)+block*MLK_XOF_RATE,
              (uint8_t*)(tile+i+1)+block*MLK_XOF_RATE,
              (uint8_t*)(tile+i+2)+block*MLK_XOF_RATE,
              (uint8_t*)(tile+i+3)+block*MLK_XOF_RATE,0,MLK_XOF_RATE);
        }
        for(unsigned lane=0;lane<4;lane++) {
            count[lane]=lc_kem_reject_rate(work->sampling.decoded,0,(const uint8_t*)(tile+i+lane),3*MLK_XOF_RATE);
            mlk_memcpy((tile+i+lane)->coeffs,work->sampling.decoded,count[lane]*sizeof(int16_t));
        }
#endif
        while(count[0]<MLKEM_N||count[1]<MLKEM_N||count[2]<MLKEM_N||count[3]<MLKEM_N) {
            mlk_xof_x4_squeezeblocks(work->sampling.rate,1,state);
            for(unsigned lane=0;lane<4;lane++) {
#if LC_KEM_RATE_NATIVE_STAGE && defined(MLK_USE_NATIVE_REJ_UNIFORM)
                /* Upstream native rejection receives its full 256-coefficient
                 * destination. Only the public remaining prefix is appended. */
                int produced=mlk_rej_uniform_native(work->sampling.decoded,MLKEM_N,work->sampling.rate[lane],MLK_XOF_RATE);
                if(produced!=MLK_NATIVE_FUNC_FALLBACK) {
                    unsigned take=(unsigned)produced;
                    if(take>MLKEM_N-count[lane])take=MLKEM_N-count[lane];
                    mlk_memcpy((tile+i+lane)->coeffs+count[lane],work->sampling.decoded,take*sizeof(int16_t));
                    count[lane]+=take;
                } else
#endif
                count[lane]=lc_kem_reject_rate((tile+i+lane)->coeffs,count[lane],work->sampling.rate[lane],MLK_XOF_RATE);
            }
        }
        mlk_xof_x4_release(state);mlk_zeroize(state,sizeof(*state));mlk_zeroize(work->sampling.rate,sizeof(work->sampling.rate));
#endif
#else
        unsigned count[4]={0,0,0,0};
        mlk_xof_x4_ctx *state=&cache_owner->xof;
#if LC_KEM_MATRIX_INTERLEAVED
        lc_kem_interleaved_init(state->ctx,&ext[0][0],sizeof(ext[0]));
#else
        mlk_xof_x4_init(state);mlk_xof_x4_absorb(state,ext,MLKEM_SYMBYTES+2);
#endif
#if LC_KEM_DIRECT_STATE
        do {
            lc_kem_interleaved_permute(state->ctx);
            lc_kem_direct_state_rate4((int16_t (*)[256])(void*)(tile+i),count,state->ctx);
        } while(count[0]<MLKEM_N||count[1]<MLKEM_N||count[2]<MLKEM_N||count[3]<MLKEM_N);
#else
#if LC_KEM_MATRIX_INITIAL3
        /* Each dead 512-byte polynomial holds its first 504 XOF bytes.
         * Rejection writes to disjoint decoded scratch before copying back. */
        for(unsigned block=0;block<3;block++) {
#if LC_KEM_MATRIX_INTERLEAVED
            lc_kem_interleaved_permute(state->ctx);
            lc_kem_interleaved_extract((uint8_t*)(tile+i)+block*MLK_XOF_RATE,sizeof(mlk_poly),state->ctx);
#else
            mlk_keccakf1600x4_permute(state->ctx);
            mlk_keccakf1600x4_extract_bytes(state->ctx,
              (uint8_t*)(tile+i+0)+block*MLK_XOF_RATE,
              (uint8_t*)(tile+i+1)+block*MLK_XOF_RATE,
              (uint8_t*)(tile+i+2)+block*MLK_XOF_RATE,
              (uint8_t*)(tile+i+3)+block*MLK_XOF_RATE,0,MLK_XOF_RATE);
#endif
        }
        for(unsigned lane=0;lane<4;lane++) {
            count[lane]=lc_kem_reject_rate(work->sampling.decoded,0,(const uint8_t*)(tile+i+lane),3*MLK_XOF_RATE);
            mlk_memcpy((tile+i+lane)->coeffs,work->sampling.decoded,count[lane]*sizeof(int16_t));
        }
#endif
        while(count[0]<MLKEM_N||count[1]<MLKEM_N||count[2]<MLKEM_N||count[3]<MLKEM_N) {
#if LC_KEM_MATRIX_INTERLEAVED
            lc_kem_interleaved_permute(state->ctx);
            lc_kem_interleaved_extract(&work->sampling.rate[0][0],sizeof(work->sampling.rate[0]),state->ctx);
#else
            mlk_xof_x4_squeezeblocks(work->sampling.rate,1,state);
#endif
            for(unsigned lane=0;lane<4;lane++) {
#if LC_KEM_REJECT_DIRECT
                count[lane]=lc_kem_reject8((tile+i+lane)->coeffs,count[lane],work->sampling.rate[lane],MLK_XOF_RATE);
#else
#if LC_KEM_RATE_NATIVE_STAGE && defined(MLK_USE_NATIVE_REJ_UNIFORM)
                /* Upstream native rejection receives its full 256-coefficient
                 * destination. Only the public remaining prefix is appended. */
                int produced=mlk_rej_uniform_native(work->sampling.decoded,MLKEM_N,work->sampling.rate[lane],MLK_XOF_RATE);
                if(produced!=MLK_NATIVE_FUNC_FALLBACK) {
                    unsigned take=(unsigned)produced;
                    if(take>MLKEM_N-count[lane])take=MLKEM_N-count[lane];
                    mlk_memcpy((tile+i+lane)->coeffs+count[lane],work->sampling.decoded,take*sizeof(int16_t));
                    count[lane]+=take;
                } else
#endif
                count[lane]=lc_kem_reject_rate((tile+i+lane)->coeffs,count[lane],work->sampling.rate[lane],MLK_XOF_RATE);
#endif
            }
        }
#endif
        mlk_xof_x4_release(state);mlk_zeroize(state,sizeof(*state));mlk_zeroize(work->sampling.rate,sizeof(work->sampling.rate));
#endif
#else
        mlk_poly_rej_uniform_x4(tile+i,tile+i+1,tile+i+2,tile+i+3,ext);
#endif
#else
        mlk_poly_rej_uniform(tile+i,ext[0]);
#endif
    }
#if defined(MLK_USE_NATIVE_NTT_CUSTOM_ORDER)
    for(i=0;i<n;i++)mlk_poly_permute_bitrev_to_custom(tile[i].coeffs);
#endif
    mlk_zeroize(ext,sizeof ext);
}

#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#else
#include "lc_k3_linear.inc"
#ifndef LC_KEM_MIXED3_NOISE
#define LC_KEM_MIXED3_NOISE 0
#endif
#if LC_KEM_MIXED3_NOISE
_Static_assert(LC_KEM_LINEAR_K3 && LC_KEM_NOISE_INTERLEAVED && LC_KEM_NOISE_RAW,"Mixed PRF requires qualified raw interleaved path");
#endif
#include "lc_k3_mixed_noise.h"

#endif
MLK_INTERNAL_API
int mlk_indcpa_keypair_derand(uint8_t pk[MLKEM_INDCPA_PUBLICKEYBYTES],
 uint8_t sk[MLKEM_INDCPA_SECRETKEYBYTES],const uint8_t coins[32],MLK_CONFIG_CONTEXT_PARAMETER_TYPE context) {
    unsigned first,r,rows,i;int ret=0;
    MLK_ALLOC(buf,uint8_t,64,context);
    MLK_ALLOC(tile,mlk_poly,LC_TILE_POLYS,context);
    MLK_ALLOC(s,mlk_polyvec,1,context);
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#else
#if LC_KEM_MIXED3_NOISE && MLKEM_K==3
    MLK_ALLOC(mixed_tail,mlk_poly,1,context);
#endif
#endif
#if LC_KEM_TILE_BORROW
    MLK_ALLOC(cache_owner,lc_kem_cache_union,1,context);
#if LC_KEM_USE_RETAINED_CACHE
    MLK_ALLOC(retained_cache,mlk_polyvec_mulcache,1,context);
#endif
    MLK_ALLOC(work,lc_kem_work_union,1,context);
#if LC_KEM_COMPACT_NOISE4
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if !LC_KEM_KEYGEN_MIXED3
    MLK_ALLOC(epacked,uint8_t,MLKEM_K*LC_KEM_NOISE_BYTES,context);
#endif
#else
    MLK_ALLOC(epacked,uint8_t,MLKEM_K*LC_KEY_NOISE_BYTES,context);
#endif
#endif
#if LC_KEM_USE_RETAINED_CACHE
    mlk_polyvec_mulcache *cache=cache_owner?retained_cache:NULL;
#else
    mlk_polyvec_mulcache *cache=cache_owner?&cache_owner->product:NULL;
#endif
    mlk_poly *row=work?&work->polynomials.row:NULL;
#else
    MLK_ALLOC(cache,mlk_polyvec_mulcache,1,context);
    MLK_ALLOC(row,mlk_poly,1,context);
#endif
#if LC_KEM_NOISE_CACHE
    MLK_ALLOC(e,mlk_polyvec,1,context);
#elif LC_KEM_TILE_BORROW
    mlk_poly *e=work?&work->polynomials.temporary:NULL;
#else
    MLK_ALLOC(e,mlk_poly,1,context);
#endif
    if(!buf||!tile||!s||!cache||!row||!e
#if LC_KEM_COMPACT_NOISE4
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if !LC_KEM_KEYGEN_MIXED3
      ||!epacked
#endif
#else
      ||!epacked
#endif
#endif
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#else
#if LC_KEM_MIXED3_NOISE && MLKEM_K==3
      ||!mixed_tail
#endif
#endif
    ){ret=MLK_ERR_OUT_OF_MEMORY;goto cleanup;}
    /* FIPS 203 public dimension is appended to the input seed. */
    {uint8_t d[33];mlk_memcpy(d,coins,32);d[32]=MLKEM_K;mlk_hash_g(buf,d,33);mlk_zeroize(d,sizeof d);}
    MLK_CT_TESTING_DECLASSIFY(buf,32);
#if LC_KEM_COMPACT_NOISE4
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if LC_KEM_KEYGEN_MIXED3
    lc_kem_noise4_compact(&s->vec[0],&s->vec[1],&s->vec[2],&tile[0],buf+32,0,2,2,7,cache_owner);
#else
#if MLKEM_K == 2
    lc_kem_noise4_compact(&s->vec[0],&s->vec[1],&tile[0],&tile[1],buf+32,0,MLKEM_ETA1,MLKEM_ETA1,LC_KEM_NOISE_RAW?3:15,cache_owner);
#else
    lc_kem_noise4_compact(&s->vec[0],&s->vec[1],&s->vec[2],
#if MLKEM_K == 4
      &s->vec[3],
#else
      &tile[0],
#endif
      buf+32,0,MLKEM_ETA1,MLKEM_ETA1,15,cache_owner);
    lc_kem_noise4_compact(&tile[0],&tile[1],&tile[2],&tile[3],buf+32,MLKEM_K,MLKEM_ETA1,MLKEM_ETA1,LC_KEM_NOISE_RAW?0:15,cache_owner);
#endif
#if LC_KEM_NOISE_RAW
    for(i=0;i<MLKEM_K;i++)mlk_memcpy(epacked+LC_KEM_NOISE_BYTES*i,tile[i].coeffs,64*MLKEM_ETA1);
#else
    for(i=0;i<MLKEM_K;i++)lc_noise_pack3(epacked+96*i,tile[i].coeffs);
#endif
#endif /* original non-mixed ARM noise schedule */
#else
#if LC_KEM_MIXED3_NOISE && MLKEM_K==3
    lc_kem_noise4_compact(&s->vec[0],&s->vec[1],&s->vec[2],&tile[0],buf+32,0,2,2,7,cache_owner);
    mlk_memcpy(epacked,tile[0].coeffs,128);
    lc_k3_mixed_noise(mixed_tail,epacked,LC_KEY_NOISE_BYTES,0,buf,buf+32,cache_owner,work);
#else
#if MLKEM_K == 2
    lc_kem_noise4_compact(&s->vec[0],&s->vec[1],&tile[0],&tile[1],buf+32,0,MLKEM_ETA1,MLKEM_ETA1,LC_KEM_NOISE_RAW?3:15,cache_owner);
#else
    lc_kem_noise4_compact(&s->vec[0],&s->vec[1],&s->vec[2],
#if MLKEM_K == 4
      &s->vec[3],
#else
      &tile[0],
#endif
      buf+32,0,MLKEM_ETA1,MLKEM_ETA1,15,cache_owner);
    lc_kem_noise4_compact(&tile[0],&tile[1],&tile[2],&tile[3],buf+32,MLKEM_K,MLKEM_ETA1,MLKEM_ETA1,LC_KEM_NOISE_RAW?0:15,cache_owner);
#endif
#if LC_KEM_NOISE_RAW
    for(i=0;i<MLKEM_K;i++)mlk_memcpy(epacked+LC_KEY_NOISE_BYTES*i,tile[i].coeffs,64*MLKEM_ETA1);
#else
    for(i=0;i<MLKEM_K;i++)lc_noise_pack3(epacked+96*i,tile[i].coeffs);
#endif
#endif /* mixed rank3 / original compact noise */
#endif
#elif LC_KEM_NOISE_CACHE
    mlk_keypair_getnoise_eta1(s,e,buf+32);
#else
    for(i=0;i<MLKEM_K;i++)lc_kem_noise(&s->vec[i],buf+32,(uint8_t)i,MLKEM_ETA1);
#endif
    mlk_polyvec_ntt(s);
#if !LC_KEM_TILE_BORROW || LC_KEM_USE_RETAINED_CACHE
    mlk_polyvec_mulcache_compute(cache,s);
#endif
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
    for(first=0;first<MLKEM_K;first+=LC_KEM_ACTIVE_ROWS) {
        rows=MLKEM_K-first;if(rows>LC_KEM_ACTIVE_ROWS)rows=LC_KEM_ACTIVE_ROWS;
        lc_kem_tile(tile,buf,first,rows,0
#if LC_KEM_TILE_BORROW
            ,cache_owner,work,LC_KEM_KEYGEN_MIXED3?buf+32:NULL
#endif
        );
#if LC_KEM_TILE_BORROW && !LC_KEM_USE_RETAINED_CACHE
        mlk_polyvec_mulcache_compute(cache,s);
#endif
        for(r=0;r<rows;r++) {
            mlk_poly *error;
#if LC_KEM_COMPACT_NOISE4
            error=e;
#if LC_KEM_NOISE_RAW
#if defined(LC_KEM_NOISE_NEON) && LC_KEM_NOISE_NEON
#if LC_KEM_KEYGEN_MIXED3
            lc_cbd_neon(error->coeffs,(const uint8_t*)(tile+3),MLKEM_ETA1);
#else
            lc_cbd_neon(error->coeffs,epacked+LC_KEM_NOISE_BYTES*(first+r),MLKEM_ETA1);
#endif
#else
#if LC_KEM_KEYGEN_MIXED3
            mlk_poly_cbd2(error,(const uint8_t*)(tile+3));
#else
            if(MLKEM_ETA1==2)mlk_poly_cbd2(error,epacked+LC_KEM_NOISE_BYTES*(first+r));
            else mlk_poly_cbd3(error,epacked+LC_KEM_NOISE_BYTES*(first+r));
#endif
#endif
#else
            lc_noise_unpack3(error->coeffs,epacked+96*(first+r));
#endif
#elif LC_KEM_NOISE_CACHE
            error=&e->vec[first+r];
#else
            error=e;lc_kem_noise(error,buf+32,(uint8_t)(MLKEM_K+first+r),MLKEM_ETA1);
#endif
            mlk_poly_ntt(error);
            mlk_polyvec_basemul_acc_montgomery_cached(row,(const mlk_polyvec *)(tile+r*MLKEM_K),s,cache);
            mlk_poly_tomont(row);mlk_poly_add(row,error);mlk_poly_reduce(row);
            mlk_poly_tobytes(pk+(first+r)*MLKEM_POLYBYTES,row);
        }
    }
#else
#if LC_KEM_LINEAR_K3 && MLKEM_K==3
    (void)r;(void)rows;
    for(first=0;first<9;first+=4) {
        unsigned n=first==8?1:4;
#if LC_KEM_MIXED3_NOISE
        mlk_poly *active_tile=first==8?mixed_tail:tile;
        if(first<8)lc_k3_tile(tile,buf,first,0,cache_owner,work);
#else
        mlk_poly *active_tile=tile;
        lc_k3_tile(tile,buf,first,0,cache_owner,work);
#endif
        mlk_polyvec_mulcache_compute(cache,s);
        for(unsigned lane=0;lane<n;lane++) {
            unsigned index=first+lane,col=index%3;
            lc_k3_product(row->coeffs,active_tile[lane].coeffs,s->vec[col].coeffs,cache->vec[col].coeffs,col!=0);
            if(col==2) {
                lc_cbd2_avx2(e->coeffs,epacked+LC_KEY_NOISE_BYTES*(index/3));
                mlk_poly_ntt(e);mlk_poly_tomont(row);mlk_poly_add(row,e);mlk_poly_reduce(row);
                mlk_poly_tobytes(pk+(index/3)*MLKEM_POLYBYTES,row);
            }
        }
    }
#else
    for(first=0;first<MLKEM_K;first+=LC_KEM_ACTIVE_ROWS) {
        rows=MLKEM_K-first;if(rows>LC_KEM_ACTIVE_ROWS)rows=LC_KEM_ACTIVE_ROWS;
        lc_kem_tile(tile,buf,first,rows,0
#if LC_KEM_TILE_BORROW
            ,cache_owner,work
#endif
        );
#if LC_KEM_TILE_BORROW && !LC_KEM_USE_RETAINED_CACHE
        mlk_polyvec_mulcache_compute(cache,s);
#endif
        for(r=0;r<rows;r++) {
            mlk_poly *error;
#if LC_KEM_COMPACT_NOISE4
            error=e;
#if LC_KEM_NOISE_RAW
            if(MLKEM_ETA1==2)lc_cbd2_avx2(error->coeffs,epacked+LC_KEY_NOISE_BYTES*(first+r));
            else lc_cbd3_avx2(error->coeffs,epacked+LC_KEY_NOISE_BYTES*(first+r));
#else
            lc_noise_unpack3(error->coeffs,epacked+96*(first+r));
#endif
#elif LC_KEM_NOISE_CACHE
            error=&e->vec[first+r];
#else
            error=e;lc_kem_noise(error,buf+32,(uint8_t)(MLKEM_K+first+r),MLKEM_ETA1);
#endif
            mlk_poly_ntt(error);
            mlk_polyvec_basemul_acc_montgomery_cached(row,(const mlk_polyvec *)(tile+r*MLKEM_K),s,cache);
            mlk_poly_tomont(row);mlk_poly_add(row,error);mlk_poly_reduce(row);
            mlk_poly_tobytes(pk+(first+r)*MLKEM_POLYBYTES,row);
        }
    }
#endif
#endif
    mlk_polyvec_reduce(s);mlk_pack_sk(sk,s);mlk_memcpy(pk+MLKEM_POLYVECBYTES,buf,32);
cleanup:
#if LC_KEM_NOISE_CACHE
    MLK_FREE(e,mlk_polyvec,1,context);
#elif !LC_KEM_TILE_BORROW
    MLK_FREE(e,mlk_poly,1,context);
#endif
#if LC_KEM_TILE_BORROW
#if LC_KEM_COMPACT_NOISE4
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if !LC_KEM_KEYGEN_MIXED3
    MLK_FREE(epacked,uint8_t,MLKEM_K*LC_KEM_NOISE_BYTES,context);
#endif
#else
    MLK_FREE(epacked,uint8_t,MLKEM_K*LC_KEY_NOISE_BYTES,context);
#endif
#endif
    MLK_FREE(work,lc_kem_work_union,1,context);
#if LC_KEM_USE_RETAINED_CACHE
    MLK_FREE(retained_cache,mlk_polyvec_mulcache,1,context);
#endif
    MLK_FREE(cache_owner,lc_kem_cache_union,1,context);
#else
    MLK_FREE(row,mlk_poly,1,context);MLK_FREE(cache,mlk_polyvec_mulcache,1,context);
#endif
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#else
#if LC_KEM_MIXED3_NOISE && MLKEM_K==3
    MLK_FREE(mixed_tail,mlk_poly,1,context);
#endif
#endif
    MLK_FREE(s,mlk_polyvec,1,context);MLK_FREE(tile,mlk_poly,LC_TILE_POLYS,context);MLK_FREE(buf,uint8_t,64,context);
    return ret;
}

#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if LC_KEM_ARM_HJ_PREFIX
static MLK_NOINLINE
#if defined(__GNUC__) && !defined(__clang__)
__attribute__((noclone))
#endif
int MLK_ADD_PARAM_SET(lc_indcpa_enc_arm)(uint8_t c[MLKEM_INDCPA_BYTES],const uint8_t m[32],const uint8_t pk[MLKEM_INDCPA_PUBLICKEYBYTES],
 const uint8_t coins[32],MLK_CONFIG_CONTEXT_PARAMETER_TYPE context,const uint8_t *matrix_prefix) {
#else
MLK_INTERNAL_API
int mlk_indcpa_enc(uint8_t c[MLKEM_INDCPA_BYTES],const uint8_t m[32],const uint8_t pk[MLKEM_INDCPA_PUBLICKEYBYTES],
 const uint8_t coins[32],MLK_CONFIG_CONTEXT_PARAMETER_TYPE context) {
#endif
#else
#ifndef LC_KEM_DECAPS_TMP_REUSE
#define LC_KEM_DECAPS_TMP_REUSE 0
#endif
#if LC_KEM_DECAPS_TMP_REUSE
#if !LC_KEM_COMPACT_NOISE4 || !LC_KEM_NOISE_RAW
#error "Internal ciphertext scratch requires raw compact noise"
#endif
#define lc_indcpa_enc_impl MLK_ADD_PARAM_SET(lc_indcpa_enc_impl)
#define lc_indcpa_enc_internal_tmp MLK_ADD_PARAM_SET(lc_indcpa_enc_internal_tmp)
_Static_assert(LC_ENC_NOISE_BYTES<=MLKEM_POLYCOMPRESSEDBYTES_DU,"Each row contains its noise stream");
_Static_assert((LC_ENC_NOISE_COUNT-1)*MLKEM_POLYCOMPRESSEDBYTES_DU+LC_ENC_NOISE_BYTES<=MLKEM_INDCPA_BYTES,"Noise streams fit internal ciphertext");
#endif
#if LC_KEM_DECAPS_TMP_REUSE
static int lc_indcpa_enc_impl(uint8_t c[MLKEM_INDCPA_BYTES],const uint8_t m[32],const uint8_t pk[MLKEM_INDCPA_PUBLICKEYBYTES],
 const uint8_t coins[32],MLK_CONFIG_CONTEXT_PARAMETER_TYPE context,int reuse_internal_tmp
#if LC_KEM_HJ_PREFIX
 ,const uint8_t *matrix_prefix
#endif
#if LC_KEM_ENC_HYBRID
 ,uint8_t *derive_kr
#endif
 ) {
#else
MLK_INTERNAL_API
int mlk_indcpa_enc(uint8_t c[MLKEM_INDCPA_BYTES],const uint8_t m[32],const uint8_t pk[MLKEM_INDCPA_PUBLICKEYBYTES],
 const uint8_t coins[32],MLK_CONFIG_CONTEXT_PARAMETER_TYPE context) {
#endif
#endif
    unsigned first,r,rows,i;int ret=0;
    MLK_ALLOC(tile,mlk_poly,LC_TILE_POLYS,context);
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
    MLK_ALLOC(s,mlk_polyvec,1,context);
#else
#if LC_KEM_ENC_HYBRID
    MLK_ALLOC(s_owner,lc_kem_secret_union,1,context);
    mlk_polyvec *s=s_owner?&s_owner->secret:NULL;
#else
    MLK_ALLOC(s,mlk_polyvec,1,context);
#endif
#if LC_KEM_MIXED3_NOISE && MLKEM_K==3
    MLK_ALLOC(mixed_tail,mlk_poly,1,context);
#endif
#endif
#if LC_KEM_TILE_BORROW
    MLK_ALLOC(cache_owner,lc_kem_cache_union,1,context);
#if LC_KEM_USE_RETAINED_CACHE
    MLK_ALLOC(retained_cache,mlk_polyvec_mulcache,1,context);
#endif
    MLK_ALLOC(work,lc_kem_work_union,1,context);
#if LC_KEM_COMPACT_NOISE4
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
    MLK_ALLOC(epacked,uint8_t,MLKEM_K*LC_KEM_NOISE_BYTES,context);
#else
#if LC_KEM_DECAPS_TMP_REUSE
    uint8_t *epacked;
    const unsigned noise_stride=reuse_internal_tmp?MLKEM_POLYCOMPRESSEDBYTES_DU:LC_ENC_NOISE_BYTES;
    if(reuse_internal_tmp)epacked=c;
    else {MLK_ALLOC(allocated_noise,uint8_t,LC_ENC_NOISE_COUNT*LC_ENC_NOISE_BYTES,context);epacked=allocated_noise;}
#else
    MLK_ALLOC(epacked,uint8_t,LC_ENC_NOISE_COUNT*LC_ENC_NOISE_BYTES,context);
    const unsigned noise_stride=LC_ENC_NOISE_BYTES;
#endif
#endif
#endif
#if LC_KEM_USE_RETAINED_CACHE
    mlk_polyvec_mulcache *cache=cache_owner?retained_cache:NULL;
#else
    mlk_polyvec_mulcache *cache=cache_owner?&cache_owner->product:NULL;
#endif
    mlk_poly *row=work?&work->polynomials.row:NULL;
#else
    MLK_ALLOC(cache,mlk_polyvec_mulcache,1,context);
    MLK_ALLOC(row,mlk_poly,1,context);
#endif
#if LC_KEM_TILE_BORROW
    mlk_poly *temp=work?&work->polynomials.temporary:NULL;
#else
    MLK_ALLOC(temp,mlk_poly,1,context);
#endif
#if LC_KEM_NOISE_CACHE
    MLK_ALLOC(e,mlk_polyvec,1,context);
#endif
    if(!tile||!s||!cache||!row||!temp
#if LC_KEM_COMPACT_NOISE4
      ||!epacked
#endif
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#else
#if LC_KEM_MIXED3_NOISE && MLKEM_K==3
      ||!mixed_tail
#endif
#endif
#if LC_KEM_NOISE_CACHE
      ||!e
#endif
    ){ret=MLK_ERR_OUT_OF_MEMORY;goto cleanup;}
    MLK_CT_TESTING_DECLASSIFY(pk+MLKEM_POLYVECBYTES,32);
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#else
#if LC_KEM_ENC_HYBRID
    if(derive_kr) {
        lc_kem_enc_hybrid_scratch views={s_owner->hybrid_states,cache_owner->hybrid_aux,work->hybrid_decoded};
        lc_kem_enc_hybrid(derive_kr,(int16_t (*)[256])(void*)tile,pk,MLKEM_K,&views);
        mlk_memcpy(work->polynomials.row.coeffs,m,32);
        mlk_memcpy((uint8_t*)(void*)work->polynomials.row.coeffs+32,derive_kr,32);
        mlk_hash_g(derive_kr,(const uint8_t*)(const void*)work->polynomials.row.coeffs,64);
        mlk_zeroize(work->polynomials.row.coeffs,64);
        coins=derive_kr+32;
    }
#if MLKEM_K == 4
#define LC_ENC_NOISE_DEST(i) (derive_kr?(void*)work->enc_noise_raw[(i)]:(void*)&tile[(i)])
#else
#define LC_ENC_NOISE_DEST(i) (derive_kr?(void*)&work->enc_noise_poly[(i)]:(void*)&tile[(i)])
#endif
#else
#define LC_ENC_NOISE_DEST(i) ((void*)&tile[(i)])
#endif
#endif
#if LC_KEM_COMPACT_NOISE4
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if MLKEM_K == 2
    lc_kem_noise4_compact(&s->vec[0],&s->vec[1],&tile[0],&tile[1],coins,0,MLKEM_ETA1,MLKEM_ETA2,LC_KEM_NOISE_RAW?3:15,cache_owner);
#else
    lc_kem_noise4_compact(&s->vec[0],&s->vec[1],&s->vec[2],
#if MLKEM_K == 4
      &s->vec[3],
#else
      &tile[0],
#endif
      coins,0,MLKEM_ETA1,MLKEM_ETA1,15,cache_owner);
    lc_kem_noise4_compact(&tile[0],&tile[1],&tile[2],&tile[3],coins,MLKEM_K,MLKEM_ETA2,MLKEM_ETA2,LC_KEM_NOISE_RAW?0:15,cache_owner);
#endif
#if LC_KEM_NOISE_RAW
    for(i=0;i<MLKEM_K;i++)mlk_memcpy(epacked+LC_KEM_NOISE_BYTES*i,tile[i].coeffs,64*MLKEM_ETA2);
#else
    for(i=0;i<MLKEM_K;i++)lc_noise_pack3(epacked+96*i,tile[i].coeffs);
#endif
#else
#if LC_KEM_MIXED3_NOISE && MLKEM_K==3
    lc_kem_noise4_compact(&s->vec[0],&s->vec[1],&s->vec[2],LC_ENC_NOISE_DEST(0),coins,0,2,2,7,cache_owner);
    mlk_memcpy(epacked,LC_ENC_NOISE_DEST(0),128);
    lc_k3_mixed_noise(mixed_tail,epacked,noise_stride,1,pk+MLKEM_POLYVECBYTES,coins,cache_owner,work);
#else
#if MLKEM_K == 2
    lc_kem_noise4_compact(&s->vec[0],&s->vec[1],LC_ENC_NOISE_DEST(0),LC_ENC_NOISE_DEST(1),coins,0,MLKEM_ETA1,MLKEM_ETA2,LC_KEM_NOISE_RAW?3:15,cache_owner);
#else
    lc_kem_noise4_compact(&s->vec[0],&s->vec[1],&s->vec[2],
#if MLKEM_K == 4
      &s->vec[3],
#else
      LC_ENC_NOISE_DEST(0),
#endif
      coins,0,MLKEM_ETA1,MLKEM_ETA1,15,cache_owner);
    lc_kem_noise4_compact(LC_ENC_NOISE_DEST(0),LC_ENC_NOISE_DEST(1),LC_ENC_NOISE_DEST(2),LC_ENC_NOISE_DEST(3),coins,MLKEM_K,MLKEM_ETA2,MLKEM_ETA2,LC_KEM_NOISE_RAW?0:15,cache_owner);
#endif
#if LC_KEM_NOISE_RAW
    for(i=0;i<LC_ENC_NOISE_COUNT;i++)mlk_memcpy(epacked+noise_stride*i,LC_ENC_NOISE_DEST(i),64*MLKEM_ETA2);
#else
    for(i=0;i<MLKEM_K;i++)lc_noise_pack3(epacked+96*i,LC_ENC_NOISE_DEST(i));
#endif
#endif /* mixed rank3 / original compact noise */
#endif
#elif LC_KEM_NOISE_CACHE
    mlk_enc_getnoise_eta1_eta2(s,e,temp,coins);
#else
    for(i=0;i<MLKEM_K;i++)lc_kem_noise(&s->vec[i],coins,(uint8_t)i,MLKEM_ETA1);
#endif
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#else
#if LC_KEM_ENC_HYBRID
    if(derive_kr)mlk_zeroize(work,sizeof(*work));
#endif
#undef LC_ENC_NOISE_DEST
#endif
    mlk_polyvec_ntt(s);
#if !LC_KEM_TILE_BORROW || LC_KEM_USE_RETAINED_CACHE
    mlk_polyvec_mulcache_compute(cache,s);
#endif
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
    for(first=0;first<MLKEM_K;first+=LC_KEM_ACTIVE_ROWS) {
        rows=MLKEM_K-first;if(rows>LC_KEM_ACTIVE_ROWS)rows=LC_KEM_ACTIVE_ROWS;
#if LC_KEM_ARM_HJ_PREFIX
        if(matrix_prefix && first<LC_KEM_ARM_HJ_ROWS) {
            for(unsigned j=0;j<rows*MLKEM_K;++j) {
                mlk_poly_frombytes(&tile[j],matrix_prefix+384*(first*MLKEM_K+j));
            }
        } else
#endif
        lc_kem_tile(tile,pk+MLKEM_POLYVECBYTES,first,rows,1
#if LC_KEM_TILE_BORROW
            ,cache_owner,work,NULL
#endif
        );
#if LC_KEM_TILE_BORROW && !LC_KEM_USE_RETAINED_CACHE
        mlk_polyvec_mulcache_compute(cache,s);
#endif
        for(r=0;r<rows;r++) {
            mlk_polyvec_basemul_acc_montgomery_cached(row,(const mlk_polyvec *)(tile+r*MLKEM_K),s,cache);
            mlk_poly_invntt_tomont(row);
#if LC_KEM_COMPACT_NOISE4
#if LC_KEM_NOISE_RAW
#if defined(LC_KEM_NOISE_NEON) && LC_KEM_NOISE_NEON
            lc_cbd_neon(temp->coeffs,epacked+LC_KEM_NOISE_BYTES*(first+r),2);
#else
            mlk_poly_cbd2(temp,epacked+LC_KEM_NOISE_BYTES*(first+r));
#endif
#else
            lc_noise_unpack3(temp->coeffs,epacked+96*(first+r));
#endif
            mlk_poly_add(row,temp);
#elif LC_KEM_NOISE_CACHE
            mlk_poly_add(row,&e->vec[first+r]);
#else
            lc_kem_noise(temp,coins,(uint8_t)(MLKEM_K+first+r),MLKEM_ETA2);mlk_poly_add(row,temp);
#endif
            mlk_poly_reduce(row);mlk_poly_compress_du(c+(first+r)*MLKEM_POLYCOMPRESSEDBYTES_DU,row);
        }
    }
#else
#if LC_KEM_LINEAR_K3 && MLKEM_K==3
    (void)r;(void)rows;
    for(first=0;first<9;first+=4) {
        unsigned n=first==8?1:4;
#if LC_KEM_MIXED3_NOISE
        mlk_poly *active_tile=first==8?mixed_tail:tile;
#if LC_KEM_ENC_HYBRID
        if(first==0 && derive_kr) { /* Current tile already contains the four public polynomials. */ } else
#endif
#if LC_KEM_HJ_PREFIX
        if(first==0 && matrix_prefix) {
            for(unsigned lane=0;lane<4;lane++)mlk_poly_frombytes(tile+lane,matrix_prefix+384*lane);
        } else
#endif
        if(first<8)lc_k3_tile(tile,pk+MLKEM_POLYVECBYTES,first,1,cache_owner,work);
#else
        mlk_poly *active_tile=tile;
        lc_k3_tile(tile,pk+MLKEM_POLYVECBYTES,first,1,cache_owner,work);
#endif
        mlk_polyvec_mulcache_compute(cache,s);
        for(unsigned lane=0;lane<n;lane++) {
            unsigned index=first+lane,col=index%3;
            lc_k3_product(row->coeffs,active_tile[lane].coeffs,s->vec[col].coeffs,cache->vec[col].coeffs,col!=0);
            if(col==2) {
                mlk_poly_invntt_tomont(row);
                lc_cbd2_avx2(temp->coeffs,epacked+noise_stride*(index/3));
                mlk_poly_add(row,temp);mlk_poly_reduce(row);
                mlk_poly_compress_du(c+(index/3)*MLKEM_POLYCOMPRESSEDBYTES_DU,row);
            }
        }
    }
#else
    for(first=0;first<MLKEM_K;first+=LC_KEM_ACTIVE_ROWS) {
        rows=MLKEM_K-first;if(rows>LC_KEM_ACTIVE_ROWS)rows=LC_KEM_ACTIVE_ROWS;
#if LC_KEM_ENC_HYBRID
        if(first==0 && derive_kr) { /* Current tile already contains the four public polynomials. */ } else
#endif
#if LC_KEM_HJ_PREFIX
        if(first==0 && matrix_prefix) {
            for(unsigned lane=0;lane<4;lane++)mlk_poly_frombytes(tile+lane,matrix_prefix+384*lane);
        } else
#endif
        lc_kem_tile(tile,pk+MLKEM_POLYVECBYTES,first,rows,1
#if LC_KEM_TILE_BORROW
            ,cache_owner,work
#endif
        );
#if LC_KEM_TILE_BORROW && !LC_KEM_USE_RETAINED_CACHE
        mlk_polyvec_mulcache_compute(cache,s);
#endif
        for(r=0;r<rows;r++) {
            mlk_polyvec_basemul_acc_montgomery_cached(row,(const mlk_polyvec *)(tile+r*MLKEM_K),s,cache);
            mlk_poly_invntt_tomont(row);
#if LC_KEM_COMPACT_NOISE4
#if LC_KEM_NOISE_RAW
            lc_cbd2_avx2(temp->coeffs,epacked+noise_stride*(first+r));
#else
            lc_noise_unpack3(temp->coeffs,epacked+96*(first+r));
#endif
            mlk_poly_add(row,temp);
#elif LC_KEM_NOISE_CACHE
            mlk_poly_add(row,&e->vec[first+r]);
#else
            lc_kem_noise(temp,coins,(uint8_t)(MLKEM_K+first+r),MLKEM_ETA2);mlk_poly_add(row,temp);
#endif
            mlk_poly_reduce(row);mlk_poly_compress_du(c+(first+r)*MLKEM_POLYCOMPRESSEDBYTES_DU,row);
        }
    }
#endif
#endif
    /* The public matrix tile is dead; reuse it for decoding the public key. */
    mlk_polyvec_frombytes((mlk_polyvec *)tile,pk);
    mlk_polyvec_basemul_acc_montgomery_cached(row,(const mlk_polyvec *)tile,s,cache);
    mlk_poly_invntt_tomont(row);
#if !LC_KEM_NOISE_CACHE
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
    lc_kem_noise(temp,coins,(uint8_t)(2*MLKEM_K),MLKEM_ETA2);
#else
#if LC_KEM_NOISE_REUSE_E2 && MLKEM_K==3
    lc_cbd2_avx2(temp->coeffs,epacked+MLKEM_K*noise_stride);
#else
    lc_kem_noise(temp,coins,(uint8_t)(2*MLKEM_K),MLKEM_ETA2);
#endif
#endif
#endif
    mlk_poly_add(row,temp);
    /* The noise temporary is dead after its addition. */
    mlk_poly_frommsg(temp,m);mlk_poly_add(row,temp);mlk_poly_reduce(row);
    mlk_poly_compress_dv(c+MLKEM_POLYVECCOMPRESSEDBYTES_DU,row);
cleanup:
#if LC_KEM_NOISE_CACHE
    MLK_FREE(e,mlk_polyvec,1,context);
#endif
#if LC_KEM_TILE_BORROW
#if LC_KEM_COMPACT_NOISE4
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
    MLK_FREE(epacked,uint8_t,MLKEM_K*LC_KEM_NOISE_BYTES,context);
#else
#if LC_KEM_DECAPS_TMP_REUSE
    if(!reuse_internal_tmp){MLK_FREE(epacked,uint8_t,LC_ENC_NOISE_COUNT*LC_ENC_NOISE_BYTES,context);}
#else
    MLK_FREE(epacked,uint8_t,LC_ENC_NOISE_COUNT*LC_ENC_NOISE_BYTES,context);
#endif
#endif
#endif
    MLK_FREE(work,lc_kem_work_union,1,context);
#if LC_KEM_USE_RETAINED_CACHE
    MLK_FREE(retained_cache,mlk_polyvec_mulcache,1,context);
#endif
    MLK_FREE(cache_owner,lc_kem_cache_union,1,context);
#else
    MLK_FREE(temp,mlk_poly,1,context);MLK_FREE(row,mlk_poly,1,context);
    MLK_FREE(cache,mlk_polyvec_mulcache,1,context);
#endif
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
    MLK_FREE(s,mlk_polyvec,1,context);
#else
#if LC_KEM_MIXED3_NOISE && MLKEM_K==3
    MLK_FREE(mixed_tail,mlk_poly,1,context);
#endif
#if LC_KEM_ENC_HYBRID
    MLK_FREE(s_owner,lc_kem_secret_union,1,context);
#else
    MLK_FREE(s,mlk_polyvec,1,context);
#endif
#endif
    MLK_FREE(tile,mlk_poly,LC_TILE_POLYS,context);return ret;
}
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#if LC_KEM_ARM_HJ_PREFIX
MLK_INTERNAL_API
int mlk_indcpa_enc(uint8_t c[MLKEM_INDCPA_BYTES],const uint8_t m[32],const uint8_t pk[MLKEM_INDCPA_PUBLICKEYBYTES],
 const uint8_t coins[32],MLK_CONFIG_CONTEXT_PARAMETER_TYPE context) {
 return MLK_ADD_PARAM_SET(lc_indcpa_enc_arm)(c,m,pk,coins,context,NULL);
}
#endif
#else
#if LC_KEM_DECAPS_TMP_REUSE
MLK_INTERNAL_API
int mlk_indcpa_enc(uint8_t c[MLKEM_INDCPA_BYTES],const uint8_t m[32],const uint8_t pk[MLKEM_INDCPA_PUBLICKEYBYTES],
 const uint8_t coins[32],MLK_CONFIG_CONTEXT_PARAMETER_TYPE context) {
 return lc_indcpa_enc_impl(c,m,pk,coins,context,0
#if LC_KEM_HJ_PREFIX
 ,NULL
#endif
#if LC_KEM_ENC_HYBRID
 ,NULL
#endif
 );
}
/* Only kem.c decapsulation calls this static SCU-private entry, with its
 * own already-allocated temporary ciphertext. Caller ciphertext never enters. */
static int lc_indcpa_enc_internal_tmp(uint8_t c[MLKEM_INDCPA_BYTES],const uint8_t m[32],const uint8_t pk[MLKEM_INDCPA_PUBLICKEYBYTES],
 const uint8_t coins[32],MLK_CONFIG_CONTEXT_PARAMETER_TYPE context) {
 return lc_indcpa_enc_impl(c,m,pk,coins,context,1
#if LC_KEM_HJ_PREFIX
 ,NULL
#endif
#if LC_KEM_ENC_HYBRID
 ,NULL
#endif
 );
}
#if LC_KEM_HJ_PREFIX
/* The prefix and cachedJ are owned by decapsulation. K4 temporarily stores
 * its prefix in the internal ciphertext and keeps noise in its own allocation. */
static int MLK_ADD_PARAM_SET(lc_indcpa_enc_hj_tmp)(uint8_t c[MLKEM_INDCPA_BYTES],
 const uint8_t m[32],const uint8_t pk[MLKEM_INDCPA_PUBLICKEYBYTES],const uint8_t coins[32],
 MLK_CONFIG_CONTEXT_PARAMETER_TYPE context,const uint8_t prefix[1536]) {
 return lc_indcpa_enc_impl(c,m,pk,coins,context,MLKEM_K!=4,prefix
#if LC_KEM_ENC_HYBRID
 ,NULL
#endif
 );
}
#endif
#if LC_KEM_ENC_HYBRID
static int MLK_ADD_PARAM_SET(lc_indcpa_enc_hybrid)(uint8_t *c,const uint8_t m[32],
 const uint8_t *pk,uint8_t kr[64],MLK_CONFIG_CONTEXT_PARAMETER_TYPE context) {
 return lc_indcpa_enc_impl(c,m,pk,kr+32,context,0,NULL,kr);
}
#endif
#undef lc_indcpa_enc_impl
#undef lc_indcpa_enc_internal_tmp
#endif

#endif
#undef LC_TILE_POLYS
#undef lc_kem_tile
#undef lc_kem_noise

#if LC_KEM_TILE_BORROW
#undef lc_kem_cache_union
#undef lc_kem_work_union
#undef lc_kem_reject_rate
#endif

#if LC_KEM_COMPACT_NOISE4
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#undef LC_KEM_NOISE_BYTES
#else
#endif
#undef lc_kem_noise4_compact
#endif

#undef LC_KEM_ACTIVE_ROWS
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#else

#if LC_KEM_COMPACT_NOISE4
#undef LC_KEY_NOISE_BYTES
#undef LC_ENC_NOISE_BYTES
#undef LC_ENC_NOISE_COUNT
#endif

#if LC_KEM_ENC_HYBRID
#undef lc_kem_secret_union
#endif
#endif

#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
#undef LC_KEM_KEYGEN_MIXED3
#endif

#undef LC_KEM_USE_RETAINED_CACHE
