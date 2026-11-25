/* Copyright (c) 2026 A1-27 project authors
 * SPDX-License-Identifier: Apache-2.0
 * Rank-three PRF nonces4/5/6 and public A[2][2] share one permutation.
 * Output streams retain their independent SHAKE256/128 domain and rate.
 */
#if LC_KEM_MIXED3_NOISE && MLKEM_K==3
static void lc_k3_mixed_noise(mlk_poly *tail,uint8_t *noise,unsigned stride,
    unsigned keep_third,const uint8_t public_seed[32],const uint8_t secret_seed[32],
    lc_kem_cache_union *owner,lc_kem_work_union *work) {
    uint64_t *state=owner->xof.ctx;
    mlk_memset(state,0,800);
    for(unsigned word=0;word<4;word++) {
        uint64_t pub,sec;mlk_memcpy(&pub,public_seed+8*word,8);mlk_memcpy(&sec,secret_seed+8*word,8);
        for(unsigned lane=0;lane<3;lane++)state[4*word+lane]=sec;
        state[4*word+3]=pub;
    }
    for(unsigned lane=0;lane<3;lane++) {
        state[16+lane]=(uint64_t)(4+lane)|((uint64_t)0x1f<<8);
        state[44+lane]=(uint64_t)0x80<<56;
    }
    state[19]=UINT64_C(0x1f0202);state[59]=UINT64_C(0x80)<<56;
    lc_kem_interleaved_permute(state);
    for(unsigned lane=0;lane<2+keep_third;lane++)
        for(unsigned word=0;word<16;word++)
            mlk_memcpy(noise+stride*(lane+1)+8*word,state+4*lc_kem_word_to_slot[word]+lane,8);
    /* Every future source index 4*slot[word]+3 exceeds word. Forward
     * copying the public lane to the same owner's first25 words is safe.
     * All private lanes have already completed their last read. */
    for(unsigned word=0;word<25;word++)state[word]=state[4*lc_kem_word_to_slot[word]+3];
    mlk_memcpy(tail,owner->single.ctx,168);
    mlk_xof_squeezeblocks((uint8_t*)tail+168,2,&owner->single);
    unsigned count=0;lc_k3_append(tail,&count,work,(const uint8_t*)tail,504);
    while(count<256) {
        mlk_xof_squeezeblocks(work->linear.rate,1,&owner->single);
        lc_k3_append(tail,&count,work,work->linear.rate,168);
    }
    mlk_poly_permute_bitrev_to_custom(tail->coeffs);
    mlk_zeroize(owner,sizeof(*owner));
    mlk_zeroize(work->linear.rate,sizeof work->linear.rate);
    mlk_zeroize(work->linear.decoded,sizeof work->linear.decoded);
}
#endif
