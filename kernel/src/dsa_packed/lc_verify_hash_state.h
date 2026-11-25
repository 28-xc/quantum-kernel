/* Copyright (c) 2026 A1-27 project authors
 * SPDX-License-Identifier: Apache-2.0
 * ML-DSA-65 public matrix streams share their fourth lane with H(pk), then mu.
 * Two encoded rows bound the deferral for arbitrary public message lengths. */
#ifndef LC_VERIFY_HASH3_STATE_H
#define LC_VERIFY_HASH3_STATE_H
#ifndef LC_VERIFY_HASH3_RATE_HOOK
#define LC_VERIFY_HASH3_RATE_HOOK(rate,index,round) ((void)0)
#endif
#ifndef LC_VERIFY_HASH3_MU_HOOK
#define LC_VERIFY_HASH3_MU_HOOK(mu) ((void)0)
#endif
typedef struct {
 const uint8_t *input[4],*message,*prefix,*prefix1;
 size_t left[4],message_length,prefix_length,prefix1_length;
 uint8_t *mu;
 unsigned segment,phase,final,done;
} lc_verify_hash3_state;

static void lc_vh_start(lc_verify_hash3_state *s,mld_shake256ctx *saved,
 uint8_t mu[64],const uint8_t *pk,const uint8_t *prefix,size_t prefix_length,
 const uint8_t *prefix1,size_t prefix1_length,
 const uint8_t *message,size_t message_length) {
 mld_memset(s,0,sizeof(*s));mld_memset(saved,0,sizeof(*saved));
 s->input[0]=pk;s->left[0]=MLDSA_CRYPTO_PUBLICKEYBYTES;s->mu=mu;
 s->prefix=prefix;s->prefix_length=prefix_length;
 s->prefix1=prefix1;s->prefix1_length=prefix1_length;
 s->message=message;s->message_length=message_length;
}
/* Every length is decremented independently; no concatenated size_t sum. */
static void lc_vh_block(lc_verify_hash3_state *s,uint8_t rate[136]) {
 size_t used=0;mld_memset(rate,0,136);
 while(used<136 && s->segment<4) {
  unsigned i=s->segment;size_t take=s->left[i];
  if(take>136-used)take=136-used;
  if(take){mld_memcpy(rate+used,s->input[i],take);s->input[i]+=take;s->left[i]-=take;used+=take;}
  if(s->left[i]==0)s->segment++;
 }
 s->final=(unsigned)(used<136);
 if(s->final){rate[used]^=0x1f;rate[135]^=0x80;}
}
static unsigned lc_vh_slot(unsigned word,unsigned interleaved) {
#if defined(LC_BUILD_ARM_PROFILE) && LC_BUILD_ARM_PROFILE
 return interleaved?75+word:word;
#else
 return interleaved?4*lc_matrix_word_to_slot[word]+3:word;
#endif
}
static void lc_vh_after(lc_verify_hash3_state *s,uint64_t *state,unsigned interleaved) {
 if(!s->final)return;
 for(unsigned word=0;word<8;word++)mld_memcpy(s->mu+8*word,state+lc_vh_slot(word,interleaved),8);
 if(s->phase==0) {
  for(unsigned word=0;word<25;word++)state[lc_vh_slot(word,interleaved)]=0;
  s->phase=1;s->segment=0;s->final=0;
  s->input[0]=s->mu;s->left[0]=64;
  s->input[1]=s->prefix;s->left[1]=s->prefix_length;
  s->input[2]=s->prefix1;s->left[2]=s->prefix1_length;
  s->input[3]=s->message;s->left[3]=s->message_length;
 } else {s->done=1;LC_VERIFY_HASH3_MU_HOOK(s->mu);}
}
static void lc_vh_finish(lc_verify_hash3_state *s,mld_shake256ctx *saved,mld_polymat *mat) {
 while(!s->done) {
  lc_vh_block(s,mat->stream4.rate);
  for(unsigned word=0;word<17;word++){uint64_t x;mld_memcpy(&x,mat->stream4.rate+8*word,8);saved->s[word]^=x;}
  mld_keccakf1600_permute(saved->s);lc_vh_after(s,saved->s,0);
 }
 mld_zeroize(saved,sizeof(*saved));mld_zeroize(&mat->stream4,sizeof(mat->stream4));
}
#endif
