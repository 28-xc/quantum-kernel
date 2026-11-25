/* Ordinary fixed-input checks of the actual source helpers in one SCU.
 * No feedback-guided input generation, external targets or core edits. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
void *lc_dsa_alloc(struct lc_dsa_arena *a,size_t n){(void)a;(void)n;abort();}
void lc_dsa_free(struct lc_dsa_arena *a,void *p,size_t n){(void)a;(void)p;(void)n;abort();}
int lc_dsa_system_random(uint8_t *p,size_t n){(void)p;(void)n;abort();}
#define CHECK(x) do{if(!(x)){fprintf(stderr,"check:%u:%s\n",__LINE__,#x);return 1;}}while(0)
static uint32_t bitmap_rng=0x20260925u;
static uint32_t draw(void){bitmap_rng^=bitmap_rng<<13;bitmap_rng^=bitmap_rng>>17;bitmap_rng^=bitmap_rng<<5;return bitmap_rng;}
static int32_t canonical(int64_t x){int32_t r=(int32_t)(x%MLDSA_Q);return r<0?r+MLDSA_Q:r;}
/* Division-based specification; independent of native reciprocal arithmetic. */
static int32_t high_ref(int32_t x,int32_t *low){
  int32_t a=canonical(x),v=a%(2*MLDSA_GAMMA2);
  if(v>MLDSA_GAMMA2)v-=2*MLDSA_GAMMA2;
  if(a-v==MLDSA_Q-1){*low=v-1;return 0;}
  *low=v;return (a-v)/(2*MLDSA_GAMMA2);
}
static unsigned hint_formula(int32_t low,int32_t high){return low>MLDSA_GAMMA2||low< -MLDSA_GAMMA2||(low== -MLDSA_GAMMA2&&high!=0);}
static unsigned fips_hint(int32_t z,int32_t r){int32_t ignored;return high_ref(canonical(r),&ignored)!=high_ref(canonical((int64_t)r+z),&ignored);}
static void high_pack_ref(uint8_t *out,const mld_poly *h){
  unsigned bits=MLD_CONFIG_PARAMETER_SET==44?6:4;memset(out,0,MLDSA_POLYW1_PACKEDBYTES);
  for(unsigned i=0;i<256;i++)for(unsigned j=0;j<bits;j++)out[(i*bits+j)/8]|=(uint8_t)((((uint32_t)h->coeffs[i]>>j)&1u)<<((i*bits+j)%8));
}
static unsigned retained(const lc_sign_w0_storage *s,unsigned k,unsigned j){
#if LC_DSA_RETAIN_FULL_HIGH
  unsigned bits=MLD_CONFIG_PARAMETER_SET==44?6:4,pos=j*bits,value=0;
  for(unsigned b=0;b<bits;b++)value|=((s->high_encoded[k][(pos+b)/8]>>((pos+b)%8))&1u)<<b;
  return value;
#else
  const uint8_t *p=(const uint8_t*)s+k*LC_W0_FLAG_STRIDE+LC_W0_ROW_BYTES;
  return (p[j/8]>>(j%8))&1u;
#endif
}
static void set_high(lc_sign_w0_storage *s,unsigned k,const mld_poly *high){
#if LC_DSA_RETAIN_FULL_HIGH
  high_pack_ref(s->high_encoded[k],high);
#else
  uint8_t *p=(uint8_t*)s+k*LC_W0_FLAG_STRIDE+LC_W0_ROW_BYTES;memset(p,0,32);
  for(unsigned j=0;j<256;j++)p[j/8]|=(uint8_t)((high->coeffs[j]!=0)<<(j%8));
#endif
}
int main(void){
  const int32_t maxlow=2*MLDSA_GAMMA2-MLDSA_BETA-2;
  const int32_t endpoint[]={-maxlow,-MLDSA_GAMMA2-1,-MLDSA_GAMMA2,-MLDSA_GAMMA2+1,-1,0,1,MLDSA_GAMMA2-1,MLDSA_GAMMA2,MLDSA_GAMMA2+1,maxlow};
  const unsigned high_count=(MLDSA_Q-1)/(2*MLDSA_GAMMA2);
  uint64_t hints=0,fips_cases=0,codec_values=0;unsigned positive=0;
  static struct{uint8_t pre[32];lc_sign_w0_storage data;uint8_t post[32];} guarded;
  static mld_polyveck original,expected_low,expected_high;
  mld_poly low,high,saved,unpacked;uint8_t packed[768],challenge[MLDSA_CTILDEBYTES],want[MLDSA_CTILDEBYTES];
  uint8_t transcript[MLDSA_CRHBYTES+MLDSA_K*MLDSA_POLYW1_PACKEDBYTES];
  uint8_t signature[MLDSA_CRYPTO_BYTES],signature_ref[MLDSA_CRYPTO_BYTES];
  CHECK(maxlow < (1<<(LC_W0_BITS-1)));
  for(unsigned h=0;h<high_count;h++)for(unsigned i=0;i<sizeof(endpoint)/sizeof(*endpoint);i++){
    unsigned a=mld_make_hint(endpoint[i],(int32_t)h),b=mld_make_hint(endpoint[i],h!=0);
    CHECK(a==b&&a==hint_formula(endpoint[i],(int32_t)h)&&a<=1);hints++;
  }
  /* Bounds and the exact -gamma2/high==0 border distinguish this predicate. */
  CHECK(!mld_make_hint(-MLDSA_GAMMA2,0)&&mld_make_hint(-MLDSA_GAMMA2,1));positive++;
  CHECK(!fips_hint(0,2*MLDSA_GAMMA2+MLDSA_GAMMA2+1)&&mld_make_hint(MLDSA_GAMMA2+1,1));positive++;
  for(unsigned i=0;i<16384;i++){
    int32_t w=(int32_t)(draw()%MLDSA_Q),w0,w1=high_ref(w,&w0);
    int32_t cs=(int32_t)(draw()%(2*MLDSA_BETA+1))-MLDSA_BETA;
    int32_t ct=(int32_t)(draw()%(2*MLDSA_GAMMA2-1))-(MLDSA_GAMMA2-1),r0=w0-cs;
    if(r0<=-MLDSA_GAMMA2+MLDSA_BETA||r0>=MLDSA_GAMMA2-MLDSA_BETA)continue;
    CHECK(mld_make_hint(r0+ct,w1)==fips_hint(-ct,canonical((int64_t)w-cs+ct)));fips_cases++;
  }
  /* Signed low storage after BOTH strict norm tests, not just Decompose. */
  for(unsigned trial=0;trial<128;trial++){
    for(unsigned j=0;j<256;j++)low.coeffs[j]=trial==0?endpoint[j%(sizeof(endpoint)/sizeof(*endpoint))]:(int32_t)(draw()%(2*maxlow+1))-maxlow;
    lc_pack_w0_row(packed,&low);lc_unpack_w0_row(&unpacked,packed);CHECK(!memcmp(&unpacked,&low,sizeof low));
    saved=low;lc_pack_w0_row((uint8_t*)&saved,&saved);CHECK(!memcmp(&saved,packed,LC_W0_ROW_BYTES));codec_values+=256;
  }
  low.coeffs[0]=1<<(LC_W0_BITS-1);lc_pack_w0_row(packed,&low);lc_unpack_w0_row(&unpacked,packed);CHECK(unpacked.coeffs[0]!=low.coeffs[0]);positive++;
  /* Full HighBits must reach the hash before its predicate is retained. */
  for(unsigned trial=0;trial<64;trial++){
    memset(&guarded,0xa5,sizeof guarded);
    for(unsigned j=0;j<MLDSA_CRHBYTES;j++)transcript[j]=(uint8_t)draw();
    for(unsigned k=0;k<MLDSA_K;k++)for(unsigned j=0;j<256;j++){
      int32_t v=(int32_t)(draw()%MLDSA_Q);
      if(trial==0){const int32_t edge[]={0,1,MLDSA_Q-1,MLDSA_Q-MLDSA_GAMMA2,MLDSA_GAMMA2,MLDSA_GAMMA2+1};v=edge[j%6];}
      original.vec[k].coeffs[j]=v;expected_high.vec[k].coeffs[j]=high_ref(v,&expected_low.vec[k].coeffs[j]);
    }
    for(unsigned k=0;k<MLDSA_K;k++)high_pack_ref(transcript+MLDSA_CRHBYTES+k*MLDSA_POLYW1_PACKEDBYTES,&expected_high.vec[k]);
    mld_shake256(want,sizeof want,transcript,sizeof transcript);guarded.data.full=original;
    lc_sign_decompose_hash_bitmap(challenge,transcript,&guarded.data,&saved,&high);CHECK(!memcmp(challenge,want,sizeof want));
    for(unsigned k=0;k<MLDSA_K;k++){
      lc_unpack_w0_row(&unpacked,(uint8_t*)&guarded.data+k*LC_W0_FLAG_STRIDE);CHECK(!memcmp(&unpacked,&expected_low.vec[k],sizeof unpacked));
      for(unsigned j=0;j<256;j++)CHECK(retained(&guarded.data,k,j)==(LC_DSA_RETAIN_FULL_HIGH?(unsigned)expected_high.vec[k].coeffs[j]:(unsigned)(expected_high.vec[k].coeffs[j]!=0)));
    }
    for(unsigned j=0;j<32;j++)CHECK(guarded.pre[j]==0xa5&&guarded.post[j]==0xa5);
  }
  for(unsigned j=0;j<256;j++)high.coeffs[j]=2;
  high_pack_ref(packed,&high);for(unsigned j=0;j<256;j++)high.coeffs[j]=1;
  high_pack_ref(transcript,&high);CHECK(memcmp(packed,transcript,MLDSA_POLYW1_PACKEDBYTES)!=0);positive++;
  /* Same sorted hint encoding and exact omega rejection boundary. */
  for(unsigned trial=0;trial<5;trial++){
    const unsigned target=trial==0?0:trial==1?MLDSA_OMEGA-1:trial==2?MLDSA_OMEGA:trial==3?MLDSA_OMEGA+1:MLDSA_K*256;
    unsigned count=0;memset(&guarded.data,0,sizeof guarded.data);memset(signature,0xa5,sizeof signature);memcpy(signature_ref,signature,sizeof signature);
    uint8_t *hbytes=signature_ref+MLDSA_SIG_H_OFFSET;memset(hbytes,0,MLDSA_POLYVECH_PACKEDBYTES);
    for(unsigned k=0;k<MLDSA_K;k++){
      for(unsigned j=0;j<256;j++){
        high.coeffs[j]=(int32_t)((j+k)%high_count);low.coeffs[j]=(k*256+j<target)?MLDSA_GAMMA2+1:0;
        if(k*256+j<target&&count<MLDSA_OMEGA)hbytes[count++]=(uint8_t)j;
      }
      hbytes[MLDSA_OMEGA+k]=(uint8_t)count;lc_pack_w0_row((uint8_t*)&guarded.data+k*LC_W0_FLAG_STRIDE,&low);set_high(&guarded.data,k,&high);
    }
    int rc=lc_pack_sig_h_bitmap(signature,(const uint8_t*)&guarded.data,&unpacked);
    CHECK((target<=MLDSA_OMEGA&&rc==0)||(target>MLDSA_OMEGA&&rc==MLD_ERR_FAIL));
    if(rc==0)CHECK(!memcmp(signature,signature_ref,sizeof signature));
    CHECK(!memcmp(signature,signature_ref,MLDSA_SIG_H_OFFSET));
  }
  printf("{\"status\":\"PASS\",\"parameter\":%d,\"codec\":%d,\"full_high\":%d,\"seed\":\"20260925\",\"low_bits\":%d,\"max_abs_post_norm_low\":%d,\"hint_endpoints\":%"PRIu64",\"fips_accepted_fixed_cases\":%"PRIu64",\"low_roundtrip_coefficients\":%"PRIu64",\"full_hash_storage_cases\":64,\"hint_weight_cases\":5,\"scope_counterexamples_detected\":%u}\n",MLD_CONFIG_PARAMETER_SET,LC_DSA_W0_CODEC,LC_DSA_RETAIN_FULL_HIGH,LC_W0_BITS,maxlow,hints,fips_cases,codec_values,positive);
  return 0;
}
