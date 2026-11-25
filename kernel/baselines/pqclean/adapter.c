/* Benchmark adapter for the unchanged, individually licensed PQClean sources.
 * Public ABI and object validation follow this project's src/common/public_api.c.
 * This is a third-party comparison, not an arena-backed deployment backend.
 * PQClean's original malloc/free, automatic arrays and allocation-failure exit
 * remain part of its behavior. See README.md for the precise comparison scope.
 */
#include "latticecore.h"
#include "lc_platform.h"
#include "fips202.h"
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>
#include "upstream/crypto_kem/ml-kem-512/clean/api.h"
#include "upstream/crypto_kem/ml-kem-768/clean/api.h"
#include "upstream/crypto_kem/ml-kem-1024/clean/api.h"
#include "upstream/crypto_sign/ml-dsa-44/clean/api.h"
#include "upstream/crypto_sign/ml-dsa-65/clean/api.h"
#include "upstream/crypto_sign/ml-dsa-87/clean/api.h"

typedef struct {const void *p;size_t n;} region;
typedef struct entropy_frame {jmp_buf escape;const uint8_t *bytes;size_t length,used;} entropy_frame;
static _Thread_local entropy_frame *current_entropy;
static void erase(void *p,size_t n){volatile uint8_t *v=p;while(n--)*v++=0;}
static int kem(int p){return p==512||p==768||p==1024;}
static int dsa(int p){return p==44||p==65||p==87;}
static int overlaps(region a,region b){uintptr_t x=(uintptr_t)a.p,y=(uintptr_t)b.p;if(!a.n||!b.n)return 0;return x<=y?y-x<a.n:x-y<b.n;}
static int validate(lc_context*c,region*r,size_t n){
 size_t i,j;if(!c||!c->workspace||!c->workspace_bytes)return LC_E_ARGUMENT;
 r[n++]=(region){c->workspace,c->workspace_bytes};r[n++]=(region){c,sizeof(*c)};
 for(i=0;i<n;i++){
  if((!r[i].p&&r[i].n)||r[i].n>UINTPTR_MAX-(uintptr_t)r[i].p)return LC_E_ARGUMENT;
  for(j=0;j<i;j++)if(overlaps(r[i],r[j]))return LC_E_ALIAS;
 }
 /* Zero is the truthful caller-arena allocation count, not total memory. */
 c->arena_high_water=c->allocations=c->allocation_failures=0;c->last_error=0;return 0;
}
int lc_get_sizes(int p,lc_sizes*s){
 if(!s)return LC_E_ARGUMENT;memset(s,0,sizeof(*s));
 switch(p){
 case 512:s->public_key=800;s->secret_key=1632;s->ciphertext=768;break;
 case 768:s->public_key=1184;s->secret_key=2400;s->ciphertext=1088;break;
 case 1024:s->public_key=1568;s->secret_key=3168;s->ciphertext=1568;break;
 case 44:s->public_key=1312;s->secret_key=2560;s->signature=2420;break;
 case 65:s->public_key=1952;s->secret_key=4032;s->signature=3309;break;
 case 87:s->public_key=2592;s->secret_key=4896;s->signature=4627;break;
 default:return LC_E_ARGUMENT;
 }if(kem(p))s->shared_secret=32;return 0;
}
int lc_context_init(lc_context*c,void*w,size_t n,lc_random_fn f,void*u){
 if(!c||!w||!n||n>UINTPTR_MAX-(uintptr_t)w)return LC_E_ARGUMENT;
 if(overlaps((region){c,sizeof(*c)},(region){w,n}))return LC_E_ALIAS;
 memset(c,0,sizeof(*c));c->workspace=w;c->workspace_bytes=n;c->random=f;c->random_user=u;return 0;
}

/* RNG is acquired once before calling upstream. Its ignored randombytes return
 * cannot turn a caller RNG failure into an apparently successful operation.
 * Nested callbacks finish before the frame is installed; separate threads have
 * independent pointers. No secret state remains cached between API calls. */
int PQCLEAN_randombytes(uint8_t*out,size_t n){
 entropy_frame*f=current_entropy;
 if(!f)abort();
 if(n>f->length-f->used)longjmp(f->escape,1);
 memcpy(out,f->bytes+f->used,n);f->used+=n;return 0;
}
void pqc_nonce_guard(unsigned nonce,unsigned width){
 if(!current_entropy)abort();
 /* Public attempt count; avoid the original uint16_t nonce wrap. Bound is
  * >=821 for every parameter and leaves every measured valid attempt intact. */
 if(nonce>=(65535u-width)/width)longjmp(current_entropy->escape,2);
}
static int canonical_pk(const uint8_t*pk,size_t n){
 size_t i;unsigned bad=0;
 for(i=0;i<n-32;i+=3){unsigned a=(pk[i]|((unsigned)pk[i+1]<<8))&4095u;unsigned b=(pk[i+1]>>4)|((unsigned)pk[i+2]<<4);bad|=(a>=3329u)|(b>=3329u);}
 return bad==0;
}
static int checked_dk(const uint8_t*sk,const lc_sizes*z){
 uint8_t h[32];size_t i;unsigned bad=0;size_t offset=z->secret_key-z->public_key-64;
 sha3_256(h,sk+offset,z->public_key);
 for(i=0;i<32;i++)bad|=(unsigned)(h[i]^sk[z->secret_key-64+i]);
 erase(h,sizeof(h));return bad==0;
}
static int raw_keypair(int p,uint8_t*pk,uint8_t*sk){switch(p){
 case 512:return PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(pk,sk);
 case 768:return PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pk,sk);
 case 1024:return PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair(pk,sk);
 case 44:return PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk,sk);
 case 65:return PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(pk,sk);
 default:return PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair(pk,sk);}}
static int raw_enc(int p,uint8_t*ct,uint8_t*ss,const uint8_t*pk){switch(p){
 case 512:return PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct,ss,pk);
 case 768:return PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ct,ss,pk);
 default:return PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc(ct,ss,pk);}}
static int raw_dec(int p,uint8_t*ss,const uint8_t*ct,const uint8_t*sk){switch(p){
 case 512:return PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss,ct,sk);
 case 768:return PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss,ct,sk);
 default:return PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec(ss,ct,sk);}}
static int raw_sign(int p,uint8_t*sig,size_t*sn,const uint8_t*m,size_t mn,const uint8_t*d,size_t dn,const uint8_t*sk){switch(p){
 case 44:return PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature_ctx(sig,sn,m,mn,d,dn,sk);
 case 65:return PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature_ctx(sig,sn,m,mn,d,dn,sk);
 default:return PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature_ctx(sig,sn,m,mn,d,dn,sk);}}
static int raw_verify(int p,const uint8_t*sig,size_t sn,const uint8_t*m,size_t mn,const uint8_t*d,size_t dn,const uint8_t*pk){switch(p){
 case 44:return PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify_ctx(sig,sn,m,mn,d,dn,pk);
 case 65:return PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_ctx(sig,sn,m,mn,d,dn,pk);
 default:return PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify_ctx(sig,sn,m,mn,d,dn,pk);}}
static int execute(lc_context*c,int p,int op,const lc_sizes*z,uint8_t*out1,uint8_t*out2,const uint8_t*in1,const uint8_t*in2,const uint8_t*m,size_t mn,const uint8_t*d,size_t dn){
 uint8_t entropy[64];size_t n=op==0?(kem(p)?64u:32u):(op==1?32u:0u);size_t sn=0;
 entropy_frame frame;entropy_frame*previous=current_entropy;int result;
 if(n&&(c->random?c->random(c->random_user,entropy,n):lc_system_random(entropy,n))){erase(entropy,sizeof(entropy));return LC_E_RANDOM;}
 frame.bytes=entropy;frame.length=n;frame.used=0;current_entropy=&frame;
 switch(setjmp(frame.escape)){
 case 0:
  if(op==0)result=raw_keypair(p,out1,out2);
  else if(kem(p)&&op==1)result=canonical_pk(in1,z->public_key)?raw_enc(p,out1,out2,in1):-1;
  else if(kem(p))result=checked_dk(in2,z)?raw_dec(p,out1,in1,in2):-1;
  else if(op==1){result=raw_sign(p,out1,&sn,m,mn,d,dn,in1);if(!result&&sn!=z->signature)result=-1;}
  else result=raw_verify(p,in1,z->signature,m,mn,d,dn,in2);
  result=result?LC_E_REJECT:LC_OK;
  /* Invalid public keys are rejected before upstream requests its entropy. */
  if(result==0&&frame.used!=n)result=LC_E_INTERNAL;
  break;
 case 2:result=LC_E_REJECT;break;
 default:result=LC_E_INTERNAL;break;
 }
 current_entropy=previous;
 /* After longjmp no modified automatic frame field is read. */
 erase(&frame,sizeof(frame));erase(entropy,sizeof(entropy));return result;
}
int lc_keypair(lc_context*c,int p,uint8_t*pk,size_t pn,uint8_t*sk,size_t sn){
 lc_sizes z;region r[4];int e;if(lc_get_sizes(p,&z))return LC_E_ARGUMENT;
 if(pn<z.public_key||sn<z.secret_key)return LC_E_LENGTH;
 r[0]=(region){pk,pn};r[1]=(region){sk,sn};if((e=validate(c,r,2)))return e;
 e=execute(c,p,0,&z,pk,sk,NULL,NULL,NULL,0,NULL,0);if(e){erase(pk,z.public_key);erase(sk,z.secret_key);}c->last_error=e;return e;
}
int lc_encaps(lc_context*c,int p,uint8_t*ct,size_t cn,uint8_t*ss,size_t sn,const uint8_t*pk,size_t pn){
 lc_sizes z;region r[5];int e;if(!kem(p)||lc_get_sizes(p,&z))return LC_E_ARGUMENT;
 if(cn<z.ciphertext||sn<32||pn!=z.public_key)return LC_E_LENGTH;
 r[0]=(region){ct,cn};r[1]=(region){ss,sn};r[2]=(region){pk,pn};if((e=validate(c,r,3)))return e;
 e=execute(c,p,1,&z,ct,ss,pk,NULL,NULL,0,NULL,0);if(e){erase(ct,z.ciphertext);erase(ss,32);}c->last_error=e;return e;
}
int lc_decaps(lc_context*c,int p,uint8_t*ss,size_t sn,const uint8_t*ct,size_t cn,const uint8_t*sk,size_t kn){
 lc_sizes z;region r[5];int e;if(!kem(p)||lc_get_sizes(p,&z))return LC_E_ARGUMENT;
 if(sn<32||cn!=z.ciphertext||kn!=z.secret_key)return LC_E_LENGTH;
 r[0]=(region){ss,sn};r[1]=(region){ct,cn};r[2]=(region){sk,kn};if((e=validate(c,r,3)))return e;
 e=execute(c,p,2,&z,ss,NULL,ct,sk,NULL,0,NULL,0);if(e)erase(ss,32);c->last_error=e;return e;
}
int lc_sign(lc_context*c,int p,uint8_t*sig,size_t sn,const uint8_t*m,size_t mn,const uint8_t*d,size_t dn,const uint8_t*sk,size_t kn){
 lc_sizes z;region r[6];int e;if(!dsa(p)||lc_get_sizes(p,&z))return LC_E_ARGUMENT;
 if(sn<z.signature||kn!=z.secret_key||dn>255)return LC_E_LENGTH;
 r[0]=(region){sig,sn};r[1]=(region){m,mn};r[2]=(region){d,dn};r[3]=(region){sk,kn};if((e=validate(c,r,4)))return e;
 e=execute(c,p,1,&z,sig,NULL,sk,NULL,m,mn,d,dn);if(e)erase(sig,z.signature);c->last_error=e;return e;
}
int lc_verify(lc_context*c,int p,const uint8_t*sig,size_t sn,const uint8_t*m,size_t mn,const uint8_t*d,size_t dn,const uint8_t*pk,size_t pn){
 lc_sizes z;region r[6];int e;if(!dsa(p)||lc_get_sizes(p,&z))return LC_E_ARGUMENT;
 if(sn!=z.signature||pn!=z.public_key||dn>255)return LC_E_LENGTH;
 r[0]=(region){sig,sn};r[1]=(region){m,mn};r[2]=(region){d,dn};r[3]=(region){pk,pn};if((e=validate(c,r,4)))return e;
 e=execute(c,p,2,&z,NULL,NULL,sig,pk,m,mn,d,dn);c->last_error=e;return e;
}
const char*lc_error_string(int e){switch(e){case 0:return "success";case -1:return "invalid argument";case -2:return "invalid length";case -3:return "overlapping objects";case -4:return "random source failed";case -5:return "insufficient workspace";case -6:return "operation rejected";default:return "internal invariant failure";}}
