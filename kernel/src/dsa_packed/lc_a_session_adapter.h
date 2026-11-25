#if LC_DSA_PUBLIC_A_SESSION
#define LC_A_DECLARE(L) \
extern size_t lcbase##L##_a_cache_size(void); \
extern uint32_t lcbase##L##_a_format_tag(void); \
extern size_t lcbase##L##_a_scratch_size(int); \
extern int lcbase##L##_a_prepare(uint8_t*,const uint8_t*,struct lc_dsa_arena*); \
extern int lcbase##L##_a_verify(const uint8_t*,const uint8_t*,const uint8_t*,const uint8_t*,struct lc_dsa_arena*)
LC_A_DECLARE(44);LC_A_DECLARE(65);LC_A_DECLARE(87);
#undef LC_A_DECLARE
size_t lc_dsa_a_cache_bytes(int l) {
  switch(l){case 44:return lcbase44_a_cache_size();case 65:return lcbase65_a_cache_size();case 87:return lcbase87_a_cache_size();default:return 0;}
}
uint32_t lc_dsa_a_format_tag(int l) {
  switch(l){case 44:return lcbase44_a_format_tag();case 65:return lcbase65_a_format_tag();case 87:return lcbase87_a_format_tag();default:return 0;}
}
size_t lc_dsa_a_workspace_bound(int l,int op) {
  if(op==1){size_t b=lc_dsa_workspace_bound(l,1),a=lc_dsa_a_cache_bytes(l);return a && b>=a ? b-a : 0;}
  switch(l){case 44:return lcbase44_a_scratch_size(op);case 65:return lcbase65_a_scratch_size(op);case 87:return lcbase87_a_scratch_size(op);default:return 0;}
}
int lc_dsa_a_prepare(int l,uint8_t *cache,const uint8_t rho[32],void *w,size_t n,lc_dsa_stats *s) {
  struct lc_dsa_arena a;int ret;init(&a,w,n);
  if(!cache||!rho||!w||!lc_dsa_a_cache_bytes(l))return finish(&a,s,-9);
  DISPATCH(a_prepare,cache,rho);return finish(&a,s,ret);
}
int lc_dsa_a_sign_seed(int l,const uint8_t *cache,uint8_t *sig,const uint8_t *m,size_t ml,
 const uint8_t *ctx,size_t cl,const uint8_t rnd[32],const uint8_t *sk,void *w,size_t n,lc_dsa_stats *s) {
  struct lc_dsa_arena a;int ret;uint8_t mu[64];init(&a,w,n);
  if(!cache||!sig||!sk||!rnd||!w||cl>255||(!m&&ml)||(!ctx&&cl)||!lc_dsa_a_cache_bytes(l))return finish(&a,s,-9);
  a.a_cache=cache;a.a_cache_bytes=lc_dsa_a_cache_bytes(l);
  lc_dsa_pure_mu(mu,sk+64,0,ctx,cl,m,ml);
  DISPATCH(signature_internal,sig,mu,64,NULL,0,rnd,sk,1);
  mld_zeroize(mu,sizeof(mu));return finish(&a,s,ret);
}
int lc_dsa_a_verify(int l,const uint8_t *cache,const uint8_t *sig,size_t sl,const uint8_t *m,size_t ml,
 const uint8_t *ctx,size_t cl,const uint8_t *pk,void *w,size_t n,lc_dsa_stats *s) {
  struct lc_dsa_arena a;int ret;uint8_t mu[64];init(&a,w,n);
  if(!cache||!sig||!pk||!w||cl>255||(!m&&ml)||(!ctx&&cl)||!lc_dsa_a_cache_bytes(l))return finish(&a,s,-9);
  if(sl!=lc_dsa_size(l,2))return finish(&a,s,-6);
  lc_dsa_pure_mu(mu,pk,lc_dsa_size(l,0),ctx,cl,m,ml);
  DISPATCH(a_verify,cache,sig,mu,pk);
  mld_zeroize(mu,sizeof(mu));return finish(&a,s,ret);
}
#endif
