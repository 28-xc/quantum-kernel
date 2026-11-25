/* SPDX-License-Identifier: Apache-2.0 */
#define main prior_layout_qualification_main
#include "../check.c"
#undef main
static int same_state(const app_state*a,const app_state*b,const capture*c){
 return !c->error&&a->rc==b->rc&&a->completed==b->completed&&a->entropy==b->entropy&&a->requests==b->requests&&a->entropy_bytes==b->entropy_bytes&&a->flows==b->flows&&a->transcript==b->transcript&&app_temporaries_clear(a)&&app_temporaries_clear(b);
}
int main(int argc,char**argv){
 if((argc!=3&&argc!=4)||(argc==4&&!parse_workspace(argv[3])))return 2;
 app_api apis[2];
 if(!load(&apis[0],argv[1])||!load(&apis[1],argv[2]))return 3;
 unsigned comparisons=0;int ks[3]={512,768,1024},ds[3]={44,65,87};
 capture*c=calloc(1,sizeof *c);if(!c)return 4;
 for(unsigned seed=0;seed<24;seed++)for(int pair=0;pair<3;pair++)for(int fresh=0;fresh<2;fresh++){
  guarded g[4];app_state*s[4];memset(c,0,sizeof *c);
  for(int arm=0;arm<4;arm++){
   const app_api*a=&apis[arm/2];size_t w=arm<2?262144:test_workspace;
   size_t n=app_pool_bytes(a,ks[pair],ds[pair],arm%2,w);g[arm]=allocate(n);
   s[arm]=app_open(g[arm].p,n,a,ks[pair],ds[pair],arm%2,fresh,w,202610039999ULL+seed*104729+ks[pair]);
   if(!s[arm])return 5;
   s[arm]->observer=snapshot;s[arm]->observer_user=c;
   c->compare=arm!=0;if(app_prepare(s[arm])||c->error)return 6;
  }
  for(unsigned i=0;i<4;i++){
   memset(c,0,sizeof *c);if(app_flow(s[0]))return 7;c->compare=1;
   for(int arm=1;arm<4;arm++){
    if(app_flow(s[arm])||!same_state(s[0],s[arm],c))return 8;
    for(unsigned stage=0;stage<6;stage++)if(c->seen[stage]==1)return 9;
    comparisons++;
   }
  }
  for(int arm=0;arm<4;arm++){
   if(!intact(&g[arm]))return 10;
   app_finish(s[arm]);
   if(!zero(s[arm]->objects,s[arm]->object_bytes)||!zero(s[arm]->work,s[arm]->workspace_bytes)||s[arm]->entropy)return 11;
   app_close(s[arm]);if(!zero(g[arm].p,g[arm].n))return 12;_aligned_free(g[arm].raw);
  }
 }
 memset(c,0,sizeof *c);free(c);
 printf("{\"status\":\"PASS\",\"independent_seed_groups\":24,\"parameter_pairs\":3,\"identity_modes\":2,\"arms\":4,\"flows_per_session\":4,\"complete_byte_comparisons\":%u,\"actual_flows\":2304}\n",comparisons);return 0;
}
