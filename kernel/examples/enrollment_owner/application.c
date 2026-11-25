/* SPDX-License-Identifier: Apache-2.0 */
#include "application.h"
#include <string.h>
static const uint8_t domain[]="A1-27 device enrollment v2";
static void wipe(void*p,size_t n){volatile uint8_t*q=p;while(n--)*q++=0;}
static size_t align32(size_t n){return (n+31)&~(size_t)31;}
static uint64_t digest(uint64_t h,const uint8_t*p,size_t n){while(n--){h^=*p++;h*=UINT64_C(1099511628211);}return h;}
static int zeros(const uint8_t*p,size_t n){uint8_t v=0;while(n--)v|=*p++;return v==0;}
size_t app_object_bytes(const lc_sizes*k,const lc_sizes*d,int layout){
 return (layout==APP_SEPARATE?k->public_key:0)+k->secret_key+d->public_key+d->secret_key+d->signature+
        (layout==APP_SEPARATE?k->ciphertext+64:0);
}
size_t app_pool_bytes(const app_api*a,int kem,int dsa,int layout,size_t workspace){
 lc_sizes k,d;
 if(!a||!a->sizes||layout<0||layout>1||!workspace||a->sizes(kem,&k)||a->sizes(dsa,&d)||!k.ciphertext||!d.signature||d.signature<k.ciphertext+64||d.signature<k.public_key||k.public_key<32||k.secret_key<k.public_key+64)return 0;
 size_t prefix=align32(align32(sizeof(app_state))+app_object_bytes(&k,&d,layout));
 if(workspace>SIZE_MAX-prefix)return 0;
 return prefix+workspace;
}
void app_get_views(const app_state*s,app_views*v){
 /* FIPS203 Algorithm16: dk = dkPKE || ek || H(ek) || z.
    ek has its exact standard representation inside dk. The reused layout
    keeps that view live through certification, encapsulation and decapsulation.
    Its owner is the complete secret-key object and is erased at flow cleanup. */
 if(s->layout==APP_SIGNATURE_REUSE){
  v->ksk=s->objects;v->kpk=v->ksk+s->k.secret_key-s->k.public_key-64;
 }else{v->kpk=s->objects;v->ksk=v->kpk+s->k.public_key;}
 v->spk=v->ksk+s->k.secret_key;v->ssk=v->spk+s->d.public_key;
 v->signature=v->ssk+s->d.secret_key;
 v->ciphertext=s->layout==APP_SIGNATURE_REUSE?v->signature:v->signature+s->d.signature;
 v->secret=v->ciphertext+s->k.ciphertext;v->peer_secret=v->secret+32;
}
static int entropy(void*u,uint8_t*p,size_t n){
 app_state*s=u;s->requests++;s->entropy_bytes+=n;
 if(s->entropy_failure){if(n)p[0]=0x7c;return -1;}
 while(n--){s->entropy^=s->entropy<<13;s->entropy^=s->entropy>>7;s->entropy^=s->entropy<<17;*p++=(uint8_t)s->entropy;}
 return 0;
}
app_state *app_open(void*pool,size_t bytes,const app_api*a,int kem,int dsa,
                   int layout,int fresh,size_t workspace,uint64_t seed){
 if(!a||!a->init||!a->sizes||!a->key||!a->enc||!a->dec||!a->sign||!a->verify)return NULL;
 app_api selected=*a;
 size_t need=app_pool_bytes(a,kem,dsa,layout,workspace);
 if(!pool||((uintptr_t)pool&31)||!need||bytes<need||(fresh!=0&&fresh!=1))return NULL;
 memset(pool,0,need);app_state*s=pool;s->api=selected;s->kem=kem;s->dsa=dsa;s->layout=layout;s->fresh=fresh;
 if(selected.sizes(kem,&s->k)||selected.sizes(dsa,&s->d))return NULL;
 s->object_bytes=app_object_bytes(&s->k,&s->d,layout);s->pool_bytes=need;
 s->objects=(uint8_t*)pool+align32(sizeof *s);
 s->work=(uint8_t*)pool+align32(align32(sizeof *s)+s->object_bytes);
 s->workspace_bytes=workspace;s->entropy=seed;s->transcript=UINT64_C(1469598103934665603);
 if(selected.init(&s->context,s->work,workspace,seed?entropy:NULL,seed?s:NULL))return NULL;
 return s;
}
static void observe(app_state*s,unsigned stage){if(s->observer)s->observer(s->observer_user,stage,s);}
static int before(app_state*s,unsigned stage){
 s->phase=(int)stage;s->entropy_failure=s->fault==APP_FAULT_RANDOM&&s->fault_stage==(int)stage;
 s->context.workspace_bytes=s->fault==APP_FAULT_CAPACITY&&s->fault_stage==(int)stage?32:s->workspace_bytes;
 if(s->fault==APP_FAULT_CANCEL&&s->fault_stage==(int)stage)return APP_E_CANCEL;
 return 0;
}
static int after(app_state*s,int rc,unsigned stage){
 s->context.workspace_bytes=s->workspace_bytes;s->entropy_failure=0;
 if(s->context.arena_high_water>s->high)s->high=s->context.arena_high_water;
 if(!rc){s->completed++;observe(s,stage);}return rc;
}
static int authority(app_state*s,app_views*v){
 int rc=before(s,0);if(rc)return rc;
 rc=after(s,s->api.key(&s->context,s->dsa,v->spk,s->d.public_key,v->ssk,s->d.secret_key),0);
 s->identity_ready=rc==0;return rc;
}
int app_prepare(app_state*s){
 if(!s||!s->pool_bytes||s->phase<0||!s->api.init)return LC_E_ARGUMENT;
 app_views v;app_get_views(s,&v);s->completed=0;s->rc=0;
 if(!s->fresh&&!s->identity_ready)s->rc=authority(s,&v);
 if(s->rc){wipe(v.ssk,s->d.secret_key);s->identity_ready=0;}
 s->context.workspace_bytes=s->workspace_bytes;s->entropy_failure=0;return s->rc;
}
int app_flow(app_state*s){
 if(!s||!s->pool_bytes||s->phase<0||!s->api.init)return LC_E_ARGUMENT;
 app_views v;app_get_views(s,&v);s->completed=0;s->rc=0;
 if(s->fresh||!s->identity_ready){s->rc=authority(s,&v);if(s->rc)goto cleanup;}
#define STEP(stage,call) do{s->rc=before(s,stage);if(s->rc)goto cleanup;s->rc=after(s,(call),stage);if(s->rc)goto cleanup;}while(0)
 /* KeyGen requires disjoint public and private output buffers. The signature
    is not live yet, so it receives the temporary public output. Afterwards
    every public-key read uses the standard embedded copy. No key generation,
    hash, entropy request or cleanup step is omitted. */
 STEP(1,s->api.key(&s->context,s->kem,
      s->layout==APP_SIGNATURE_REUSE?v.signature:v.kpk,
      s->k.public_key,v.ksk,s->k.secret_key));
 STEP(2,s->api.sign(&s->context,s->dsa,v.signature,s->d.signature,v.kpk,s->k.public_key,domain,sizeof domain-1,v.ssk,s->d.secret_key));
 if(s->fault==APP_FAULT_SIGNATURE&&s->fault_stage==3)v.signature[0]^=1;
 STEP(3,s->api.verify(&s->context,s->dsa,v.signature,s->d.signature,v.kpk,s->k.public_key,domain,sizeof domain-1,v.spk,s->d.public_key));
 /* This is the final signature read. The authority key remains live across
    repeated workflows; only the per-workflow signature owner is reusable. */
 s->transcript=digest(s->transcript,v.kpk,s->k.public_key);
 s->transcript=digest(s->transcript,v.signature,s->d.signature);
 STEP(4,s->api.enc(&s->context,s->kem,v.ciphertext,s->k.ciphertext,v.secret,32,v.kpk,s->k.public_key));
 if(s->fault==APP_FAULT_CIPHERTEXT&&s->fault_stage==5)v.ciphertext[0]^=1;
 STEP(5,s->api.dec(&s->context,s->kem,v.peer_secret,32,v.ciphertext,s->k.ciphertext,v.ksk,s->k.secret_key));
 uint8_t different=0;for(unsigned i=0;i<32;i++)different|=v.secret[i]^v.peer_secret[i];
 if(different){s->rc=APP_E_SECRET;goto cleanup;}
 s->transcript=digest(s->transcript,v.ciphertext,s->k.ciphertext);s->flows++;
cleanup:
 s->context.workspace_bytes=s->workspace_bytes;s->entropy_failure=0;
 wipe(v.ksk,s->k.secret_key);wipe(v.secret,64);
 if(s->fresh){wipe(v.ssk,s->d.secret_key);s->identity_ready=0;}
 return s->rc;
#undef STEP
}
int app_temporaries_clear(const app_state*s){
 app_views v;app_get_views(s,&v);
 return zeros(v.ksk,s->k.secret_key)&&zeros(v.secret,64)&&
        (!s->fresh||zeros(v.ssk,s->d.secret_key))&&zeros(s->work,s->high);
}
void app_finish(app_state*s){
 if(!s||!s->pool_bytes)return;
 wipe(s->objects,s->object_bytes);wipe(s->work,s->workspace_bytes);
 s->identity_ready=0;s->entropy=0;s->entropy_failure=0;s->phase=-1;
 s->context.random=NULL;s->context.random_user=NULL;
}
void app_close(app_state*s){if(!s)return;size_t n=s->pool_bytes;wipe(s,n);}
