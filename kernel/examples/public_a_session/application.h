/* SPDX-License-Identifier: Apache-2.0 */
#ifndef LC_APPLICATION_OWNER_H
#define LC_APPLICATION_OWNER_H
#include "lattice_session.h"
#include <stdint.h>
typedef struct {
 int (*init)(lc_context*,void*,size_t,lc_random_fn,void*);
 int (*sizes)(int,lc_sizes*);
 int (*key)(lc_context*,int,uint8_t*,size_t,uint8_t*,size_t);
 int (*enc)(lc_context*,int,uint8_t*,size_t,uint8_t*,size_t,const uint8_t*,size_t);
 int (*dec)(lc_context*,int,uint8_t*,size_t,const uint8_t*,size_t,const uint8_t*,size_t);
 int (*sign)(lc_context*,int,uint8_t*,size_t,const uint8_t*,size_t,const uint8_t*,size_t,const uint8_t*,size_t);
 int (*verify)(lc_context*,int,const uint8_t*,size_t,const uint8_t*,size_t,const uint8_t*,size_t,const uint8_t*,size_t);
 size_t (*cache_bytes)(int);
 size_t (*session_workspace)(int,int);
 int (*session_init)(lc_a_session*,int,void*,size_t);
 int (*session_prepare)(lc_context*,lc_a_session*,const uint8_t*,size_t);
 int (*session_sign)(lc_context*,lc_a_session*,int,uint8_t*,size_t,const uint8_t*,size_t,const uint8_t*,size_t,const uint8_t*,size_t);
 int (*session_verify)(lc_context*,lc_a_session*,int,const uint8_t*,size_t,const uint8_t*,size_t,const uint8_t*,size_t,const uint8_t*,size_t);
 int (*session_close)(lc_a_session*);
} app_api;
enum {APP_SEPARATE=0,APP_SIGNATURE_REUSE=1};
enum {APP_E_CANCEL=-101,APP_E_SECRET=-102};
enum {APP_FAULT_NONE=0,APP_FAULT_RANDOM=1,APP_FAULT_CAPACITY=2,
      APP_FAULT_SIGNATURE=3,APP_FAULT_CANCEL=4,APP_FAULT_CIPHERTEXT=5};
typedef struct app_state app_state;
typedef void (*app_observer)(void*,unsigned,const app_state*);
struct app_state {
 app_api api;lc_context context;lc_sizes k,d;
 lc_a_session session;uint8_t *public_cache;size_t cache_bytes,authority_high;
 uint8_t *objects,*work;
 size_t object_bytes,workspace_bytes,pool_bytes,high;
 int kem,dsa,layout,fresh,identity_ready,rc,completed,phase;
 int fault,fault_stage,entropy_failure;
 uint64_t entropy,requests,entropy_bytes,flows,transcript;
 app_observer observer;void *observer_user;
};
typedef struct {uint8_t *kpk,*ksk,*spk,*ssk,*signature,*ciphertext,*secret,*peer_secret;} app_views;
size_t app_object_bytes(const lc_sizes*,const lc_sizes*,int layout);
size_t app_pool_bytes(const app_api*,int kem,int dsa,int layout,size_t workspace);
app_state *app_open(void*,size_t,const app_api*,int kem,int dsa,int layout,
                    int fresh,size_t workspace,uint64_t seed);
void app_get_views(const app_state*,app_views*);
int app_prepare(app_state*);
int app_flow(app_state*);
void app_finish(app_state*);
void app_close(app_state*);
int app_temporaries_clear(const app_state*);
#endif
