/* Shared FIPS 204 signing control. The fixed-layout, arithmetic-heavy rejection test
 * belongs to the parameter/schedule worker selected in the immutable descriptor. */
#include "dsa_sign_shared.h"
#include <string.h>
static void wipe(void *p,size_t n){memset(p,0,n);__asm__ volatile(""::"r"(p):"memory");}
int a127_sign_message(const a127_sign_route *route,uint8_t *sig,const uint8_t *message,size_t length,
                      const uint8_t *prefix,size_t prefix_length,const uint8_t *randomizer,
                      const uint8_t *sk,int external_mu,struct lc_dsa_arena *arena){
    a127_sign_state state={0};int rc=-2;
    for(unsigned i=0;i<D_COUNT;i++){
        if(route->bytes[i]){
            state.slot[i]=route->allocate(arena,route->bytes[i]);
            if(!state.slot[i])goto done;
        }
    }
    route->unpack(&state,sk);
    uint8_t *seed=(uint8_t*)state.slot[D_SEED];
    uint8_t *tr=seed+32,*key=tr+64,*mu=key+32,*rho_prime=mu+64;
    if(external_mu)memcpy(mu,message,64);
    else route->hash3(mu,64,tr,64,prefix,prefix_length,message,length);
    route->hash3(rho_prime,64,key,32,randomizer,32,mu,64);
    route->matrix(&state);
    state.look.pending=state.slot[D_PENDING];state.look.pending_nonce=UINT32_MAX;
    for(unsigned attempt=0;attempt<route->limit;attempt++){
        uint16_t kappa=(uint16_t)(attempt*route->l);
        state.look.can_look_ahead=state.look.pending &&
            attempt+1u<route->limit && (uint32_t)kappa+2u*route->l-1u<=UINT16_MAX;
        rc=route->candidate(&state,sig,kappa,arena);
        if(rc!=-1)goto done;
    }
    rc=-4;
done:
    if(rc)wipe(sig,route->signature_bytes);
    for(unsigned i=D_COUNT;i-- >0;){
        if(state.slot[i]){wipe(state.slot[i],route->bytes[i]);route->release(arena,state.slot[i],route->bytes[i]);}
    }
    wipe(&state,sizeof(state));
    return rc;
}

