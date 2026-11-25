#include "dsa_operations.h"
#include <string.h>
static void secure_clear(void *p,size_t n){memset(p,0,n);__asm__ volatile(""::"r"(p):"memory");}
static int acquire_all(const a127_dsa_route *r,struct lc_dsa_arena *arena,const uint16_t size[6],void *objects[6]){
    int ok=1;
    for(unsigned i=0;i<6;i++){objects[i]=r->allocate(arena,size[i]);ok&=objects[i]!=0;}
    return ok;
}
static void release_all(const a127_dsa_route *r,struct lc_dsa_arena *arena,const uint16_t size[6],void *objects[6]){
    for(unsigned i=6;i-- >0;){if(objects[i]){secure_clear(objects[i],size[i]);r->release(arena,objects[i],size[i]);}}
}
int a127_dsa_keygen(const a127_dsa_route *r,uint8_t *pk,uint8_t *sk,const uint8_t *seed,struct lc_dsa_arena *arena){
    void *a[6];int rc=-2;
    if(!acquire_all(r,arena,r->key_storage,a))goto end;
    uint8_t *expanded=a[0],*input=a[1],*tr=a[2],*s1=a[3],*mat=a[4],*row=a[5];
    void *tmp=mat+r->matrix_tmp_offset;const uint8_t *rho_prime=expanded+32;
    memcpy(input,seed,32);input[32]=r->k;input[33]=r->l;r->hash(expanded,128,input,34);
    if(r->prepare_s)for(unsigned i=0;i<r->l;i++)r->prepare_s(s1,tmp,rho_prime,i,sk+128+i*r->eta_bytes);
    memcpy(pk,expanded,32);r->matrix_init(mat,expanded);
    for(unsigned i=0;i<r->k;i++){
        r->keyrow(row,mat,s1,rho_prime,tmp,i,sk);
        r->finish_keyrow(row,tmp,rho_prime,r->l+i,
            sk+128+(r->l+i)*r->eta_bytes,pk+32+i*320,sk+128+(r->l+r->k)*r->eta_bytes+i*416);
    }
    r->hash(tr,64,pk,r->pk_bytes);memcpy(sk,expanded,32);memcpy(sk+32,expanded+96,32);memcpy(sk+64,tr,64);rc=0;
end:
    release_all(r,arena,r->key_storage,a);
    if(rc){secure_clear(pk,r->pk_bytes);secure_clear(sk,r->sk_bytes);}
    return rc;
}
int a127_dsa_verify(const a127_dsa_route *r,const uint8_t *sig,const uint8_t *msg,size_t length,
                    const uint8_t *pre,size_t prelen,const uint8_t *pre1,size_t prelen1,
                    const uint8_t *pk,int external_mu,struct lc_dsa_arena *arena){
    void *a[6];int rc=-2,hash_live=0;
    if(!acquire_all(r,arena,r->verify_storage,a))goto end;
    uint8_t *state=a[0],*mu=a[1],*z=a[2],*cp=a[3],*mat=a[4],*w=a[5];void *tmp=mat+r->matrix_tmp_offset;
    rc=-6;
    for(unsigned i=0;i<r->l;i++)if(r->unpack_z(tmp,z,sig+r->challenge_bytes+i*r->z_bytes,i))goto end;
    if(external_mu)memcpy(mu,msg,64);
    else{
        uint8_t hpk[64] __attribute__((aligned(32)));r->hash(hpk,64,pk,r->pk_bytes);
        r->make_mu(mu,hpk,pre,prelen,pre1,prelen1,msg,length);secure_clear(hpk,sizeof(hpk));
    }
    r->start_verify(state,cp,mat,mu,pk,sig);hash_live=1;
    for(unsigned i=0;i<r->k;i++){
        if(r->verifyrow(w,mat,z,cp,tmp,sig,pk,i))goto end;
        r->absorb_row(state,tmp,r->w_bytes);
    }
    rc=r->finish_verify(state,mu,sig,r->challenge_bytes);
end:
    if(hash_live)r->finish_hash(a[0]);
    release_all(r,arena,r->verify_storage,a);return rc;
}

