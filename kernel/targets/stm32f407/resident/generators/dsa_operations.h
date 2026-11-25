#ifndef A127_DSA_OPERATIONS
#define A127_DSA_OPERATIONS
#include "dsa_sign_shared.h"
typedef struct {
    uint16_t k,l,pk_bytes,sk_bytes,eta_bytes,z_bytes,challenge_bytes,w_bytes;
    uint16_t key_storage[6], verify_storage[6],matrix_tmp_offset;
    void *(*allocate)(struct lc_dsa_arena*,size_t);
    void (*release)(struct lc_dsa_arena*,void*,size_t);
    void (*hash)(uint8_t*,size_t,const uint8_t*,size_t);
    void (*matrix_init)(void*,const uint8_t*);
    void (*prepare_s)(void*,void*,const uint8_t*,unsigned,uint8_t*);
    void (*keyrow)(void*,void*,void*,const uint8_t*,void*,unsigned,uint8_t*);
    void (*finish_keyrow)(void*,void*,const uint8_t*,unsigned,uint8_t*,uint8_t*,uint8_t*);
    int (*unpack_z)(void*,void*,const uint8_t*,unsigned);
    void (*make_mu)(uint8_t*,const uint8_t*,const uint8_t*,size_t,const uint8_t*,size_t,const uint8_t*,size_t);
    void (*start_verify)(void*,void*,void*,const uint8_t*,const uint8_t*,const uint8_t*);
    int (*verifyrow)(void*,void*,void*,void*,void*,const uint8_t*,const uint8_t*,unsigned);
    void (*absorb_row)(void*,const uint8_t*,size_t);
    int (*finish_verify)(void*,uint8_t*,const uint8_t*,size_t);
    void (*finish_hash)(void*);
} a127_dsa_route;
int a127_dsa_keygen(const a127_dsa_route*,uint8_t*,uint8_t*,const uint8_t*,struct lc_dsa_arena*);
int a127_dsa_verify(const a127_dsa_route*,const uint8_t*,const uint8_t*,size_t,const uint8_t*,size_t,const uint8_t*,size_t,const uint8_t*,int,struct lc_dsa_arena*);
#endif

