#ifndef A127_F407_DSA_SIGN_SHARED
#define A127_F407_DSA_SIGN_SHARED
#ifndef A127_PREPROCESSED_TYPES
#include <stdint.h>
#include <stddef.h>
#endif
struct lc_dsa_arena;
typedef struct {
    uint8_t *pending;
    uint32_t pending_nonce;
    unsigned can_look_ahead;
} a127_pending;
enum { D_SEED,D_MATRIX,D_ACACHE,D_PENDING,D_S1,D_T0,D_S2,D_COUNT };
typedef struct {
    void *slot[D_COUNT];
    a127_pending look;
} a127_sign_state;
typedef struct {
    uint16_t k,l,signature_bytes,limit,bytes[D_COUNT];
    void *(*allocate)(struct lc_dsa_arena *,size_t);
    void (*release)(struct lc_dsa_arena *,void *,size_t);
    void (*unpack)(a127_sign_state *,const uint8_t *);
    void (*hash3)(uint8_t *,size_t,const uint8_t *,size_t,const uint8_t *,size_t,const uint8_t *,size_t);
    void (*matrix)(a127_sign_state *);
    int (*candidate)(a127_sign_state *,uint8_t *,uint16_t,struct lc_dsa_arena *);
} a127_sign_route;
int a127_sign_message(const a127_sign_route*,uint8_t*,const uint8_t*,size_t,const uint8_t*,size_t,const uint8_t*,const uint8_t*,int,struct lc_dsa_arena*);
#endif

