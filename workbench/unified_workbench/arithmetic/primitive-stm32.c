#include "primitive-dispatch.h"

typedef struct { uint32_t w[16]; } m4_request;
typedef struct { uint32_t w[64]; } m4_response;
extern void *memcpy(void *, const void *, size_t);
extern uint32_t cycle_stamp(void);
extern void clear_bytes(void *, size_t);
static primitive_input work;
static unsigned received, ready;

void unified_idle(void) {
    clear_bytes(&work,sizeof(work));
    received = ready = 0;
}
void unified_hello(m4_response *r) { r->w[23] = 1; r->w[41] = 0x504f4c59u; }
void unified_hash(m4_response *r) { (void)r; }
int unified_select(const m4_request *q, m4_response *r) { (void)q; (void)r; return 0; }
void selected_layout(const m4_request *q, m4_response *r) { (void)q; (void)r; }

void experiment(const m4_request *q, m4_response *r) {
    unsigned command = q->w[2], offset = q->w[8];
    if (command == 34) {
        unified_idle();
        r->w[23] = 1;
    } else if (command == 35) {
        if (ready || offset != received || offset >= sizeof(work)) return;
        uint8_t buffer[36];
        memcpy(buffer,q->w+4,16);
        memcpy(buffer+16,q->w+10,20);
        unsigned count = sizeof(work) - received;
        if (count > sizeof(buffer)) count = sizeof(buffer);
        memcpy((uint8_t *)&work+received,buffer,count);
        received += count;
        r->w[24] = received;
        r->w[23] = 1;
    } else if (command == 36) {
        if (ready || received != sizeof(work) || work.cookie != offset) return;
        uint32_t start = cycle_stamp();
        int status = run_primitive(&work);
        r->w[26] = cycle_stamp() - start;
        r->w[24] = (uint32_t)status;
        r->w[25] = work.cookie;
        r->w[23] = 1;
        ready = 1;
    } else if (command == 37) {
        if (!ready || offset >= sizeof(work.coefficients)+sizeof(work.octets) || work.cookie != q->w[9]) return;
        unsigned length = sizeof(work.coefficients)+sizeof(work.octets)-offset;
        if (length > 128) length = 128;
        memcpy(r->w+24,(uint8_t *)&work+offsetof(primitive_input,coefficients)+offset,length);
        r->w[56] = offset;
        r->w[57] = length;
        r->w[58] = work.cookie;
        r->w[23] = 1;
    }
}
