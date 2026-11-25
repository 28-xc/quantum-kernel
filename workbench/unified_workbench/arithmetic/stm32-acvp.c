/* Public ACVP fixtures only. Uses the API entries of the matched resident
 * image and a bounded SRAM packet buffer. The host compares returned bytes. */
#include <stdint.h>
#include <stddef.h>
#include "latticecore.h"

typedef struct { uint32_t w[16]; } m4_request;
typedef struct { uint32_t w[64]; } m4_response;
extern void *memcpy(void *, const void *, size_t);
extern void *memset(void *, int, size_t);
extern uint32_t cycle_stamp(void);
extern void clear_bytes(void *, size_t);

typedef struct {
    uint16_t parameter, strategy, capacity, fixture_count, io_size, pk_len, sk_len, ct_len, sig_len;
    void *legacy_buffers[10];
    __typeof__(&lc_context_init) init;
    __typeof__(&lc_keypair) keypair;
    __typeof__(&lc_encaps) encaps;
    __typeof__(&lc_decaps) decaps;
    __typeof__(&lc_sign) sign;
    __typeof__(&lc_verify) verify;
} resident_route;
_Static_assert(offsetof(resident_route, init) == 60, "resident route ABI");
#include "acvp_routes.h"

enum { COINS, PK, SK, CT, SIG, MSG, DOM, FIELDS };
enum { BEGIN = 29, PUSH, RUN, READ, CLEAR };
typedef struct { uint32_t offset, length; } field;
typedef struct {
    uint32_t parameter, operation, tc, extra;
    field fields[FIELDS];
    uint8_t bytes[12288];
} fixture;

static fixture input;
static unsigned total, received, output_size[2], ready;
static size_t consumed;
static struct {
    uint8_t before[32], arena[WORKSPACE], after[32];
    uint8_t output0[4896], output1[4896];
} guarded __attribute__((aligned(32)));

void unified_idle(void) {
    clear_bytes(&input, sizeof(input));
    clear_bytes(&guarded, sizeof(guarded));
    total = received = ready = 0;
}
void unified_hello(m4_response *r) { r->w[23] = 1; r->w[41] = 0x41564350u; }
void unified_hash(m4_response *r) { (void)r; }
int unified_select(const m4_request *q, m4_response *r) { (void)q; (void)r; return 0; }
void selected_layout(const m4_request *q, m4_response *r) { (void)q; (void)r; }

static const uint8_t *value(unsigned id) { return input.bytes + input.fields[id].offset; }
static size_t length(unsigned id) { return input.fields[id].length; }

static int random_bytes(void *user, uint8_t *out, size_t len) {
    (void)user;
    if (consumed > length(COINS) || len > length(COINS) - consumed) return -1;
    memcpy(out, value(COINS) + consumed, len);
    consumed += len;
    return 0;
}

static void run_case(m4_response *r) {
    const resident_route *route = 0;
    for (unsigned i = 0; i < sizeof(routes)/sizeof(routes[0]); ++i)
        if (routes[i]->parameter == input.parameter) route = routes[i];
    if (!route || route->strategy != STRATEGY || !route->capacity || route->capacity > WORKSPACE ||
        total != received || total < offsetof(fixture,bytes) || input.operation > 2) return;
    unsigned payload = total - offsetof(fixture,bytes);
    for (unsigned i = 0; i < FIELDS; ++i)
        if (input.fields[i].offset > payload || length(i) > payload - input.fields[i].offset) return;
    lc_context ctx;
    unsigned char *arena = guarded.arena + WORKSPACE - route->capacity;
    consumed = 0;
    memset(arena - 32, 0x69, 32);
    memset(arena, 0, route->capacity);
    memset(guarded.after, 0x96, 32);
    memset(guarded.output0, 0xa5, sizeof(guarded.output0));
    memset(guarded.output1, 0x5a, sizeof(guarded.output1));
    if (route->init(&ctx, arena, route->capacity, random_bytes, 0)) return;
    output_size[0] = output_size[1] = 0;
    uint8_t *a = guarded.output0, *b = guarded.output1;
    unsigned p = input.parameter, op = input.operation;
    int rc;
    uint32_t start = cycle_stamp();
    if (op == 0) {
        output_size[0] = route->pk_len;
        output_size[1] = route->sk_len;
        rc = route->keypair(&ctx, p, a, output_size[0], b, output_size[1]);
    } else if (p > 100 && op == 1) {
        output_size[0] = route->ct_len;
        output_size[1] = 32;
        rc = route->encaps(&ctx,p,a,output_size[0],b,32,value(PK),length(PK));
    } else if (p > 100) {
        output_size[0] = 32;
        rc = route->decaps(&ctx,p,a,32,value(CT),length(CT),value(SK),length(SK));
    } else if (op == 1) {
        output_size[0] = route->sig_len;
        rc = route->sign(&ctx,p,a,output_size[0],value(MSG),length(MSG),value(DOM),length(DOM),value(SK),length(SK));
    } else {
        rc = route->verify(&ctx,p,value(SIG),length(SIG),value(MSG),length(MSG),value(DOM),length(DOM),value(PK),length(PK));
    }
    uint32_t cycles = cycle_stamp() - start;
    unsigned guard = 0, used = 0;
    for (unsigned i = 0; i < 32; ++i)
        guard |= ((arena-32)[i] ^ 0x69u) | (guarded.after[i] ^ 0x96u);
    for (unsigned i = 0; i < route->capacity; ++i) used |= arena[i];
    r->w[23] = 1;
    r->w[24] = (uint32_t)rc;
    r->w[25] = input.tc;
    r->w[26] = output_size[0];
    r->w[27] = output_size[1];
    r->w[28] = guard == 0;
    r->w[29] = ctx.arena_high_water;
    r->w[30] = ctx.allocation_failures;
    r->w[31] = consumed == length(COINS);
    r->w[32] = cycles;
    r->w[33] = used == 0;
    ready = 1;
}

void experiment(const m4_request *q, m4_response *r) {
    unsigned command = q->w[2], arg = q->w[8], offset = q->w[9];
    if (command == BEGIN || command == CLEAR) {
        unified_idle();
        if (command == BEGIN && (arg < offsetof(fixture, bytes) || arg > sizeof(input))) return;
        if (command == BEGIN) total = arg;
        r->w[23] = 1;
    } else if (command == PUSH) {
        if (ready || arg != received || received >= total) return;
        uint8_t buffer[36];
        memcpy(buffer, q->w + 4, 16);
        memcpy(buffer + 16, q->w + 10, 20);
        unsigned count = total - received;
        if (count > sizeof(buffer)) count = sizeof(buffer);
        memcpy((uint8_t *)&input + received, buffer, count);
        received += count;
        r->w[23] = 1;
        r->w[24] = received;
    } else if (command == RUN) {
        if (!ready && arg == input.parameter && offset == input.tc) run_case(r);
    } else if (command == READ) {
        if (!ready || arg > 1 || offset >= output_size[arg]) return;
        const uint8_t *source = arg ? guarded.output1 : guarded.output0;
        unsigned count = output_size[arg] - offset;
        if (count > 128) count = 128;
        memcpy(r->w + 24, source + offset, count);
        r->w[23] = 1;
        r->w[56] = arg;
        r->w[57] = offset;
        r->w[58] = count;
    }
}
