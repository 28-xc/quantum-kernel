#ifndef A127_M4_BOARD_H
#define A127_M4_BOARD_H
#include <stdint.h>
#include <stddef.h>
#define REG(a) (*(volatile uint32_t *)(uintptr_t)(a))
#define REQ_MAGIC 0x514d3441u
#define RSP_MAGIC 0x524d3441u
enum { M4_HELLO=1,M4_RUN=2,M4_KAT=3,M4_BOUNDARY=4,M4_CLOCK=5,M4_RETURN_DFU=6,M4_TIMING=7,M4_POLY=8 };
/* q[0..3]: magic, protocol, command, sequence; q[4..7]: nonce.
   q[8..14]: parameter, profile, budget bytes, message bytes, context bytes,
   entropy(0=test,1=board RNG), flags. q[15]: FNV1a of first 60 bytes, transport only. */
typedef struct {uint32_t w[16];} m4_request;
typedef struct {uint32_t w[64];} m4_response;
void experiment(const m4_request*,m4_response*);
void hardware_info(m4_response*);
void clear_bytes(void*,size_t);
uint32_t m4_checksum(const void*,size_t);
void reset_to_dfu(void) __attribute__((noreturn));
uint32_t stack_used(void);
uint32_t cycle_stamp(void);
void board_start(void) __attribute__((noreturn));
extern uint32_t __stack_bottom[],__stack_top[];
#endif

