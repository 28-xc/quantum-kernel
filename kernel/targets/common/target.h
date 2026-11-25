#ifndef LC_TARGET_H
#define LC_TARGET_H
#include <stddef.h>
#include <stdint.h>
#ifndef LC_TARGET_WORKSPACE
#define LC_TARGET_WORKSPACE 24576
#endif
extern unsigned char __test_stack_bottom[], __test_stack_top[];
extern unsigned char __code_start[], __code_end[], __data_start[], __data_end[];
extern unsigned char __bss_start[], __bss_end[], __arena_start[], __arena_end[];
extern unsigned char __io_start[], __io_end[], __control_stack_bottom[], __control_stack_top[];
extern unsigned char __ram_start[], __ram_end[];
int target_call(int (*fn)(void *), void *argument);
void target_putc(char c);
void target_exit(int status) __attribute__((noreturn));
void target_fault(void) __attribute__((noreturn));
void target_text(const char *text);
void target_uint(uint32_t value);
void target_int(int value);
int target_main(void);
#endif
