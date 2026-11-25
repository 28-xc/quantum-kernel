/* WCH startup symbol contract; test buffers have separately charged owners. */
ENTRY(_start)
MEMORY {
  FLASH (rx) : ORIGIN = 0x00000000, LENGTH = 64K
  RAM (rwx) : ORIGIN = 0x20000000, LENGTH = 64K
}
SECTIONS {
  .init : { __code_start = .; KEEP(*(SORT_NONE(.init))) } > FLASH
  .vector : { KEEP(*(.vector)) . = ALIGN(64); } > FLASH
  .text : { *(.text*) *(.rodata*) *(.srodata*) . = ALIGN(4); } > FLASH
  .fini : { KEEP(*(SORT_NONE(.fini))) . = ALIGN(4); } > FLASH
  .data : ALIGN(32) {
    __data_start = .; _data_vma = .;
    *(.data*) *(.gnu.linkonce.d.*) . = ALIGN(8);
    __global_pointer$ = . + 0x800;
    *(.sdata*) *(.gnu.linkonce.s.*) . = ALIGN(32);
    __data_end = .; _edata = .;
  } > RAM AT > FLASH
  _data_lma = LOADADDR(.data);
  __code_end = LOADADDR(.data) + SIZEOF(.data);
  .bss (NOLOAD) : ALIGN(32) {
    _sbss = .; __bss_start = .;
    *(.sbss*) *(.bss*) *(.gnu.linkonce.b.*) *(COMMON)
    . = ALIGN(32); _ebss = .; __bss_end = .;
  } > RAM
  .arena (NOLOAD) : ALIGN(32) { __arena_start = .; *(.arena) . = ALIGN(32); __arena_end = .; } > RAM
  .caller_io (NOLOAD) : ALIGN(32) { __io_start = .; *(.caller_io) . = ALIGN(32); __io_end = .; } > RAM
  .test_stack (NOLOAD) : ALIGN(32) {
    __test_stack_bottom = .; . += 2048; __test_stack_top = .;
  } > RAM
  .control_stack (NOLOAD) : ALIGN(32) {
    __control_stack_bottom = .; . += 1024; __control_stack_top = .;
  } > RAM
  _eusrstack = __control_stack_top;
  _susrstack = __control_stack_bottom;
  _end = __control_stack_top;
  __ram_start = ORIGIN(RAM); __ram_end = .;
  /DISCARD/ : { *(.comment*) *(.note*) *(.eh_frame*) }
  ASSERT(__code_end <= ORIGIN(FLASH) + LENGTH(FLASH), "Flash capacity exceeded")
  ASSERT(__ram_end <= ORIGIN(RAM) + LENGTH(RAM), "RAM capacity exceeded")
  ASSERT((__test_stack_top % 16) == 0, "Test stack must be ABI aligned")
  ASSERT((__control_stack_top % 16) == 0, "Control stack must be ABI aligned")
}
