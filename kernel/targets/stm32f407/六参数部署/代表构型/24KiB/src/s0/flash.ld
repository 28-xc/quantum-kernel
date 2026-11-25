ENTRY(Reset_Handler)
MEMORY {
 FLASH (rx) : ORIGIN = 0x8020000, LENGTH = 896K
 SRAM (rw) : ORIGIN = 0x20008000, LENGTH = 24K
}
SECTIONS {
 .vectors ORIGIN(FLASH) : {KEEP(*(.vectors))} >FLASH
 .text : {KEEP(*(.text.entry)) *(.text*) *(.rodata*)} >FLASH
 .ARM.exidx : {*(.ARM.exidx*)} >FLASH
 .data : {__data_begin = .; *(.data*) . = ALIGN(4); __data_end = .;} >SRAM AT>FLASH
 __data_load = LOADADDR(.data);
 .bss (NOLOAD) : {. = ALIGN(32); __bss_begin = .; *(.bss*) *(COMMON) KEEP(*(.usb_diag)) . = ALIGN(8); __bss_end = .;} >SRAM
 .ccm (NOLOAD) : {. = ALIGN(32); __ccm_begin = .; *(.ccm*) . = ALIGN(8); __ccm_end = .;} >SRAM
 .stack (NOLOAD) : {. = ALIGN(8); __stack_guard_bottom = .; . += 64; __stack_bottom = .; . += 2880; __stack_top = .; . += 128; __boot_stack_top = .;} >SRAM
 /DISCARD/ : {*(.comment) *(.note*)}
}
__image_bytes = ABSOLUTE(LOADADDR(.data) + SIZEOF(.data) - 0x8020000);
__reserved_ram = ABSOLUTE(__boot_stack_top - 0x20008000);
ASSERT(__reserved_ram <= 24576, "complete writable allocation exceeds selected budget")


__flash_start = ABSOLUTE(0x8020000);
ASSERT(__image_bytes <= 917504, "flash envelope exceeded")
