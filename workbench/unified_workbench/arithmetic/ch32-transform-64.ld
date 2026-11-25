MEMORY { RAM(rx): ORIGIN = 0x20018000, LENGTH = 4096 }
ENTRY(qual_entry)
SECTIONS { .text : { KEEP(*(.text.qual_entry)) *(.text*) *(.rodata*) } > RAM }
__production_gp = 0x20000820;
__qual_stack_top = 0x2000f5e0;
source_a = 0x20019400;
source_b = 0x20019c00;
work_a = 0x2001a400;
work_b = 0x2001ac00;
mulcache = 0x2001b400;
target = 0x2001bc00;
snapshots = 0x2001c400;
request = 0x20019000;
result = 0x20019100;
kem_ntt = 0x2254;
kem_intt = 0x2098;
kem_reduce = 0x2642;
kem_cache = 0x2488;
kem_dot = 0x24f0;
dsa_ntt = 0x1e24;
dsa_intt = 0x1cdc;
dsa_reduce = 0x1fec;
dsa_pointwise = 0x1c94;
