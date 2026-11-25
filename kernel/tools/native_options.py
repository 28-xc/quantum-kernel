"""Explicit AArch64 native build options, preserved in public build plans."""
import argparse

ARM_OPTION_NAMES = ['linker', 'inline_single_call', 'omit_unwind_metadata', 'inline_stream_leaves', 'direct_stream_state', 'codec24_neon', 'sparse_neon', 'sparse_t0_neon', 'ct_memcmp_neon', 'verify_t1_centered_neon', 'assembly_archive', 'canonical12_neon', 'compact_dsa_fused3', 'early_low_all', 'mixed_head65', 'packed_rejection_table', 'compact_kem_ntt', 'compact_dsa_barrett', 'compact_dsa_ntt', 'gamma_neon', 'shared_kem_sampler', 'raw_y_prefix', 'raw_y4_cache', 'shared_sensitive_free', 'shared_challenge', 'crosscol6_workspace', 'crosscol6', 'omit_frame_pointer', 'kem_k2rows', 'safe_icf', 'shared_c_owners', 'machine_outline', 'minimal_elf_startup']

def add_arm_arguments(parser):
    parser.add_argument('--linker',choices=['default','gold','lld-14'],default='default',help='Record explicit linker selection for compiler comparison')
    parser.add_argument('--inline-single-call',action=argparse.BooleanOptionalAction,default=False,help='Retain compiler default inlining of functions called once')
    parser.add_argument('--omit-unwind-metadata',action=argparse.BooleanOptionalAction,default=False,help='Build the C kernel without asynchronous or synchronous unwind tables')
    parser.add_argument('--inline-stream-leaves',action=argparse.BooleanOptionalAction,default=False,help='Inline the two NEON packed arithmetic leaves')
    parser.add_argument('--direct-stream-state',action=argparse.BooleanOptionalAction,default=False,help='Consume canonical little-endian ARM public Keccak state bytes directly')
    parser.add_argument('--codec24-neon',action=argparse.BooleanOptionalAction,default=False,help='Vectorize the three exact signed24 representation conversions')
    parser.add_argument('--sparse-neon',action=argparse.BooleanOptionalAction,default=False,help='Use exact byte-bounded sparse challenge products for eta secrets')
    parser.add_argument('--sparse-t0-neon',action=argparse.BooleanOptionalAction,default=False,help='Use exact signed16-bounded sparse t0 products in the packed signing schedule')
    parser.add_argument('--ct-memcmp-neon',action=argparse.BooleanOptionalAction,default=False,help='Use NEON dual OR/XOR byte comparison with original value barriers')
    parser.add_argument('--verify-t1-centered-neon',action=argparse.BooleanOptionalAction,default=False,help='Use a shared exact centered10-bit sparse t1 verification kernel')
    parser.add_argument('--assembly-archive',action=argparse.BooleanOptionalAction,default=False,help='Link individual AArch64 assembly members through an archive')
    parser.add_argument('--canonical12-neon',action=argparse.BooleanOptionalAction,default=False,help='Scan canonical packed KEM public coefficients with NEON, retaining the allocation protocol')
    parser.add_argument('--compact-dsa-fused3',action=argparse.BooleanOptionalAction,default=False,help='Fuse first and last three layers in compact Barrett DSA transforms')
    parser.add_argument('--early-low-all',action=argparse.BooleanOptionalAction,default=False,help='Evaluate every low row before z for parameter65/87 using the existing compact owners')
    parser.add_argument('--mixed-head65',action=argparse.BooleanOptionalAction,default=False,help='Mix first two matrix and mask streams with explicit640-byte arena cache')
    parser.add_argument('--packed-rejection-table',action=argparse.BooleanOptionalAction,default=False,help='Use one1024-byte stable4-bit rejection-selector table for KEM and DSA eta')
    parser.add_argument('--compact-kem-ntt',action=argparse.BooleanOptionalAction,default=False,help='Use compact NEON ML-KEM butterfly loops and ordinary twiddles')
    parser.add_argument('--compact-dsa-barrett',action=argparse.BooleanOptionalAction,default=False,help='Use ordinary twiddles and rounded Barrett products inside compact NEON DSA transforms')
    parser.add_argument('--compact-dsa-ntt',action=argparse.BooleanOptionalAction,default=False,help='Use compact natural-order NEON butterfly loops and one standard twiddle table')
    parser.add_argument('--gamma-neon',action=argparse.BooleanOptionalAction,default=False,help='Reverse-expand fixed gamma samples with exact NEON loads')
    parser.add_argument('--shared-kem-sampler',action=argparse.BooleanOptionalAction,default=False,help='Use one four-lane KEM matrix sampler with original scratch pointers')
    parser.add_argument('--raw-y-prefix',choices=['none','65','87','both'],default='none',help='Public prefix cache: two65 encodings and/or one87 encoding')
    parser.add_argument('--raw-y4-cache',action=argparse.BooleanOptionalAction,default=False,help='Retain four44 raw gamma encodings for both matrix product and z')
    parser.add_argument('--shared-sensitive-free',action=argparse.BooleanOptionalAction,default=False,help='Use one non-cloned wipe-and-LIFO-release entity')
    parser.add_argument('--shared-challenge',action=argparse.BooleanOptionalAction,default=False,help='Use one challenge entity with public tau and seed size')
    parser.add_argument('--crosscol6-workspace',action=argparse.BooleanOptionalAction,default=False,help='K6 cross-column schedule with an explicit arena polynomial')
    parser.add_argument('--crosscol6',action=argparse.BooleanOptionalAction,default=False,help='K6 across-column four-lane schedule with 1024 bytes of explicit caller signature scratch')
    parser.add_argument('--omit-frame-pointer',action=argparse.BooleanOptionalAction,default=False,help='Use compiler frame-pointer omission as an explicit build policy')
    parser.add_argument('--kem-k2rows',action=argparse.BooleanOptionalAction,default=False,help='Coalesce both public rank-two matrix rows in the existing four-polynomial tile')
    parser.add_argument('--safe-icf',action=argparse.BooleanOptionalAction,default=False,help='LLD address-significance-aware safe identical code folding')
    parser.add_argument('--shared-c-owners',action=argparse.BooleanOptionalAction,default=False,help='Use one hidden DSA stream/sparse C entity across all parameters')
    parser.add_argument('--machine-outline',action=argparse.BooleanOptionalAction,default=False,help='Explicit Clang AArch64 machine outlining policy at full LTO link')
    parser.add_argument('--minimal-elf-startup',action=argparse.BooleanOptionalAction,default=False,help='Omit unused C runtime startup objects from the ELF shared-library link; normal executable startup retained')

def arm_values(args):
    return {name:getattr(args,name) for name in ARM_OPTION_NAMES}

def arm_argv(values):
    if set(values)!=set(ARM_OPTION_NAMES):raise ValueError('Exact ARM option set required')
    out=[]
    for name,value in values.items():
        option='--'+name.replace('_','-')
        if isinstance(value,bool):
            if value:out.append(option)
        else:out.extend([option,str(value)])
    return out
