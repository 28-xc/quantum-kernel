/* Copyright (c) 2026 A1-27 contributors
 * SPDX-License-Identifier: Apache-2.0
 * Eight stable 4-bit candidate indices per acceptance mask;15 is padding.
 * Input x3 points to256 four-byte rows. A single128-bit TBL maps padding
 * selectors30/31 tozero, matching the original255 padding semantics.
 */
#ifndef LC_REJECTION_SELECTOR4_H
#define LC_REJECTION_SELECTOR4_H
#ifndef LC_KEM_REJECTION_BYTE_TABLE
#define LC_KEM_REJECTION_BYTE_TABLE 0
#endif
#if LC_KEM_REJECTION_BYTE_TABLE < 0 || LC_KEM_REJECTION_BYTE_TABLE > 1
#error "KEM byte selector must be zero or one"
#endif
/* ML-DSA includes this same macro header. Its original nibble table,
 * load width and address mapping remain unchanged even if the global
 * KEM-only build option is present in that translation unit. */
#if LC_KEM_REJECTION_BYTE_TABLE && defined(MLK_ARITH_BACKEND_AARCH64)
#if defined(MLD_ARITH_BACKEND_AARCH64)
#error "KEM and DSA selector translation-unit domains must be distinct"
#endif
#if !(defined(LC_ARM_PACKED_REJECTION_TABLE) && LC_ARM_PACKED_REJECTION_TABLE)
#error "KEM byte selector requires the compressed-table build contract"
#endif
#endif
.macro LC_REJ_SELECTOR4_CONSTANTS nibble, pair
        movi v\nibble\().8b, #0xf
        movi v\pair\().8h, #1, lsl #8
.endm
.macro LC_REJ_SELECTOR4 dst, index, tmp, nibble, pair
#if LC_KEM_REJECTION_BYTE_TABLE && defined(MLK_ARITH_BACKEND_AARCH64)
        ldr d\dst, [x3, x\index, lsl #3]
        zip1 v\dst\().16b, v\dst\().16b, v\dst\().16b
        orr v\dst\().16b, v\dst\().16b, v\pair\().16b
#else
        ldr s\dst, [x3, x\index, lsl #2]
        ushr v\tmp\().8b, v\dst\().8b, #4
        zip1 v\dst\().8b, v\dst\().8b, v\tmp\().8b
        and v\dst\().8b, v\dst\().8b, v\nibble\().8b
        shl v\dst\().8b, v\dst\().8b, #1
        zip1 v\dst\().16b, v\dst\().16b, v\dst\().16b
        orr v\dst\().16b, v\dst\().16b, v\pair\().16b
#endif
.endm
#endif
