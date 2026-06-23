/* mka_mem.h
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This file is part of wolfMKA.
 *
 * wolfMKA is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfMKA is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * Memory and small-stack support for wolfMKA.
 *
 * Allocation is funnelled through WOLFMKA_MALLOC / WOLFMKA_FREE so a platform
 * can redefine them (e.g. to a static pool allocator) by defining them before
 * including any wolfMKA header, or via -DWOLFMKA_MALLOC=... on the cmd line.
 * Their signature mirrors wolfSSL's XMALLOC/XFREE: (size, heap, type).
 *
 * When WOLFMKA_SMALL_STACK is defined, large local variables (>= 64 octets) are
 * moved off the stack and onto the heap using the MKA_DECLARE_VAR /
 * MKA_ALLOC_VAR_EX / MKA_FREE_VAR_EX macros, which are modelled on wolfSSL's
 * WC_DECLARE_VAR / WC_ALLOC_VAR_EX / WC_FREE_VAR_EX.
 *
 * The key property (as in wolfSSL): MKA_DECLARE_VAR declares the variable as a
 * pointer under small-stack and as a stack array otherwise. Because a stack
 * array decays to a pointer, the *usage* is identical in both modes - index it,
 * memcpy into it, or pass it to a function expecting a pointer, and the same
 * source compiles either way. Access single-struct variables (VAR_SIZE == 1)
 * through `name->field` and pass `name` (not `&name`).
 */

#ifndef WOLFMKA_MEM_H
#define WOLFMKA_MEM_H

#include <stddef.h>

/* Optional single place for a platform to set WOLFMKA_SMALL_STACK,
 * WOLFMKA_MALLOC, WOLFMKA_FREE, WOLFMKA_HEAP_HINT, etc. Compile every source
 * with -DWOLFMKA_USER_SETTINGS so all translation units agree. */
#ifdef WOLFMKA_USER_SETTINGS
    #include "wolfmka_user_settings.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------- *
 * Redefinable allocation primitives. Default to the C library; a platform may
 * override either macro. The (heap, type) arguments mirror wolfSSL so they can
 * drive a custom allocator, and are ignored by the defaults.
 *
 * When WOLFMKA_NO_MALLOC is defined the library makes no dynamic allocations at
 * all, so these are neither needed nor pulled in (no <stdlib.h>).
 * ------------------------------------------------------------------------- */
#ifndef WOLFMKA_NO_MALLOC
    #if !defined(WOLFMKA_MALLOC) || !defined(WOLFMKA_FREE)
        #include <stdlib.h>
    #endif
    #ifndef WOLFMKA_MALLOC
        #define WOLFMKA_MALLOC(sz, heap, type) malloc((size_t)(sz))
    #endif
    #ifndef WOLFMKA_FREE
        #define WOLFMKA_FREE(ptr, heap, type) free((ptr))
    #endif
#endif

/* ------------------------------------------------------------------------- *
 * Memory / string primitives. Like wolfSSL's XMEMCPY/XMEMSET/etc., these route
 * through redefinable macros so a platform can supply its own (e.g. a
 * constant-time or hardware-accelerated implementation, or to avoid libc).
 * Override any subset before including this header, or via -D.
 * ------------------------------------------------------------------------- */
#if !defined(WOLFMKA_MEMCPY) || !defined(WOLFMKA_MEMSET) ||                    \
    !defined(WOLFMKA_MEMCMP) || !defined(WOLFMKA_MEMMOVE) ||                   \
    !defined(WOLFMKA_STRLEN)
    #include <string.h>
#endif

#ifndef WOLFMKA_MEMCPY
    #define WOLFMKA_MEMCPY(dst, src, n) memcpy((dst), (src), (n))
#endif
#ifndef WOLFMKA_MEMSET
    #define WOLFMKA_MEMSET(dst, c, n) memset((dst), (c), (n))
#endif
#ifndef WOLFMKA_MEMCMP
    #define WOLFMKA_MEMCMP(a, b, n) memcmp((a), (b), (n))
#endif
#ifndef WOLFMKA_MEMMOVE
    #define WOLFMKA_MEMMOVE(dst, src, n) memmove((dst), (src), (n))
#endif
#ifndef WOLFMKA_STRLEN
    #define WOLFMKA_STRLEN(s) strlen((s))
#endif

/* Debug-only invariant check. Active only when WOLFMKA_DEBUG is defined (then
 * it maps to the C library assert by default); it compiles to nothing
 * otherwise, so release builds carry no check and no branch. A platform may
 * redefine WOLFMKA_ASSERT to route to its own diagnostics. */
#ifndef WOLFMKA_ASSERT
    #ifdef WOLFMKA_DEBUG
        #include <assert.h>
        #define WOLFMKA_ASSERT(cond) assert(cond)
    #else
        #define WOLFMKA_ASSERT(cond) ((void)0)
    #endif
#endif

/* Dynamic memory "type" tags (analogous to wolfSSL's DYNAMIC_TYPE_*). A custom
 * WOLFMKA_MALLOC can use these to route allocations. */
enum {
    /* scratch buffers (KDF input, MKPDU frame) */
    MKA_DYN_TMP_BUFFER = 1,
    /* a decoded/encoded MkaPdu */
    MKA_DYN_PDU = 2
};

/* The default heap handle passed to WOLFMKA_MALLOC/FREE. */
#ifndef WOLFMKA_HEAP_HINT
    #define WOLFMKA_HEAP_HINT NULL
#endif

/* ------------------------------------------------------------------------- *
 * Large-local placement. Three configurations:
 *
 *   (default)                      on the stack (a plain array / struct)
 *   WOLFMKA_SMALL_STACK            off the stack, on the heap (WOLFMKA_MALLOC)
 *   WOLFMKA_SMALL_STACK            off the stack, bound to an object field
 *     + WOLFMKA_NO_MALLOC          supplied by the caller (no allocation)
 *
 * MKA_DECLARE_VAR makes `name` a pointer (small-stack) or an array (otherwise);
 * either way `name[i]`, memcpy(name,...) and passing `name` to a pointer
 * parameter compile identically. Acquire storage with MKA_ALLOC_VAR_BACKED,
 * passing `backing` = address of the object field to use in the no-malloc case
 * (it is referenced only in that configuration). Release with MKA_FREE_VAR.
 * ------------------------------------------------------------------------- */
/* Macro parameters are abbreviated (nm=name, ty=type, ct=count, hp=heap,
 * dt=dyntype, bk=backing, fl=onfail) to keep these definitions within 80
 * columns. Abbreviations are local to each macro and do not affect callers. */
#ifdef WOLFMKA_SMALL_STACK

    #define MKA_DECLARE_VAR(name, type, count, heap) type* name = NULL

    #ifdef WOLFMKA_NO_MALLOC
        /* Off-stack storage is a field of a caller-provided object, so the
         * pointer is always valid - there is no allocation that can fail. */
        #define MKA_SMALL_STACK_IS_OBJECT 1
        #define MKA_VAR_OK(name)          1
        #define MKA_ALLOC_VAR_BACKED(nm, ty, ct, hp, dt, bk, fl)               \
            do {                                                               \
                (nm) = (bk);                                                   \
            } while (0)
        #define MKA_FREE_VAR_EX(name, heap, dyntype)                           \
            do {                                                               \
                (name) = NULL;                                                 \
            } while (0)
    #else
        /* Off-stack storage comes from the heap, so the allocation can fail. */
        #define MKA_SMALL_STACK_IS_HEAP 1
        #define MKA_VAR_OK(name)        ((name) != NULL)
        #define MKA_ALLOC_VAR_BACKED(nm, ty, ct, hp, dt, bk, fl)               \
            do {                                                               \
                (nm) = (ty*)WOLFMKA_MALLOC(sizeof(ty) * (size_t)(ct), (hp),    \
                    (dt));                                                     \
                if ((nm) == NULL) {                                            \
                    fl;                                                        \
                }                                                              \
            } while (0)
        #define MKA_FREE_VAR_EX(name, heap, dyntype)                           \
            do {                                                               \
                if ((name) != NULL) {                                          \
                    WOLFMKA_FREE((name), (heap), (dyntype));                   \
                    (name) = NULL;                                             \
                }                                                              \
            } while (0)
    #endif

#else /* !WOLFMKA_SMALL_STACK : plain stack storage */

    #define MKA_DECLARE_VAR(name, type, count, heap)         type name[(count)]
    #define MKA_ALLOC_VAR_BACKED(nm, ty, ct, hp, dt, bk, fl) ((void)0)
    #define MKA_FREE_VAR_EX(name, heap, dyntype)             ((void)0)
    #define MKA_VAR_OK(name)                                 1

#endif /* WOLFMKA_SMALL_STACK */

/* Convenience wrappers using the default heap hint. `bk` is the object field
 * used when WOLFMKA_NO_MALLOC is in effect. */
#define MKA_ALLOC_VAR(nm, ty, ct, dt, bk, fl)                                  \
    MKA_ALLOC_VAR_BACKED(nm, ty, ct, WOLFMKA_HEAP_HINT, dt, bk, fl)
#define MKA_FREE_VAR(name, dyntype)                                            \
    MKA_FREE_VAR_EX(name, WOLFMKA_HEAP_HINT, dyntype)

#ifdef __cplusplus
}
#endif

#endif /* WOLFMKA_MEM_H */
