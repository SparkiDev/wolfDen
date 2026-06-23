/* test_util.h - minimal test harness for wolfMKA.
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
 */
#ifndef WOLFMKA_TEST_UTIL_H
#define WOLFMKA_TEST_UTIL_H

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include "wolfmka/mka_types.h"

extern int g_tests_run;
extern int g_tests_failed;

/* A shared CMAC workspace, acquired once in main(). The CMAC-consuming APIs
 * require a caller-supplied workspace, so the tests pass this. */
extern MkaCmacCtx* g_cmac;

#define CHECK(cond, msg)                                                       \
    do {                                                                       \
        g_tests_run++;                                                         \
        if (!(cond)) {                                                         \
            g_tests_failed++;                                                  \
            printf("  [FAIL] %s (%s:%d)\n", (msg), __FILE__, __LINE__);        \
        }                                                                      \
    } while (0)

#define CHECK_EQ_MEM(a, b, n, msg)                                             \
    do {                                                                       \
        g_tests_run++;                                                         \
        if (memcmp((a), (b), (n)) != 0) {                                      \
            g_tests_failed++;                                                  \
            printf("  [FAIL] %s (%s:%d)\n", (msg), __FILE__, __LINE__);        \
            print_hex("    got ", (const uint8_t*)(a), (n));                   \
            print_hex("    exp ", (const uint8_t*)(b), (n));                   \
        }                                                                      \
    } while (0)

static inline void print_hex(const char* tag, const uint8_t* p, size_t n)
{
    size_t i;
    printf("%s", tag);
    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
    printf("\n");
}

/* Parse a hex string (no separators) into buf; returns byte count. */
static inline size_t hexparse(const char* hex, uint8_t* buf, size_t cap)
{
    size_t n = 0;
    while (hex[0] && hex[1] && n < cap) {
        unsigned v;
        if (sscanf(hex, "%2x", &v) != 1)
            break;
        buf[n++] = (uint8_t)v;
        hex += 2;
    }
    return n;
}

#endif /* WOLFMKA_TEST_UTIL_H */
