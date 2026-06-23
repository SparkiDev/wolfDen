/* test_endian.c
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
 * Big-endian serialization conformance. The MKPDU writers in mka_bytes.h take a
 * native-representation fast path under WOLFMKA_BIG_ENDIAN (a memcpy) and an
 * explicit-shift path otherwise; the readers are always shift-based. The
 * shift paths run on every x86 CI host, but the native path is ONLY correct on
 * a genuinely big-endian machine and is otherwise never executed. This test is
 * deliberately self-contained (no wolfSSL, no test harness) so it can be
 * cross-compiled and run under an emulator for a big-endian target - see
 * `make test-endian`, which runs it natively AND on big-endian ppc64 via qemu.
 *
 * It asserts every writer/reader produces exact network byte order against
 * fixed vectors, so a wrong native-path width or swap is caught.
 */
#include <stdio.h>
#include <string.h>

#include "wolfmka/mka_bytes.h"

static int g_fail = 0;

static void check(int cond, const char* what)
{
    if (cond) {
        printf("  ok:   %s\n", what);
    }
    else {
        printf("  FAIL: %s\n", what);
        g_fail++;
    }
}

static int eq(const uint8_t* got, const uint8_t* exp, size_t n)
{
    return memcmp(got, exp, n) == 0;
}

int main(void)
{
    uint8_t b[8];
    static const uint8_t z16[2] = {0x00, 0x00};
    static const uint8_t v16[2] = {0x12, 0x34};
    static const uint8_t m16[2] = {0xFF, 0xFF};
    static const uint8_t v32[4] = {0x12, 0x34, 0x56, 0x78};
    static const uint8_t m32[4] = {0xFF, 0xFF, 0xFF, 0xFF};
    static const uint8_t v48[6] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};
    static const uint8_t m48[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

#ifdef WOLFMKA_BIG_ENDIAN
    printf("byte order: BIG-endian (native-memcpy write path)\n");
#else
    printf("byte order: little-endian (explicit-shift write path)\n");
#endif

    /* 16-bit writer. */
    memset(b, 0xEE, sizeof b);
    w_be16(b, (uint16_t)0x0000U);
    check(eq(b, z16, 2), "w_be16(0x0000)");
    w_be16(b, (uint16_t)0x1234U);
    check(eq(b, v16, 2), "w_be16(0x1234)");
    w_be16(b, (uint16_t)0xFFFFU);
    check(eq(b, m16, 2), "w_be16(0xFFFF)");

    /* 32-bit writer. */
    w_be32(b, (uint32_t)0x12345678U);
    check(eq(b, v32, 4), "w_be32(0x12345678)");
    w_be32(b, (uint32_t)0xFFFFFFFFU);
    check(eq(b, m32, 4), "w_be32(0xFFFFFFFF)");

    /* 48-bit writer (the native path left-aligns then copies 6 octets). */
    w_be48(b, (uint64_t)0x123456789ABCULL);
    check(eq(b, v48, 6), "w_be48(0x123456789ABC)");
    w_be48(b, (uint64_t)0xFFFFFFFFFFFFULL);
    check(eq(b, m48, 6), "w_be48(0xFFFFFFFFFFFF)");

    /* Readers and round-trips. */
    check(rd_be16(v16) == 0x1234U, "rd_be16");
    check(rd_be32(v32) == 0x12345678U, "rd_be32");
    check(rd_be48(v48) == (uint64_t)0x123456789ABCULL, "rd_be48");

    w_be16(b, (uint16_t)0xBEEFU);
    check(rd_be16(b) == 0xBEEFU, "w_be16/rd_be16 round-trip");
    w_be32(b, (uint32_t)0xDEADBEEFU);
    check(rd_be32(b) == 0xDEADBEEFU, "w_be32/rd_be32 round-trip");
    w_be48(b, (uint64_t)0xCAFEF00DBA5EULL);
    check(rd_be48(b) == (uint64_t)0xCAFEF00DBA5EULL,
        "w_be48/rd_be48 round-trip");

    printf("%s\n", (g_fail == 0) ? "endian: PASS" : "endian: FAIL");
    return (g_fail == 0) ? 0 : 1;
}
