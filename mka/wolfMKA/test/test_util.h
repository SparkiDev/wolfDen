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
#include "wolfmka/mka_crypto.h"

extern int g_tests_run;
extern int g_tests_failed;

/* A shared CMAC workspace, acquired once in main(). The CMAC-consuming APIs
 * require a caller-supplied workspace, so the tests pass this. */
extern MkaCmacCtx* g_cmac;
/* The RNG workspace is mandatory too (MkaParticipantConfig::rng), so the
 * harness acquires one for the whole run just as it does the CMAC context. */
extern MkaRandom* g_rng;

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

/* Re-seal a frame's ICV in place after a test has altered its body, so the
 * decoder rejects on the field under test rather than on a broken seal.
 *
 * It signs exactly what the library verifies, which includes the L2 prefix
 * the PDU layer derives from the frame itself - the PAE group address, the SA
 * taken from the SCI in the Basic Parameter Set, and the EAPOL EtherType (IEEE
 * Std 802.1X-2020, 9.4.1) - so a test that sealed only the PDU body would fail
 * the ICV instead of reaching the check it is aiming at.
 * @param[in]     cmac     CMAC workspace.
 * @param[in]     ick      the ICK to sign with.
 * @param[in]     ick_len  its length in octets.
 * @param[in,out] f        the frame; its trailing ICV is overwritten.
 * @param[in]     covered  octets of f the ICV covers (the ICV follows them).
 */
static inline void test_seal_icv(MkaCmacCtx* cmac, const uint8_t* ick,
    size_t ick_len, uint8_t* f, size_t covered)
{
    static const uint8_t pae_group[6] = MKA_PAE_GROUP_ADDR;
    uint8_t l2[MKA_ICV_L2_PREFIX_LEN];

    memcpy(&l2[0], pae_group, sizeof pae_group);
    memcpy(&l2[6], &f[EAPOL_HDR_LEN + 4U], 6);
    l2[12] = (uint8_t)(EAPOL_ETHERTYPE >> 8);
    l2[13] = (uint8_t)(EAPOL_ETHERTYPE & 0xFFU);
    (void)wm_Crypto_IcvComputeL2(cmac, ick, ick_len, l2, sizeof l2, f, covered,
        &f[covered]);
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
