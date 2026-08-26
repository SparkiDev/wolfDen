/* test_icv_l2.c - standalone unit test for the L2-inclusive MKPDU ICV
 * (WOLFMKA_ICV_L2_ADDR).
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

/* The full test suite's PDU/KAY frame builders bake in the non-L2 ICV, so the
 * L2 ICV compute/verify path is pinned here in isolation: compute + verify
 * success, a wrong prefix length rejected, and a tamper of either the L2 prefix
 * or the data failing the ICV. Built only with -DWOLFMKA_ICV_L2_ADDR. */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "wolfmka/mka_crypto.h"
#include "test_util.h"

int g_tests_run = 0;
int g_tests_failed = 0;
/* Declared in test_util.h for the shared harness; unused here but defined so
 * the header links cleanly. */
MkaCmacCtx* g_cmac = NULL;
MkaRandom* g_rng = NULL;

#ifndef WOLFMKA_ICV_L2_ADDR
/* Built by `make test-icv-l2`, which supplies -DWOLFMKA_ICV_L2_ADDR. Without it
 * there is nothing to test, but the file must still compile: `make cxx` and the
 * feature sweep build every test source in the default configuration. */
int main(void)
{
    printf("wolfMKA L2 ICV test: SKIP (build with -DWOLFMKA_ICV_L2_ADDR)\n");
    return 0;
}
#else
int main(void)
{
    uint8_t ick[16], l2[MKA_ICV_L2_PREFIX_LEN], data[64], icv[16];
    MkaCmacCtx* cmac;

    printf("wolfMKA L2 ICV test\n===================\n");

    cmac = wm_Crypto_CmacInit();
    if (cmac == NULL) {
        printf("FAIL: could not acquire CMAC workspace\n");
        return 1;
    }

    memset(ick, 0x11, sizeof(ick));
    memset(l2, 0x33, sizeof(l2));
    memset(data, 0x22, sizeof(data));

    CHECK(wm_Crypto_IcvComputeL2(cmac, ick, sizeof(ick), l2, sizeof(l2), data,
              sizeof(data), icv) == MKA_OK,
        "icv L2 compute");
    CHECK(wm_Crypto_IcvVerifyL2(cmac, ick, sizeof(ick), l2, sizeof(l2), data,
              sizeof(data), icv) == MKA_OK,
        "icv L2 verify ok");
    /* A prefix length other than 14 octets is rejected. */
    CHECK(wm_Crypto_IcvComputeL2(cmac, ick, sizeof(ick), l2, sizeof(l2) - 1U,
              data, sizeof(data), icv) == MKA_ERR_BAD_ARG,
        "icv L2 wrong prefix length rejected");
    /* Tamper the L2 prefix: the ICV must fail (proves the prefix is bound in).
     */
    l2[0] ^= 0x01;
    CHECK(wm_Crypto_IcvVerifyL2(cmac, ick, sizeof(ick), l2, sizeof(l2), data,
              sizeof(data), icv) == MKA_ERR_ICV,
        "icv L2 verify tamper prefix");
    l2[0] ^= 0x01;
    /* Tamper the data: the ICV must fail. */
    data[0] ^= 0x01;
    CHECK(wm_Crypto_IcvVerifyL2(cmac, ick, sizeof(ick), l2, sizeof(l2), data,
              sizeof(data), icv) == MKA_ERR_ICV,
        "icv L2 verify tamper data");

    wm_Crypto_CmacFree(cmac);

    printf("\n------------------\n");
    printf("checks: %d, failures: %d => %s\n", g_tests_run, g_tests_failed,
        g_tests_failed == 0 ? "PASS" : "FAIL");
    return g_tests_failed == 0 ? 0 : 1;
}
#endif /* WOLFMKA_ICV_L2_ADDR */
