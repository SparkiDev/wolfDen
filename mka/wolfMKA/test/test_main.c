/* test_main.c - wolfMKA test runner.
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
 */

#include "test_util.h"
#include "wolfmka/mka_crypto.h"

int g_tests_run = 0;
int g_tests_failed = 0;
MkaCmacCtx* g_cmac = NULL;
MkaRandom* g_rng = NULL;

void run_crypto_tests(void);
void run_pdu_tests(void);
void run_kay_tests(void);
void run_fault_tests(void);
void run_status_tests(void);

int main(void)
{
    printf("wolfMKA test suite\n==================\n");

    /* The CMAC-consuming APIs require a caller-supplied workspace; acquire one
     * shared context for the whole run. */
    g_cmac = wm_Crypto_CmacInit();
    if (g_cmac == NULL) {
        printf("FAIL: could not acquire CMAC workspace\n");
        return 1;
    }
    /* Likewise the RNG: wolfSSL's WC_RNG never lives on wolfMKA's stack or
     * heap, so every participant needs one supplied. */
    g_rng = wm_Crypto_RandomInit();
    if (g_rng == NULL) {
        printf("FAIL: could not acquire RNG workspace\n");
        wm_Crypto_RandomFree(g_rng);
        wm_Crypto_CmacFree(g_cmac);
        return 1;
    }

    run_crypto_tests();
    run_pdu_tests();
    run_kay_tests();
    run_fault_tests();
    run_status_tests();

    wm_Crypto_CmacFree(g_cmac);

    printf("\n------------------\n");
    printf("checks: %d, failures: %d => %s\n", g_tests_run, g_tests_failed,
        g_tests_failed == 0 ? "PASS" : "FAIL");
    return g_tests_failed == 0 ? 0 : 1;
}
