/* test_custom_alloc.c
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
 * Verifies that, under WOLFMKA_SMALL_STACK with a platform-supplied allocator
 * (see wolfmka_user_settings.h), the library actually routes its large-local
 * storage through WOLFMKA_MALLOC/WOLFMKA_FREE, and that every allocation is
 * released (no leaks). Build: make test-alloc
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* The counting allocator referenced by wolfmka_user_settings.h. */
static int g_allocs = 0;
static int g_frees = 0;
static size_t g_live = 0;
static size_t g_peak = 0;
static int g_fail_alloc =
    0; /* one-shot: when set, the next alloc returns NULL */

void* mka_test_malloc(size_t sz, void* heap, int type)
{
    void* p;
    (void)heap;
    (void)type;
    if (g_fail_alloc) {
        g_fail_alloc = 0; /* one-shot, before any allocation is counted */
        return NULL;
    }
    p = malloc(sz);
    if (p) {
        g_allocs++;
        g_live += sz;
        if (g_live > g_peak)
            g_peak = g_live;
    }
    return p;
}
void mka_test_free(void* ptr, void* heap, int type)
{
    (void)heap;
    (void)type;
    if (ptr)
        g_frees++;
    free(ptr);
}

#include "wolfmka/mka_kay.h"
#include "wolfmka/mka_crypto.h"

static int fails = 0;
#define CK(c, m)                                                               \
    do {                                                                       \
        if (!(c)) {                                                            \
            printf("  [FAIL] %s\n", (m));                                      \
            fails++;                                                           \
        }                                                                      \
    } while (0)

static int dummy_send(void* ctx, const uint8_t* f, size_t n)
{
    (void)ctx;
    (void)f;
    (void)n;
    return 0;
}

int main(void)
{
    MkaCakPair cak;
    MkaDerivedKeys dk;
    MkaParticipant p;
    MkaParticipantConfig cfg;
    MkaCmacCtx* cmacw;
    MkaRandom* rngw;
    uint8_t out[256];
    size_t n = sizeof(out);
    int before;

    printf("custom-allocator / small-stack test\n");

    /* The wolfSSL Cmac context (~1 KB) is the caller's pooled workspace
     * (wm_Crypto_CmacInit), backed by static pool storage, so a CMAC
     * operation never lands on the stack and never touches the allocator. A
     * NULL workspace is rejected rather than silently allocated or stacked. */
    memset(&cak, 0, sizeof cak);
    memset(cak.cak, 0xCA, 16);
    cak.cak_len = 16;
    memcpy(cak.ckn, "ckn", 3);
    cak.ckn_len = 3;

    cmacw = wm_Crypto_CmacInit();
    CK(cmacw != NULL, "cmac init");
    rngw = wm_Crypto_RandomInit();
    CK(rngw != NULL, "rng init");
    before = g_allocs;
    CK(wm_Crypto_DeriveKeys(cmacw, &cak, &dk) == MKA_OK, "derive_keys");
    CK(g_allocs == before, "pooled CMAC workspace makes no allocation");
    CK(wm_Crypto_DeriveKeys(NULL, &cak, &dk) == MKA_ERR_BAD_ARG,
        "NULL workspace rejected");

    /* Exercise the MKPDU build path (allocates an MkaPdu + frame). */
    memset(&cfg, 0, sizeof cfg);
    cfg.cak = cak;
    {
        uint8_t s[8] = {0, 0, 0, 0, 0, 0x0A, 0, 1};
        memcpy(cfg.sci, s, 8);
    }
    cfg.priority = 16;
    cfg.macsec_desired = 1;
    cfg.macsec_capability = MKA_CAP_INTEGRITY_CONF_OFFSET;
    cfg.key_server_capable = 1;
    cfg.sak_len = 16;
    cfg.send = dummy_send;
    cfg.cmac = cmacw;
    cfg.rng = rngw;
    CK(wm_Participant_Init(&p, &cfg) == MKA_OK, "init");
    before = g_allocs;
    CK(wm_Participant_BuildMkpdu(&p, out, sizeof out, &n) == MKA_OK,
        "build mkpdu");
    CK(g_allocs > before, "build used custom allocator");

    /* A working-buffer allocation failure surfaces MKA_ERR_INTERNAL - otherwise
     * the only library error code with no behavioural test. The one-shot
     * failure hits the first (working-buffer) allocation, so nothing is left
     * allocated and the leak balance below is preserved. */
    n = sizeof out;
    g_fail_alloc = 1;
    CK(wm_Participant_BuildMkpdu(&p, out, sizeof out, &n) == MKA_ERR_INTERNAL,
        "build alloc failure -> INTERNAL");
    n = sizeof out;
    CK(wm_Participant_BuildMkpdu(&p, out, sizeof out, &n) == MKA_OK,
        "rebuild ok after fail");
    g_fail_alloc = 1;
    CK(wm_Participant_Receive(&p, out, n, 0) == MKA_ERR_INTERNAL,
        "receive alloc failure -> INTERNAL");

    /* Run a couple of ticks (transmit path allocates + frees the frame). */
    wm_Participant_Run(&p, 0, NULL);
    wm_Participant_Run(&p, MKA_HELLO_TIME_MS, NULL);
    wm_Crypto_RandomFree(rngw);
    wm_Crypto_CmacFree(cmacw);

    printf("  allocations=%d frees=%d peak=%zu bytes\n", g_allocs, g_frees,
        g_peak);
    CK(g_allocs == g_frees, "no leaks (allocs == frees)");
    CK(g_allocs > 0, "allocator actually exercised");

    printf("%s\n", fails == 0 ? "PASS" : "FAIL");
    return fails ? 1 : 0;
}
