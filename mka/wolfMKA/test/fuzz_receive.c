/* fuzz_receive.c
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
 * Stateful libFuzzer harness for the participant receive path
 * (wm_Participant_Receive + wm_Participant_Run). Where fuzz_pdu stops at the
 * stateless decoder, this drives the whole KaY state machine - peer table,
 * liveness, Key Server election, SAK generation/distribution - across a
 * SEQUENCE of frames interleaved with clock ticks.
 *
 * The participant authenticates every MKPDU, so random bytes would be rejected
 * before reaching any interesting state. To get past authentication the harness
 * derives the SAME ICK the participant uses (wm_Crypto_DeriveKeys over the
 * known CAK) and forges a valid ICV over each fuzzer-controlled body. Each fuzz
 * input is decoded as a little script: a 2-octet header per step either
 * advances the clock by one Hello Time (high bit set) or delivers a forged
 * frame whose body is the next run of fuzz bytes. A fresh participant is built
 * per input so runs stay deterministic and isolated.
 *
 * Build/run with `make fuzz-receive` (clang
 * -fsanitize=fuzzer,address,undefined).
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "wolfmka/mka_kay.h"
#include "wolfmka/mka_crypto.h"
#include "wolfmka/mka_types.h"

static MkaCmacCtx* g_cmac;
/* One seeded RNG for the whole campaign: without it every MI and SAK draw
 * seeds a throwaway generator, which dominates the run time and starves the
 * fuzzer of executions. */
static MkaRandom* g_rng;
static uint8_t g_ick[MKA_MAX_CAK_LEN];
static size_t g_ick_len;
static MkaCakPair g_cak;
static int g_ready;

/* No-op data plane: the receive path may install/enable SAs once a SAK is
 * agreed; absorb those calls so the state machine runs to completion. */
static int sc_noop(void* c, const uint8_t* sci)
{
    (void)c;
    (void)sci;
    return 0;
}
static int install_noop(void* c, const uint8_t* sci, uint8_t an, uint32_t kn,
    const uint8_t* sak, size_t len)
{
    (void)c;
    (void)sci;
    (void)an;
    (void)kn;
    (void)sak;
    (void)len;
    return 0;
}
static int en_tx_noop(void* c, uint8_t an, bool e)
{
    (void)c;
    (void)an;
    (void)e;
    return 0;
}
static int en_rx_noop(void* c, const uint8_t* s, uint8_t an, bool e)
{
    (void)c;
    (void)s;
    (void)an;
    (void)e;
    return 0;
}
static int send_noop(void* ctx, const uint8_t* f, size_t n)
{
    (void)ctx;
    (void)f;
    (void)n;
    return 0;
}

int LLVMFuzzerInitialize(int* argc, char*** argv)
{
    MkaDerivedKeys keys;

    (void)argc;
    (void)argv;
    g_cmac = wm_Crypto_CmacInit();
    if (g_rng == NULL) {
        g_rng = wm_Crypto_RandomInit();
    }
    if (g_cmac == NULL) {
        return 0;
    }
    memset(&g_cak, 0, sizeof g_cak);
    memset(g_cak.cak, 0xCA, 16);
    g_cak.cak_len = 16;
    memcpy(g_cak.ckn, "fuzz-ckn", 8);
    g_cak.ckn_len = 8;
    if (wm_Crypto_DeriveKeys(g_cmac, &g_cak, &keys) != MKA_OK) {
        return 0;
    }
    memcpy(g_ick, keys.ick, keys.ick_len);
    g_ick_len = keys.ick_len;
    g_ready = 1;
    return 0;
}

/* Forge an authentic frame: [EAPOL header][body][valid ICV]. Returns the total
 * length, or 0 on failure. */
static size_t forge(const uint8_t* body, size_t body_n, uint8_t* out,
    size_t out_cap)
{
    uint8_t icv[MKA_DEFAULT_ICV_LEN];
    size_t declared;
    size_t covered;

    if (body_n > out_cap - EAPOL_HDR_LEN - MKA_DEFAULT_ICV_LEN) {
        body_n = out_cap - EAPOL_HDR_LEN - MKA_DEFAULT_ICV_LEN;
    }
    declared = body_n + MKA_DEFAULT_ICV_LEN;
    out[0] = (uint8_t)EAPOL_VERSION_2010;
    out[1] = (uint8_t)EAPOL_TYPE_MKA;
    out[2] = (uint8_t)(declared >> 8);
    out[3] = (uint8_t)(declared & 0xFFU);
    if (body_n != 0U) {
        memcpy(&out[EAPOL_HDR_LEN], body, body_n);
    }
    covered = EAPOL_HDR_LEN + body_n;
    /* Seal exactly what the library verifies. Under WOLFMKA_ICV_L2_ADDR that
     * includes the L2 prefix derived from the frame; sealing without it would
     * make every frame fail the ICV and the fuzzer would never reach the state
     * machine it is aimed at. */
#ifdef WOLFMKA_ICV_L2_ADDR
    {
        static const uint8_t pae_group[6] = MKA_PAE_GROUP_ADDR;
        uint8_t l2[MKA_ICV_L2_PREFIX_LEN];

        memcpy(&l2[0], pae_group, sizeof pae_group);
        memcpy(&l2[6], &out[EAPOL_HDR_LEN + 4U], 6);
        l2[12] = (uint8_t)(EAPOL_ETHERTYPE >> 8);
        l2[13] = (uint8_t)(EAPOL_ETHERTYPE & 0xFFU);
        if (wm_Crypto_IcvComputeL2(g_cmac, g_ick, g_ick_len, l2, sizeof l2, out,
                covered, icv) != MKA_OK) {
            return 0;
        }
    }
#else
    if (wm_Crypto_IcvCompute(g_cmac, g_ick, g_ick_len, out, covered, icv) !=
        MKA_OK) {
        return 0;
    }
#endif
    memcpy(&out[covered], icv, MKA_DEFAULT_ICV_LEN);
    return covered + MKA_DEFAULT_ICV_LEN;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    MkaParticipant p;
    MkaParticipantConfig cfg;
    uint8_t frame[MKA_MKPDU_MAX_LEN];
    uint8_t sci[MKA_SCI_LEN] = {0x02, 0, 0, 0, 0, 0xAA, 0, 0x01};
    size_t off = 0;
    uint32_t now = 0;

    if (!g_ready) {
        return 0;
    }

    memset(&cfg, 0, sizeof cfg);
    cfg.cak = g_cak;
    cfg.cmac = g_cmac;
    cfg.rng = g_rng;
    memcpy(cfg.sci, sci, sizeof sci);
    cfg.priority = 10;
    cfg.macsec_desired = 1;
    cfg.macsec_capability = MKA_CAP_INTEGRITY_CONF_OFFSET;
    cfg.key_server_capable = 1;
    cfg.sak_len = 16;
    cfg.secy.create_tx_sc = sc_noop;
    cfg.secy.create_rx_sc = sc_noop;
    cfg.secy.install_tx_sa = install_noop;
    cfg.secy.install_rx_sa = install_noop;
    cfg.secy.enable_transmit = en_tx_noop;
    cfg.secy.enable_receive = en_rx_noop;
    cfg.send = send_noop;
    if (wm_Participant_Init(&p, &cfg) != MKA_OK) {
        return 0;
    }

    /* Walk the input as a script of clock-tick / deliver-frame steps. */
    while ((off + 2U) <= size) {
        uint16_t hdr = (uint16_t)(((uint16_t)data[off] << 8) | data[off + 1U]);
        size_t body_n;
        size_t total;

        off += 2U;
        if ((hdr & 0x8000U) != 0U) {
            now += MKA_HELLO_TIME_MS;
            (void)wm_Participant_Run(&p, now, NULL);
            continue;
        }
        body_n = hdr & 0x01FFU; /* 0..511, within the body bound */
        if (body_n > (size - off)) {
            body_n = size - off;
        }
        total = forge(&data[off], body_n, frame, sizeof frame);
        off += body_n;
        if (total != 0U) {
            (void)wm_Participant_Receive(&p, frame, total, now);
        }
    }
    now += MKA_HELLO_TIME_MS;
    (void)wm_Participant_Run(&p, now, NULL);

    wm_Participant_Free(&p);
    return 0;
}
