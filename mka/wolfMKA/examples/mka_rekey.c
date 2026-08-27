/* mka_rekey.c
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
 * SAK rekey - make-before-break key rollover (IEEE Std 802.1X-2010, 9.8).
 *
 * A Secure Association Key does not last forever: the Key Server rolls it over
 * before the packet number exhausts (or on a timer, or when a peer leaves for
 * forward secrecy). wolfMKA exposes this as wm_Participant_Rekey(): the current
 * key becomes the Old key and stays installed for in-flight traffic while a new
 * Latest key (next Key Number) is distributed, so no frame is dropped during
 * the handover. The Key Server can also rekey automatically every
 * sak_rekey_time_ms; here we trigger it explicitly to show the Key Number
 * advancing 1 -> 2 on both ends.
 *
 * Build:  make examples   (or see README.md)
 */

#include <stdio.h>
#include <string.h>

#include "wolfmka/mka_kay.h"
#include "wolfmka/mka_crypto.h"

/* ------------------------------------------------------------------ link -- */
typedef struct {
    uint8_t buf[8][MKA_MKPDU_MAX_LEN];
    size_t len[8];
    int head, tail;
} Queue;

static void q_push(Queue* q, const uint8_t* f, size_t n)
{
    int s = q->tail % 8;
    if (n > sizeof(q->buf[0]))
        return;
    memcpy(q->buf[s], f, n);
    q->len[s] = n;
    q->tail++;
}
static int q_pop(Queue* q, uint8_t* f, size_t* n)
{
    int s;
    if (q->head == q->tail)
        return 0;
    s = q->head % 8;
    memcpy(f, q->buf[s], q->len[s]);
    *n = q->len[s];
    q->head++;
    return 1;
}

static int send_to(void* ctx, const uint8_t* f, size_t n)
{
    q_push((Queue*)ctx, f, n);
    return 0;
}

/* ------------------------------------------------------------------ SecY --
 * No-op data plane, except sak_installed is narrated through the event hook so
 * the rollover is visible as it happens. */
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

static MkaSecyOps secy_for(const char* who)
{
    MkaSecyOps o;
    memset(&o, 0, sizeof(o));
    o.create_tx_sc = sc_noop;
    o.create_rx_sc = sc_noop;
    o.install_tx_sa = install_noop;
    o.install_rx_sa = install_noop;
    o.enable_transmit = en_tx_noop;
    o.enable_receive = en_rx_noop;
    o.ctx = (void*)who;
    return o;
}

static void ev_sak_installed(void* ctx, uint32_t kn, uint8_t an,
    uint64_t cipher_suite)
{
    (void)cipher_suite;
    printf("  [%s] event: SAK installed kn=%u an=%u\n", (const char*)ctx, kn,
        an);
}

static MkaEventOps events_for(const char* who)
{
    MkaEventOps e;
    memset(&e, 0, sizeof(e));
    e.sak_installed = ev_sak_installed;
    e.ctx = (void*)who;
    return e;
}

static void pump(MkaParticipant* A, MkaParticipant* B, Queue* a2b, Queue* b2a,
    uint32_t t)
{
    uint8_t f[MKA_MKPDU_MAX_LEN];
    size_t n;
    wm_Participant_Run(A, t, NULL);
    wm_Participant_Run(B, t, NULL);
    while (q_pop(a2b, f, &n))
        wm_Participant_Receive(B, f, n, t);
    while (q_pop(b2a, f, &n))
        wm_Participant_Receive(A, f, n, t);
}

int main(void)
{
    Queue a2b, b2a;
    MkaParticipant A, B;
    MkaParticipantConfig ca, cb;
    MkaParticipant* ks;
    MkaCmacCtx* cmac;
    MkaRandom* rng;
    int tick;
    int rc;

    memset(&a2b, 0, sizeof(a2b));
    memset(&b2a, 0, sizeof(b2a));

    printf("wolfMKA rekey demo - make-before-break SAK rollover\n");
    printf("========================================================\n");

    cmac = wm_Crypto_CmacInit();
    if (cmac == NULL) {
        printf("cmac init failed\n");
        return 1;
    }
    rng = wm_Crypto_RandomInit();
    if (rng == NULL) {
        fprintf(stderr, "could not acquire RNG workspace\n");
        wm_Crypto_RandomFree(rng);
        wm_Crypto_CmacFree(cmac);
        return 1;
    }

    memset(&ca, 0, sizeof(ca));
    memset(ca.cak.cak, 0xCA, 16);
    ca.cak.cak_len = 16;
    memcpy(ca.cak.ckn, "rekey-connectivity-association", 30);
    ca.cak.ckn_len = 30;
    ca.cmac = cmac;
    ca.rng = rng;
    cb = ca;

    {
        uint8_t sci[8] = {0x02, 0, 0, 0, 0, 0xAA, 0, 0x01};
        memcpy(ca.sci, sci, 8);
    }
    ca.priority = 10;
    ca.macsec_desired = 1;
    ca.macsec_capability = MKA_CAP_INTEGRITY_CONF_OFFSET;
    ca.confidentiality_offset = MKA_CONF_OFFSET_0;
    ca.key_server_capable = 1;
    ca.sak_len = 16;
    ca.secy = secy_for("A");
    ca.events = events_for("A");
    ca.send = send_to;
    ca.send_ctx = &a2b;

    {
        uint8_t sci[8] = {0x02, 0, 0, 0, 0, 0xBB, 0, 0x01};
        memcpy(cb.sci, sci, 8);
    }
    cb.priority = 20;
    cb.macsec_desired = 1;
    cb.macsec_capability = MKA_CAP_INTEGRITY_CONF_OFFSET;
    cb.confidentiality_offset = MKA_CONF_OFFSET_0;
    cb.key_server_capable = 1;
    cb.sak_len = 16;
    cb.secy = secy_for("B");
    cb.events = events_for("B");
    cb.send = send_to;
    cb.send_ctx = &b2a;

    if (wm_Participant_Init(&A, &ca) != MKA_OK ||
        wm_Participant_Init(&B, &cb) != MKA_OK) {
        printf("init failed\n");
        wm_Crypto_RandomFree(rng);
        wm_Crypto_CmacFree(cmac);
        return 1;
    }

    /* Phase 1: converge on the first SAK (kn=1). */
    printf("-- converging on the initial SAK --\n");
    for (tick = 0; tick < 8; tick++)
        pump(&A, &B, &a2b, &b2a, (uint32_t)tick * MKA_HELLO_TIME_MS);

    if (!wm_Participant_HasSak(&A) || !wm_Participant_HasSak(&B)) {
        printf("Result     : FAILURE - initial SAK not established\n");
        wm_Participant_Free(&A);
        wm_Participant_Free(&B);
        wm_Crypto_RandomFree(rng);
        wm_Crypto_CmacFree(cmac);
        return 1;
    }
    printf("   initial SAK: A kn=%u, B kn=%u\n", A.latest.kn, B.latest.kn);

    /* Phase 2: the Key Server rolls the key over. Rekey is a Key-Server-only
     * operation, so issue it on whichever participant won the election. */
    ks = wm_Participant_IsKeyServer(&A) ? &A : &B;
    printf("-- Key Server (%s) issues a rekey --\n", (ks == &A) ? "A" : "B");
    if (wm_Participant_Rekey(ks) != MKA_OK) {
        printf("Result     : FAILURE - rekey request rejected\n");
        wm_Participant_Free(&A);
        wm_Participant_Free(&B);
        wm_Crypto_RandomFree(rng);
        wm_Crypto_CmacFree(cmac);
        return 1;
    }

    /* Run the handover to completion. */
    for (tick = 8; tick < 18; tick++)
        pump(&A, &B, &a2b, &b2a, (uint32_t)tick * MKA_HELLO_TIME_MS);

    printf("========================================================\n");
    printf("   after rekey: A kn=%u, B kn=%u\n", A.latest.kn, B.latest.kn);
    if (A.latest.kn == 2 && B.latest.kn == 2 &&
        A.latest.sak_len == B.latest.sak_len &&
        memcmp(A.latest.sak, B.latest.sak, A.latest.sak_len) == 0) {
        printf("Result     : SUCCESS - both endpoints rolled to the new SAK "
               "(kn 1 -> 2)\n");
        rc = 0;
    }
    else {
        printf("Result     : FAILURE - rekey did not converge\n");
        rc = 1;
    }
    wm_Participant_Free(&A);
    wm_Participant_Free(&B);
    wm_Crypto_RandomFree(rng);
    wm_Crypto_CmacFree(cmac);
    return rc;
}
