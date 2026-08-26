/* mka_demo.c
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
 * A self-contained demonstration of wolfMKA: two MKA participants on opposite
 * ends of a (simulated) point-to-point link share a pre-shared CAK, discover
 * one another, elect a Key Server, and agree on a Secure Association Key.
 *
 * The "link" is just two in-process frame queues; in a real deployment the
 * send callback would write the EAPOL-MKA frame to a raw socket (EtherType
 * 0x888E, destination 01-80-C2-00-00-03) and received frames would be fed to
 * wm_Participant_Receive().
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

/* ------------------------------------------------------------------ SecY -- */
static int sc_noop(void* c, const uint8_t* sci)
{
    (void)c;
    (void)sci;
    return 0;
}

static void hexline(const char* tag, const uint8_t* p, size_t n)
{
    size_t i;
    printf("%s", tag);
    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
    printf("\n");
}

static int install_tx(void* c, const uint8_t* sci, uint8_t an, uint32_t kn,
    const uint8_t* sak, size_t len)
{
    const char* who = (const char*)c;
    (void)sci;
    printf("  [%s] SecY install TX SA  an=%u kn=%u\n", who, an, kn);
    hexline("        SAK = ", sak, len);
    return 0;
}
static int install_rx(void* c, const uint8_t* sci, uint8_t an, uint32_t kn,
    const uint8_t* sak, size_t len)
{
    const char* who = (const char*)c;
    (void)sci;
    (void)kn;
    printf("  [%s] SecY install RX SA  an=%u\n", who, an);
    hexline("        SAK = ", sak, len);
    return 0;
}
static int en_tx(void* c, uint8_t an, bool e)
{
    (void)c;
    (void)an;
    (void)e;
    return 0;
}
static int en_rx(void* c, const uint8_t* s, uint8_t an, bool e)
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
    o.install_tx_sa = install_tx;
    o.install_rx_sa = install_rx;
    o.enable_transmit = en_tx;
    o.enable_receive = en_rx;
    o.ctx = (void*)who;
    return o;
}

/* ---------------------------------------------------------------- events -- */
/* The optional MkaEventOps hooks narrate the protocol's milestones - peer
 * discovery, liveness, Key Server election, SAK install and the transmit gate
 * opening - as they happen, instead of polling the state each tick. A real
 * integration would route these to syslog, a management MIB or a status LED;
 * here they just print. Every field is optional: leave a hook NULL to ignore
 * that event. */
static void ev_peer_added(void* ctx, const uint8_t mi[MKA_MI_LEN],
    const uint8_t sci[MKA_SCI_LEN])
{
    (void)mi;
    (void)sci;
    printf("  [%s] event: peer added\n", (const char*)ctx);
}
static void ev_peer_live(void* ctx, const uint8_t mi[MKA_MI_LEN])
{
    (void)mi;
    printf("  [%s] event: peer is live\n", (const char*)ctx);
}
static void ev_peer_lost(void* ctx, const uint8_t mi[MKA_MI_LEN], bool was_live)
{
    (void)mi;
    printf("  [%s] event: peer lost (was_live=%d)\n", (const char*)ctx,
        (int)was_live);
}
static void ev_key_server(void* ctx, const uint8_t sci[MKA_SCI_LEN],
    bool is_self)
{
    (void)sci;
    printf("  [%s] event: key server elected (self=%d)\n", (const char*)ctx,
        (int)is_self);
}
static void ev_sak_installed(void* ctx, uint32_t kn, uint8_t an,
    uint64_t cipher_suite)
{
    printf("  [%s] event: SAK installed kn=%u an=%u cipher=0x%08lx%08lx\n",
        (const char*)ctx, kn, an, (unsigned long)(cipher_suite >> 32),
        (unsigned long)(cipher_suite & 0xFFFFFFFFU));
}
static void ev_macsec_up(void* ctx, uint32_t kn, uint8_t an)
{
    printf("  [%s] event: MACsec transmit enabled kn=%u an=%u\n",
        (const char*)ctx, kn, an);
}
static void ev_auth_fail(void* ctx)
{
    printf("  [%s] event: AUTH FAIL - an MKPDU failed ICV\n", (const char*)ctx);
}

static MkaEventOps events_for(const char* who)
{
    MkaEventOps e;
    memset(&e, 0, sizeof(e));
    e.peer_added = ev_peer_added;
    e.peer_live = ev_peer_live;
    e.peer_lost = ev_peer_lost;
    e.key_server_elected = ev_key_server;
    e.sak_installed = ev_sak_installed;
    e.macsec_up = ev_macsec_up;
    e.auth_fail = ev_auth_fail;
    e.ctx = (void*)who;
    return e;
}

int main(void)
{
    Queue a2b, b2a;
    MkaParticipant A, B;
    MkaParticipantConfig ca, cb;
    MkaCmacCtx* cmac;
    MkaRandom* rng;
    int tick;
    int rc;

    memset(&a2b, 0, sizeof(a2b));
    memset(&b2a, 0, sizeof(b2a));

    printf("wolfMKA demo - two participants sharing a pre-shared CAK\n");
    printf("========================================================\n");

    /* A CMAC workspace is required by every participant (ICV + key derivation);
     * one is shared here since the demo drives A and B sequentially. */
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

    /* Shared CAK/CKN (in practice provisioned out of band or via EAP). */
    memset(&ca, 0, sizeof(ca));
    memset(ca.cak.cak, 0xCA, 16);
    ca.cak.cak_len = 16;
    memcpy(ca.cak.ckn, "demo-connectivity-association", 29);
    ca.cak.ckn_len = 29;
    ca.cmac = cmac;
    ca.rng = rng;
    cb = ca; /* same CAK/CKN and (shared) CMAC workspace */

    /* Endpoint A: priority 10 (favoured as Key Server). */
    {
        uint8_t sci[8] = {0x02, 0, 0, 0, 0, 0xAA, 0, 0x01};
        memcpy(ca.sci, sci, 8);
    }
    ca.priority = 10;
    ca.macsec_desired = 1;
    ca.macsec_capability = MKA_CAP_INTEGRITY_CONF_OFFSET;
    ca.key_server_capable = 1;
    ca.sak_len = 16;
    ca.secy = secy_for("A");
    ca.events = events_for("A");
    ca.send = send_to;
    ca.send_ctx = &a2b;

    /* Endpoint B: priority 20. */
    {
        uint8_t sci[8] = {0x02, 0, 0, 0, 0, 0xBB, 0, 0x01};
        memcpy(cb.sci, sci, 8);
    }
    cb.priority = 20;
    cb.macsec_desired = 1;
    cb.macsec_capability = MKA_CAP_INTEGRITY_CONF_OFFSET;
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

    for (tick = 0; tick < 8; tick++) {
        uint32_t t = (uint32_t)tick * MKA_HELLO_TIME_MS;
        uint8_t f[MKA_MKPDU_MAX_LEN];
        size_t n;

        printf("\n-- t = %u ms --\n", t);
        wm_Participant_Run(&A, t, NULL);
        wm_Participant_Run(&B, t, NULL);

        while (q_pop(&a2b, f, &n)) {
            printf("  A -> B  (%lu octet EAPOL-MKA frame)\n", (unsigned long)n);
            wm_Participant_Receive(&B, f, n, t);
        }
        while (q_pop(&b2a, f, &n)) {
            printf("  B -> A  (%lu octet EAPOL-MKA frame)\n", (unsigned long)n);
            wm_Participant_Receive(&A, f, n, t);
        }

        printf("  state: A{live=%lu ks=%d sak=%d}  B{live=%lu ks=%d sak=%d}\n",
            (unsigned long)wm_Participant_LivePeerCount(&A),
            wm_Participant_IsKeyServer(&A), wm_Participant_HasSak(&A),
            (unsigned long)wm_Participant_LivePeerCount(&B),
            wm_Participant_IsKeyServer(&B), wm_Participant_HasSak(&B));
    }

    printf("\n========================================================\n");
    printf("Key Server : %s\n", wm_Participant_IsKeyServer(&A) ? "A" : "B");
    if (wm_Participant_HasSak(&A) && wm_Participant_HasSak(&B) &&
        A.latest.sak_len == B.latest.sak_len &&
        memcmp(A.latest.sak, B.latest.sak, A.latest.sak_len) == 0) {
        printf("Result     : SUCCESS - both endpoints agreed on SAK (kn=%u)\n",
            A.latest.kn);
        hexline("Agreed SAK : ", A.latest.sak, A.latest.sak_len);
        rc = 0;
    }
    else {
        printf("Result     : FAILURE - endpoints did not converge\n");
        rc = 1;
    }
    wm_Participant_Free(&A);
    wm_Participant_Free(&B);
    wm_Crypto_RandomFree(rng);
    wm_Crypto_CmacFree(cmac);
    return rc;
}
