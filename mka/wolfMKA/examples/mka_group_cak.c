/* mka_group_cak.c
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
 * Demonstrates the optional Distributed CAK feature (WOLFMKA_DISTRIBUTED_CAK):
 * a Key Server on an established (pairwise) Connectivity Association hands a
 * *group* CAK to a member, and the member's integrator starts a brand-new group
 * CA for it. This closes the loop wolfMKA deliberately leaves open - the
 * library unwraps and *delivers* the CAK through the cak_received event; the
 * integrator decides whether to create the CA, here with
 * wm_Kay_AddParticipant.
 *
 * Each port runs an MkaKay manager that carries several CKN participants and
 * routes inbound MKPDUs to the right one by CKN, so the pairwise CA and the
 * bootstrapped group CA share one link.
 *
 * Build:  make example-distcak
 */

#include <stdio.h>
#include <string.h>

#include "wolfmka/mka_kay.h"
#include "wolfmka/mka_crypto.h"

#ifdef WOLFMKA_DISTRIBUTED_CAK

/* ------------------------------------------------------------------ link -- */
typedef struct {
    uint8_t buf[16][MKA_MKPDU_MAX_LEN];
    size_t len[16];
    int head, tail;
} Queue;

static void q_push(Queue* q, const uint8_t* f, size_t n)
{
    int s = q->tail % 16;
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
    s = q->head % 16;
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
/* This demo is about the control plane, so the SecY hooks are no-ops. */
static int sc_noop(void* c, const uint8_t* sci)
{
    (void)c;
    (void)sci;
    return 0;
}
static int sa_noop(void* c, const uint8_t* sci, uint8_t an, uint32_t kn,
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
static MkaSecyOps secy_noop(void)
{
    MkaSecyOps o;
    memset(&o, 0, sizeof(o));
    o.create_tx_sc = sc_noop;
    o.create_rx_sc = sc_noop;
    o.install_tx_sa = sa_noop;
    o.install_rx_sa = sa_noop;
    o.enable_transmit = en_tx_noop;
    o.enable_receive = en_rx_noop;
    return o;
}

static void hexline(const char* tag, const uint8_t* p, size_t n)
{
    size_t i;
    printf("%s", tag);
    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
    printf("\n");
}

/* -------------------------------------------------- integrator CAK policy --
 */
/* The cak_received event fires from inside wm_Kay_Receive, and a handler
 * must not re-enter the KaY it is called from. So the member's policy here just
 * *records* the delivered group CAK; the new CA is created after the receive
 * returns (the deferred-add pattern). */
typedef struct {
    int have;
    uint8_t cak[MKA_MAX_CAK_LEN];
    size_t cak_len;
    uint8_t ckn[MKA_MAX_CKN_LEN];
    size_t ckn_len;
} CakInbox;

static void on_cak_received(void* ctx, const uint8_t* cak, size_t cak_len,
    const uint8_t* ckn, size_t ckn_len)
{
    CakInbox* in = (CakInbox*)ctx;
    if (in->have) {
        return; /* already delivered; a real integrator ignores re-sends */
    }
    /* Defensive bound an integrator should keep even though the library never
     * delivers more than the inbox (MKA_MAX_*) can hold. */
    if ((cak_len > sizeof in->cak) || (ckn_len > sizeof in->ckn)) {
        return;
    }
    memcpy(in->cak, cak, cak_len);
    in->cak_len = cak_len;
    memcpy(in->ckn, ckn, ckn_len);
    in->ckn_len = ckn_len;
    in->have = 1;
    printf("  [B] cak_received: a group CAK was distributed to us\n");
    hexline("        CAK = ", cak, cak_len);
    hexline("        CKN = ", ckn, ckn_len);
}

/* Build a group-CA participant config from a (just-learned or chosen) CAK. */
static void group_cfg(MkaParticipantConfig* c, const uint8_t* cak,
    size_t cak_len, const uint8_t* ckn, size_t ckn_len, const uint8_t sci[8],
    uint8_t priority, Queue* tx, MkaCmacCtx* cmac)
{
    memset(c, 0, sizeof(*c));
    memcpy(c->cak.cak, cak, cak_len);
    c->cak.cak_len = cak_len;
    memcpy(c->cak.ckn, ckn, ckn_len);
    c->cak.ckn_len = ckn_len;
    memcpy(c->sci, sci, 8);
    c->priority = priority;
    c->macsec_desired = 1;
    c->macsec_capability = MKA_CAP_INTEGRITY_CONF_OFFSET;
    c->key_server_capable = 1;
    c->sak_len = 16;
    c->secy = secy_noop();
    c->send = send_to;
    c->send_ctx = tx;
    c->cmac = cmac;
}

int main(void)
{
    /* Shared pairwise CAK (provisioned out of band or via EAP). */
    static const uint8_t pw_cak[16] = {0xCA, 0xCA, 0xCA, 0xCA, 0xCA, 0xCA, 0xCA,
        0xCA, 0xCA, 0xCA, 0xCA, 0xCA, 0xCA, 0xCA, 0xCA, 0xCA};
    static const uint8_t pw_ckn[8] = {'p', 'a', 'i', 'r', 'w', 'i', 's', 'e'};
    /* The group CAK the Key Server will distribute (a real KS would generate it
     * randomly with wm_Crypto_Random; fixed here for a reproducible demo).
     */
    static const uint8_t grp_cak[16] = {0x67, 0x66, 0x65, 0x64, 0x63, 0x62,
        0x61, 0x60, 0x6F, 0x6E, 0x6D, 0x6C, 0x6B, 0x6A, 0x69, 0x68};
    static const uint8_t grp_ckn[7] = {'g', 'r', 'o', 'u', 'p', '-', 'a'};
    static const uint8_t sci_a[8] = {0x02, 0, 0, 0, 0, 0xAA, 0, 0x01};
    static const uint8_t sci_b[8] = {0x02, 0, 0, 0, 0, 0xBB, 0, 0x01};

    Queue a2b, b2a;
    MkaKay kayA, kayB;
    MkaParticipantConfig ca, cb;
    MkaCmacCtx* cmac;
    CakInbox inbox;
    int tick;
    int a_group_started = 0;
    int b_group_started = 0;

    memset(&a2b, 0, sizeof(a2b));
    memset(&b2a, 0, sizeof(b2a));
    memset(&inbox, 0, sizeof(inbox));

    printf("wolfMKA Distributed CAK demo\n");
    printf("============================\n");
    printf("A pairwise Key Server distributes a group CAK; B's integrator\n"
           "starts a new group CA from the cak_received event.\n");

    /* One CMAC workspace shared by every participant (required for ICV + key
     * derivation); the demo is single-threaded so sequential use is safe. */
    cmac = wm_Crypto_CmacInit();
    if (cmac == NULL) {
        printf("cmac init failed\n");
        return 1;
    }

    if ((wm_Kay_Init(&kayA) != MKA_OK) || (wm_Kay_Init(&kayB) != MKA_OK)) {
        printf("kay init failed\n");
        wm_Crypto_CmacFree(cmac);
        return 1;
    }

    /* Pairwise CA on each port (A favoured as Key Server: priority 10). */
    group_cfg(&ca, pw_cak, 16, pw_ckn, 8, sci_a, 10, &a2b, cmac);
    group_cfg(&cb, pw_cak, 16, pw_ckn, 8, sci_b, 20, &b2a, cmac);
    /* B's pairwise participant reports any distributed CAK to our policy. */
    cb.events.cak_received = on_cak_received;
    cb.events.ctx = &inbox;
    if ((wm_Kay_AddParticipant(&kayA, &ca, NULL) != MKA_OK) ||
        (wm_Kay_AddParticipant(&kayB, &cb, NULL) != MKA_OK)) {
        printf("pairwise setup failed\n");
        wm_Kay_Free(&kayA);
        wm_Kay_Free(&kayB);
        wm_Crypto_CmacFree(cmac);
        return 1;
    }

    for (tick = 0; tick < 20; tick++) {
        uint32_t t = (uint32_t)tick * MKA_HELLO_TIME_MS;
        uint8_t f[MKA_MKPDU_MAX_LEN];
        size_t n;

        /* Once the pairwise CA is up, the Key Server (A) stages the group CAK
         * for distribution and starts its own side of the group CA. */
        if (!a_group_started) {
            MkaParticipant* pw_a = wm_Kay_Find(&kayA, pw_ckn, 8);
            if ((pw_a != NULL) && wm_Participant_IsKeyServer(pw_a) &&
                (wm_Participant_LivePeerCount(pw_a) > 0U)) {
                MkaParticipantConfig gc;
                printf("\n-- t = %u ms : pairwise CA up, A distributes a group "
                       "CAK --\n",
                    t);
                if (wm_Participant_DistributeCak(pw_a, grp_cak, 16, grp_ckn,
                        7) != MKA_OK) {
                    printf("  [A] DistributeCak failed\n");
                }
                group_cfg(&gc, grp_cak, 16, grp_ckn, 7, sci_a, 10, &a2b, cmac);
                if (wm_Kay_AddParticipant(&kayA, &gc, NULL) != MKA_OK) {
                    printf("  [A] group CA add failed\n");
                }
                a_group_started = 1;
            }
        }

        wm_Kay_Run(&kayA, t);
        wm_Kay_Run(&kayB, t);

        while (q_pop(&a2b, f, &n))
            wm_Kay_Receive(&kayB, f, n, t);
        while (q_pop(&b2a, f, &n))
            wm_Kay_Receive(&kayA, f, n, t);

        /* Deferred add: now that Receive has returned, B's integrator creates
         * the group CA for the CAK that was delivered to the inbox. */
        if (inbox.have && !b_group_started) {
            MkaParticipantConfig gc;
            printf(
                "  [B] integrator starts a group CA for the delivered CAK\n");
            group_cfg(&gc, inbox.cak, inbox.cak_len, inbox.ckn, inbox.ckn_len,
                sci_b, 20, &b2a, cmac);
            if (wm_Kay_AddParticipant(&kayB, &gc, NULL) != MKA_OK) {
                printf("  [B] group CA add failed\n");
            }
            b_group_started = 1;
        }
    }

    /* Did the bootstrapped group CA converge on a shared SAK? */
    {
        MkaParticipant* ga = wm_Kay_Find(&kayA, grp_ckn, 7);
        MkaParticipant* gb = wm_Kay_Find(&kayB, grp_ckn, 7);
        int ok =
            (ga != NULL) && (gb != NULL) && wm_Participant_HasSak(ga) &&
            wm_Participant_HasSak(gb) &&
            (ga->latest.sak_len == gb->latest.sak_len) &&
            (memcmp(ga->latest.sak, gb->latest.sak, ga->latest.sak_len) == 0);

        printf("\n============================\n");
        if (ok) {
            printf("Result : SUCCESS - group CA bootstrapped from the pairwise "
                   "CA;\n         both ends agreed a group SAK (kn=%u)\n",
                ga->latest.kn);
            hexline("Group SAK : ", ga->latest.sak, ga->latest.sak_len);
        }
        else {
            printf("Result : FAILURE - group CA did not converge\n");
        }
        wm_Kay_Free(&kayA);
        wm_Kay_Free(&kayB);
        wm_Crypto_CmacFree(cmac);
        return ok ? 0 : 1;
    }
}

#else /* !WOLFMKA_DISTRIBUTED_CAK */

int main(void)
{
    printf("mka_group_cak: build with -DWOLFMKA_DISTRIBUTED_CAK "
           "(make example-distcak)\n");
    return 0;
}

#endif /* WOLFMKA_DISTRIBUTED_CAK */
