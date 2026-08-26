/* mka_xpn.c
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
 * Extended Packet Numbering (XPN, IEEE Std 802.1Xbx-2014 / 802.1AE-2018).
 *
 * The default GCM-AES suites carry a 32-bit packet number, which exhausts in
 * seconds at 100 Gb/s and forces frequent rekeys. The XPN suites widen the PN
 * to 64 bits, at the cost of a per-SA Short SCI (SSCI) and an initialisation
 * vector salt that the SecY derives from the Key Identifier. wolfMKA surfaces
 * exactly two
 * XPN-specific obligations on the data plane:
 *
 *   - set_cipher_suite() receives the negotiated suite, the per-channel SSCI
 *     (assigned by the Key Server) and the confidentiality offset, and is
 *     called before any SA is installed.
 *   - get_next_pn() / set_lowest_pn() carry the FULL 64-bit packet number: the
 *     low 32 bits travel in the SAK Use set and the high 32 bits in the XPN
 *     parameter set (11.11.6). The same hooks serve the 32-bit suites, which
 *     simply leave the high half zero.
 *
 * This example selects GCM-AES-XPN-128, drives those hooks (printing the SSCI
 * and a deliberately >2^32 packet number to show the wide numbering), and
 * converges two participants on an XPN SAK.
 *
 * Build:  make examples   (or see README.md)
 */

#include <stdio.h>
#include <string.h>

#include "wolfmka/mka_kay.h"
#include "wolfmka/mka_crypto.h"

#ifdef WOLFMKA_NO_XPN

int main(void)
{
    printf("wolfMKA was built with WOLFMKA_NO_XPN; "
           "the XPN cipher suites are not compiled in.\n");
    return 0;
}

#else

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
 * An XPN-aware data plane. The transmit packet number is seeded past 2^32 so
 * get_next_pn returns a value whose high half is non-zero - the case the
 * 32-bit suites can never reach and the reason XPN exists. */
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

/* The Key Server hands each channel its negotiated suite and SSCI here. */
static int set_cipher(void* c, const uint8_t sci[MKA_SCI_LEN],
    uint64_t cipher_suite, uint32_t ssci, uint8_t conf_offset)
{
    (void)sci;
    printf("  [%s] SecY set cipher=0x%08lx%08lx ssci=%u conf_offset=%u\n",
        (const char*)c, (unsigned long)(cipher_suite >> 32),
        (unsigned long)(cipher_suite & 0xFFFFFFFFU), (unsigned)ssci,
        (unsigned)conf_offset);
    return 0;
}

/* Advertise a 64-bit next-PN well past the 32-bit ceiling (0x1_0000_0000+),
 * so the high 32 bits must travel in the XPN parameter set. Printed once - the
 * KaY polls it every transmit cycle, but the value is what matters here. */
static int g_shown_pn;
static int get_next_pn(void* c, uint8_t an, uint64_t* next_pn)
{
    (void)an;
    *next_pn = (uint64_t)0x00000001U << 32 | (uint64_t)0x23456789U;
    if (!g_shown_pn) {
        g_shown_pn = 1;
        printf("  [%s] SecY get_next_pn -> 0x%08lx%08lx "
               "(high half is non-zero: XPN)\n",
            (const char*)c, (unsigned long)(*next_pn >> 32),
            (unsigned long)(*next_pn & 0xFFFFFFFFU));
    }
    return 0;
}

/* Receive the peer's full 64-bit Lowest Acceptable PN (delay protection);
 * printed once for the same reason. */
static int g_shown_low;
static int set_lowest_pn(void* c, const uint8_t sci[MKA_SCI_LEN], uint8_t an,
    uint64_t lowest_pn)
{
    (void)sci;
    (void)an;
    if (!g_shown_low) {
        g_shown_low = 1;
        printf("  [%s] SecY set_lowest_pn <- 0x%08lx%08lx\n", (const char*)c,
            (unsigned long)(lowest_pn >> 32),
            (unsigned long)(lowest_pn & 0xFFFFFFFFU));
    }
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
    o.set_cipher_suite = set_cipher;
    o.get_next_pn = get_next_pn;
    o.set_lowest_pn = set_lowest_pn;
    o.ctx = (void*)who;
    return o;
}

int main(void)
{
    Queue a2b, b2a;
    MkaParticipant A, B;
    MkaParticipantConfig ca, cb;
    MkaCmacCtx* cmac;
    MkaRandom* rng;
    MkaSakInfo info;
    int tick;
    int rc;

    memset(&a2b, 0, sizeof(a2b));
    memset(&b2a, 0, sizeof(b2a));

    printf("wolfMKA XPN demo - GCM-AES-XPN-128 with 64-bit packet numbers\n");
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
    memcpy(ca.cak.ckn, "xpn-connectivity-association", 28);
    ca.cak.ckn_len = 28;
    /* Select the XPN suite; its 128-bit key keeps sak_len at 16 (XPN-256 would
     * be sak_len 32). delay_protect drives the get_next_pn / set_lowest_pn
     * exchange that advertises the wide PN. */
    ca.cipher_suite = MKA_CIPHER_GCM_AES_XPN_128;
    ca.cmac = cmac;
    ca.rng = rng;
    cb = ca; /* same CAK/CKN, suite and (shared) CMAC workspace */

    {
        uint8_t sci[8] = {0x02, 0, 0, 0, 0, 0xAA, 0, 0x01};
        memcpy(ca.sci, sci, 8);
    }
    ca.priority = 10;
    ca.macsec_desired = 1;
    ca.macsec_capability = MKA_CAP_INTEGRITY_CONF_OFFSET;
    ca.confidentiality_offset = MKA_CONF_OFFSET_0;
    ca.key_server_capable = 1;
    ca.delay_protect = 1;
    ca.sak_len = 16;
    ca.secy = secy_for("A");
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
    cb.delay_protect = 1;
    cb.sak_len = 16;
    cb.secy = secy_for("B");
    cb.send = send_to;
    cb.send_ctx = &b2a;

    if (wm_Participant_Init(&A, &ca) != MKA_OK ||
        wm_Participant_Init(&B, &cb) != MKA_OK) {
        printf("init failed\n");
        wm_Crypto_RandomFree(rng);
        wm_Crypto_CmacFree(cmac);
        return 1;
    }

    for (tick = 0; tick < 10; tick++) {
        uint32_t t = (uint32_t)tick * MKA_HELLO_TIME_MS;
        uint8_t f[MKA_MKPDU_MAX_LEN];
        size_t n;

        wm_Participant_Run(&A, t, NULL);
        wm_Participant_Run(&B, t, NULL);
        while (q_pop(&a2b, f, &n))
            wm_Participant_Receive(&B, f, n, t);
        while (q_pop(&b2a, f, &n))
            wm_Participant_Receive(&A, f, n, t);
    }

    printf("========================================================\n");
    /* The in-force cipher suite is read through the public snapshot getter
     * (MkaSakInfo deliberately omits the key bytes); the SAK octets themselves
     * are compared directly to prove both ends hold the same key. */
    if (wm_Participant_HasSak(&A) && wm_Participant_HasSak(&B) &&
        A.latest.sak_len == B.latest.sak_len &&
        memcmp(A.latest.sak, B.latest.sak, A.latest.sak_len) == 0 &&
        wm_Participant_GetSak(&A, &info) == MKA_OK &&
        info.cipher_suite == MKA_CIPHER_GCM_AES_XPN_128) {
        printf("Result     : SUCCESS - agreed an XPN SAK "
               "(suite=0x%08lx%08lx kn=%u)\n",
            (unsigned long)(info.cipher_suite >> 32),
            (unsigned long)(info.cipher_suite & 0xFFFFFFFFU), info.kn);
        rc = 0;
    }
    else {
        printf("Result     : FAILURE - endpoints did not converge on XPN\n");
        rc = 1;
    }
    wm_Participant_Free(&A);
    wm_Participant_Free(&B);
    wm_Crypto_RandomFree(rng);
    wm_Crypto_CmacFree(cmac);
    return rc;
}

#endif /* WOLFMKA_NO_XPN */
