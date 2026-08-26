/* mka_eap.c
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
 * Bootstrapping MKA from an 802.1X EAP exchange rather than a pre-shared CAK.
 *
 * After a successful EAP authentication both peers hold the same Master
 * Session Key (MSK). IEEE Std 802.1X-2010, 9.3.2 derives the CAK and its name
 * (CKN) from that MSK and the two PAE MAC addresses, so neither key is ever
 * configured by hand:
 *
 *   CAK = KDF(MSK, "IEEE8021 EAP CAK", lowerMAC || higherMAC)
 *   CKN = KDF(MSK, "IEEE8021 EAP CKN", SessionId || lowerMAC || higherMAC)
 *
 * The MAC addresses are concatenated lowest-first internally, so both ends
 * derive an identical CAK/CKN regardless of which order they pass them. This
 * example derives the pair on each side (deliberately passing the MACs in
 * opposite orders), confirms they match, and then runs MKA to a SAK exactly as
 * the pre-shared demo does - proving the EAP-derived keys interoperate.
 *
 * The MSK is the KDF key in full, so its length is what selects AES-128 or
 * AES-256 CMAC and must match the CAK length: the 32-octet MSK here derives a
 * 256-bit CAK. Supplying more MSK than CAK is refused rather than silently
 * derived from a prefix - see wm_Crypto_DeriveCakFromMsk.
 *
 * Build:  make examples   (or see README.md)
 */

#include <stdio.h>
#include <string.h>

#include "wolfmka/mka_kay.h"
#include "wolfmka/mka_crypto.h"

#ifdef WOLFMKA_NO_EAP

int main(void)
{
    printf("wolfMKA was built with WOLFMKA_NO_EAP; "
           "the EAP-MSK derivation API is not compiled in.\n");
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

/* ------------------------------------------------------------------ SecY -- */
/* Silent no-op data plane: this example is about key derivation, not SecY
 * programming (see mka_demo.c for a narrated SecY). */
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

static MkaSecyOps secy_noop(void)
{
    MkaSecyOps o;
    memset(&o, 0, sizeof(o));
    o.create_tx_sc = sc_noop;
    o.create_rx_sc = sc_noop;
    o.install_tx_sa = install_noop;
    o.install_rx_sa = install_noop;
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

int main(void)
{
    /* Shared EAP outputs (in a real system these come from the EAP server /
     * AAA, never hard-coded). The MSK is the KDF key in full, and its length is
     * what selects AES-128 or AES-256 CMAC - so it must match the CAK length,
     * and a 32-octet MSK here derives a 256-bit CAK. hostapd arranges the same
     * thing from the other end: wpa_supplicant clamps the MSK to the CAK length
     * before deriving. */
    static const uint8_t msk[32] = {0x4D, 0x53, 0x4B, 0x21, 0x00, 0x01, 0x02,
        0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A,
        0x1B};
    static const uint8_t sid[16] = {'E', 'A', 'P', '-', 'S', 'e', 's', 's', 'i',
        'o', 'n', '-', 'I', 'd', 0x00, 0x01};
    static const uint8_t macA[MKA_MAC_LEN] = {0x02, 0, 0, 0, 0, 0xAA};
    static const uint8_t macB[MKA_MAC_LEN] = {0x02, 0, 0, 0, 0, 0xBB};

    Queue a2b, b2a;
    MkaParticipant A, B;
    MkaParticipantConfig ca, cb;
    MkaCmacCtx* cmac;
    MkaRandom* rng;
    uint8_t cakA[32], cakB[32];
    uint8_t cknA[16], cknB[16];
    int tick;
    int rc;

    memset(&a2b, 0, sizeof(a2b));
    memset(&b2a, 0, sizeof(b2a));

    printf("wolfMKA EAP demo - CAK/CKN derived from an 802.1X EAP MSK\n");
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

    /* Each PAE derives the pair from the MSK and the two MAC addresses. A
     * passes (macA, macB); B passes (macB, macA) - opposite order, to show the
     * derivation is order-independent and both arrive at the same keys. */
    if (wm_Crypto_DeriveCakFromMsk(cmac, msk, sizeof(msk), macA, macB, cakA,
            sizeof(cakA)) != MKA_OK ||
        wm_Crypto_DeriveCknFromMsk(cmac, msk, sizeof(msk), sid, sizeof(sid),
            macA, macB, cknA, sizeof(cknA)) != MKA_OK ||
        wm_Crypto_DeriveCakFromMsk(cmac, msk, sizeof(msk), macB, macA, cakB,
            sizeof(cakB)) != MKA_OK ||
        wm_Crypto_DeriveCknFromMsk(cmac, msk, sizeof(msk), sid, sizeof(sid),
            macB, macA, cknB, sizeof(cknB)) != MKA_OK) {
        printf("EAP key derivation failed\n");
        wm_Crypto_RandomFree(rng);
        wm_Crypto_CmacFree(cmac);
        return 1;
    }

    hexline("A derived CAK = ", cakA, sizeof(cakA));
    hexline("B derived CAK = ", cakB, sizeof(cakB));
    hexline("A derived CKN = ", cknA, sizeof(cknA));
    hexline("B derived CKN = ", cknB, sizeof(cknB));
    if (memcmp(cakA, cakB, sizeof(cakA)) != 0 ||
        memcmp(cknA, cknB, sizeof(cknA)) != 0) {
        printf("Result     : FAILURE - the two ends derived different keys\n");
        wm_Crypto_RandomFree(rng);
        wm_Crypto_CmacFree(cmac);
        return 1;
    }
    printf("Both ends derived an identical CAK/CKN from the shared MSK.\n");

    /* Key the participants with the EAP-derived CAK/CKN and converge. */
    memset(&ca, 0, sizeof(ca));
    memcpy(ca.cak.cak, cakA, sizeof(cakA));
    ca.cak.cak_len = (uint8_t)sizeof(cakA);
    memcpy(ca.cak.ckn, cknA, sizeof(cknA));
    ca.cak.ckn_len = (uint8_t)sizeof(cknA);
    ca.cmac = cmac;
    ca.rng = rng;
    cb = ca; /* same derived CAK/CKN and (shared) CMAC workspace */

    memcpy(ca.sci, macA, MKA_MAC_LEN);
    ca.sci[7] = 1;
    ca.priority = 10;
    ca.macsec_desired = 1;
    ca.macsec_capability = MKA_CAP_INTEGRITY_CONF_OFFSET;
    ca.key_server_capable = 1;
    ca.sak_len = 16;
    ca.secy = secy_noop();
    ca.send = send_to;
    ca.send_ctx = &a2b;

    memcpy(cb.sci, macB, MKA_MAC_LEN);
    cb.sci[7] = 1;
    cb.priority = 20;
    cb.macsec_desired = 1;
    cb.macsec_capability = MKA_CAP_INTEGRITY_CONF_OFFSET;
    cb.key_server_capable = 1;
    cb.sak_len = 16;
    cb.secy = secy_noop();
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

        wm_Participant_Run(&A, t, NULL);
        wm_Participant_Run(&B, t, NULL);
        while (q_pop(&a2b, f, &n))
            wm_Participant_Receive(&B, f, n, t);
        while (q_pop(&b2a, f, &n))
            wm_Participant_Receive(&A, f, n, t);
    }

    printf("========================================================\n");
    if (wm_Participant_HasSak(&A) && wm_Participant_HasSak(&B) &&
        A.latest.sak_len == B.latest.sak_len &&
        memcmp(A.latest.sak, B.latest.sak, A.latest.sak_len) == 0) {
        printf("Result     : SUCCESS - EAP-keyed endpoints agreed on a SAK "
               "(kn=%u)\n",
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

#endif /* WOLFMKA_NO_EAP */
