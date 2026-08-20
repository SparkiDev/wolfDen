/* test_kay.c - drive two MKA participants to a common SAK in process.
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

#include "test_util.h"
#include "wolfmka/mka_kay.h"
#include "wolfmka/mka_crypto.h"

/* ---- a one-direction frame queue ---------------------------------------- */
/* Depth chosen with headroom: the busiest test peaks at 7 in-flight frames, so
 * 16 leaves margin. wire_push surfaces any overflow or over-size frame through
 * g_wire_errors (asserted zero at the end of the suite) rather than silently
 * dropping it, so a future test that exceeds these bounds fails loudly instead
 * of masking a lost frame. */
#define WIRE_SLOTS     16
#define WIRE_FRAME_MAX 512
static int g_wire_errors;
typedef struct {
    uint8_t buf[WIRE_SLOTS][WIRE_FRAME_MAX];
    size_t len[WIRE_SLOTS];
    int head, tail;
} Wire;

static void wire_push(Wire* w, const uint8_t* f, size_t n)
{
    int slot = w->tail % WIRE_SLOTS;
    if ((n > WIRE_FRAME_MAX) || ((w->tail - w->head) >= WIRE_SLOTS)) {
        g_wire_errors++; /* would silently drop/overwrite - flag it instead */
        return;
    }
    memcpy(w->buf[slot], f, n);
    w->len[slot] = n;
    w->tail++;
}
static int wire_pop(Wire* w, uint8_t* f, size_t* n)
{
    int slot;
    if (w->head == w->tail)
        return 0;
    slot = w->head % WIRE_SLOTS;
    memcpy(f, w->buf[slot], w->len[slot]);
    *n = w->len[slot];
    w->head++;
    return 1;
}

/* ---- SecY shim: record what gets installed ------------------------------ */
typedef struct {
    int tx_installed;
    uint8_t tx_sak[32];
    size_t tx_sak_len;
    uint32_t tx_kn;
    int rx_installed;
    uint8_t rx_sak[32];
    size_t rx_sak_len;
    int tx_enabled;
    int rx_enabled;
    /* cipher suite / XPN */
    uint64_t cipher_suite;
    uint8_t conf_offset; /* confidentiality offset from set_cipher_suite */
    uint32_t tx_ssci;    /* SSCI for our own (tx) SC */
    uint32_t rx_ssci;    /* SSCI for the peer (rx) SC */
    uint8_t my_sci[8];   /* set by the test to distinguish tx vs rx SC */
    /* delay protection */
    uint32_t next_pn;
    int set_lowest_pn_calls;
    uint64_t last_lowest_pn;
    /* XPN: 64-bit transmit PN reported to the KaY */
    uint64_t xpn_val;
    /* SA deletion (rekey retirement) */
    int del_calls;
    uint8_t last_del_an;
    /* async SecY: when set, install_tx_sa reports MKA_SECY_PENDING */
    int tx_sa_async;
} Secy;

static int secy_tx_sc(void* c, const uint8_t* sci)
{
    (void)c;
    (void)sci;
    return 0;
}
static int secy_rx_sc(void* c, const uint8_t* sci)
{
    (void)c;
    (void)sci;
    return 0;
}
static int secy_tx_sa(void* c, const uint8_t* sci, uint8_t an, uint32_t kn,
    const uint8_t* sak, size_t len)
{
    Secy* s = (Secy*)c;
    (void)sci;
    (void)an;
    memcpy(s->tx_sak, sak, len);
    s->tx_sak_len = len;
    s->tx_kn = kn;
    s->tx_installed = 1;
    /* Model an asynchronous data plane: accept now, complete later. */
    return s->tx_sa_async ? MKA_SECY_PENDING : 0;
}
static int secy_rx_sa(void* c, const uint8_t* sci, uint8_t an, uint32_t kn,
    const uint8_t* sak, size_t len)
{
    Secy* s = (Secy*)c;
    (void)sci;
    (void)an;
    (void)kn;
    memcpy(s->rx_sak, sak, len);
    s->rx_sak_len = len;
    s->rx_installed = 1;
    return 0;
}
static int secy_en_tx(void* c, uint8_t an, bool en)
{
    Secy* s = (Secy*)c;
    (void)an;
    s->tx_enabled = en;
    return 0;
}
static int secy_en_rx(void* c, const uint8_t* sci, uint8_t an, bool en)
{
    Secy* s = (Secy*)c;
    (void)sci;
    (void)an;
    s->rx_enabled = en;
    return 0;
}
static int secy_del(void* c, const uint8_t* sci, uint8_t an)
{
    Secy* s = (Secy*)c;
    (void)sci;
    s->del_calls++;
    s->last_del_an = an;
    return 0;
}
static int secy_set_cs(void* c, const uint8_t* sci, uint64_t cs, uint32_t ssci,
    uint8_t conf_offset)
{
    Secy* s = (Secy*)c;
    s->cipher_suite = cs;
    s->conf_offset = conf_offset;
    if (memcmp(sci, s->my_sci, 8) == 0) {
        s->tx_ssci = ssci;
    }
    else {
        s->rx_ssci = ssci;
    }
    return 0;
}
static int secy_get_pn(void* c, uint8_t an, uint64_t* pn)
{
    Secy* s = (Secy*)c;
    (void)an;
    s->next_pn++;
    *pn = s->next_pn;
    return 0;
}
#ifndef WOLFMKA_NO_XPN
static int secy_get_pn_xpn(void* c, uint8_t an, uint64_t* pn)
{
    Secy* s = (Secy*)c;
    (void)an;
    *pn = s->xpn_val;
    return 0;
}
#endif
static int secy_set_lpn(void* c, const uint8_t* sci, uint8_t an, uint64_t lpn)
{
    Secy* s = (Secy*)c;
    (void)sci;
    (void)an;
    s->last_lowest_pn = lpn;
    s->set_lowest_pn_calls++;
    return 0;
}

static MkaSecyOps make_secy(Secy* s)
{
    MkaSecyOps ops;
    memset(&ops, 0, sizeof(ops));
    ops.create_tx_sc = secy_tx_sc;
    ops.create_rx_sc = secy_rx_sc;
    ops.install_tx_sa = secy_tx_sa;
    ops.install_rx_sa = secy_rx_sa;
    ops.enable_transmit = secy_en_tx;
    ops.enable_receive = secy_en_rx;
    ops.delete_sa = secy_del;
    ops.set_cipher_suite = secy_set_cs;
    ops.get_next_pn = secy_get_pn;
    ops.set_lowest_pn = secy_set_lpn;
    ops.ctx = s;
    return ops;
}

/* ---- send callbacks: queue onto the peer's wire ------------------------- */
static int send_a(void* ctx, const uint8_t* f, size_t n)
{
    wire_push((Wire*)ctx, f, n);
    return 0;
}
static int send_b(void* ctx, const uint8_t* f, size_t n)
{
    wire_push((Wire*)ctx, f, n);
    return 0;
}
static int send_c(void* ctx, const uint8_t* f, size_t n)
{
    wire_push((Wire*)ctx, f, n);
    return 0;
}
/* A transmit callback that reports failure (non-zero). */
static int send_fail(void* ctx, const uint8_t* f, size_t n)
{
    (void)ctx;
    (void)f;
    (void)n;
    return -1;
}
/* A get-next-PN hook that reports failure (non-zero). */
static int secy_get_pn_fail(void* c, uint8_t an, uint64_t* pn)
{
    (void)c;
    (void)an;
    (void)pn;
    return -1;
}
/* A get-next-PN hook that succeeds (returns 0) with a fixed, recognizable PN,
 * so a test can pin the emitted Lowest-PN to the hook's value. */
static int secy_get_pn_const(void* c, uint8_t an, uint64_t* pn)
{
    (void)c;
    (void)an;
    *pn = 0x12345678U;
    return 0;
}
#ifndef WOLFMKA_NO_XPN
/* An XPN PN hook whose value depends on the AN, so a test can distinguish the
 * Old-key (an 1) PN read from the Latest-key (an 0) read - if the code reused
 * one AN's PN for the other, the emitted Old/Latest LPNs would not differ. */
static int secy_get_pn_xpn_byan(void* c, uint8_t an, uint64_t* pn)
{
    (void)c;
    *pn = (an == 0U) ? 0x0000000B00000007ull : 0x0000000D00000009ull;
    return 0;
}
#endif /* WOLFMKA_NO_XPN */

/* The Message Number a crafted frame must echo for the victim to accept it as
 * proof of liveness: the most recent one the victim emitted (802.1X 9.4.3).
 * A participant that has not transmitted yet is made to emit one first, since
 * no number it never sent can be acceptably recent. */
static uint32_t echo_mn(MkaParticipant* v)
{
    if (v->actor_mn <= 1U) {
        uint8_t f[512];
        size_t n = sizeof f;
        CHECK(wm_Participant_BuildMkpdu(v, f, sizeof f, &n) == MKA_OK,
            "prime the victim's Message Number");
    }
    return v->actor_mn - 1U;
}

static void make_cak(MkaCakPair* cak)
{
    memset(cak, 0, sizeof(*cak));
    memset(cak->cak, 0xCA, 16);
    cak->cak_len = 16; /* shared PSK CAK       */
    memcpy(cak->ckn, "shared-ckn", 10);
    cak->ckn_len = 10;
}

/* The flagship happy path: two participants discover each other, elect a Key
 * Server by priority then SCI, and the elected server distributes a SAK that
 * both install - exercising discovery, election (IEEE Std 802.1X-2010, 9.5)
 * and SAK distribution end to end, with each side's frames routed to the other
 * over the Wire shims. */
static void test_two_party_agreement(void)
{
    Wire a2b, b2a; /* a2b: frames A sends, destined for B          */
    Secy secy_a, secy_b;
    MkaParticipant A, B;
    MkaParticipantConfig ca, cb;
    uint32_t t;
    int tick;

    printf("two-party MKA: discovery, election, SAK distribution:\n");

    memset(&a2b, 0, sizeof(a2b));
    memset(&b2a, 0, sizeof(b2a));
    memset(&secy_a, 0, sizeof(secy_a));
    memset(&secy_b, 0, sizeof(secy_b));

    /* A: higher priority (lower number) -> should win Key Server. */
    memset(&ca, 0, sizeof(ca));
    make_cak(&ca.cak);
    {
        uint8_t sci[8] = {0, 0, 0, 0, 0, 0x0A, 0, 1};
        memcpy(ca.sci, sci, 8);
    }
    ca.priority = 10;
    ca.macsec_desired = 1;
    ca.macsec_capability = MKA_CAP_INTEGRITY_CONF_OFFSET;
    ca.key_server_capable = 1;
    ca.sak_len = 16;
    ca.secy = make_secy(&secy_a);
    ca.send = send_a;
    ca.send_ctx = &a2b;
    ca.cmac = g_cmac;

    /* B: lower priority (higher number). */
    memset(&cb, 0, sizeof(cb));
    make_cak(&cb.cak);
    {
        uint8_t sci[8] = {0, 0, 0, 0, 0, 0x0B, 0, 1};
        memcpy(cb.sci, sci, 8);
    }
    cb.priority = 20;
    cb.macsec_desired = 1;
    cb.macsec_capability = MKA_CAP_INTEGRITY_CONF_OFFSET;
    cb.key_server_capable = 1;
    cb.sak_len = 16;
    cb.secy = make_secy(&secy_b);
    cb.send = send_b;
    cb.send_ctx = &b2a;
    cb.cmac = g_cmac;

    CHECK(wm_Participant_Init(&A, &ca) == MKA_OK, "init A");
    CHECK(wm_Participant_Init(&B, &cb) == MKA_OK, "init B");

    /* Run for several Hello intervals, delivering frames each tick. */
    for (tick = 0; tick < 12; tick++) {
        uint8_t f[512];
        size_t n;
        t = (uint32_t)tick * MKA_HELLO_TIME_MS;

        wm_Participant_Run(&A, t, NULL);
        wm_Participant_Run(&B, t, NULL);

        /* Deliver everything A queued to B and vice versa. */
        while (wire_pop(&a2b, f, &n))
            wm_Participant_Receive(&B, f, n, t);
        while (wire_pop(&b2a, f, &n))
            wm_Participant_Receive(&A, f, n, t);
    }

    /* Liveness established both ways. */
    CHECK(wm_Participant_LivePeerCount(&A) == 1, "A sees 1 live peer");
    CHECK(wm_Participant_LivePeerCount(&B) == 1, "B sees 1 live peer");

    /* Exactly one Key Server, and it is A (priority 10 < 20). */
    CHECK(wm_Participant_IsKeyServer(&A) == 1, "A is key server");
    CHECK(wm_Participant_IsKeyServer(&B) == 0, "B is not key server");

    /* Both installed a SAK and they agree. */
    CHECK(wm_Participant_HasSak(&A), "A has SAK");
    CHECK(wm_Participant_HasSak(&B), "B has SAK");
    CHECK(A.latest.sak_len == 16 && B.latest.sak_len == 16, "SAK len 16");
    CHECK_EQ_MEM(A.latest.sak, B.latest.sak, 16, "A and B agree on SAK");
    CHECK(A.latest.kn == B.latest.kn, "same key number");

    /* SecY received the agreed key on both sides. */
    CHECK(secy_a.tx_installed && secy_b.tx_installed, "tx SAs installed");
    CHECK(secy_a.rx_installed && secy_b.rx_installed, "rx SAs installed");
    CHECK_EQ_MEM(secy_a.tx_sak, secy_b.rx_sak, 16, "A tx == B rx");
    CHECK_EQ_MEM(secy_b.tx_sak, secy_a.rx_sak, 16, "B tx == A rx");
    CHECK(secy_a.tx_enabled && secy_b.tx_enabled, "tx enabled both");

    /* B is Key-Server-capable but LOST the election (A has higher priority), so
     * a rekey on B is rejected - the NOT_KS guard fires on a
     * dynamically-elected non-Key-Server, not just a statically-incapable one.
     */
    CHECK(wm_Participant_Rekey(&B) == MKA_ERR_NOT_KS,
        "KS-capable member that lost the election cannot rekey");
}

/* A participant that is not Key-Server-capable must never self-elect. */
static void test_non_ks_capable(void)
{
    MkaParticipant A;
    MkaParticipantConfig ca;
    Secy secy_a;
    bool sent;

    printf("non-key-server-capable participant:\n");
    memset(&secy_a, 0, sizeof(secy_a));
    memset(&ca, 0, sizeof(ca));
    make_cak(&ca.cak);
    {
        uint8_t sci[8] = {0, 0, 0, 0, 0, 0x0A, 0, 1};
        memcpy(ca.sci, sci, 8);
    }
    ca.priority = 10;
    ca.macsec_desired = 1;
    ca.macsec_capability = MKA_CAP_INTEGRITY_CONF_OFFSET;
    ca.key_server_capable = 0; /* cannot be Key Server              */
    ca.sak_len = 16;
    ca.secy = make_secy(&secy_a);
    ca.cmac = g_cmac;

    CHECK(wm_Participant_Init(&A, &ca) == MKA_OK, "init");
    wm_Participant_Run(&A, 0, &sent);
    CHECK(wm_Participant_IsKeyServer(&A) == 0, "not self-elected");
    CHECK(wm_Participant_HasSak(&A) == 0, "no SAK without KS");
}

static void cfg_part(MkaParticipantConfig* c, Secy* s, Wire* tx, MkaSendFn snd,
    uint8_t last_octet, uint8_t pri)
{
    uint8_t sci[8] = {0, 0, 0, 0, 0, 0, 0, 1};
    memset(c, 0, sizeof(*c));
    make_cak(&c->cak);
    sci[5] = last_octet;
    memcpy(c->sci, sci, 8);
    c->priority = pri;
    c->macsec_desired = 1;
    c->macsec_capability = MKA_CAP_INTEGRITY_CONF_OFFSET;
    c->key_server_capable = 1;
    c->sak_len = 16;
    c->secy = make_secy(s);
    c->send = snd;
    c->send_ctx = tx;
    c->cmac = g_cmac;
}

/* Equal priority -> Key Server decided by the numerically lower SCI (IEEE Std
 * 802.1X-2010, 9.5). */
static void test_election_tie_break(void)
{
    Wire a2b, b2a;
    Secy sa, sb;
    MkaParticipant A, B;
    MkaParticipantConfig ca, cb;
    int tick;

    printf("election tie-break (equal priority, lower SCI wins):\n");
    memset(&a2b, 0, sizeof a2b);
    memset(&b2a, 0, sizeof b2a);
    memset(&sa, 0, sizeof sa);
    memset(&sb, 0, sizeof sb);
    cfg_part(&ca, &sa, &a2b, send_a, 0x0A, 50); /* same priority 50 */
    cfg_part(&cb, &sb, &b2a, send_b, 0x0B, 50);
    CHECK(wm_Participant_Init(&A, &ca) == MKA_OK, "init A");
    CHECK(wm_Participant_Init(&B, &cb) == MKA_OK, "init B");

    for (tick = 0; tick < 8; tick++) {
        uint8_t f[512];
        size_t n;
        uint32_t t = (uint32_t)tick * MKA_HELLO_TIME_MS;
        wm_Participant_Run(&A, t, NULL);
        wm_Participant_Run(&B, t, NULL);
        while (wire_pop(&a2b, f, &n))
            wm_Participant_Receive(&B, f, n, t);
        while (wire_pop(&b2a, f, &n))
            wm_Participant_Receive(&A, f, n, t);
    }
    CHECK(wm_Participant_IsKeyServer(&A) == 1, "A (lower SCI) is KS");
    CHECK(wm_Participant_IsKeyServer(&B) == 0, "B yields on tie");
}

/* A peer that goes silent is expired after the MKA Life Time. */
static void test_peer_expiry(void)
{
    Wire a2b, b2a;
    Secy sa, sb;
    MkaParticipant A, B;
    MkaParticipantConfig ca, cb;
    uint32_t t = 0;
    int tick;

    printf("peer expiry after MKA Life Time:\n");
    memset(&a2b, 0, sizeof a2b);
    memset(&b2a, 0, sizeof b2a);
    memset(&sa, 0, sizeof sa);
    memset(&sb, 0, sizeof sb);
    cfg_part(&ca, &sa, &a2b, send_a, 0x0A, 10);
    cfg_part(&cb, &sb, &b2a, send_b, 0x0B, 20);
    CHECK(wm_Participant_Init(&A, &ca) == MKA_OK, "init A");
    CHECK(wm_Participant_Init(&B, &cb) == MKA_OK, "init B");

    for (tick = 0; tick < 8; tick++) {
        uint8_t f[512];
        size_t n;
        t = (uint32_t)tick * MKA_HELLO_TIME_MS;
        wm_Participant_Run(&A, t, NULL);
        wm_Participant_Run(&B, t, NULL);
        while (wire_pop(&a2b, f, &n))
            wm_Participant_Receive(&B, f, n, t);
        while (wire_pop(&b2a, f, &n))
            wm_Participant_Receive(&A, f, n, t);
    }
    CHECK(wm_Participant_LivePeerCount(&A) == 1, "A has live peer");

    /* B goes silent; advance A's clock past the Life Time without delivery. */
    t += MKA_LIFE_TIME_MS + MKA_HELLO_TIME_MS;
    wm_Participant_Run(&A, t, NULL);
    CHECK(wm_Participant_LivePeerCount(&A) == 0, "A expired silent peer");
}

/* Argument validation and a frame for a foreign CKN. */
static void test_kay_errors(void)
{
    MkaParticipant A;
    MkaParticipantConfig c;
    Secy s;
    uint8_t frame[8] = {0};

    uint8_t out[256];
    size_t olen = sizeof out;

    printf("kay error paths:\n");
    memset(&s, 0, sizeof s);
    cfg_part(&c, &s, NULL, NULL, 0x0A, 10);
    c.sak_len = 20; /* invalid */
    CHECK(wm_Participant_Init(&A, &c) == MKA_ERR_BAD_ARG, "init bad sak_len");
    c.sak_len = 16;
    CHECK(wm_Participant_Init(NULL, &c) == MKA_ERR_BAD_ARG, "init null p");
    CHECK(wm_Participant_Init(&A, NULL) == MKA_ERR_BAD_ARG, "init null cfg");

    /* mka_cipher_suite_valid: every branch. */
    c.cipher_suite = 0xABCDU; /* unsupported */
    CHECK(wm_Participant_Init(&A, &c) == MKA_ERR_BAD_ARG, "init bad cipher");
    c.cipher_suite = MKA_CIPHER_GCM_AES_256; /* needs 32, sak_len 16 */
    CHECK(wm_Participant_Init(&A, &c) == MKA_ERR_BAD_ARG, "init 256 vs 16");
    c.cipher_suite = MKA_CIPHER_GCM_AES_XPN_128;
    c.sak_len = 32;
    CHECK(wm_Participant_Init(&A, &c) == MKA_ERR_BAD_ARG, "init xpn128 vs 32");
    c.cipher_suite = MKA_CIPHER_GCM_AES_128;
    c.sak_len = 16;
    CHECK(wm_Participant_Init(&A, &c) == MKA_OK, "init cs128 ok");
#ifndef WOLFMKA_NO_XPN
    c.cipher_suite = MKA_CIPHER_GCM_AES_XPN_256;
    c.sak_len = 32;
    CHECK(wm_Participant_Init(&A, &c) == MKA_OK, "init xpn256 ok");
#endif
    c.cipher_suite = 0;
    c.sak_len = 16;

    CHECK(wm_Participant_Init(&A, &c) == MKA_OK, "init ok");
    CHECK(wm_Participant_Receive(&A, NULL, 0, 0) == MKA_ERR_BAD_ARG,
        "recv null");
    /* Garbage frame -> rejected (bad ICV or parse), never accepted. */
    CHECK(wm_Participant_Receive(&A, frame, sizeof frame, 0) != MKA_OK,
        "recv garbage");
    /* build_mkpdu / run argument validation. */
    CHECK(wm_Participant_BuildMkpdu(NULL, out, olen, &olen) == MKA_ERR_BAD_ARG,
        "build null p");
    CHECK(wm_Participant_BuildMkpdu(&A, NULL, olen, &olen) == MKA_ERR_BAD_ARG,
        "build null out");
    CHECK(wm_Participant_BuildMkpdu(&A, out, olen, NULL) == MKA_ERR_BAD_ARG,
        "build null len");
    CHECK(wm_Participant_Run(NULL, 0, NULL) == MKA_ERR_BAD_ARG, "run null");
}

/* A valid frame whose CKN differs from ours must be ignored (foreign CA). */
static void test_kay_foreign_ckn(void)
{
    MkaParticipant A;
    MkaParticipantConfig ca;
    Secy sa;
    MkaParticipant Z;
    MkaParticipantConfig cz;
    Secy sz;
    uint8_t frame[256];
    size_t n = sizeof frame;

    printf("foreign-CKN frame ignored:\n");
    memset(&sa, 0, sizeof sa);
    memset(&sz, 0, sizeof sz);
    cfg_part(&ca, &sa, NULL, NULL, 0x0A, 10);
    cfg_part(&cz, &sz, NULL, NULL, 0x0C, 10);
    /* Z uses a different CKN (hence different ICK), so its ICV won't verify
     * under A's ICK -> A rejects it (the CKN check is also exercised when the
     * keys happen to align). */
    memcpy(cz.cak.ckn, "other-ckn!!", 11);
    cz.cak.ckn_len = 11;
    wm_Participant_Init(&A, &ca);
    wm_Participant_Init(&Z, &cz);

    CHECK(wm_Participant_BuildMkpdu(&Z, frame, sizeof frame, &n) == MKA_OK,
        "Z builds");
    CHECK(wm_Participant_Receive(&A, frame, n, 0) != MKA_OK,
        "A rejects foreign CKN");
    CHECK(wm_Participant_LivePeerCount(&A) == 0, "no peer added");
}

/* MKPDU replay protection: the Message Number must strictly increase for a
 * given Member Identifier (IEEE Std 802.1X-2010, 9.4.2). */
static void test_replay_protection(void)
{
    Secy sa, sz;
    MkaParticipant A, Z;
    MkaParticipantConfig ca, cz;
    uint8_t f1[512], f2[512];
    size_t n1 = sizeof f1, n2 = sizeof f2;

    printf("MKPDU replay protection (Message Number):\n");
    memset(&sa, 0, sizeof sa);
    memset(&sz, 0, sizeof sz);
    cfg_part(&ca, &sa, NULL, NULL, 0x0A, 10);
    cfg_part(&cz, &sz, NULL, NULL, 0x0C, 20);
    CHECK(wm_Participant_Init(&A, &ca) == MKA_OK, "init A");
    CHECK(wm_Participant_Init(&Z, &cz) == MKA_OK, "init Z");

    /* Z emits two MKPDUs with increasing MN (1 then 2). */
    CHECK(wm_Participant_BuildMkpdu(&Z, f1, sizeof f1, &n1) == MKA_OK,
        "build1");
    CHECK(wm_Participant_BuildMkpdu(&Z, f2, sizeof f2, &n2) == MKA_OK,
        "build2");

    CHECK(wm_Participant_Receive(&A, f2, n2, 0) == MKA_OK, "accept MN=2");
    CHECK(wm_Participant_Receive(&A, f1, n1, 0) == MKA_ERR_REPLAY,
        "reject older MN");
    CHECK(wm_Participant_Receive(&A, f2, n2, 0) == MKA_ERR_REPLAY,
        "reject duplicate");
}

/* Helper: run A and B to convergence, optionally observing Tx gating. */
static void run_pair(MkaParticipant* A, MkaParticipant* B, Wire* a2b, Wire* b2a,
    int ticks, int* gated_seen)
{
    int tick;
    for (tick = 0; tick < ticks; tick++) {
        uint8_t f[512];
        size_t n;
        uint32_t t = (uint32_t)tick * MKA_HELLO_TIME_MS;
        wm_Participant_Run(A, t, NULL);
        wm_Participant_Run(B, t, NULL);
        if ((gated_seen != NULL) && wm_Participant_HasSak(A) && !A->latest.tx) {
            *gated_seen = 1;
        }
        while (wire_pop(a2b, f, &n))
            wm_Participant_Receive(B, f, n, t);
        while (wire_pop(b2a, f, &n))
            wm_Participant_Receive(A, f, n, t);
    }
}

/* Transmit must stay disabled until the peer reports receiving on the SAK. */
static void test_tx_gating(void)
{
    Wire a2b, b2a;
    Secy sa, sb;
    MkaParticipant A, B;
    MkaParticipantConfig ca, cb;
    int gated = 0;

    printf("Tx gating on peer Rx-readiness:\n");
    memset(&a2b, 0, sizeof a2b);
    memset(&b2a, 0, sizeof b2a);
    memset(&sa, 0, sizeof sa);
    memset(&sb, 0, sizeof sb);
    cfg_part(&ca, &sa, &a2b, send_a, 0x0A, 10);
    cfg_part(&cb, &sb, &b2a, send_b, 0x0B, 20);
    CHECK(wm_Participant_Init(&A, &ca) == MKA_OK, "init A");
    CHECK(wm_Participant_Init(&B, &cb) == MKA_OK, "init B");

    run_pair(&A, &B, &a2b, &b2a, 12, &gated);
    CHECK(gated == 1, "tx was gated while peer not yet rx-ready");
    CHECK(A.latest.tx && B.latest.tx, "tx enabled after rx handshake");
    CHECK(sa.tx_enabled && sb.tx_enabled, "SecY tx enabled both ends");
}

/* Make-before-break rekey: the Key Server rolls to a fresh SAK while the old
 * one stays installed until every peer has moved over, then is retired. */
static void test_rekey(void)
{
    Wire a2b, b2a;
    Secy sa, sb;
    MkaParticipant A, B;
    MkaParticipantConfig ca, cb;
    uint8_t sak1[16];
    int tick;

    printf("make-before-break SAK rekey:\n");
    memset(&a2b, 0, sizeof a2b);
    memset(&b2a, 0, sizeof b2a);
    memset(&sa, 0, sizeof sa);
    memset(&sb, 0, sizeof sb);
    cfg_part(&ca, &sa, &a2b, send_a, 0x0A, 10); /* A: lower pri -> KS */
    cfg_part(&cb, &sb, &b2a, send_b, 0x0B, 20);
    wm_Participant_Init(&A, &ca);
    wm_Participant_Init(&B, &cb);

    /* Converge on the first SAK (kn = 1). */
    run_pair(&A, &B, &a2b, &b2a, 12, NULL);
    CHECK(wm_Participant_IsKeyServer(&A) == 1, "A is key server");
    CHECK(A.latest.valid && A.latest.kn == 1, "A on kn=1");
    CHECK(B.latest.valid && B.latest.kn == 1, "B on kn=1");
    CHECK_EQ_MEM(A.latest.sak, B.latest.sak, 16, "agree on first SAK");
    memcpy(sak1, A.latest.sak, 16);

    /* Trigger a rekey on the Key Server. */
    CHECK(wm_Participant_Rekey(&A) == MKA_OK, "rekey accepted");
    CHECK(A.old.valid && A.old.kn == 1, "old key kept (kn=1)");
    CHECK(A.latest.valid && A.latest.kn == 2, "latest advanced to kn=2");
    CHECK(memcmp(A.latest.sak, sak1, 16) != 0, "new SAK differs from old");
    CHECK(A.old.an != A.latest.an, "old and latest use distinct AN");

    /* A non-Key-Server peer cannot drive a rekey. */
    CHECK(wm_Participant_Rekey(&B) == MKA_ERR_NOT_KS, "B cannot rekey");

    /* Continue running; the new SAK must propagate and the old retire. The
     * clock keeps advancing past the first convergence window. */
    for (tick = 12; tick < 28; tick++) {
        uint8_t f[512];
        size_t n;
        uint32_t t = (uint32_t)tick * MKA_HELLO_TIME_MS;
        wm_Participant_Run(&A, t, NULL);
        wm_Participant_Run(&B, t, NULL);
        while (wire_pop(&a2b, f, &n))
            wm_Participant_Receive(&B, f, n, t);
        while (wire_pop(&b2a, f, &n))
            wm_Participant_Receive(&A, f, n, t);
    }

    /* Both ends now run the new key and agree on it. */
    CHECK(A.latest.kn == 2 && B.latest.kn == 2, "both on kn=2");
    CHECK_EQ_MEM(A.latest.sak, B.latest.sak, 16, "agree on rekeyed SAK");
    CHECK(memcmp(B.latest.sak, sak1, 16) != 0, "B moved off the old SAK");

    /* The old key has been retired on both ends and its SAs deleted. */
    CHECK(A.old.valid == 0, "A retired the old key");
    CHECK(B.old.valid == 0, "B retired the old key");
    CHECK(sa.del_calls > 0, "A deleted old SAs");
    CHECK(sb.del_calls > 0, "B deleted old SAs");
}

/* Two rekeys in a row: the second runs while kn=1 is still the Old key, so
 * kn=1's SAs are force-retired as kn=2 demotes to Old (delete path). */
static void rekey_double_retires_old(MkaParticipant* A, Secy* sa)
{
    CHECK(wm_Participant_Rekey(A) == MKA_OK, "first rekey");
    CHECK(A->old.valid && A->old.kn == 1, "old=kn1 after first rekey");
    sa->del_calls = 0;
    CHECK(wm_Participant_Rekey(A) == MKA_OK, "second rekey (old unfinished)");
    CHECK(A->latest.kn == 3, "latest advanced to kn=3");
    CHECK(A->old.kn == 2, "old is now kn=2");
    CHECK(sa->del_calls > 0, "unfinished old (kn1) SAs force-retired");
}

/* A peer that goes silent during a rekey is expired with the Old key still
 * installed (drop tears down both Latest and Old receive SAs). */
static void rekey_peer_expiry_with_old(MkaParticipant* A, Secy* sa)
{
    uint32_t t;

    sa->del_calls = 0;
    t = 12U * MKA_HELLO_TIME_MS + MKA_LIFE_TIME_MS + MKA_HELLO_TIME_MS;
    wm_Participant_Run(A, t, NULL);
    CHECK(wm_Participant_LivePeerCount(A) == 0, "silent peer expired");
    CHECK(A->old.valid, "old key still installed at expiry");
    CHECK(sa->del_calls > 0, "expired peer's Old + Latest rx SAs deleted");
}

/* A brand-new peer that becomes live mid-rekey gets receive SAs for BOTH the
 * Latest and the still-installed Old key. Bring C up now and deliver only
 * A<->C, so the Old key is never retired while C goes live. */
static void rekey_midjoin_installs_rx(MkaParticipant* A, Secy* sa, Wire* a2b)
{
    Wire c2a;
    Secy sc;
    MkaParticipant C;
    MkaParticipantConfig cc;
    uint32_t t;
    int tick;

    memset(&c2a, 0, sizeof c2a);
    memset(&sc, 0, sizeof sc);
    cfg_part(&cc, &sc, &c2a, send_c, 0x0C, 30);
    wm_Participant_Init(&C, &cc);
    CHECK(A->old.valid, "old key present before C joins");
    sa->rx_installed = 0;
    for (tick = 13; tick < 19; tick++) {
        uint8_t f[512];
        size_t n;
        t = (uint32_t)tick * MKA_HELLO_TIME_MS;
        wm_Participant_Run(A, t, NULL);
        wm_Participant_Run(&C, t, NULL);
        /* A transmits on its own wire (a2b); route those frames to C. */
        while (wire_pop(a2b, f, &n))
            wm_Participant_Receive(&C, f, n, t);
        while (wire_pop(&c2a, f, &n))
            wm_Participant_Receive(A, f, n, t);
    }
    CHECK(wm_Participant_LivePeerCount(A) == 1, "exactly C became live at A");
    CHECK(sa->rx_installed, "A installed a receive SA for the new peer C");
}

/* Rekey edge cases driven as one continuous narrative on a single Key Server A:
 * a second rekey before the first completes, a peer expiring mid-rekey, then a
 * new peer joining mid-rekey. The continuity between stages - A holding its Old
 * key throughout - is itself part of what is verified, so the stages share A
 * (and its SecY) by pointer rather than re-establishing state. */
static void test_rekey_churn(void)
{
    Wire a2b, b2a;
    Secy sa, sb;
    MkaParticipant A, B;
    MkaParticipantConfig ca, cb;

    printf("rekey churn (double rekey, peer expiry, mid-rekey join):\n");
    memset(&a2b, 0, sizeof a2b);
    memset(&b2a, 0, sizeof b2a);
    memset(&sa, 0, sizeof sa);
    memset(&sb, 0, sizeof sb);
    cfg_part(&ca, &sa, &a2b, send_a, 0x0A, 10); /* A: KS */
    cfg_part(&cb, &sb, &b2a, send_b, 0x0B, 20);
    wm_Participant_Init(&A, &ca);
    wm_Participant_Init(&B, &cb);

    /* Converge on kn=1. */
    run_pair(&A, &B, &a2b, &b2a, 12, NULL);
    CHECK(A.latest.kn == 1 && B.latest.kn == 1, "converged on kn=1");

    rekey_double_retires_old(&A, &sa);
    rekey_peer_expiry_with_old(&A, &sa);
    rekey_midjoin_installs_rx(&A, &sa, &a2b);
}

/* White-box: drive the Key Number to its 32-bit maximum so the next rekey
 * increment wraps to 0 and must be reset to the lowest valid KN (1). Reaching
 * this guard in normal operation would take 2^32 rekeys. */
static void test_rekey_kn_wrap(void)
{
    Wire a2b, b2a;
    Secy sa, sb;
    MkaParticipant A, B;
    MkaParticipantConfig ca, cb;

    printf("rekey Key Number wrap-around guard:\n");
    memset(&a2b, 0, sizeof a2b);
    memset(&b2a, 0, sizeof b2a);
    memset(&sa, 0, sizeof sa);
    memset(&sb, 0, sizeof sb);
    cfg_part(&ca, &sa, &a2b, send_a, 0x0A, 10); /* A: KS */
    cfg_part(&cb, &sb, &b2a, send_b, 0x0B, 20);
    wm_Participant_Init(&A, &ca);
    wm_Participant_Init(&B, &cb);

    run_pair(&A, &B, &a2b, &b2a, 12, NULL);
    CHECK(wm_Participant_IsKeyServer(&A), "A is key server");
    CHECK(A.latest.valid, "A holds a SAK");

    A.latest.kn = 0xFFFFFFFFu; /* next increment wraps to 0 */
    CHECK(wm_Participant_Rekey(&A) == MKA_OK, "rekey at max Key Number");
    CHECK(A.latest.kn == 1u, "wrapped KN reset to 1");
}

/* Argument validation and saturation paths of the participant + KaY-manager
 * APIs that valid runs never reach. */
static void test_kay_negative(void)
{
    Wire w;
    Secy s;
    MkaKay kay;
    MkaParticipant* pp;
    MkaParticipantConfig c;
    uint8_t f[512];
    size_t n = sizeof f;
    int i;

    printf("kay negative (arg validation, saturation, routing misses):\n");

    /* Participant rekey: NULL and non-Key-Server. */
    CHECK(wm_Participant_Rekey(NULL) == MKA_ERR_BAD_ARG, "rekey NULL");

    /* Manager argument validation. */
    CHECK(wm_Kay_Init(NULL) == MKA_ERR_BAD_ARG, "kay_init NULL");
    CHECK(wm_Kay_Run(NULL, 0) == MKA_ERR_BAD_ARG, "kay_run NULL");
    CHECK(wm_Kay_Receive(NULL, f, n, 0) == MKA_ERR_BAD_ARG, "recv NULL kay");
    CHECK(wm_Kay_Init(&kay) == MKA_OK, "kay_init ok");
    CHECK(wm_Kay_Receive(&kay, NULL, n, 0) == MKA_ERR_BAD_ARG,
        "receive NULL frame");
    CHECK(wm_Kay_AddParticipant(NULL, &c, NULL) == MKA_ERR_BAD_ARG,
        "add NULL kay");
    CHECK(wm_Kay_AddParticipant(&kay, NULL, NULL) == MKA_ERR_BAD_ARG,
        "add NULL cfg");

    /* Saturate the participant table -> MKA_ERR_FULL on the overflow add. */
    memset(&w, 0, sizeof w);
    memset(&s, 0, sizeof s);
    for (i = 0; i < (int)MKA_MAX_PARTICIPANTS; i++) {
        char ckn[8];
        cfg_part(&c, &s, &w, send_a, (uint8_t)(0x20 + i), 10);
        ckn[0] = 'c';
        ckn[1] = 'a';
        ckn[2] = (char)('0' + i);
        ckn[3] = '\0';
        memcpy(c.cak.ckn, ckn, 4);
        c.cak.ckn_len = 4;
        CHECK(wm_Kay_AddParticipant(&kay, &c, NULL) == MKA_OK, "add CA");
    }
    cfg_part(&c, &s, &w, send_a, 0x2F, 10);
    memcpy(c.cak.ckn, "full", 4);
    c.cak.ckn_len = 4;
    CHECK(wm_Kay_AddParticipant(&kay, &c, &pp) == MKA_ERR_FULL,
        "add past capacity -> FULL");

    /* A frame that fails the basic-set peek is reported, not routed. */
    memset(f, 0, sizeof f);
    n = 4;
    CHECK(wm_Kay_Receive(&kay, f, n, 0) != MKA_OK, "malformed frame rejected");

    /* Remaining pointer positions of the participant/manager guards. */
    CHECK(wm_Participant_Receive(NULL, f, n, 0) == MKA_ERR_BAD_ARG,
        "participant recv NULL p");
    CHECK(wm_Kay_Find(NULL, (const uint8_t*)"x", 1) == NULL, "find NULL kay");
    CHECK(wm_Kay_Find(&kay, NULL, 1) == NULL, "find NULL ckn");
    CHECK(wm_Kay_ParticipantCount(NULL) == 0, "participant_count NULL");

    /* live_peer_count tolerates a NULL participant (returns a benign default).
     * is_key_server/has_sak are accessor macros that require a non-NULL p. */
    CHECK(wm_Participant_LivePeerCount(NULL) == 0, "live count NULL");
}

/* A frame whose ICV verifies but whose CKN does not match the participant's CA
 * is rejected (defence in depth behind the ICV, IEEE Std 802.1X-2010 9.x). */
static void test_kay_ckn_mismatch(void)
{
    Wire w;
    Secy s;
    MkaParticipant A, P;
    MkaParticipantConfig ca, cp;
    uint8_t f[512];
    size_t n = sizeof f;
    size_t i;
    int found = 0;

    printf("kay CKN mismatch behind a valid ICV:\n");
    memset(&w, 0, sizeof w);
    memset(&s, 0, sizeof s);
    cfg_part(&ca, &s, &w, send_a, 0x0A, 10);
    cfg_part(&cp, &s, &w, send_a, 0x0B, 20); /* same CAK+CKN as A */
    wm_Participant_Init(&A, &ca);
    wm_Participant_Init(&P, &cp);

    CHECK(wm_Participant_BuildMkpdu(&P, f, sizeof f, &n) == MKA_OK, "build");

    /* Flip the first CKN octet ("shared-ckn") then re-seal with A's ICK, so the
     * ICV still verifies but mka_receive_process sees a foreign CKN. */
    for (i = 0; (i + 10U) <= n; i++) {
        if (memcmp(&f[i], "shared-ckn", 10) == 0) {
            f[i] ^= 0xFFu;
            found = 1;
            break;
        }
    }
    CHECK(found, "located CKN in frame");
    wm_Crypto_IcvCompute(g_cmac, A.keys.ick, A.keys.ick_len, f, n - 16U,
        &f[n - 16U]);
    CHECK(wm_Participant_Receive(&A, f, n, 0) == MKA_ERR_NO_PEER,
        "valid ICV but foreign CKN -> NO_PEER");
}

/* The peer table saturates at MKA_MAX_PEERS; the next distinct peer is
 * rejected with MKA_ERR_FULL rather than overwriting an entry. */
static void test_peer_table_full(void)
{
    Secy s;
    MkaParticipant A;
    MkaParticipantConfig ca;
    MkaStatus last = MKA_OK;
    bool all_added = true;
    int i;

    printf("peer table saturation (MKA_ERR_FULL):\n");
    memset(&s, 0, sizeof s);
    cfg_part(&ca, &s, NULL, NULL, 0x0A, 10);
    wm_Participant_Init(&A, &ca);

    /* Each fresh sender shares A's CAK+CKN (so its ICV verifies) but gets a new
     * random MI, so A allocates a new peer slot per frame. */
    for (i = 0; i < (int)MKA_MAX_PEERS + 1; i++) {
        Secy ss;
        MkaParticipant S;
        MkaParticipantConfig cs;
        uint8_t f[512];
        size_t n = sizeof f;
        memset(&ss, 0, sizeof ss);
        cfg_part(&cs, &ss, NULL, NULL, 0x0B, 20);
        wm_Participant_Init(&S, &cs);
        CHECK(wm_Participant_BuildMkpdu(&S, f, sizeof f, &n) == MKA_OK,
            "build sender frame");
        last = wm_Participant_Receive(&A, f, n, 0);
        if ((i < (int)MKA_MAX_PEERS) && (last != MKA_OK)) {
            all_added = false; /* a slot below the bound was rejected early */
        }
    }
    CHECK(all_added, "the first MKA_MAX_PEERS peers are admitted");
    CHECK(last == MKA_ERR_FULL, "peer beyond MKA_MAX_PEERS -> FULL");
}

/* Make a crafted single-frame peer the victim's elected Key Server: advertise
 * MACsec desire and echo the victim's MI so the peer is seen as live. The
 * victim must be non-Key-Server-capable, so this peer wins the election within
 * the same Receive() - the state in which a member acts on a distributed SAK.
 * (Without this, a Distributed SAK is correctly ignored as coming from a
 * non-Key-Server; see test_dist_sak_only_from_key_server.) */
static void craft_peer_as_key_server(MkaPdu* in, MkaParticipant* victim)
{
    in->basic.macsec_desired = 1;
    in->live_peers.present = 1;
    in->live_peers.count = 1;
    memcpy(in->live_peers.peers[0].mi, victim->actor_mi, MKA_MI_LEN);
    /* echo the victim's most recently emitted MN, as a real peer would */
    in->live_peers.peers[0].mn = echo_mn(victim);
}

/* A non-Key-Server that receives a Distributed SAK carrying no key (MACsec not
 * yet in use) from its elected Key Server accepts the frame without installing
 * anything. */
static void test_kay_plain_dist_sak(void)
{
    Secy s;
    MkaParticipant A;
    MkaParticipantConfig ca;
    MkaPdu in;
    uint8_t f[512];
    size_t n = sizeof f;

    printf("plain (keyless) Distributed SAK at a non-Key-Server:\n");
    memset(&s, 0, sizeof s);
    cfg_part(&ca, &s, NULL, NULL, 0x0A, 10);
    ca.key_server_capable = 0; /* stays a non-Key-Server */
    wm_Participant_Init(&A, &ca);

    /* Craft a peer frame (same CAK/CKN, so the ICV verifies under A's ICK) that
     * advertises a Distributed SAK with an empty wrap. */
    memset(&in, 0, sizeof in);
    in.basic.version = 1;
    in.basic.algo_agility = MKA_ALGO_AGILITY_DEFAULT;
    memcpy(in.basic.ckn, "shared-ckn", 10);
    in.basic.ckn_len = 10;
    memset(in.basic.mi, 0x77, MKA_MI_LEN); /* not A's MI */
    in.basic.mn = 1;
    in.dist_sak.present = 1;
    in.dist_sak.kn = 1;
    in.dist_sak.wrapped_len = 0;       /* no key */
    craft_peer_as_key_server(&in, &A); /* sender is A's elected Key Server */
    CHECK(wm_Pdu_Encode(g_cmac, &in, A.keys.ick, A.keys.ick_len, f, sizeof f,
              &n) == MKA_OK,
        "encode plain dist-sak frame");

    CHECK(wm_Participant_Receive(&A, f, n, 0) == MKA_OK,
        "keyless dist-sak accepted, nothing installed");
    CHECK(wm_Participant_HasSak(&A) == 0, "no SAK installed from empty wrap");
}

/* A Distributed SAK whose wrapped key unwraps to a length that is not a valid
 * AES key size (here 24 octets) is rejected: the AES key unwrap succeeds (any
 * multiple of 8 is structurally valid) but the engine refuses to install a key
 * that is neither 16 nor 32 octets. */
static void test_kay_dist_sak_bad_len(void)
{
    Secy s;
    MkaParticipant A;
    MkaParticipantConfig ca;
    MkaPdu in;
    uint8_t f[512];
    size_t n = sizeof f;
    uint8_t bad_sak[24];
    uint8_t wrapped[MKA_MAX_WRAPPED_SAK];
    size_t wlen = sizeof wrapped;

    uint8_t good_sak[16];
    uint8_t good_wrap[MKA_MAX_WRAPPED_SAK];
    size_t gwlen = sizeof good_wrap;
    uint8_t saved_sak[16];
    uint32_t saved_kn;

    printf("Distributed SAK unwrapping to an illegal key length:\n");
    memset(&s, 0, sizeof s);
    cfg_part(&ca, &s, NULL, NULL, 0x0A, 10);
    ca.key_server_capable =
        0; /* stays a non-Key-Server so it acts on dist-SAK */
    wm_Participant_Init(&A, &ca);

    /* First install a valid SAK (kn=1) from the elected Key Server, so the
     * later rejection can be shown NOT to disturb the in-force key. */
    memset(good_sak, 0x3C, sizeof good_sak);
    CHECK(wm_Crypto_WrapSak(A.keys.kek, A.keys.kek_len, good_sak,
              sizeof good_sak, good_wrap, &gwlen) == MKA_OK,
        "wrap good sak");
    memset(&in, 0, sizeof in);
    in.basic.version = 1;
    in.basic.algo_agility = MKA_ALGO_AGILITY_DEFAULT;
    memcpy(in.basic.ckn, "shared-ckn", 10);
    in.basic.ckn_len = 10;
    memset(in.basic.mi, 0x77, MKA_MI_LEN);
    in.basic.mn = 1;
    in.dist_sak.present = 1;
    in.dist_sak.kn = 1;
    memcpy(in.dist_sak.wrapped_sak, good_wrap, gwlen);
    in.dist_sak.wrapped_len = gwlen;
    craft_peer_as_key_server(&in, &A);
    n = sizeof f;
    CHECK(wm_Pdu_Encode(g_cmac, &in, A.keys.ick, A.keys.ick_len, f, sizeof f,
              &n) == MKA_OK,
        "encode good dist-sak frame");
    CHECK(wm_Participant_Receive(&A, f, n, 0) == MKA_OK, "good SAK accepted");
    CHECK(wm_Participant_HasSak(&A), "good SAK installed");
    saved_kn = A.latest.kn;
    memcpy(saved_sak, A.latest.sak, 16);

    /* Now a Distributed SAK (kn=2) whose wrap unwraps to a 24-octet (illegal)
     * length: it must be rejected without disturbing the installed SAK. */
    memset(bad_sak, 0x5A, sizeof bad_sak);
    CHECK(wm_Crypto_WrapSak(A.keys.kek, A.keys.kek_len, bad_sak, sizeof bad_sak,
              wrapped, &wlen) == MKA_OK,
        "wrap 24-octet key for the bad-length frame");

    memset(&in, 0, sizeof in);
    in.basic.version = 1;
    in.basic.algo_agility = MKA_ALGO_AGILITY_DEFAULT;
    memcpy(in.basic.ckn, "shared-ckn", 10);
    in.basic.ckn_len = 10;
    memset(in.basic.mi, 0x77, MKA_MI_LEN); /* not A's MI */
    in.basic.mn = 2;
    in.dist_sak.present = 1;
    in.dist_sak.kn = 2;
    memcpy(in.dist_sak.wrapped_sak, wrapped, wlen);
    in.dist_sak.wrapped_len = wlen;
    craft_peer_as_key_server(&in, &A); /* sender is A's elected Key Server */
    n = sizeof f;
    CHECK(wm_Pdu_Encode(g_cmac, &in, A.keys.ick, A.keys.ick_len, f, sizeof f,
              &n) == MKA_OK,
        "encode bad-length dist-sak frame");

    CHECK(wm_Participant_Receive(&A, f, n, 0) == MKA_ERR_PARSE,
        "dist-sak with non-{16,32} key length rejected");
    CHECK(A.latest.kn == saved_kn, "in-force SAK key number unchanged");
    CHECK_EQ_MEM(A.latest.sak, saved_sak, 16, "in-force SAK unchanged");
}

/* Security regression (IEEE Std 802.1X-2010, 9.8): a Distributed SAK is
 * honoured only from the elected Key Server. A different CA member - one
 * holding the CAK, so its MKPDU passes the ICV check, but which is not the Key
 * Server - must not be able to install or override a SAK. Without the
 * sender-is-Key-Server check the rogue SAK below would be installed. */
static void test_dist_sak_only_from_key_server(void)
{
    Secy s;
    MkaParticipant B;
    MkaParticipantConfig cb;
    MkaPdu in;
    uint8_t f[512];
    size_t n;
    uint8_t rogue_sak[16];
    uint8_t wrapped[MKA_MAX_WRAPPED_SAK];
    size_t wlen = sizeof wrapped;
    uint8_t ks_sci[8] = {0, 0, 0, 0, 0, 0x0A, 0, 1};
    uint8_t rogue_sci[8] = {0, 0, 0, 0, 0, 0x0C, 0, 1};

    printf("Distributed SAK honoured only from the elected Key Server:\n");
    memset(&s, 0, sizeof s);
    cfg_part(&cb, &s, NULL, NULL, 0x0B, 30);
    cb.key_server_capable = 0; /* non-KS, so it elects a peer */
    wm_Participant_Init(&B, &cb);

    /* Frame 1: a higher-priority Key-Server-capable peer that echoes B's MI, so
     * B elects it as Key Server (no SAK distributed yet). */
    memset(&in, 0, sizeof in);
    in.basic.version = 1;
    in.basic.priority = 10;
    in.basic.macsec_desired = 1;
    in.basic.algo_agility = MKA_ALGO_AGILITY_DEFAULT;
    memcpy(in.basic.ckn, cb.cak.ckn, cb.cak.ckn_len);
    in.basic.ckn_len = cb.cak.ckn_len;
    memcpy(in.basic.sci, ks_sci, 8);
    memset(in.basic.mi, 0xAA, MKA_MI_LEN);
    in.basic.mn = 1;
    in.live_peers.present = 1;
    in.live_peers.count = 1;
    memcpy(in.live_peers.peers[0].mi, B.actor_mi, MKA_MI_LEN);
    in.live_peers.peers[0].mn = echo_mn(&B);
    n = sizeof f;
    CHECK(wm_Pdu_Encode(g_cmac, &in, B.keys.ick, B.keys.ick_len, f, sizeof f,
              &n) == MKA_OK,
        "encode key-server frame");
    CHECK(wm_Participant_Receive(&B, f, n, 0) == MKA_OK, "accept KS frame");
    CHECK(memcmp(B.ks_sci, ks_sci, 8) == 0, "B elected the key server");

    /* Frame 2: a rogue non-Key-Server peer (different SCI, not live, so it
     * never wins election) wraps an attacker-chosen SAK with the shared KEK and
     * advertises it. It must be ignored. */
    memset(rogue_sak, 0xCC, sizeof rogue_sak);
    CHECK(wm_Crypto_WrapSak(B.keys.kek, B.keys.kek_len, rogue_sak,
              sizeof rogue_sak, wrapped, &wlen) == MKA_OK,
        "wrap rogue sak");
    memset(&in, 0, sizeof in);
    in.basic.version = 1;
    in.basic.priority = 20;
    in.basic.macsec_desired = 1;
    in.basic.algo_agility = MKA_ALGO_AGILITY_DEFAULT;
    memcpy(in.basic.ckn, cb.cak.ckn, cb.cak.ckn_len);
    in.basic.ckn_len = cb.cak.ckn_len;
    memcpy(in.basic.sci, rogue_sci, 8);
    memset(in.basic.mi, 0xCC, MKA_MI_LEN);
    in.basic.mn = 1;
    in.dist_sak.present = 1;
    in.dist_sak.kn = 7;
    in.dist_sak.distributed_an = 1;
    memcpy(in.dist_sak.wrapped_sak, wrapped, wlen);
    in.dist_sak.wrapped_len = wlen;
    n = sizeof f;
    CHECK(wm_Pdu_Encode(g_cmac, &in, B.keys.ick, B.keys.ick_len, f, sizeof f,
              &n) == MKA_OK,
        "encode rogue dist-sak frame");
    CHECK(wm_Participant_Receive(&B, f, n, 0) == MKA_OK, "rogue frame parsed");
    CHECK(wm_Participant_HasSak(&B) == 0,
        "rogue (non-Key-Server) SAK not installed");
}

/* A Distributed SAK advertising the reserved confidentiality-offset value (3:
 * the decoder masks the field to 2 bits, but only 0/30/50 are valid) is
 * rejected rather than passed to the SecY. */
static void test_kay_dist_sak_bad_offset(void)
{
    Secy s;
    MkaParticipant A;
    MkaParticipantConfig ca;
    MkaPdu in;
    uint8_t f[512];
    size_t n = sizeof f;
    uint8_t sak[16];
    uint8_t wrapped[MKA_MAX_WRAPPED_SAK];
    size_t wlen = sizeof wrapped;

    uint8_t saved_sak[16];
    uint32_t saved_kn;

    printf("Distributed SAK with a reserved confidentiality offset:\n");
    memset(&s, 0, sizeof s);
    cfg_part(&ca, &s, NULL, NULL, 0x0A, 10);
    ca.key_server_capable = 0;
    wm_Participant_Init(&A, &ca);

    memset(sak, 0x5A, sizeof sak);
    CHECK(wm_Crypto_WrapSak(A.keys.kek, A.keys.kek_len, sak, sizeof sak,
              wrapped, &wlen) == MKA_OK,
        "wrap a valid 16-octet sak");

    /* Install a valid SAK first (kn=1, offset 0) so the rejection below can be
     * shown not to disturb the in-force key. */
    memset(&in, 0, sizeof in);
    in.basic.version = 1;
    in.basic.algo_agility = MKA_ALGO_AGILITY_DEFAULT;
    memcpy(in.basic.ckn, "shared-ckn", 10);
    in.basic.ckn_len = 10;
    memset(in.basic.mi, 0x77, MKA_MI_LEN);
    in.basic.mn = 1;
    in.dist_sak.present = 1;
    in.dist_sak.kn = 1;
    in.dist_sak.confidentiality_offset = 0;
    memcpy(in.dist_sak.wrapped_sak, wrapped, wlen);
    in.dist_sak.wrapped_len = wlen;
    craft_peer_as_key_server(&in, &A);
    n = sizeof f;
    CHECK(wm_Pdu_Encode(g_cmac, &in, A.keys.ick, A.keys.ick_len, f, sizeof f,
              &n) == MKA_OK,
        "encode good dist-sak frame");
    CHECK(wm_Participant_Receive(&A, f, n, 0) == MKA_OK, "good SAK accepted");
    CHECK(wm_Participant_HasSak(&A), "good SAK installed");
    saved_kn = A.latest.kn;
    memcpy(saved_sak, A.latest.sak, 16);

    /* Now a Distributed SAK (kn=2) advertising the reserved offset value 3. */
    memset(&in, 0, sizeof in);
    in.basic.version = 1;
    in.basic.algo_agility = MKA_ALGO_AGILITY_DEFAULT;
    memcpy(in.basic.ckn, "shared-ckn", 10);
    in.basic.ckn_len = 10;
    memset(in.basic.mi, 0x77, MKA_MI_LEN);
    in.basic.mn = 2;
    in.dist_sak.present = 1;
    in.dist_sak.kn = 2;
    in.dist_sak.confidentiality_offset = 3; /* reserved / invalid */
    memcpy(in.dist_sak.wrapped_sak, wrapped, wlen);
    in.dist_sak.wrapped_len = wlen;
    craft_peer_as_key_server(&in, &A); /* sender is A's elected Key Server */
    n = sizeof f;
    CHECK(wm_Pdu_Encode(g_cmac, &in, A.keys.ick, A.keys.ick_len, f, sizeof f,
              &n) == MKA_OK,
        "encode bad-offset dist-sak frame");

    CHECK(wm_Participant_Receive(&A, f, n, 0) == MKA_ERR_PARSE,
        "dist-sak with reserved confidentiality offset rejected");
    CHECK(A.latest.kn == saved_kn, "in-force SAK key number unchanged");
    CHECK_EQ_MEM(A.latest.sak, saved_sak, 16, "in-force SAK unchanged");
}

#ifndef WOLFMKA_NO_XPN
/* Build a crafted live-peer frame from SCI `sci` that echoes the victim's MI
 * (so it is seen as live) and carries no parameter sets; returns its length. */
static size_t craft_live_member(uint8_t* f, size_t cap, MkaParticipant* v,
    const uint8_t* sci, uint8_t mi_fill)
{
    MkaPdu in;
    size_t n = cap;

    memset(&in, 0, sizeof in);
    in.basic.version = 1;
    in.basic.priority = 20; /* lower priority than the victim Key Server */
    in.basic.macsec_desired = 1;
    in.basic.algo_agility = MKA_ALGO_AGILITY_DEFAULT;
    memcpy(in.basic.ckn, v->cfg.cak.ckn, v->cfg.cak.ckn_len);
    in.basic.ckn_len = v->cfg.cak.ckn_len;
    memcpy(in.basic.sci, sci, 8);
    memset(in.basic.mi, mi_fill, MKA_MI_LEN);
    in.basic.mn = 1;
    in.live_peers.present = 1;
    in.live_peers.count = 1;
    memcpy(in.live_peers.peers[0].mi, v->actor_mi, MKA_MI_LEN);
    in.live_peers.peers[0].mn = echo_mn(v);
    CHECK(wm_Pdu_Encode(g_cmac, &in, v->keys.ick, v->keys.ick_len, f, cap,
              &n) == MKA_OK,
        "encode live-member frame");
    return n;
}

/* XPN SSCI consistency on a staggered join: an SSCI is the rank of a member's
 * SCI in the live membership, so when a lower-sorting member joins an already-
 * keyed XPN CA, the existing members' channels must be reprogrammed with their
 * new (higher) rank - otherwise they transmit XPN frames with a stale SSCI. */
static void test_xpn_ssci_membership_change(void)
{
    Wire tx;
    Secy s;
    MkaParticipant M;
    MkaParticipantConfig c;
    uint8_t f[512];
    size_t n;
    uint8_t p_sci[8] = {0, 0, 0, 0, 0, 0x0A, 0, 1};
    uint8_t n_sci[8] = {0, 0, 0, 0, 0, 0x05, 0, 1};

    printf("XPN SSCI reprogrammed when a member joins after SAK install:\n");
    memset(&tx, 0, sizeof tx);
    memset(&s, 0, sizeof s);
    cfg_part(&c, &s, &tx, send_a, 0x0B, 10); /* M: Key Server, SCI ...0x0B */
    c.cipher_suite = MKA_CIPHER_GCM_AES_XPN_128;
    c.secy.get_next_pn = secy_get_pn_xpn;
    s.xpn_val = 1;
    CHECK(wm_Participant_Init(&M, &c) == MKA_OK, "init M (XPN Key Server)");
    memcpy(s.my_sci, c.sci, 8);

    /* Peer P (SCI 0x0A < M) becomes live, then M installs the SAK. Membership
     * {M=0x0B, P=0x0A} -> M's rank (tx SSCI) is 2. */
    n = craft_live_member(f, sizeof f, &M, p_sci, 0xAA);
    CHECK(wm_Participant_Receive(&M, f, n, 0) == MKA_OK, "P becomes live");
    (void)wm_Participant_Run(&M, MKA_HELLO_TIME_MS, NULL);
    CHECK(wm_Participant_HasSak(&M), "M installed the XPN SAK");
    CHECK(s.tx_ssci == 2U, "M tx SSCI is 2 with two members");

    /* A potential peer Q (does NOT echo M's MI, so it stays not-live) is in the
     * table when the reapply runs; it is skipped (not counted in any rank). */
    {
        MkaPdu q;
        uint8_t qf[512];
        size_t qn = sizeof qf;
        uint8_t q_sci[8] = {0, 0, 0, 0, 0, 0x0C, 0, 1};
        memset(&q, 0, sizeof q);
        q.basic.version = 1;
        q.basic.macsec_desired = 1;
        q.basic.algo_agility = MKA_ALGO_AGILITY_DEFAULT;
        memcpy(q.basic.ckn, c.cak.ckn, c.cak.ckn_len);
        q.basic.ckn_len = c.cak.ckn_len;
        memcpy(q.basic.sci, q_sci, 8);
        memset(q.basic.mi, 0x33, MKA_MI_LEN);
        q.basic.mn = 1;
        CHECK(wm_Pdu_Encode(g_cmac, &q, M.keys.ick, M.keys.ick_len, qf,
                  sizeof qf, &qn) == MKA_OK,
            "encode potential peer Q");
        CHECK(wm_Participant_Receive(&M, qf, qn, MKA_HELLO_TIME_MS) == MKA_OK,
            "Q admitted as a potential (not-live) peer");
    }

    /* Member N (SCI 0x05 < both) joins after the SAK. Membership becomes
     * {0x0B, 0x0A, 0x05} -> M's rank is 3; its tx SC must be reprogrammed. */
    n = craft_live_member(f, sizeof f, &M, n_sci, 0x55);
    CHECK(wm_Participant_Receive(&M, f, n, MKA_HELLO_TIME_MS) == MKA_OK,
        "N becomes live");
    CHECK(s.tx_ssci == 3U, "M tx SSCI reprogrammed to 3 after N joins");
}

    #ifndef WOLFMKA_NO_DELAY_PROTECT
/* XPN delay protection must convey the FULL 64-bit Lowest Acceptable PN to the
 * SecY: the low 32 bits from the SAK Use set paired with the high 32 from the
 * XPN set, not just the low word. */
static void test_xpn_delay_protect_lpn64(void)
{
    Wire tx;
    Secy s;
    MkaParticipant M;
    MkaParticipantConfig c;
    MkaPdu in;
    uint8_t f[512];
    size_t n;
    uint8_t p_sci[8] = {0, 0, 0, 0, 0, 0x0A, 0, 1};

    printf("XPN delay protection conveys a 64-bit lowest PN:\n");
    memset(&tx, 0, sizeof tx);
    memset(&s, 0, sizeof s);
    cfg_part(&c, &s, &tx, send_a, 0x0B, 10); /* M: Key Server, XPN */
    c.cipher_suite = MKA_CIPHER_GCM_AES_XPN_128;
    c.delay_protect = 1;
    c.secy.get_next_pn = secy_get_pn_xpn;
    s.xpn_val = 1;
    CHECK(wm_Participant_Init(&M, &c) == MKA_OK, "init M (XPN, delay-protect)");
    memcpy(s.my_sci, c.sci, 8);

    /* P becomes live, then M installs the XPN SAK. */
    n = craft_live_member(f, sizeof f, &M, p_sci, 0xAA);
    CHECK(wm_Participant_Receive(&M, f, n, 0) == MKA_OK, "P becomes live");
    (void)wm_Participant_Run(&M, MKA_HELLO_TIME_MS, NULL);
    CHECK(wm_Participant_HasSak(&M), "M installed the XPN SAK");

    /* P (same MI, next MN) reports a Lowest PN of 0x0000000A_00000005: low 5 in
     * the SAK Use set, high 0x0A in the XPN set. */
    memset(&in, 0, sizeof in);
    in.basic.version = 1;
    in.basic.priority = 20;
    in.basic.macsec_desired = 1;
    in.basic.algo_agility = MKA_ALGO_AGILITY_DEFAULT;
    memcpy(in.basic.ckn, c.cak.ckn, c.cak.ckn_len);
    in.basic.ckn_len = c.cak.ckn_len;
    memcpy(in.basic.sci, p_sci, 8);
    memset(in.basic.mi, 0xAA, MKA_MI_LEN);
    in.basic.mn = 2;
    in.live_peers.present = 1;
    in.live_peers.count = 1;
    memcpy(in.live_peers.peers[0].mi, M.actor_mi, MKA_MI_LEN);
    in.live_peers.peers[0].mn = echo_mn(&M);
    in.sak_use.present = 1;
    MKA_SAK_USE_SET_LATEST_RX(
        &in.sak_use); /* latest key in use -> body emitted */
    in.sak_use.latest_kn = M.latest.kn;
    in.sak_use.latest_lpn = 0x00000005U;
    in.xpn.present = 1;
    in.xpn.latest_lpn_msb = 0x0000000AU;
    n = sizeof f;
    CHECK(wm_Pdu_Encode(g_cmac, &in, M.keys.ick, M.keys.ick_len, f, sizeof f,
              &n) == MKA_OK,
        "encode SAK-use + XPN frame");
    CHECK(wm_Participant_Receive(&M, f, n, MKA_HELLO_TIME_MS) == MKA_OK,
        "process peer SAK-use");
    CHECK(s.set_lowest_pn_calls > 0, "delay-protect advanced the rx window");
    CHECK(s.last_lowest_pn == 0x0000000A00000005ULL,
        "full 64-bit lowest PN (msb<<32 | lpn) conveyed to the SecY");
}
    #endif /* WOLFMKA_NO_DELAY_PROTECT */
#endif     /* WOLFMKA_NO_XPN */

/* Read-only introspection getters, the MKA counters, and the configurable
 * transmit confidentiality offset. */
static void test_kay_introspection(void)
{
    Wire a2b, b2a;
    Secy sa, sb;
    MkaParticipant A, B;
    MkaParticipantConfig ca, cb;
    MkaPeerInfo pi;
    MkaSakInfo sk;
    MkaCounters c0, c1;
    uint8_t kssci[MKA_SCI_LEN];
    uint8_t f[512];
    size_t n = sizeof f;

    printf("introspection getters, counters, confidentiality offset:\n");
    memset(&a2b, 0, sizeof a2b);
    memset(&b2a, 0, sizeof b2a);
    memset(&sa, 0, sizeof sa);
    memset(&sb, 0, sizeof sb);
    cfg_part(&ca, &sa, &a2b, send_a, 0x0A, 10); /* lower priority -> A is KS */
    cfg_part(&cb, &sb, &b2a, send_b, 0x0B, 20);
    ca.confidentiality_offset = (uint8_t)MKA_CONF_OFFSET_50;
    wm_Participant_Init(&A, &ca);
    wm_Participant_Init(&B, &cb);

    /* Before any election / SAK. */
    CHECK(wm_Participant_GetKeyServerSci(&A, kssci) == MKA_ERR_STATE,
        "KS SCI unavailable before election");
    CHECK(wm_Participant_GetSak(&A, &sk) == MKA_OK && !sk.valid,
        "no SAK before convergence");
    CHECK(wm_Participant_PeerCount(&A) == 0, "no peers before convergence");

    run_pair(&A, &B, &a2b, &b2a, 12, NULL);

    /* Peer enumeration. */
    CHECK(wm_Participant_PeerCount(&A) == 1, "A tracks one peer");
    CHECK(wm_Participant_GetPeer(&A, 0, &pi) == MKA_OK, "get peer 0");
    CHECK(pi.live, "peer 0 is live");
    CHECK_EQ_MEM(pi.sci, cb.sci, MKA_SCI_LEN, "peer 0 SCI is B's");
    CHECK(wm_Participant_GetPeer(&A, 1, &pi) == MKA_ERR_NO_PEER,
        "peer index past end");

    /* In-force SAK metadata (GCM-AES-128 by default). */
    CHECK(wm_Participant_GetSak(&A, &sk) == MKA_OK && sk.valid, "SAK present");
    CHECK(sk.cipher_suite == MKA_CIPHER_GCM_AES_128, "GCM-128 in force");
    CHECK(sk.kn == A.latest.kn && sk.an == A.latest.an, "KN/AN reported");

    /* Elected Key Server SCI is A's own (A is the Key Server). */
    CHECK(wm_Participant_GetKeyServerSci(&A, kssci) == MKA_OK, "KS SCI ok");
    CHECK_EQ_MEM(kssci, ca.sci, MKA_SCI_LEN, "KS SCI == A's SCI");

    /* Counters advanced during convergence. */
    CHECK(wm_Participant_GetCounters(&A, &c0) == MKA_OK, "counters ok");
    CHECK((c0.mkpdu_in > 0U) && (c0.mkpdu_out > 0U) && (c0.sak_installs > 0U),
        "counters advanced");

    /* NULL-argument rejection on every getter. The predicates are NULL-safe and
     * return false (not a crash) - they are real functions, not field macros.
     */
    CHECK(wm_Participant_PeerCount(NULL) == 0, "PeerCount(NULL)");
    CHECK(!wm_Participant_IsKeyServer(NULL), "IsKeyServer(NULL) is false");
    CHECK(!wm_Participant_HasSak(NULL), "HasSak(NULL) is false");
    CHECK(wm_Participant_GetPeer(NULL, 0, &pi) == MKA_ERR_BAD_ARG,
        "GetPeer(NULL,)");
    CHECK(wm_Participant_GetPeer(&A, 0, NULL) == MKA_ERR_BAD_ARG,
        "GetPeer(,NULL)");
    CHECK(wm_Participant_GetSak(NULL, &sk) == MKA_ERR_BAD_ARG, "GetSak(NULL,)");
    CHECK(wm_Participant_GetSak(&A, NULL) == MKA_ERR_BAD_ARG, "GetSak(,NULL)");
    CHECK(wm_Participant_GetKeyServerSci(NULL, kssci) == MKA_ERR_BAD_ARG,
        "GetKeyServerSci(NULL,)");
    CHECK(wm_Participant_GetKeyServerSci(&A, NULL) == MKA_ERR_BAD_ARG,
        "GetKeyServerSci(,NULL)");
    CHECK(wm_Participant_GetCounters(NULL, &c0) == MKA_ERR_BAD_ARG,
        "GetCounters(NULL,)");
    CHECK(wm_Participant_GetCounters(&A, NULL) == MKA_ERR_BAD_ARG,
        "GetCounters(,NULL)");

    /* The Key Server advertised the configured confidentiality offset. */
    {
        MkaPdu dec;
        CHECK(wm_Participant_BuildMkpdu(&A, f, sizeof f, &n) == MKA_OK,
            "build A MKPDU");
        CHECK(wm_Pdu_Decode(g_cmac, f, n, A.keys.ick, A.keys.ick_len, &dec) ==
                  MKA_OK,
            "decode A MKPDU");
        CHECK(dec.dist_sak.present && (dec.dist_sak.confidentiality_offset ==
                                          (uint8_t)MKA_CONF_OFFSET_50),
            "advertised confidentiality offset 50");
    }

    /* The offset reached both SecYs: the Key Server applied its configured
     * offset, and the peer adopted it from the Distributed SAK. */
    CHECK(sa.conf_offset == (uint8_t)MKA_CONF_OFFSET_50,
        "Key Server applied offset 50 to its SecY");
    CHECK(sb.conf_offset == (uint8_t)MKA_CONF_OFFSET_50,
        "peer adopted offset 50 from the Distributed SAK");

    /* A bad-ICV frame increments icv_failures; a truncated frame is a parse
     * error and is not counted as an ICV failure. */
    (void)wm_Participant_GetCounters(&A, &c0);
    n = sizeof f;
    CHECK(wm_Participant_BuildMkpdu(&B, f, sizeof f, &n) == MKA_OK,
        "build B MKPDU");
    f[8] ^=
        0x01; /* corrupt the body (shared CAK -> ICV would otherwise pass) */
    CHECK(wm_Participant_Receive(&A, f, n, 0) == MKA_ERR_ICV,
        "bad ICV rejected");
    CHECK(wm_Participant_Receive(&A, f, 3U, 0) == MKA_ERR_PARSE,
        "truncated frame is a parse error");
    CHECK(wm_Participant_GetCounters(&A, &c1) == MKA_OK, "counters reread");
    CHECK(c1.icv_failures == (c0.icv_failures + 1U),
        "icv_failures incremented once");

    /* An out-of-range confidentiality offset is rejected at init. */
    {
        MkaParticipant X;
        MkaParticipantConfig cx;
        Secy sx;
        memset(&sx, 0, sizeof sx);
        cfg_part(&cx, &sx, NULL, NULL, 0x0C, 30);
        cx.confidentiality_offset = 3U; /* > MKA_CONF_OFFSET_50 */
        CHECK(wm_Participant_Init(&X, &cx) == MKA_ERR_BAD_ARG,
            "invalid confidentiality offset rejected");
    }
}

/* Recorder for the MkaEventOps callbacks. */
typedef struct {
    int added;
    int live;
    int lost;
    int lost_livecount; /* losses where was_live was set */
    int ks;
    int sak;
    int up;
    int fail;
    int last_ks_self;
    uint8_t last_ks_sci[MKA_SCI_LEN];
    uint8_t last_added_sci[MKA_SCI_LEN];
    uint64_t last_sak_cs;
} EvRec;

static void ev_added(void* c, const uint8_t* mi, const uint8_t* sci)
{
    EvRec* e = (EvRec*)c;
    (void)mi;
    e->added++;
    memcpy(e->last_added_sci, sci, MKA_SCI_LEN);
}
static void ev_live(void* c, const uint8_t* mi)
{
    EvRec* e = (EvRec*)c;
    (void)mi;
    e->live++;
}
static void ev_lost(void* c, const uint8_t* mi, bool was_live)
{
    EvRec* e = (EvRec*)c;
    (void)mi;
    e->lost++;
    if (was_live) {
        e->lost_livecount++;
    }
}
static void ev_ks(void* c, const uint8_t* sci, bool is_self)
{
    EvRec* e = (EvRec*)c;
    e->ks++;
    e->last_ks_self = is_self;
    memcpy(e->last_ks_sci, sci, MKA_SCI_LEN);
}
static void ev_sak(void* c, uint32_t kn, uint8_t an, uint64_t cs)
{
    EvRec* e = (EvRec*)c;
    (void)kn;
    (void)an;
    e->sak++;
    e->last_sak_cs = cs;
}
static void ev_up(void* c, uint32_t kn, uint8_t an)
{
    EvRec* e = (EvRec*)c;
    (void)kn;
    (void)an;
    e->up++;
}
static void ev_fail(void* c)
{
    EvRec* e = (EvRec*)c;
    e->fail++;
}
static void set_events(MkaParticipantConfig* c, EvRec* e)
{
    c->events.peer_added = ev_added;
    c->events.peer_live = ev_live;
    c->events.peer_lost = ev_lost;
    c->events.key_server_elected = ev_ks;
    c->events.sak_installed = ev_sak;
    c->events.macsec_up = ev_up;
    c->events.auth_fail = ev_fail;
    c->events.ctx = e;
}

/* The typed event hooks fire at each state transition: peer discovery and
 * liveness, Key Server election (self and remote), SAK install, transmit
 * enable, ICV failure, and peer loss (both live and potential). */
static void test_kay_events(void)
{
    Wire a2b, b2a;
    Secy sa, sb;
    MkaParticipant A, B;
    MkaParticipantConfig ca, cb;
    EvRec ea, eb;
    uint8_t f[512];
    size_t n;

    printf("event callbacks:\n");
    memset(&a2b, 0, sizeof a2b);
    memset(&b2a, 0, sizeof b2a);
    memset(&sa, 0, sizeof sa);
    memset(&sb, 0, sizeof sb);
    memset(&ea, 0, sizeof ea);
    memset(&eb, 0, sizeof eb);
    cfg_part(&ca, &sa, &a2b, send_a, 0x0A, 10); /* A: Key Server */
    cfg_part(&cb, &sb, &b2a, send_b, 0x0B, 20);
    set_events(&ca, &ea);
    set_events(&cb, &eb);
    wm_Participant_Init(&A, &ca);
    wm_Participant_Init(&B, &cb);

    run_pair(&A, &B, &a2b, &b2a, 16, NULL);

    /* Key Server side (A). */
    CHECK(ea.added == 1, "A: peer_added once");
    CHECK_EQ_MEM(ea.last_added_sci, cb.sci, MKA_SCI_LEN, "A: added SCI is B's");
    CHECK(ea.live == 1, "A: peer_live once");
    CHECK(ea.ks == 1 && ea.last_ks_self == 1, "A: elected self as KS once");
    CHECK_EQ_MEM(ea.last_ks_sci, ca.sci, MKA_SCI_LEN, "A: KS SCI is A's");
    CHECK(ea.sak >= 1 && ea.last_sak_cs == MKA_CIPHER_GCM_AES_128,
        "A: sak_installed with GCM-128");
    CHECK(ea.up == 1, "A: macsec_up once");

    /* Non-Key-Server side (B): it first elects itself (lone candidate), then
     * switches to A once A is live, so the final election result is a remote
     * Key Server. */
    CHECK(eb.ks >= 1 && eb.last_ks_self == 0, "B: settled on a remote KS");
    CHECK_EQ_MEM(eb.last_ks_sci, ca.sci, MKA_SCI_LEN, "B: KS SCI is A's");
    CHECK(eb.sak >= 1 && eb.up == 1, "B: SAK installed and macsec up");

    /* auth_fail: corrupt a valid B frame and hand it to A. */
    n = sizeof f;
    CHECK(wm_Participant_BuildMkpdu(&B, f, sizeof f, &n) == MKA_OK,
        "build B frame");
    f[8] ^= 0x01;
    CHECK(wm_Participant_Receive(&A, f, n, 0) == MKA_ERR_ICV,
        "A rejects bad ICV");
    CHECK(ea.fail == 1, "A: auth_fail fired");

    /* Add a non-live (potential) peer to A so peer_lost exercises both the
     * live and the potential case when everyone expires. */
    {
        Secy ss;
        MkaParticipant S;
        MkaParticipantConfig cs2;
        memset(&ss, 0, sizeof ss);
        cfg_part(&cs2, &ss, NULL, NULL, 0x0C, 30);
        wm_Participant_Init(&S, &cs2);
        n = sizeof f;
        CHECK(wm_Participant_BuildMkpdu(&S, f, sizeof f, &n) == MKA_OK,
            "build S frame");
        /* S lists no peers, so A keeps it Potential (never live). */
        CHECK(wm_Participant_Receive(&A, f, n, 0) == MKA_OK, "A sees S");
    }
    ea.lost = 0;
    ea.lost_livecount = 0;
    /* Run A far in the future with no inbound frames: B and S both expire. */
    (void)wm_Participant_Run(&A, MKA_LIFE_TIME_MS * 100U, NULL);
    CHECK(ea.lost == 2, "A: peer_lost for both peers");
    CHECK(ea.lost_livecount == 1, "A: exactly one lost peer was live");
}

/* The Key Server election event also fires when the elected *remote* Key Server
 * changes identity (same non-self role, different SCI). A non-KS-capable
 * participant adopts remote B, then a higher-priority remote C. */
static void test_kay_event_ks_change(void)
{
    Secy sp;
    MkaParticipant P;
    MkaParticipantConfig cp;
    EvRec ep;
    MkaPdu in;
    uint8_t f[512];
    size_t n;
    uint8_t sci_b[MKA_SCI_LEN] = {0, 0, 0, 0, 0, 0xBB, 0, 1};
    uint8_t sci_c[MKA_SCI_LEN] = {0, 0, 0, 0, 0, 0xCC, 0, 1};

    printf("Key Server change event (remote KS identity changes):\n");
    memset(&sp, 0, sizeof sp);
    memset(&ep, 0, sizeof ep);
    cfg_part(&cp, &sp, NULL, NULL, 0x0A, 50);
    cp.key_server_capable = 0; /* never self: election only ever picks a peer */
    set_events(&cp, &ep);
    wm_Participant_Init(&P, &cp);

    /* Remote B: Key Server, priority 10, and lists P so P sees it live. */
    memset(&in, 0, sizeof in);
    in.basic.version = 1;
    in.basic.algo_agility = MKA_ALGO_AGILITY_DEFAULT;
    memcpy(in.basic.ckn, "shared-ckn", 10);
    in.basic.ckn_len = 10;
    memset(in.basic.mi, 0xB1, MKA_MI_LEN);
    memcpy(in.basic.sci, sci_b, MKA_SCI_LEN);
    in.basic.priority = 10;
    in.basic.key_server = 1;
    in.basic.macsec_desired = 1;
    in.basic.mn = 1;
    in.live_peers.present = 1;
    in.live_peers.count = 1;
    memcpy(in.live_peers.peers[0].mi, P.actor_mi, MKA_MI_LEN);
    in.live_peers.peers[0].mn = echo_mn(&P);
    n = sizeof f;
    CHECK(wm_Pdu_Encode(g_cmac, &in, P.keys.ick, P.keys.ick_len, f, sizeof f,
              &n) == MKA_OK,
        "encode B");
    CHECK(wm_Participant_Receive(&P, f, n, 0) == MKA_OK, "P sees B");
    CHECK(ep.ks == 1 && ep.last_ks_self == 0, "P elects remote B");
    CHECK_EQ_MEM(ep.last_ks_sci, sci_b, MKA_SCI_LEN, "elected KS is B");

    /* Remote C: better priority -> election switches to C (same remote role,
     * different SCI), firing the event again. */
    memset(in.basic.mi, 0xC1, MKA_MI_LEN);
    memcpy(in.basic.sci, sci_c, MKA_SCI_LEN);
    in.basic.priority = 5;
    in.basic.mn = 1;
    n = sizeof f;
    CHECK(wm_Pdu_Encode(g_cmac, &in, P.keys.ick, P.keys.ick_len, f, sizeof f,
              &n) == MKA_OK,
        "encode C");
    CHECK(wm_Participant_Receive(&P, f, n, 0) == MKA_OK, "P sees C");
    CHECK(ep.ks == 2 && ep.last_ks_self == 0, "P switches to remote C");
    CHECK_EQ_MEM(ep.last_ks_sci, sci_c, MKA_SCI_LEN, "elected KS is C");
}

/* SecY/transport callbacks that return failure: the engine tolerates a failing
 * transmit and a failing get-next-PN hook (the "callback reported error" arm of
 * each call, which the success-only stubs never take). */
static void test_kay_cb_failures(void)
{
    Wire a2b, b2a;
    Secy sa, sb;
    MkaParticipant A, B;
    MkaParticipantConfig ca, cb;
    uint8_t f[512];
    size_t n = sizeof f;
    bool sent =
        true; /* poison: Run() must clear it to false on a failed send */

    printf("failing transmit and get-next-PN callbacks:\n");

    /* Transmit callback returns non-zero: run still succeeds, sent stays 0. */
    {
        Secy s;
        MkaParticipant P;
        MkaParticipantConfig c;
        memset(&s, 0, sizeof s);
        cfg_part(&c, &s, NULL, send_fail, 0x0A, 10);
        wm_Participant_Init(&P, &c);
        CHECK(wm_Participant_Run(&P, 0, &sent) == MKA_OK,
            "run tolerates failing send");
        CHECK(!sent, "sent flag not set when send fails");
    }

    /* get_next_pn returns non-zero during SAK Use build: LPN falls back to its
     * default and the build still succeeds. */
    memset(&a2b, 0, sizeof a2b);
    memset(&b2a, 0, sizeof b2a);
    memset(&sa, 0, sizeof sa);
    memset(&sb, 0, sizeof sb);
    cfg_part(&ca, &sa, &a2b, send_a, 0x0A, 10);
    cfg_part(&cb, &sb, &b2a, send_b, 0x0B, 20);
    ca.delay_protect = 1;
    wm_Participant_Init(&A, &ca);
    wm_Participant_Init(&B, &cb);
    run_pair(&A, &B, &a2b, &b2a, 12, NULL);
    CHECK(wm_Participant_HasSak(&A), "A keyed");

    A.cfg.secy.get_next_pn = secy_get_pn_fail; /* now report PN failure */
    CHECK(wm_Participant_BuildMkpdu(&A, f, sizeof f, &n) == MKA_OK,
        "build tolerates failing get_next_pn");
    /* The hook failed, so the Lowest-PN must fall back to its build default
     * (1), not whatever the poisoned hook left - observe it on the wire. */
    {
        MkaPdu out;
        CHECK(wm_Pdu_Decode(g_cmac, f, n, A.keys.ick, A.keys.ick_len, &out) ==
                  MKA_OK,
            "decode frame built with failing get_next_pn");
        CHECK(out.sak_use.latest_lpn == 1U,
            "LPN falls back to default when get_next_pn fails");
    }

#ifndef WOLFMKA_NO_DELAY_PROTECT
    /* Success counterpart: a *succeeding* get_next_pn (returns 0) must place
     * its PN into the emitted Lowest-PN rather than the fallback - pins the `==
     * 0` success branch, which the failure case above (LPN stays 1 either way)
     * cannot distinguish. */
    A.cfg.secy.get_next_pn = secy_get_pn_const;
    n = sizeof f;
    CHECK(wm_Participant_BuildMkpdu(&A, f, sizeof f, &n) == MKA_OK,
        "build with succeeding get_next_pn");
    {
        MkaPdu out;
        CHECK(wm_Pdu_Decode(g_cmac, f, n, A.keys.ick, A.keys.ick_len, &out) ==
                  MKA_OK,
            "decode frame with succeeding get_next_pn");
        CHECK(out.sak_use.latest_lpn == 0x12345678U,
            "succeeding get_next_pn PN appears as the emitted Lowest-PN");
    }
#endif
}

/* A peer that is added but expires before any SAK is installed: mka_drop_peer
 * runs with no Latest key present (the latest.valid == false arm). */
static void test_kay_drop_no_sak(void)
{
    Secy s, sp;
    MkaParticipant A, P;
    MkaParticipantConfig ca, cp;
    uint8_t f[512];
    size_t n = sizeof f;

    printf("peer expiry before any SAK (drop with no key):\n");
    memset(&s, 0, sizeof s);
    memset(&sp, 0, sizeof sp);
    cfg_part(&ca, &s, NULL, NULL, 0x0A, 10);
    ca.key_server_capable = 0; /* never becomes KS -> never keyed */
    cfg_part(&cp, &sp, NULL, NULL, 0x0B, 20);
    wm_Participant_Init(&A, &ca);
    wm_Participant_Init(&P, &cp);

    /* A learns of peer P, then P goes silent. A holds no SAK throughout. */
    CHECK(wm_Participant_BuildMkpdu(&P, f, sizeof f, &n) == MKA_OK, "bld P");
    CHECK(wm_Participant_Receive(&A, f, n, 0) == MKA_OK, "A adds peer P");
    CHECK(wm_Participant_HasSak(&A) == 0, "A has no SAK");

    wm_Participant_Run(&A, MKA_LIFE_TIME_MS + MKA_HELLO_TIME_MS, NULL);
    CHECK(wm_Participant_LivePeerCount(&A) == 0, "peer expired without key");
    CHECK(wm_Participant_HasSak(&A) == 0, "still no SAK after drop");
}

/* A third peer joins after convergence but with NO rekey, so a receive SA is
 * installed for the Latest key while there is no Old key, and (with no SecY
 * hooks) via the create_rx_sc == NULL path. */
static void test_kay_join_no_rekey(void)
{
    Wire a2b, b2a, c2a;
    Secy sa, sb, sc;
    MkaParticipant A, B, C;
    MkaParticipantConfig ca, cb, cc;
    int tick;

    printf("mid-life peer join, no rekey, no SecY hooks:\n");
    memset(&a2b, 0, sizeof a2b);
    memset(&b2a, 0, sizeof b2a);
    memset(&c2a, 0, sizeof c2a);
    memset(&sa, 0, sizeof sa);
    memset(&sb, 0, sizeof sb);
    memset(&sc, 0, sizeof sc);
    cfg_part(&ca, &sa, &a2b, send_a, 0x0A, 10); /* A: KS */
    cfg_part(&cb, &sb, &b2a, send_b, 0x0B, 20);
    cfg_part(&cc, &sc, &c2a, send_c, 0x0C, 30);
    memset(&ca.secy, 0, sizeof ca.secy); /* no hooks -> NULL paths */
    memset(&cb.secy, 0, sizeof cb.secy);
    memset(&cc.secy, 0, sizeof cc.secy);
    wm_Participant_Init(&A, &ca);
    wm_Participant_Init(&B, &cb);
    wm_Participant_Init(&C, &cc);

    run_pair(&A, &B, &a2b, &b2a, 12, NULL);
    CHECK(A.latest.valid && !A.old.valid, "A keyed, no Old key");

    /* Bring C up; route A's frames to C and back. C goes live while A holds a
     * Latest key but no Old key. */
    for (tick = 12; tick < 18; tick++) {
        uint8_t f[512];
        size_t nn;
        uint32_t t = (uint32_t)tick * MKA_HELLO_TIME_MS;
        wm_Participant_Run(&A, t, NULL);
        wm_Participant_Run(&C, t, NULL);
        while (wire_pop(&a2b, f, &nn))
            wm_Participant_Receive(&C, f, nn, t);
        while (wire_pop(&c2a, f, &nn))
            wm_Participant_Receive(&A, f, nn, t);
    }
    CHECK(wm_Participant_LivePeerCount(&A) >= 1, "C joined A");
    CHECK(!A.old.valid, "still no Old key (no rekey occurred)");
}

/* The full protocol runs with no SecY hooks installed at all: the engine must
 * still discover, elect, key, rekey and expire peers, simply without touching a
 * data plane. This exercises the "hook absent" side of every optional SecY
 * call (create/install/enable/delete/cipher-suite/PN), which the hook-populated
 * tests never take. */
static void test_kay_no_secy_hooks(void)
{
    Wire a2b, b2a;
    Secy sa, sb;
    MkaParticipant A, B;
    MkaParticipantConfig ca, cb;
    int tick;

    printf("convergence with no SecY hooks (NULL-hook branches):\n");
    memset(&a2b, 0, sizeof a2b);
    memset(&b2a, 0, sizeof b2a);
    memset(&sa, 0, sizeof sa);
    memset(&sb, 0, sizeof sb);
    cfg_part(&ca, &sa, &a2b, send_a, 0x0A, 10);
    cfg_part(&cb, &sb, &b2a, send_b, 0x0B, 20);
    ca.delay_protect = 1;
    cb.delay_protect = 1;                /* hit PN-hook NULL paths */
    memset(&ca.secy, 0, sizeof ca.secy); /* drop every SecY hook */
    memset(&cb.secy, 0, sizeof cb.secy);
    wm_Participant_Init(&A, &ca);
    wm_Participant_Init(&B, &cb);

    run_pair(&A, &B, &a2b, &b2a, 12, NULL);
    CHECK(wm_Participant_IsKeyServer(&A), "A is KS without SecY");
    CHECK(wm_Participant_HasSak(&A) && wm_Participant_HasSak(&B),
        "both converge on a SAK with no SecY hooks");
    CHECK_EQ_MEM(A.latest.sak, B.latest.sak, 16, "SAK agrees sans SecY");

    /* Rekey and complete the handover (install + retire with NULL hooks). */
    CHECK(wm_Participant_Rekey(&A) == MKA_OK, "rekey with no SecY");
    for (tick = 12; tick < 28; tick++) {
        uint8_t f[512];
        size_t n;
        uint32_t t = (uint32_t)tick * MKA_HELLO_TIME_MS;
        wm_Participant_Run(&A, t, NULL);
        wm_Participant_Run(&B, t, NULL);
        while (wire_pop(&a2b, f, &n))
            wm_Participant_Receive(&B, f, n, t);
        while (wire_pop(&b2a, f, &n))
            wm_Participant_Receive(&A, f, n, t);
    }
    CHECK(A.latest.kn == 2 && B.latest.kn == 2, "rekey completed sans SecY");
    CHECK(A.old.valid == 0, "old key retired (NULL delete path taken)");

    /* Let B expire so mka_drop_peer runs with delete_sa NULL. */
    wm_Participant_Run(&A,
        28U * MKA_HELLO_TIME_MS + MKA_LIFE_TIME_MS + MKA_HELLO_TIME_MS, NULL);
    CHECK(wm_Participant_LivePeerCount(&A) == 0, "peer expired sans SecY");
}

/* XPN: deterministic SSCI assignment, consistent between the two ends. */
#ifndef WOLFMKA_NO_XPN
static void test_xpn_ssci(void)
{
    Wire a2b, b2a;
    Secy sa, sb;
    MkaParticipant A, B;
    MkaParticipantConfig ca, cb;

    printf("XPN cipher suite + SSCI assignment:\n");
    memset(&a2b, 0, sizeof a2b);
    memset(&b2a, 0, sizeof b2a);
    memset(&sa, 0, sizeof sa);
    memset(&sb, 0, sizeof sb);
    cfg_part(&ca, &sa, &a2b, send_a, 0x0A, 10);
    cfg_part(&cb, &sb, &b2a, send_b, 0x0B, 20);
    ca.cipher_suite = MKA_CIPHER_GCM_AES_XPN_128;
    cb.cipher_suite = MKA_CIPHER_GCM_AES_XPN_128;
    memcpy(sa.my_sci, ca.sci, 8);
    memcpy(sb.my_sci, cb.sci, 8);
    wm_Participant_Init(&A, &ca);
    wm_Participant_Init(&B, &cb);

    run_pair(&A, &B, &a2b, &b2a, 12, NULL);

    CHECK(A.sak_cipher_suite == MKA_CIPHER_GCM_AES_XPN_128, "A uses XPN-128");
    CHECK(B.sak_cipher_suite == MKA_CIPHER_GCM_AES_XPN_128, "B uses XPN-128");
    CHECK(sa.cipher_suite == MKA_CIPHER_GCM_AES_XPN_128, "SecY A told XPN");
    CHECK(sb.cipher_suite == MKA_CIPHER_GCM_AES_XPN_128, "SecY B told XPN");
    /* A has the lower SCI -> SSCI 1; B -> SSCI 2. */
    CHECK(sa.tx_ssci == 1 && sa.rx_ssci == 2, "A: own SSCI 1, peer SSCI 2");
    CHECK(sb.tx_ssci == 2 && sb.rx_ssci == 1, "B: own SSCI 2, peer SSCI 1");
    /* Consistency: each end's view of a given SC's SSCI agrees. */
    CHECK(sa.tx_ssci == sb.rx_ssci, "A.tx SSCI == B.rx SSCI");
    CHECK(sb.tx_ssci == sa.rx_ssci, "B.tx SSCI == A.rx SSCI");
}
#endif /* WOLFMKA_NO_XPN */

/* Delay protection: the peer's reported PN advances our Rx replay window (IEEE
 * Std 802.1X-2010, 9.4.1). */
#ifndef WOLFMKA_NO_DELAY_PROTECT
static void test_delay_protection(void)
{
    Wire a2b, b2a;
    Secy sa, sb;
    MkaParticipant A, B;
    MkaParticipantConfig ca, cb;

    printf("Delay protection (LPN exchange):\n");
    memset(&a2b, 0, sizeof a2b);
    memset(&b2a, 0, sizeof b2a);
    memset(&sa, 0, sizeof sa);
    memset(&sb, 0, sizeof sb);
    cfg_part(&ca, &sa, &a2b, send_a, 0x0A, 10);
    cfg_part(&cb, &sb, &b2a, send_b, 0x0B, 20);
    ca.delay_protect = 1;
    cb.delay_protect = 1;
    wm_Participant_Init(&A, &ca);
    wm_Participant_Init(&B, &cb);

    run_pair(&A, &B, &a2b, &b2a, 14, NULL);
    CHECK(sa.set_lowest_pn_calls > 0, "A advanced rx window from peer PN");
    CHECK(sb.set_lowest_pn_calls > 0, "B advanced rx window from peer PN");
    CHECK(sa.last_lowest_pn > 0, "A received a non-zero LPN");
}
#endif /* WOLFMKA_NO_DELAY_PROTECT */

/* Loopback of our own MKPDU is ignored; the sent flag tracks transmission. */
static void test_kay_misc(void)
{
    Wire w;
    Secy s;
    MkaParticipant A;
    MkaParticipantConfig c;
    uint8_t f[512];
    size_t n = sizeof f;
    bool sent = false;

    printf("kay misc (loopback ignore, sent flag):\n");
    memset(&w, 0, sizeof w);
    memset(&s, 0, sizeof s);
    cfg_part(&c, &s, &w, send_a, 0x0A, 10);
    wm_Participant_Init(&A, &c);

    CHECK(wm_Participant_BuildMkpdu(&A, f, sizeof f, &n) == MKA_OK, "build");
    CHECK(wm_Participant_Receive(&A, f, n, 0) == MKA_OK, "loopback ignored");
    CHECK(wm_Participant_LivePeerCount(&A) == 0, "no self peer");

    wm_Participant_Run(&A, 0, &sent);
    CHECK(sent, "sent flag set on transmit");
}

/* Configure one CA: distinct CAK + CKN, given SCI octet / priority / wire. */
static void cfg_ca(MkaParticipantConfig* c, Secy* s, Wire* tx, MkaSendFn snd,
    uint8_t last_octet, uint8_t pri, uint8_t cak_fill, const char* ckn)
{
    uint8_t sci[8] = {0, 0, 0, 0, 0, 0, 0, 1};
    memset(c, 0, sizeof(*c));
    memset(&c->cak, 0, sizeof(c->cak));
    memset(c->cak.cak, cak_fill, 16);
    c->cak.cak_len = 16;
    memcpy(c->cak.ckn, ckn, strlen(ckn));
    c->cak.ckn_len = strlen(ckn);
    sci[5] = last_octet;
    memcpy(c->sci, sci, 8);
    c->priority = pri;
    c->macsec_desired = 1;
    c->macsec_capability = MKA_CAP_INTEGRITY_CONF_OFFSET;
    c->key_server_capable = 1;
    c->sak_len = 16;
    c->secy = make_secy(s);
    c->send = snd;
    c->send_ctx = tx;
    c->cmac = g_cmac;
}

/* Two Connectivity Associations sharing one port: each MKPDU is routed to the
 * participant that owns its CKN, and the two CAs converge independently. */
static void test_kay_manager(void)
{
    Wire a2b, b2a;
    Secy sa1, sa2, sb1, sb2;
    MkaKay A, B;
    MkaParticipantConfig ca1, ca2, cb1, cb2;
    MkaParticipant *pa1, *pa2, *pb1, *pb2;
    int tick;

    printf("KaY manager: multiple CAs on one port, routed by CKN:\n");
    memset(&a2b, 0, sizeof a2b);
    memset(&b2a, 0, sizeof b2a);
    memset(&sa1, 0, sizeof sa1);
    memset(&sa2, 0, sizeof sa2);
    memset(&sb1, 0, sizeof sb1);
    memset(&sb2, 0, sizeof sb2);

    CHECK(wm_Kay_Init(&A) == MKA_OK, "init KaY A");
    CHECK(wm_Kay_Init(&B) == MKA_OK, "init KaY B");

    /* A is Key Server on both CAs (lower priority numbers). Both CAs on a
     * port share that port's send wire. */
    cfg_ca(&ca1, &sa1, &a2b, send_a, 0x0A, 10, 0xC1, "ckn-one");
    cfg_ca(&ca2, &sa2, &a2b, send_a, 0x0A, 10, 0xC2, "ckn-two");
    cfg_ca(&cb1, &sb1, &b2a, send_b, 0x0B, 20, 0xC1, "ckn-one");
    cfg_ca(&cb2, &sb2, &b2a, send_b, 0x0B, 20, 0xC2, "ckn-two");

    CHECK(wm_Kay_AddParticipant(&A, &ca1, &pa1) == MKA_OK, "A add ckn-one");
    CHECK(wm_Kay_AddParticipant(&A, &ca2, &pa2) == MKA_OK, "A add ckn-two");
    CHECK(wm_Kay_AddParticipant(&B, &cb1, &pb1) == MKA_OK, "B add ckn-one");
    CHECK(wm_Kay_AddParticipant(&B, &cb2, &pb2) == MKA_OK, "B add ckn-two");
    CHECK(wm_Kay_ParticipantCount(&A) == 2, "A has 2 CAs");

    /* Adding a CA whose CKN is already present is rejected. */
    CHECK(wm_Kay_AddParticipant(&A, &ca1, NULL) == MKA_ERR_STATE,
        "duplicate CKN rejected");

    /* Lookup by CKN resolves to the right participant. */
    CHECK(wm_Kay_Find(&A, (const uint8_t*)"ckn-two", 7) == pa2, "find two");
    CHECK(wm_Kay_Find(&A, (const uint8_t*)"nope", 4) == NULL, "find miss");

    /* Run both ports; the manager demuxes each frame to its CA by CKN. */
    for (tick = 0; tick < 12; tick++) {
        uint8_t f[512];
        size_t n;
        uint32_t t = (uint32_t)tick * MKA_HELLO_TIME_MS;
        wm_Kay_Run(&A, t);
        wm_Kay_Run(&B, t);
        while (wire_pop(&a2b, f, &n))
            wm_Kay_Receive(&B, f, n, t);
        while (wire_pop(&b2a, f, &n))
            wm_Kay_Receive(&A, f, n, t);
    }

    /* Each CA discovered exactly its own peer and agreed on a SAK. */
    CHECK(wm_Participant_LivePeerCount(pa1) == 1, "ckn-one: 1 peer at A");
    CHECK(wm_Participant_LivePeerCount(pa2) == 1, "ckn-two: 1 peer at A");
    CHECK(wm_Participant_HasSak(pa1) && wm_Participant_HasSak(pb1),
        "ckn-one converged");
    CHECK(wm_Participant_HasSak(pa2) && wm_Participant_HasSak(pb2),
        "ckn-two converged");
    CHECK_EQ_MEM(pa1->latest.sak, pb1->latest.sak, 16, "ckn-one SAK agrees");
    CHECK_EQ_MEM(pa2->latest.sak, pb2->latest.sak, 16, "ckn-two SAK agrees");

    /* The two CAs derive independent keys - no cross-talk. */
    CHECK(memcmp(pa1->latest.sak, pa2->latest.sak, 16) != 0,
        "the two CAs use different SAKs");

    /* A frame for an unmanaged CKN is dropped, not misrouted. */
    {
        uint8_t f[512];
        size_t n = sizeof f;
        MkaParticipantConfig cx;
        Secy sx;
        MkaParticipant X;
        memset(&sx, 0, sizeof sx);
        cfg_ca(&cx, &sx, NULL, NULL, 0x0E, 30, 0xCE, "ckn-alien");
        wm_Participant_Init(&X, &cx);
        CHECK(wm_Participant_BuildMkpdu(&X, f, sizeof f, &n) == MKA_OK,
            "build alien frame");
        CHECK(wm_Kay_Receive(&A, f, n, 0) == MKA_ERR_NO_PEER,
            "unmanaged CKN dropped");
    }

    /* Remove a CA: MKA stops for that CKN and the table compacts around it. */
    CHECK(wm_Kay_RemoveParticipant(NULL, (const uint8_t*)"ckn-one", 7) ==
              MKA_ERR_BAD_ARG,
        "remove NULL kay");
    CHECK(wm_Kay_RemoveParticipant(&A, NULL, 7) == MKA_ERR_BAD_ARG,
        "remove NULL ckn");
    CHECK(wm_Kay_RemoveParticipant(&A, (const uint8_t*)"ckn-gone", 8) ==
              MKA_ERR_NO_PEER,
        "remove unknown CKN (length differs)");
    /* Same length as the managed CKNs but different content, so the scan
     * compares contents and still finds no match. */
    CHECK(wm_Kay_RemoveParticipant(&A, (const uint8_t*)"ckn-zzz", 7) ==
              MKA_ERR_NO_PEER,
        "remove unknown CKN (length matches, content differs)");
    /* ckn-one is the first slot, so removing it shifts ckn-two down. */
    CHECK(wm_Kay_RemoveParticipant(&A, (const uint8_t*)"ckn-one", 7) == MKA_OK,
        "remove ckn-one");
    CHECK(wm_Kay_ParticipantCount(&A) == 1, "A down to 1 CA");
    CHECK(wm_Kay_Find(&A, (const uint8_t*)"ckn-one", 7) == NULL,
        "ckn-one gone after remove");
    {
        /* ckn-two survived the compaction and kept its agreed SAK. */
        MkaParticipant* survivor =
            wm_Kay_Find(&A, (const uint8_t*)"ckn-two", 7);
        CHECK(survivor != NULL, "ckn-two still present");
        CHECK((survivor != NULL) && wm_Participant_HasSak(survivor),
            "ckn-two kept its SAK across compaction");
    }
}

/* A peer that does not desire MACsec is skipped by the Key Server election (and
 * such a participant never self-elects): exercises the macsec_desired operands
 * of the self- and peer-candidacy tests. */
static void test_kay_macsec_undesired(void)
{
    Wire a2b, b2a;
    Secy sa, sb;
    MkaParticipant A, B;
    MkaParticipantConfig ca, cb;

    printf("peer not desiring MACsec is skipped in election:\n");
    memset(&a2b, 0, sizeof a2b);
    memset(&b2a, 0, sizeof b2a);
    memset(&sa, 0, sizeof sa);
    memset(&sb, 0, sizeof sb);
    cfg_part(&ca, &sa, &a2b, send_a, 0x0A, 10);
    cfg_part(&cb, &sb, &b2a, send_b, 0x0B, 20);
    cb.macsec_desired = 0; /* B advertises no MACsec desire */
    wm_Participant_Init(&A, &ca);
    wm_Participant_Init(&B, &cb);

    run_pair(&A, &B, &a2b, &b2a, 12, NULL);
    CHECK(wm_Participant_LivePeerCount(&A) == 1, "A sees B live");
    CHECK(wm_Participant_IsKeyServer(&A) == 1, "A is key server");
    CHECK(wm_Participant_IsKeyServer(&B) == 0, "B never self-elects");

    /* MKA keeps running, but a participant that does not want MACsec takes no
     * part in protecting traffic: it declines the Key Server's SAK rather than
     * programming the data plane it was configured not to have (OPEN Alliance
     * AutoMKA-12002). */
    CHECK(!wm_Participant_HasSak(&B), "B installs no SAK");
    CHECK(sb.tx_installed == 0 && sb.rx_installed == 0,
        "B's SecY was never programmed");
    CHECK(sb.tx_enabled == 0 && sb.rx_enabled == 0, "B enabled no protection");
    CHECK(sb.set_lowest_pn_calls == 0, "B read/wrote no packet numbers");
    CHECK(wm_Participant_PeerCount(&B) == 1U, "B still runs MKA with its "
                                              "peer");
    CHECK(wm_Participant_HasSak(&A), "the Key Server still holds its own SAK");
}

/* A second run inside the Hello interval must not retransmit (the do_tx false
 * arm of the transmit gate). */
static void test_kay_no_retransmit(void)
{
    Wire w;
    Secy s;
    MkaParticipant A;
    MkaParticipantConfig c;
    bool sent;

    printf("transmit suppressed within the Hello interval:\n");
    memset(&w, 0, sizeof w);
    memset(&s, 0, sizeof s);
    cfg_part(&c, &s, &w, send_a, 0x0A, 10);
    wm_Participant_Init(&A, &c);

    wm_Participant_Run(&A, 0, &sent);
    CHECK(sent, "first run transmits");
    wm_Participant_Run(&A, 100, &sent);
    CHECK(!sent, "no retransmit before Hello Time elapses");
}

/* 256-bit SAK with the default cipher selects GCM-AES-256, and an XPN-256
 * configuration converges: exercises the 256-bit cipher-selection ternary and
 * the XPN-256 arm of mka_cipher_is_xpn. */
static void test_kay_cipher_variants(void)
{
    Wire a2b, b2a;
    Secy sa, sb;
    MkaParticipant A, B;
    MkaParticipantConfig ca, cb;

    printf("256-bit SAK (GCM-256 default) and XPN-256 convergence:\n");

    memset(&a2b, 0, sizeof a2b);
    memset(&b2a, 0, sizeof b2a);
    memset(&sa, 0, sizeof sa);
    memset(&sb, 0, sizeof sb);
    cfg_part(&ca, &sa, &a2b, send_a, 0x0A, 10);
    cfg_part(&cb, &sb, &b2a, send_b, 0x0B, 20);
    ca.sak_len = 32;
    cb.sak_len = 32; /* default cipher -> GCM-256 */
    wm_Participant_Init(&A, &ca);
    wm_Participant_Init(&B, &cb);
    run_pair(&A, &B, &a2b, &b2a, 12, NULL);
    CHECK(A.latest.sak_len == 32 && B.latest.sak_len == 32, "256-bit SAK");
    CHECK(A.sak_cipher_suite == MKA_CIPHER_GCM_AES_256, "GCM-AES-256 selected");

#ifndef WOLFMKA_NO_XPN
    memset(&a2b, 0, sizeof a2b);
    memset(&b2a, 0, sizeof b2a);
    memset(&sa, 0, sizeof sa);
    memset(&sb, 0, sizeof sb);
    cfg_part(&ca, &sa, &a2b, send_a, 0x0A, 10);
    cfg_part(&cb, &sb, &b2a, send_b, 0x0B, 20);
    ca.sak_len = 32;
    cb.sak_len = 32;
    ca.cipher_suite = MKA_CIPHER_GCM_AES_XPN_256;
    cb.cipher_suite = MKA_CIPHER_GCM_AES_XPN_256;
    memcpy(sa.my_sci, ca.sci, 8);
    memcpy(sb.my_sci, cb.sci, 8);
    wm_Participant_Init(&A, &ca);
    wm_Participant_Init(&B, &cb);
    run_pair(&A, &B, &a2b, &b2a, 12, NULL);
    CHECK(A.sak_cipher_suite == MKA_CIPHER_GCM_AES_XPN_256, "XPN-256 selected");
    CHECK(sa.cipher_suite == MKA_CIPHER_GCM_AES_XPN_256, "SecY told XPN-256");
#endif
}

/* Targeted condition-operand coverage: a frame whose CKN *length* differs from
 * the participant's CA, and a frame that lists our MI only in its Potential
 * (not Live) Peer List. Both are crafted and sealed with the participant's own
 * ICK so they pass ICV verification and reach the inner checks. */
static void test_kay_branch_combos(void)
{
    Secy s;
    MkaParticipant A;
    MkaParticipantConfig ca;
    MkaPdu in;
    uint8_t f[512];
    size_t n;

    printf("kay condition-operand coverage (CKN length, potential list):\n");
    memset(&s, 0, sizeof s);
    cfg_part(&ca, &s, NULL, NULL, 0x0A, 10); /* CKN "shared-ckn", len 10 */
    wm_Participant_Init(&A, &ca);

    /* (1) CKN length mismatch: same CAK/ICK, shorter CKN -> ckn_len differs. */
    memset(&in, 0, sizeof in);
    in.basic.version = 1;
    in.basic.algo_agility = MKA_ALGO_AGILITY_DEFAULT;
    memcpy(in.basic.ckn, "shared-ckn", 8);
    in.basic.ckn_len = 8; /* vs 10 */
    memset(in.basic.mi, 0x99, MKA_MI_LEN);
    in.basic.mn = 1;
    n = sizeof f;
    CHECK(wm_Pdu_Encode(g_cmac, &in, A.keys.ick, A.keys.ick_len, f, sizeof f,
              &n) == MKA_OK,
        "encode ckn-len frame");
    CHECK(wm_Participant_Receive(&A, f, n, 0) == MKA_ERR_NO_PEER,
        "CKN length mismatch -> NO_PEER");

    /* (2) Our MI appears only in the sender's Potential Peer List. */
    memset(&in, 0, sizeof in);
    in.basic.version = 1;
    in.basic.algo_agility = MKA_ALGO_AGILITY_DEFAULT;
    memcpy(in.basic.ckn, "shared-ckn", 10);
    in.basic.ckn_len = 10;
    memset(in.basic.mi, 0x98, MKA_MI_LEN);
    in.basic.mn = 1;
    in.potential_peers.present = 1;
    in.potential_peers.count = 2;
    memset(in.potential_peers.peers[0].mi, 0x11, MKA_MI_LEN); /* not ours */
    memcpy(in.potential_peers.peers[1].mi, A.actor_mi, MKA_MI_LEN);
    in.potential_peers.peers[1].mn = echo_mn(&A);
    n = sizeof f;
    CHECK(wm_Pdu_Encode(g_cmac, &in, A.keys.ick, A.keys.ick_len, f, sizeof f,
              &n) == MKA_OK,
        "encode potential-list frame");
    CHECK(wm_Participant_Receive(&A, f, n, 0) == MKA_OK,
        "frame listing our MI in potential list accepted");
    CHECK(wm_Participant_LivePeerCount(&A) == 1,
        "peer became live via potential-list echo");
}

/* Build a peer states that the convergence tests never produce: a valid but
 * non-live peer present while an XPN Key Server installs a SAK (exercised by
 * mka_compute_ssci and the SAK-install loop), and a non-Key-Server with a peer
 * that is not the Key Server (the SAK-Use Key-Server-MI search skips it). */
static void test_kay_peer_state_combos(void)
{
    Wire a2b, b2a;
    Secy sa, sb;
    MkaParticipant A, B;
    MkaParticipantConfig ca, cb;
    MkaPdu in;
    uint8_t f[512];
    size_t n;

    printf("peer-state combinations (non-live peer, non-KS peer):\n");
    memset(&a2b, 0, sizeof a2b);
    memset(&b2a, 0, sizeof b2a);
    memset(&sa, 0, sizeof sa);
    memset(&sb, 0, sizeof sb);
    cfg_part(&ca, &sa, &a2b, send_a, 0x0A, 10); /* A: KS */
    cfg_part(&cb, &sb, &b2a, send_b, 0x0B, 20);
#ifdef WOLFMKA_NO_XPN
    ca.cipher_suite = MKA_CIPHER_GCM_AES_256;
    cb.cipher_suite = MKA_CIPHER_GCM_AES_256;
#else
    ca.cipher_suite = MKA_CIPHER_GCM_AES_XPN_256;
    cb.cipher_suite = MKA_CIPHER_GCM_AES_XPN_256;
#endif
    ca.sak_len = 32;
    cb.sak_len = 32;
    memcpy(sa.my_sci, ca.sci, 8);
    memcpy(sb.my_sci, cb.sci, 8);
    wm_Participant_Init(&A, &ca);
    wm_Participant_Init(&B, &cb);

    run_pair(&A, &B, &a2b, &b2a, 12, NULL);
    CHECK(wm_Participant_IsKeyServer(&A) && wm_Participant_HasSak(&B),
        "XPN-256 converged, A is KS");

    /* Craft a third identity C (distinct SCI, distinct MI) that does NOT echo
     * anyone, sealed with the shared ICK (A and B share CAK/CKN, hence ICK). */
    memset(&in, 0, sizeof in);
    in.basic.version = 1;
    in.basic.algo_agility = MKA_ALGO_AGILITY_DEFAULT;
    memcpy(in.basic.ckn, "shared-ckn", 10);
    in.basic.ckn_len = 10;
    memset(in.basic.mi, 0xCC, MKA_MI_LEN);
    in.basic.mn = 1;
    {
        uint8_t sci[8] = {0, 0, 0, 0, 0, 0x0C, 0, 1};
        memcpy(in.basic.sci, sci, 8);
    }

    /* Deliver C to A: C becomes a valid-but-not-live peer. */
    n = sizeof f;
    wm_Pdu_Encode(g_cmac, &in, A.keys.ick, A.keys.ick_len, f, sizeof f, &n);
    CHECK(wm_Participant_Receive(&A, f, n, 0) == MKA_OK, "A learns of C");

    /* Rekey: mka_install_sak (and mka_compute_ssci for XPN) now iterate over B
     * (live) and C (valid, not live). */
    CHECK(wm_Participant_Rekey(&A) == MKA_OK, "A rekeys with a non-live peer");

    /* Deliver C to B: B (a non-Key-Server) now has a peer that is not the Key
     * Server. Its next transmit builds SAK Use, whose KS-MI search skips C. */
    n = sizeof f;
    wm_Pdu_Encode(g_cmac, &in, B.keys.ick, B.keys.ick_len, f, sizeof f, &n);
    CHECK(wm_Participant_Receive(&B, f, n, 0) == MKA_OK, "B learns of C");
    n = sizeof f;
    CHECK(wm_Participant_BuildMkpdu(&B, f, sizeof f, &n) == MKA_OK,
        "B builds SAK Use with a non-KS peer present");
}

/* AUTOSAR CP profile: a configured fixed Key Server overrides priority-based
 * election, and the Key Server auto-rekeys after the configured time span. */
static void test_fixed_role_and_auto_rekey(void)
{
    Wire a2b, b2a;
    Secy sa, sb;
    MkaParticipant A, B;
    MkaParticipantConfig ca, cb;
    uint32_t t;
    int tick;

    printf("fixed role override + automatic rekey (time span):\n");
    memset(&a2b, 0, sizeof a2b);
    memset(&b2a, 0, sizeof b2a);
    memset(&sa, 0, sizeof sa);
    memset(&sb, 0, sizeof sb);

    /* A is the *configured* Key Server despite the worse priority (200); B is
     * the configured peer despite the better priority (10). */
    cfg_part(&ca, &sa, &a2b, send_a, 0x0A, 200);
    cfg_part(&cb, &sb, &b2a, send_b, 0x0B, 10);
    ca.role = MKA_ROLE_KEY_SERVER;
    cb.role = MKA_ROLE_PEER;
    /* Auto-rekey disabled during convergence so the handover is quiescent;
     * switched on below once a clean single SAK is in use. */

    CHECK(wm_Participant_Init(&A, &ca) == MKA_OK, "init A");
    CHECK(wm_Participant_Init(&B, &cb) == MKA_OK, "init B");

    for (tick = 0; tick < 12; tick++) {
        uint8_t f[512];
        size_t n;
        t = (uint32_t)tick * MKA_HELLO_TIME_MS;
        wm_Participant_Run(&A, t, NULL);
        wm_Participant_Run(&B, t, NULL);
        while (wire_pop(&a2b, f, &n)) {
            wm_Participant_Receive(&B, f, n, t);
        }
        while (wire_pop(&b2a, f, &n)) {
            wm_Participant_Receive(&A, f, n, t);
        }
    }

    CHECK(wm_Participant_IsKeyServer(&A) == 1,
        "A is the configured Key Server (overrides priority)");
    CHECK(wm_Participant_IsKeyServer(&B) == 0,
        "B is the configured peer (overrides priority)");
    CHECK(wm_Participant_HasSak(&A) && wm_Participant_HasSak(&B),
        "both installed a SAK");
    CHECK_EQ_MEM(A.latest.sak, B.latest.sak, 16, "fixed-role SAK agreement");
    CHECK(!A.old.valid, "no handover in progress before auto-rekey");

#ifndef WOLFMKA_NO_AUTO_REKEY
    /* Enable auto-rekey and keep advancing time in sub-life-time steps (so the
     * peer stays live) until the period elapses and one rekey fires. */
    uint32_t kn_before;
    A.cfg.sak_rekey_time_ms = 5000U;
    kn_before = A.latest.kn;
    for (tick = 12; (tick < 20) && (A.latest.kn == kn_before); tick++) {
        uint8_t f[512];
        size_t n;
        t = (uint32_t)tick * MKA_HELLO_TIME_MS; /* +2 s/tick < 6 s life */
        wm_Participant_Run(&A, t, NULL);
        wm_Participant_Run(&B, t, NULL);
        while (wire_pop(&a2b, f, &n)) {
            wm_Participant_Receive(&B, f, n, t);
        }
        while (wire_pop(&b2a, f, &n)) {
            wm_Participant_Receive(&A, f, n, t);
        }
    }
    CHECK(A.latest.kn > kn_before, "auto-rekey advanced the Key Number");

    /* Disable further rekeys and let the make-before-break handover settle so
     * both ends converge deterministically on the new key. */
    A.cfg.sak_rekey_time_ms = 0U;
    for (; tick < 28; tick++) {
        uint8_t f[512];
        size_t n;
        t = (uint32_t)tick * MKA_HELLO_TIME_MS;
        wm_Participant_Run(&A, t, NULL);
        wm_Participant_Run(&B, t, NULL);
        while (wire_pop(&a2b, f, &n)) {
            wm_Participant_Receive(&B, f, n, t);
        }
        while (wire_pop(&b2a, f, &n)) {
            wm_Participant_Receive(&A, f, n, t);
        }
    }
    CHECK(B.latest.kn == A.latest.kn, "peer followed the rekey");
    CHECK_EQ_MEM(A.latest.sak, B.latest.sak, 16, "post-rekey SAK agreement");
#endif /* WOLFMKA_NO_AUTO_REKEY */
}

/* MKA retry interval grows base, 2x, 4x, ... and clamps at the cyclic ceiling
 * while no peer is established (AUTOSAR CP_SWS_Mka_00012). */
#ifndef WOLFMKA_NO_RETRY
static void test_retry_backoff(void)
{
    Wire a_out;
    Secy sa;
    MkaParticipant A;
    MkaParticipantConfig ca;

    printf("MKA retry exponential back-off:\n");
    memset(&a_out, 0, sizeof a_out);
    memset(&sa, 0, sizeof sa);
    cfg_part(&ca, &sa, &a_out, send_a, 0x0A, 10);
    ca.retry_base_ms = 20;
    ca.retry_cyclic_ms = 500;
    CHECK(wm_Participant_Init(&A, &ca) == MKA_OK, "init");

    /* No peer ever becomes live, so the retry back-off governs transmission. */
    CHECK(A.retry_delay_ms == 20U, "initial retry delay = base");
    wm_Participant_Run(&A, 0U, NULL); /* first (immediate) tx */
    CHECK(A.retry_delay_ms == 20U, "base held after first tx");
    wm_Participant_Run(&A, 20U, NULL); /* gate 20 met -> tx, double */
    CHECK(A.retry_delay_ms == 40U, "doubled to 40");
    wm_Participant_Run(&A, 60U, NULL); /* gate 40 met -> double */
    CHECK(A.retry_delay_ms == 80U, "doubled to 80");
    wm_Participant_Run(&A, 140U, NULL); /* gate 80 met -> double */
    CHECK(A.retry_delay_ms == 160U, "doubled to 160");
    wm_Participant_Run(&A, 300U, NULL); /* 160 -> 320 */
    wm_Participant_Run(&A, 620U, NULL); /* 320*2=640 clamped to 500 */
    CHECK(A.retry_delay_ms == 500U, "clamped at cyclic ceiling");
    wm_Participant_Run(&A, 1120U, NULL); /* holds at 500 */
    CHECK(A.retry_delay_ms == 500U, "holds at ceiling");
}
#endif /* WOLFMKA_NO_RETRY */

/* XPN parameter set is emitted/reconstructed through the KaY, and a transmit PN
 * past the XPN exhaustion threshold drives an automatic rekey. */
#ifndef WOLFMKA_NO_XPN
static void test_xpn_param_set_kay(void)
{
    Wire a2b, b2a;
    Secy sa, sb;
    MkaParticipant A, B;
    MkaParticipantConfig ca, cb;
    int found;
    size_t i;

    printf("XPN parameter set emit/reconstruct + PN-exhaustion rekey:\n");
    memset(&a2b, 0, sizeof a2b);
    memset(&b2a, 0, sizeof b2a);
    memset(&sa, 0, sizeof sa);
    memset(&sb, 0, sizeof sb);
    cfg_part(&ca, &sa, &a2b, send_a, 0x0A,
        10); /* A: lower priority value -> KS */
    cfg_part(&cb, &sb, &b2a, send_b, 0x0B, 20);
    ca.cipher_suite = MKA_CIPHER_GCM_AES_XPN_128;
    cb.cipher_suite = MKA_CIPHER_GCM_AES_XPN_128;
    ca.secy.get_next_pn = secy_get_pn_xpn; /* 64-bit PN source for XPN */
    cb.secy.get_next_pn = secy_get_pn_xpn;
    memcpy(sa.my_sci, ca.sci, 8);
    memcpy(sb.my_sci, cb.sci, 8);
    /* 64-bit transmit PNs with non-zero MSBs, below the exhaustion bound. */
    sa.xpn_val = 0x0000000A00000005ull;
    sb.xpn_val = 0x0000000B00000007ull;
    wm_Participant_Init(&A, &ca);
    wm_Participant_Init(&B, &cb);

    run_pair(&A, &B, &a2b, &b2a, 12, NULL);

    /* A reconstructed B's LPN MSBs from B's XPN parameter set. */
    found = 0;
    for (i = 0; i < MKA_MAX_PEERS; i++) {
        if (A.peers[i].valid && (A.peers[i].latest_lpn_msb == 0x0000000Bu)) {
            found = 1;
        }
    }
    CHECK(found, "received XPN MSBs reconstructed into peer record");

    #ifndef WOLFMKA_NO_AUTO_REKEY
    /* Push A's transmit PN past the XPN threshold -> automatic rekey. */
    uint32_t kn_before;
    int tick;
    kn_before = A.latest.kn;
    sa.xpn_val = 0xC000000000000001ull;
    for (tick = 12; (tick < 18) && (A.latest.kn == kn_before); tick++) {
        uint8_t f[512];
        size_t n;
        uint32_t t = (uint32_t)tick * MKA_HELLO_TIME_MS;
        wm_Participant_Run(&A, t, NULL);
        wm_Participant_Run(&B, t, NULL);
        while (wire_pop(&a2b, f, &n)) {
            wm_Participant_Receive(&B, f, n, t);
        }
        while (wire_pop(&b2a, f, &n)) {
            wm_Participant_Receive(&A, f, n, t);
        }
    }
    CHECK(A.latest.kn > kn_before, "XPN PN-exhaustion triggered auto-rekey");

    /* Settle the handover (old key in SAK Use + XPN) below threshold. */
    sa.xpn_val = 0x0000000A00000005ull;
    for (; tick < 24; tick++) {
        uint8_t f[512];
        size_t n;
        uint32_t t = (uint32_t)tick * MKA_HELLO_TIME_MS;
        wm_Participant_Run(&A, t, NULL);
        wm_Participant_Run(&B, t, NULL);
        while (wire_pop(&a2b, f, &n)) {
            wm_Participant_Receive(&B, f, n, t);
        }
        while (wire_pop(&b2a, f, &n)) {
            wm_Participant_Receive(&A, f, n, t);
        }
    }
    CHECK(B.latest.kn == A.latest.kn, "peer followed the XPN-exhaustion rekey");
    #endif /* WOLFMKA_NO_AUTO_REKEY */
}
#endif /* WOLFMKA_NO_XPN */

/* The KaY emits the Announcement set when configured, advertising the cipher
 * suite resolved from cfg.cipher_suite when explicit, or from cfg.sak_len when
 * cfg.cipher_suite == 0. Each row builds an MKPDU, decodes it, and checks the
 * single announced suite and its capability. */
#ifndef WOLFMKA_NO_ANNOUNCEMENTS
static void test_announce_emission(void)
{
    static const struct {
        uint64_t cfg_suite;  /* cfg.cipher_suite (0 = resolve from sak_len)  */
        size_t sak_len;      /* configured SAK length                        */
        uint64_t want_suite; /* cipher suite expected in the announcement    */
        const char* label;   /* CHECK message identifying the row            */
    } cases[] = {
        {0, 16, MKA_CIPHER_GCM_AES_128,
            "default suite (sak_len 16) -> AES-128"},
        {MKA_CIPHER_GCM_AES_256, 32, MKA_CIPHER_GCM_AES_256,
            "explicit -> AES-256"},
        {0, 32, MKA_CIPHER_GCM_AES_256,
            "default suite (sak_len 32) -> AES-256"},
    };
    Secy sa;
    MkaParticipant A;
    MkaParticipantConfig ca;
    Wire dummy;
    uint8_t buf[512];
    size_t n;
    size_t i;
    MkaPdu out;

    printf("Announcement (cipher suites) emission:\n");
    memset(&dummy, 0, sizeof dummy);

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        memset(&sa, 0, sizeof sa);
        cfg_part(&ca, &sa, &dummy, send_a, 0x0A, 10);
        ca.cipher_suite = cases[i].cfg_suite;
        ca.sak_len = cases[i].sak_len;
        ca.announce_cipher_suites = 1;
        wm_Participant_Init(&A, &ca);

        n = sizeof buf;
        CHECK(wm_Participant_BuildMkpdu(&A, buf, sizeof buf, &n) == MKA_OK,
            cases[i].label);
        CHECK(wm_Pdu_Decode(g_cmac, buf, n, A.keys.ick, A.keys.ick_len, &out) ==
                  MKA_OK,
            cases[i].label);
        CHECK(
            out.announce.present && (out.announce.count == 1) &&
                (out.announce.suites[0].cipher_suite == cases[i].want_suite) &&
                (out.announce.suites[0].capability ==
                    MKA_CAP_INTEGRITY_CONF_OFFSET),
            cases[i].label);
    }
}
#endif /* WOLFMKA_NO_ANNOUNCEMENTS */

/* A 32-bit transmit PN past the threshold drives auto-rekey (non-XPN suite,
 * AUTOSAR CP_SWS_Mka_00014). */
#ifndef WOLFMKA_NO_AUTO_REKEY
static void test_pn32_exhaustion_rekey(void)
{
    Wire a2b, b2a;
    Secy sa, sb;
    MkaParticipant A, B;
    MkaParticipantConfig ca, cb;
    uint32_t kn_before;
    int tick;

    printf("32-bit PN-exhaustion auto-rekey:\n");
    memset(&a2b, 0, sizeof a2b);
    memset(&b2a, 0, sizeof b2a);
    memset(&sa, 0, sizeof sa);
    memset(&sb, 0, sizeof sb);
    cfg_part(&ca, &sa, &a2b, send_a, 0x0A,
        10); /* A: lower priority value -> KS */
    cfg_part(&cb, &sb, &b2a, send_b, 0x0B, 20);
    wm_Participant_Init(&A, &ca);
    wm_Participant_Init(&B, &cb);
    run_pair(&A, &B, &a2b, &b2a, 12, NULL);
    CHECK(wm_Participant_IsKeyServer(&A), "A is key server");

    kn_before = A.latest.kn;
    sa.next_pn = 0xC0000000u; /* next get_next_pn() > threshold */
    for (tick = 12; (tick < 18) && (A.latest.kn == kn_before); tick++) {
        uint8_t f[512];
        size_t n;
        uint32_t t = (uint32_t)tick * MKA_HELLO_TIME_MS;
        wm_Participant_Run(&A, t, NULL);
        wm_Participant_Run(&B, t, NULL);
        while (wire_pop(&a2b, f, &n)) {
            wm_Participant_Receive(&B, f, n, t);
        }
        while (wire_pop(&b2a, f, &n)) {
            wm_Participant_Receive(&A, f, n, t);
        }
    }
    CHECK(A.latest.kn > kn_before, "32-bit PN exhaustion triggered auto-rekey");
}
#endif /* WOLFMKA_NO_AUTO_REKEY */

/* Failing SecY PN hooks: emission falls back gracefully and mka_pn_exhausted
 * (both the XPN and 32-bit paths) reports not-exhausted rather than misfiring.
 */
static void test_pn_hook_failures(void)
{
    Wire a2b, b2a;
    Secy sa, sb;
    MkaParticipant A, B;
    MkaParticipantConfig ca, cb;

    printf("PN-hook failure paths (XPN + 32-bit):\n");

#ifndef WOLFMKA_NO_XPN
    /* XPN suite with a failing 64-bit PN hook. */
    memset(&a2b, 0, sizeof a2b);
    memset(&b2a, 0, sizeof b2a);
    memset(&sa, 0, sizeof sa);
    memset(&sb, 0, sizeof sb);
    cfg_part(&ca, &sa, &a2b, send_a, 0x0A, 10);
    cfg_part(&cb, &sb, &b2a, send_b, 0x0B, 20);
    ca.cipher_suite = MKA_CIPHER_GCM_AES_XPN_128;
    cb.cipher_suite = MKA_CIPHER_GCM_AES_XPN_128;
    ca.secy.get_next_pn = secy_get_pn_fail;
    cb.secy.get_next_pn = secy_get_pn_fail;
    wm_Participant_Init(&A, &ca);
    wm_Participant_Init(&B, &cb);
    run_pair(&A, &B, &a2b, &b2a, 12, NULL);
    CHECK(wm_Participant_HasSak(&A) && wm_Participant_HasSak(&B),
        "XPN converges despite failing 64-bit PN hook");

    /* XPN suite with NO PN hook at all (get_next_pn == NULL): mka_build_xpn
     * emits the XPN set with zero PN MSBs and mka_pn_exhausted reports
     * not-exhausted - covering the hook-absent branch that the failing-hook
     * case (hook present, returns error) does not. */
    memset(&a2b, 0, sizeof a2b);
    memset(&b2a, 0, sizeof b2a);
    memset(&sa, 0, sizeof sa);
    memset(&sb, 0, sizeof sb);
    cfg_part(&ca, &sa, &a2b, send_a, 0x0A, 10);
    cfg_part(&cb, &sb, &b2a, send_b, 0x0B, 20);
    ca.cipher_suite = MKA_CIPHER_GCM_AES_XPN_128;
    cb.cipher_suite = MKA_CIPHER_GCM_AES_XPN_128;
    ca.secy.get_next_pn = NULL;
    cb.secy.get_next_pn = NULL;
    wm_Participant_Init(&A, &ca);
    wm_Participant_Init(&B, &cb);
    run_pair(&A, &B, &a2b, &b2a, 12, NULL);
    CHECK(wm_Participant_HasSak(&A) && wm_Participant_HasSak(&B),
        "XPN converges with no PN hook");
#endif

    /* Non-XPN Key Server with a failing 32-bit PN hook. */
    memset(&a2b, 0, sizeof a2b);
    memset(&b2a, 0, sizeof b2a);
    memset(&sa, 0, sizeof sa);
    memset(&sb, 0, sizeof sb);
    cfg_part(&ca, &sa, &a2b, send_a, 0x0A, 10);
    cfg_part(&cb, &sb, &b2a, send_b, 0x0B, 20);
    ca.secy.get_next_pn = secy_get_pn_fail;
    cb.secy.get_next_pn = secy_get_pn_fail;
    wm_Participant_Init(&A, &ca);
    wm_Participant_Init(&B, &cb);
    run_pair(&A, &B, &a2b, &b2a, 12, NULL);
    CHECK(wm_Participant_HasSak(&A),
        "converges with failing 32-bit get_next_pn");
}

/* Retry back-off edges: uncapped (cyclic == 0) doubling, and the reset that
 * happens once a peer is established. */
#ifndef WOLFMKA_NO_RETRY
static void test_retry_backoff_edges(void)
{
    Secy s2;
    MkaParticipant C;
    MkaParticipantConfig cc;
    Wire c_out;
    Wire d2e, e2d;
    Secy sd, se;
    MkaParticipant D, E;
    MkaParticipantConfig cd, ce;

    printf("retry back-off edges (uncapped + established reset):\n");

    /* retry_cyclic_ms == 0: the doubling is uncapped. */
    memset(&c_out, 0, sizeof c_out);
    memset(&s2, 0, sizeof s2);
    cfg_part(&cc, &s2, &c_out, send_a, 0x0C, 10);
    cc.retry_base_ms = 20;
    cc.retry_cyclic_ms = 0;
    wm_Participant_Init(&C, &cc);
    wm_Participant_Run(&C, 0U, NULL);  /* first tx, base held */
    wm_Participant_Run(&C, 20U, NULL); /* -> 40 */
    wm_Participant_Run(&C, 60U, NULL); /* -> 80 (no ceiling) */
    CHECK(C.retry_delay_ms == 80U, "uncapped back-off doubles freely");

    /* Saturation: an uncapped back-off near the 32-bit ceiling must saturate to
     * UINT32_MAX, not wrap to a tiny interval. Drive retry_delay_ms past 2^31
     * by hand, then make the next transmit (interval elapsed) double it. */
    C.retry_delay_ms = 0x80000001U;
    C.last_tx_ms = 0U;
    wm_Participant_Run(&C, 0x80000001U, NULL);
    CHECK(C.retry_delay_ms == 0xFFFFFFFFU,
        "uncapped back-off saturates instead of wrapping");

    /* Once a peer is established, not_established is false and the interval
     * resets to the base. */
    memset(&d2e, 0, sizeof d2e);
    memset(&e2d, 0, sizeof e2d);
    memset(&sd, 0, sizeof sd);
    memset(&se, 0, sizeof se);
    cfg_part(&cd, &sd, &d2e, send_a, 0x0D, 10);
    cfg_part(&ce, &se, &e2d, send_b, 0x0E, 20);
    cd.retry_base_ms = 20;
    cd.retry_cyclic_ms = 500;
    wm_Participant_Init(&D, &cd);
    wm_Participant_Init(&E, &ce);
    run_pair(&D, &E, &d2e, &e2d, 12, NULL);
    CHECK(wm_Participant_LivePeerCount(&D) == 1, "retry peer established");
    CHECK(D.retry_delay_ms == 20U, "retry interval reset once established");
}
#endif /* WOLFMKA_NO_RETRY */

/* Full decision coverage of the fixed-PEER Key Server scan in mka_run_election
 * (`pe->valid && pe->live && pe->key_server`). The peer table is populated by
 * hand so each operand is evaluated both ways within a single election. */
static void test_fixed_peer_election_scan(void)
{
    MkaParticipant P;
    MkaParticipantConfig c;
    Secy s;
    uint8_t ks_sci[8] = {0, 0, 0, 0, 0, 0x0B, 0, 1};

    printf("fixed-PEER election scan (operand combinations):\n");
    memset(&s, 0, sizeof s);
    cfg_part(&c, &s, NULL, NULL, 0x0A, 10); /* no send: run() is quiet */
    c.role = MKA_ROLE_PEER;
    CHECK(wm_Participant_Init(&P, &c) == MKA_OK, "init fixed peer");

    /* peers[0] !valid          -> `valid` false
     * peers[1] valid !live     -> `live` false
     * peers[2] valid live !KS  -> `key_server` false
     * peers[3] valid live KS   -> all true (the elected Key Server)
     * Unset fields stay zero from init's memset; recent last_seen_ms keeps the
     * valid peers from being expired. */
    P.peers[1].valid = true;
    P.peers[2].valid = true;
    P.peers[2].live = true;
    P.peers[3].valid = true;
    P.peers[3].live = true;
    P.peers[3].key_server = true;
    memcpy(P.peers[3].sci, ks_sci, 8);
    P.peers[1].last_seen_ms = 1000U;
    P.peers[2].last_seen_ms = 1000U;
    P.peers[3].last_seen_ms = 1000U;
    P.peer_count = 3;

    wm_Participant_Run(&P, 1000U, NULL);

    CHECK(!wm_Participant_IsKeyServer(&P), "fixed peer never serves");
    CHECK(P.elected, "election adopted a Key Server");
    CHECK(memcmp(P.ks_sci, ks_sci, 8) == 0, "adopted peers[3] as Key Server");
}

/* Auto-rekey enabled but the configured period has not elapsed: the time-span
 * comparison `(now - last_rekey) >= sak_rekey_time` is evaluated false, so no
 * rekey happens this step. The Key Server state is built by hand. */
static void test_autorekey_not_due(void)
{
    MkaParticipant P;
    MkaParticipantConfig c;
    Secy s;

    printf("auto-rekey time span not yet due:\n");
    memset(&s, 0, sizeof s);
    cfg_part(&c, &s, NULL, NULL, 0x0A, 10);
    c.role = MKA_ROLE_KEY_SERVER;
    c.sak_rekey_time_ms = 100000U; /* long period */
    CHECK(wm_Participant_Init(&P, &c) == MKA_OK, "init key server");

    /* Steady state: a SAK in use, no handover, just rekeyed, one live peer. */
    P.latest.valid = true;
    P.latest.an = 0;
    P.latest.kn = 5;
    P.latest.sak_len = 16;
    P.last_rekey_ms = 1000U; /* == now, so not yet due */
    P.peers[0].valid = true;
    P.peers[0].live = true;
    P.peers[0].last_seen_ms = 1000U;
    P.peer_count = 1;

    wm_Participant_Run(&P, 1000U, NULL);

    CHECK(wm_Participant_IsKeyServer(&P), "elected key server");
    CHECK(P.latest.kn == 5U, "no rekey before the period elapses");
}

/* XPN build during a make-before-break handover (old key valid) with a failing
 * 64-bit PN hook: the old-key branch of mka_build_xpn evaluates
 * get_next_pn(...) == 0 as false. State is built by hand. */
#ifndef WOLFMKA_NO_XPN
static void test_xpn_old_key_pn_fail(void)
{
    MkaParticipant P;
    MkaParticipantConfig c;
    Secy s;
    uint8_t buf[512];
    size_t n = sizeof buf;

    printf("XPN old-key emission with failing PN hook:\n");
    memset(&s, 0, sizeof s);
    cfg_part(&c, &s, NULL, NULL, 0x0A, 10);
    c.cipher_suite = MKA_CIPHER_GCM_AES_XPN_128;
    c.secy.get_next_pn = secy_get_pn_fail;
    CHECK(wm_Participant_Init(&P, &c) == MKA_OK, "init xpn");

    P.sak_cipher_suite = MKA_CIPHER_GCM_AES_XPN_128;
    P.latest.valid = true;
    P.latest.an = 0;
    P.latest.kn = 2;
    P.latest.sak_len = 16;
    P.old.valid = true;
    P.old.an = 1;
    P.old.kn = 1;
    P.old.sak_len = 16;

    CHECK(wm_Participant_BuildMkpdu(&P, buf, sizeof buf, &n) == MKA_OK,
        "build MKPDU in XPN handover with failing PN hook");

    /* The hook fails, so the old-key branch (old.valid && hook==0) is not
     * taken: the Old-key PN stays at its mka_build_sak_use default (old_lpn ==
     * 1, msb
     * == 0). Asserting that distinguishes this from the succeeding companion.
     */
    {
        MkaPdu out;
        CHECK(wm_Pdu_Decode(g_cmac, buf, n, P.keys.ick, P.keys.ick_len, &out) ==
                  MKA_OK,
            "decode handover frame (failing hook)");
        CHECK(out.sak_use.old_lpn == 1U,
            "old-key LPN stays default when hook fails");
        CHECK(out.xpn.old_lpn_msb == 0U,
            "old-key LPN msb stays zero when hook fails");
    }
}

/* Companion to the above with a *succeeding* 64-bit PN hook, so mka_build_xpn
 * actually emits the Old key's PN (the old_lpn / old_lpn_msb assignments). A
 * make-before-break Old key is produced by any rekey - the always-available
 * manual wm_Participant_Rekey and peer-departure forward secrecy, not only
 * the optional automatic-rekey policy - so this state, and the Old-key XPN
 * emission, must be covered independently of WOLFMKA_NO_AUTO_REKEY. Built by
 * hand so no rekey machinery is needed. */
static void test_xpn_old_key_pn_emit(void)
{
    MkaParticipant P;
    MkaParticipantConfig c;
    Secy s;
    uint8_t buf[512];
    size_t n = sizeof buf;

    printf("XPN old-key PN emission during handover:\n");
    memset(&s, 0, sizeof s);
    /* AN-dependent PN source: latest (an 0) and old (an 1) get distinct PNs, so
     * the asserts below pin that the old-key branch reads the *old* AN's PN. */
    cfg_part(&c, &s, NULL, NULL, 0x0A, 10);
    c.cipher_suite = MKA_CIPHER_GCM_AES_XPN_128;
    c.secy.get_next_pn = secy_get_pn_xpn_byan;
    CHECK(wm_Participant_Init(&P, &c) == MKA_OK, "init xpn");

    P.sak_cipher_suite = MKA_CIPHER_GCM_AES_XPN_128;
    P.latest.valid = true;
    P.latest.an = 0;
    P.latest.kn = 2;
    P.latest.sak_len = 16;
    P.old.valid = true;
    P.old.an = 1;
    P.old.kn = 1;
    P.old.sak_len = 16;

    CHECK(wm_Participant_BuildMkpdu(&P, buf, sizeof buf, &n) == MKA_OK,
        "build MKPDU emitting old-key XPN PN");

    /* Latest (an 0) -> 0x0000000B00000007, Old (an 1) -> 0x0000000D00000009.
     * The emitted frame must carry each AN's own PN split into its 32-bit LPN
     * (SAK Use) and MSB (XPN) halves; distinct values prove the old-key branch
     * read the Old AN's PN, not a reuse of the Latest AN's. */
    {
        MkaPdu out;
        CHECK(wm_Pdu_Decode(g_cmac, buf, n, P.keys.ick, P.keys.ick_len, &out) ==
                  MKA_OK,
            "decode emitted XPN handover frame");
        CHECK(out.sak_use.latest_lpn == 0x00000007U, "latest LPN low emitted");
        CHECK(out.xpn.latest_lpn_msb == 0x0000000BU, "latest LPN msb emitted");
        CHECK(out.sak_use.old_lpn == 0x00000009U, "old-key LPN low emitted");
        CHECK(out.xpn.old_lpn_msb == 0x0000000DU, "old-key LPN msb emitted");
    }
}
#endif /* WOLFMKA_NO_XPN */

/* Secure teardown: wm_Participant_Free / wm_Kay_Free wipe key
 * material and delete SecY SAs. Covers the old/latest teardown branches. */
static void test_free(void)
{
    Wire a2b, b2a;
    Secy sa, sb;
    MkaParticipant A, B, fresh;
    MkaParticipantConfig ca, cb, cf, ck;
    MkaKay kay;
    uint8_t zero[MKA_MAX_CAK_LEN];

    printf("participant/kay secure teardown:\n");
    memset(zero, 0, sizeof zero);

    /* NULL-tolerant. */
    wm_Participant_Free(NULL);
    wm_Kay_Free(NULL);

    memset(&a2b, 0, sizeof a2b);
    memset(&b2a, 0, sizeof b2a);
    memset(&sa, 0, sizeof sa);
    memset(&sb, 0, sizeof sb);
    cfg_part(&ca, &sa, &a2b, send_a, 0x0A, 10);
    cfg_part(&cb, &sb, &b2a, send_b, 0x0B, 20);
    wm_Participant_Init(&A, &ca);
    wm_Participant_Init(&B, &cb);
    run_pair(&A, &B, &a2b, &b2a, 12, NULL);

    /* A is the Key Server; rekey so it holds both an old and a latest SAK. */
    CHECK(wm_Participant_Rekey(&A) == MKA_OK, "rekey for old+latest");
    CHECK(A.old.valid && A.latest.valid, "A mid-rekey: old + latest");
    CHECK(B.latest.valid && !B.old.valid, "B: latest only");

    /* free A exercises both the old and latest SA-teardown paths. */
    wm_Participant_Free(&A);
    CHECK(!A.latest.valid && !A.old.valid, "A latest/old cleared");
    CHECK((A.cfg.cak.cak_len == 0U) &&
              (memcmp(A.keys.kek, zero, sizeof A.keys.kek) == 0),
        "A CAK + KEK wiped");

    /* free B exercises latest with no old. */
    wm_Participant_Free(&B);
    CHECK(!B.latest.valid, "B latest cleared");

    /* free a fresh (un-converged) participant: no SAK installed. */
    cfg_part(&cf, &sa, &a2b, send_a, 0x0C, 30);
    wm_Participant_Init(&fresh, &cf);
    CHECK(!fresh.latest.valid && !fresh.old.valid, "fresh has no SAK");
    wm_Participant_Free(&fresh);
    CHECK(fresh.cfg.cak.cak_len == 0U, "fresh wiped");

    /* kay_free frees each participant and resets the count. */
    wm_Kay_Init(&kay);
    cfg_part(&ck, &sa, &a2b, send_a, 0x0D, 40);
    CHECK(wm_Kay_AddParticipant(&kay, &ck, NULL) == MKA_OK, "kay add");
    CHECK(kay.count == 1U, "kay has one participant");
    wm_Kay_Free(&kay);
    CHECK(kay.count == 0U, "kay_free reset count");
}

/* Async SecY (Goal A): a backend that programs the transmit SA asynchronously
 * returns MKA_SECY_PENDING; the KaY must hold back enabling transmit protection
 * until the integrator reports completion with wm_Participant_SecyComplete,
 * so it never sends on an SA the hardware has not yet installed. */
static void test_async_secy(void)
{
    Wire a2b, b2a;
    Secy sa, sb;
    MkaParticipant A, B;
    MkaParticipantConfig ca, cb;

    printf("async SecY: transmit gated until SecyComplete:\n");
    memset(&a2b, 0, sizeof a2b);
    memset(&b2a, 0, sizeof b2a);
    memset(&sa, 0, sizeof sa);
    memset(&sb, 0, sizeof sb);
    cfg_part(&ca, &sa, &a2b, send_a, 0x0A, 10); /* A: Key Server */
    cfg_part(&cb, &sb, &b2a, send_b, 0x0B, 20);
    sa.tx_sa_async = 1; /* A's transmit-SA install completes asynchronously */
    wm_Participant_Init(&A, &ca);
    wm_Participant_Init(&B, &cb);

    /* Converge: A installs the SAK and B reports receiving on it, so transmit
     * would normally be enabled now - but the tx-SA install is still pending.
     */
    run_pair(&A, &B, &a2b, &b2a, 16, NULL);
    CHECK(wm_Participant_HasSak(&A), "A installed the SAK");
    CHECK(A.secy_pending == 1U, "tx-SA install is outstanding");
    CHECK(!A.latest.tx, "transmit held back while SecY install pending");
    CHECK(sa.tx_enabled == 0, "SecY transmit not enabled yet");

    /* Report the async install complete: the gate releases and transmit is
     * enabled on the Latest key. */
    CHECK(wm_Participant_SecyComplete(&A) == MKA_OK, "complete ok");
    CHECK(A.secy_pending == 0U, "no SecY ops outstanding");
    CHECK(A.latest.tx, "transmit enabled after completion");
    CHECK(sa.tx_enabled != 0, "SecY transmit now enabled");

    /* An extra completion when nothing is outstanding is harmless: the pending
     * count does not underflow and transmit stays enabled. */
    CHECK(wm_Participant_SecyComplete(&A) == MKA_OK, "extra complete ok");
    CHECK(A.secy_pending == 0U, "pending count does not underflow");
    CHECK(A.latest.tx, "transmit stays enabled");

    /* NULL participant is rejected. */
    CHECK(wm_Participant_SecyComplete(NULL) == MKA_ERR_BAD_ARG,
        "SecyComplete NULL rejected");
}

#ifdef WOLFMKA_DISTRIBUTED_CAK
static uint8_t g_rx_cak[MKA_MAX_CAK_LEN];
static size_t g_rx_cak_len;
static uint8_t g_rx_ckn[MKA_MAX_CKN_LEN];
static size_t g_rx_ckn_len;
static int g_cak_events;

static void on_cak_received(void* ctx, const uint8_t* cak, size_t cak_len,
    const uint8_t* ckn, size_t ckn_len)
{
    (void)ctx;
    memcpy(g_rx_cak, cak, cak_len);
    g_rx_cak_len = cak_len;
    memcpy(g_rx_ckn, ckn, ckn_len);
    g_rx_ckn_len = ckn_len;
    g_cak_events++;
}

/* Inject a Distributed CAK with a chosen (malformed) body length, signed with
 * B's ICK so B accepts the frame, and assert it delivers no CAK - exercising
 * the receiver's body-length guards (too short / CKN too long). */
static void inject_dist_cak(MkaParticipant* B, const MkaParticipant* A,
    const uint8_t* body, size_t body_len, uint32_t t, const char* msg)
{
    MkaPdu inj;
    uint8_t frame[512];
    size_t flen = sizeof(frame);
    int before = g_cak_events;

    memset(&inj, 0, sizeof(inj));
    inj.basic.version = 1;
    inj.basic.priority = 10;
    inj.basic.key_server = 1;
    inj.basic.macsec_desired = 1;
    inj.basic.macsec_capability = MKA_CAP_INTEGRITY_CONF_OFFSET;
    memcpy(inj.basic.sci, A->cfg.sci, MKA_SCI_LEN);
    memcpy(inj.basic.mi, A->actor_mi, MKA_MI_LEN);
    /* MN must strictly increase per MI or the frame is dropped as a replay
     * before any dist-CAK processing; derive it from the tick so successive
     * injections (called with increasing t) stay monotonic regardless of the
     * body_len under test. */
    inj.basic.mn = 0xFFFF00U + (t / MKA_HELLO_TIME_MS);
    inj.basic.algo_agility = MKA_ALGO_AGILITY_DEFAULT;
    memcpy(inj.basic.ckn, A->cfg.cak.ckn, A->cfg.cak.ckn_len);
    inj.basic.ckn_len = A->cfg.cak.ckn_len;
    /* Echo B's MI so A stays live and B stays a (non-Key-Server) member, which
     * is the state in which a member acts on a distributed CAK. */
    inj.live_peers.present = 1;
    inj.live_peers.count = 1;
    memcpy(inj.live_peers.peers[0].mi, B->actor_mi, MKA_MI_LEN);
    inj.live_peers.peers[0].mn = echo_mn(B);
    inj.dist_cak.present = 1;
    inj.dist_cak.body_len = body_len;
    if (body != NULL) {
        memcpy(inj.dist_cak.body, body, body_len);
    }
    CHECK(wm_Pdu_Encode(g_cmac, &inj, B->keys.ick, B->keys.ick_len, frame,
              sizeof(frame), &flen) == MKA_OK,
        "encode injected dist-cak");
    wm_Participant_Receive(B, frame, flen, t);
    CHECK(g_cak_events == before, msg);
}

/* Distributed CAK (type 5): the Key Server AES-Key-Wraps a group CAK with the
 * CA's KEK; the peer unwraps it with the same KEK and reports it through the
 * cak_received event. Also checks the staging API's argument validation, the
 * NULL-hook path, and that a wrong KEK is rejected by the unwrap. */
static void test_distributed_cak(void)
{
    Wire a2b, b2a;
    Secy sa, sb;
    MkaParticipant A, B;
    MkaParticipantConfig ca, cb;
    static const uint8_t gcak[16] = {0x67, 0x66, 0x65, 0x64, 0x63, 0x62, 0x61,
        0x60, 0x6F, 0x6E, 0x6D, 0x6C, 0x6B, 0x6A, 0x69, 0x68};
    static const uint8_t gckn[6] = {'g', 'r', 'o', 'u', 'p', '1'};
    uint8_t f[512];
    size_t n;
    int tick;
    int before;

    printf("Distributed CAK: KS distributes a group CAK to the peer:\n");
    g_cak_events = 0;
    g_rx_cak_len = 0;
    g_rx_ckn_len = 0;
    memset(&a2b, 0, sizeof a2b);
    memset(&b2a, 0, sizeof b2a);
    memset(&sa, 0, sizeof sa);
    memset(&sb, 0, sizeof sb);
    cfg_part(&ca, &sa, &a2b, send_a, 0x0A, 10); /* A: Key Server */
    cfg_part(&cb, &sb, &b2a, send_b, 0x0B, 20);
    cb.events.cak_received = on_cak_received;
    wm_Participant_Init(&A, &ca);
    wm_Participant_Init(&B, &cb);

    /* Argument validation on the staging API. */
    CHECK(wm_Participant_DistributeCak(NULL, gcak, 16, gckn, 6) ==
              MKA_ERR_BAD_ARG,
        "distribute NULL participant");
    CHECK(wm_Participant_DistributeCak(&A, NULL, 16, gckn, 6) ==
              MKA_ERR_BAD_ARG,
        "distribute NULL cak");
    CHECK(wm_Participant_DistributeCak(&A, gcak, 20, gckn, 6) ==
              MKA_ERR_BAD_ARG,
        "distribute bad cak len");
    CHECK(wm_Participant_DistributeCak(&A, gcak, 16, gckn, 0) ==
              MKA_ERR_BAD_ARG,
        "distribute bad ckn len");
    CHECK(wm_Participant_DistributeCak(&A, gcak, 16, NULL, 6) ==
              MKA_ERR_BAD_ARG,
        "distribute NULL ckn");
    CHECK(wm_Participant_DistributeCak(&A, gcak, 16, gckn,
              MKA_MAX_CKN_LEN + 1U) == MKA_ERR_BAD_ARG,
        "distribute ckn too long");
    {
        /* A 256-bit CAK is also valid; stage it on the non-Key-Server B so it
         * is never actually emitted (only the length check is under test). */
        static const uint8_t gcak32[32] = {0};
        CHECK(wm_Participant_DistributeCak(&B, gcak32, 32, gckn, 6) == MKA_OK,
            "distribute 256-bit cak accepted");
    }

    /* Converge so A is the Key Server and B is live, staging the group CAK
     * mid-run (time stays monotonic across the loop). */
    for (tick = 0; tick < 20; tick++) {
        uint32_t t = (uint32_t)tick * MKA_HELLO_TIME_MS;
        if (tick == 12) {
            CHECK(wm_Participant_DistributeCak(&A, gcak, 16, gckn, 6) == MKA_OK,
                "stage group CAK");
        }
        wm_Participant_Run(&A, t, NULL);
        wm_Participant_Run(&B, t, NULL);
        while (wire_pop(&a2b, f, &n))
            wm_Participant_Receive(&B, f, n, t);
        while (wire_pop(&b2a, f, &n))
            wm_Participant_Receive(&A, f, n, t);
    }
    CHECK(wm_Participant_HasSak(&A), "A is the Key Server");
    CHECK(g_cak_events > 0, "peer received a distributed CAK");
    CHECK(g_rx_cak_len == 16, "group CAK length");
    CHECK_EQ_MEM(g_rx_cak, gcak, 16, "group CAK matches");
    CHECK(g_rx_ckn_len == 6, "group CKN length");
    CHECK_EQ_MEM(g_rx_ckn, gckn, 6, "group CKN matches");

    /* With the event hook cleared, a further successful receive is a silent
     * no-op (the NULL-callback path). */
    B.cfg.events.cak_received = NULL;
    {
        uint32_t t = (uint32_t)20U * MKA_HELLO_TIME_MS;
        wm_Participant_Run(&A, t, NULL);
        while (wire_pop(&a2b, f, &n))
            wm_Participant_Receive(&B, f, n, t);
    }

    /* A wrong KEK fails the AES Key Unwrap integrity check: nothing delivered.
     */
    B.cfg.events.cak_received = on_cak_received;
    B.keys.kek[0] ^= 0xFFU;
    before = g_cak_events;
    {
        uint32_t t = (uint32_t)21U * MKA_HELLO_TIME_MS;
        wm_Participant_Run(&A, t, NULL);
        while (wire_pop(&a2b, f, &n))
            wm_Participant_Receive(&B, f, n, t);
    }
    CHECK(g_cak_events == before, "wrong KEK: no CAK delivered");

    /* Malformed body lengths are rejected before any unwrap: a body too short
     * to hold the wrapped CAK, and one whose CKN exceeds the maximum. */
    B.keys.kek[0] ^= 0xFFU; /* restore the KEK (unused by these guards) */
    inject_dist_cak(&B, &A, NULL, 10U, (uint32_t)22U * MKA_HELLO_TIME_MS,
        "short dist-cak body rejected");
    inject_dist_cak(&B, &A, NULL, 24U + MKA_MAX_CKN_LEN + 1U,
        (uint32_t)23U * MKA_HELLO_TIME_MS, "oversized CKN dist-cak rejected");

    /* Boundary: a body exactly the wrapped-CAK length (16-octet CAK -> 24)
     * means a zero-length CKN. Even with a *valid* wrap it must be rejected,
     * because a CKN is 1..MKA_MAX_CKN_LEN - the guard is `body_len <=
     * wrapped_len`, not
     * `<`. A valid wrap is required so the rejection is the length guard, not a
     * downstream unwrap failure. */
    {
        uint8_t wrapped[MKA_MAX_WRAPPED_SAK];
        size_t wl = sizeof wrapped;
        CHECK(wm_Crypto_WrapSak(B.keys.kek, B.keys.kek_len, gcak, 16, wrapped,
                  &wl) == MKA_OK,
            "wrap group CAK for empty-CKN boundary");
        inject_dist_cak(&B, &A, wrapped, wl, (uint32_t)24U * MKA_HELLO_TIME_MS,
            "empty-CKN dist-cak (body == wrapped len) rejected");
    }
}
#endif /* WOLFMKA_DISTRIBUTED_CAK */

#ifdef WOLFMKA_KMD
/* Key Management Domain (type 6): the Key Server advertises its configured KMD;
 * the peer records it and returns it through wm_Participant_GetKmd. Also
 * checks the getter's argument and buffer-size validation. */
static void test_kmd_propagation(void)
{
    Wire a2b, b2a;
    Secy sa, sb;
    MkaParticipant A, B;
    MkaParticipantConfig ca, cb;
    static const uint8_t kmd[10] = {'d', 'o', 'm', 'a', 'i', 'n', '-', 'a', 'b',
        'c'};
    uint8_t got[MKA_MAX_KMD_LEN];
    size_t got_len = 0U;

    printf("Key Management Domain: KS advertises, peer records it:\n");
    memset(&a2b, 0, sizeof a2b);
    memset(&b2a, 0, sizeof b2a);
    memset(&sa, 0, sizeof sa);
    memset(&sb, 0, sizeof sb);
    cfg_part(&ca, &sa, &a2b, send_a, 0x0A, 10); /* A: Key Server */
    cfg_part(&cb, &sb, &b2a, send_b, 0x0B, 20);
    memcpy(ca.kmd, kmd, sizeof kmd);
    ca.kmd_len = sizeof kmd;
    wm_Participant_Init(&A, &ca);
    wm_Participant_Init(&B, &cb);

    run_pair(&A, &B, &a2b, &b2a, 12, NULL);
    CHECK(wm_Participant_IsKeyServer(&A), "A is the Key Server");

    CHECK(wm_Participant_GetKmd(&B, got, sizeof got, &got_len) == MKA_OK,
        "get kmd");
    CHECK(got_len == sizeof kmd, "kmd length");
    CHECK_EQ_MEM(got, kmd, sizeof kmd, "kmd matches advertised");

    /* The Key Server records no KMD for itself. */
    got_len = 99U;
    CHECK((wm_Participant_GetKmd(&A, got, sizeof got, &got_len) == MKA_OK) &&
              (got_len == 0U),
        "KS records no KMD");

    /* Argument and buffer-size validation. */
    CHECK(wm_Participant_GetKmd(NULL, got, sizeof got, &got_len) ==
              MKA_ERR_BAD_ARG,
        "GetKmd NULL participant");
    CHECK(wm_Participant_GetKmd(&B, NULL, sizeof got, &got_len) ==
              MKA_ERR_BAD_ARG,
        "GetKmd NULL buffer");
    CHECK(wm_Participant_GetKmd(&B, got, sizeof got, NULL) == MKA_ERR_BAD_ARG,
        "GetKmd NULL length");
    CHECK(wm_Participant_GetKmd(&B, got, sizeof kmd - 1U, &got_len) ==
              MKA_ERR_BUFFER,
        "GetKmd buffer too small");

    /* A configured KMD longer than the fixed buffer is rejected at Init (it
     * would otherwise overrun the build-side copy). */
    {
        MkaParticipant Z;
        MkaParticipantConfig cz;
        Secy sz;
        memset(&sz, 0, sizeof sz);
        cfg_part(&cz, &sz, NULL, NULL, 0x0F, 10);
        cz.kmd_len = (size_t)MKA_MAX_KMD_LEN + 1U;
        CHECK(wm_Participant_Init(&Z, &cz) == MKA_ERR_BAD_ARG,
            "oversized kmd_len rejected at Init");
    }
}
#endif /* WOLFMKA_KMD */

#ifdef WOLFMKA_SUSPENSION
/* MKA suspension (802.1Xbx): a suspended participant advertises a suspension
 * time and goes quiet; its peer holds its state past the normal Life Time
 * instead of expiring it, so the SAK survives the gap. Carried in the XPN set,
 * so the CA uses an XPN cipher suite. */
static void test_suspension(void)
{
    Wire a2b, b2a;
    Secy sa, sb;
    MkaParticipant A, B;
    MkaParticipantConfig ca, cb;
    uint8_t f[512];
    size_t n = 0U;
    int tick;
    uint32_t t;

    printf("MKA suspension: peer held across the quiet period:\n");
    memset(&a2b, 0, sizeof a2b);
    memset(&b2a, 0, sizeof b2a);
    memset(&sa, 0, sizeof sa);
    memset(&sb, 0, sizeof sb);
    cfg_part(&ca, &sa, &a2b, send_a, 0x0A, 10); /* A: Key Server */
    cfg_part(&cb, &sb, &b2a, send_b, 0x0B, 20);
    ca.cipher_suite = MKA_CIPHER_GCM_AES_XPN_128;
    cb.cipher_suite = MKA_CIPHER_GCM_AES_XPN_128;
    ca.secy.get_next_pn = secy_get_pn_xpn;
    cb.secy.get_next_pn = secy_get_pn_xpn;
    memcpy(sa.my_sci, ca.sci, 8);
    memcpy(sb.my_sci, cb.sci, 8);
    wm_Participant_Init(&A, &ca);
    wm_Participant_Init(&B, &cb);

    /* Converge over ticks 0..11 (t = 0..22000 ms). */
    for (tick = 0; tick < 12; tick++) {
        t = (uint32_t)tick * MKA_HELLO_TIME_MS;
        wm_Participant_Run(&A, t, NULL);
        wm_Participant_Run(&B, t, NULL);
        while (wire_pop(&a2b, f, &n)) {
            wm_Participant_Receive(&B, f, n, t);
        }
        while (wire_pop(&b2a, f, &n)) {
            wm_Participant_Receive(&A, f, n, t);
        }
    }
    CHECK(wm_Participant_HasSak(&A) && wm_Participant_HasSak(&B),
        "converged with an XPN SAK");
    CHECK(wm_Participant_LivePeerCount(&B) == 1U, "B sees A live");

    /* A suspends for 10 s and announces once; B records the suspension time. */
    CHECK(wm_Participant_Suspend(&A, 10U) == MKA_OK, "suspend A");
    t = 24000U;
    wm_Participant_Run(&A, t, NULL);
    CHECK(wire_pop(&a2b, f, &n), "A sent the suspension announcement");
    wm_Participant_Receive(&B, f, n, t);

    /* A is now quiet: a further run transmits nothing. */
    t = 26000U;
    wm_Participant_Run(&A, t, NULL);
    CHECK(!wire_pop(&a2b, f, &n), "A is quiet while suspended");

    /* Advance B past the normal Life Time (6000 ms) but within the suspension
     * hold (Life Time + 10 s): 34000 - 24000 = 10000 ms. A must NOT expire. */
    t = 34000U;
    wm_Participant_Run(&B, t, NULL);
    CHECK(wm_Participant_LivePeerCount(&B) == 1U,
        "suspended peer held past Life Time");

    /* A resumes and transmits again; B keeps the live peer and the SAK. */
    CHECK(wm_Participant_Resume(&A) == MKA_OK, "resume A");
    for (tick = 18; tick < 22; tick++) {
        t = (uint32_t)tick * MKA_HELLO_TIME_MS;
        wm_Participant_Run(&A, t, NULL);
        wm_Participant_Run(&B, t, NULL);
        while (wire_pop(&a2b, f, &n)) {
            wm_Participant_Receive(&B, f, n, t);
        }
        while (wire_pop(&b2a, f, &n)) {
            wm_Participant_Receive(&A, f, n, t);
        }
    }
    CHECK(wm_Participant_LivePeerCount(&B) == 1U, "A live again after resume");
    CHECK(wm_Participant_HasSak(&B), "SAK survived the suspension");

    /* Resume must clear the hold: with A quiet again, B now expires it at the
     * NORMAL Life Time (no leftover 10 s extension). B last saw A at t=42000;
     * advance just past Life Time (42000 + 6000) - a still-suspended deadline
     * (16000) would keep A alive here, so this proves suspend_for was reset. */
    t = 48001U;
    wm_Participant_Run(&B, t, NULL);
    CHECK(wm_Participant_LivePeerCount(&B) == 0U,
        "resume cleared the hold: A expires at the normal Life Time");

    CHECK(wm_Participant_Suspend(NULL, 5U) == MKA_ERR_BAD_ARG, "Suspend NULL");
    CHECK(wm_Participant_Resume(NULL) == MKA_ERR_BAD_ARG, "Resume NULL");
}
#endif /* WOLFMKA_SUSPENSION */

#ifdef WOLFMKA_CIPHER_NEGOTIATION
/* The Key Server selects the SAK cipher suite from the intersection of the
 * preference lists every participant announces (WOLFMKA_CIPHER_NEGOTIATION). */
static void test_cipher_negotiation(void)
{
    static const uint64_t a_prefs[2] = {MKA_CIPHER_GCM_AES_256,
        MKA_CIPHER_GCM_AES_128};
    static const uint64_t b_128[1] = {MKA_CIPHER_GCM_AES_128};
    static const uint64_t b_both[2] = {MKA_CIPHER_GCM_AES_256,
        MKA_CIPHER_GCM_AES_128};
    struct {
        const char* tag;
        const uint64_t* prefs;
        uint8_t count;
        int announce;
        uint64_t expect_cs;
        uint8_t expect_len;
    } cases[] = {
        {"peer 128-only -> downgrade to 128", b_128, 1, 1,
            MKA_CIPHER_GCM_AES_128, 16},
        {"peer 256+128 -> pick top (256)", b_both, 2, 1, MKA_CIPHER_GCM_AES_256,
            32},
        {"peer silent -> trust config (256)", b_both, 2, 0,
            MKA_CIPHER_GCM_AES_256, 32},
    };
    size_t c;

    printf("cipher-suite negotiation (Key Server picks the common best):\n");

    for (c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
        Wire a2b, b2a;
        Secy secy_a, secy_b;
        MkaParticipant A, B;
        MkaParticipantConfig ca, cb;
        int tick;

        memset(&a2b, 0, sizeof a2b);
        memset(&b2a, 0, sizeof b2a);
        memset(&secy_a, 0, sizeof secy_a);
        memset(&secy_b, 0, sizeof secy_b);

        /* A (priority 10) wins election; it negotiates from a_prefs. */
        cfg_part(&ca, &secy_a, &a2b, send_a, 0x0A, 10);
        ca.cipher_suite = 0;
        ca.cipher_prefs = a_prefs;
        ca.cipher_pref_count = 2;
        ca.announce_cipher_suites = 1;

        /* B (priority 20) is the peer; it announces the case's suites. */
        cfg_part(&cb, &secy_b, &b2a, send_b, 0x0B, 20);
        cb.cipher_suite = 0;
        cb.cipher_prefs = cases[c].prefs;
        cb.cipher_pref_count = cases[c].count;
        cb.announce_cipher_suites = cases[c].announce;

        CHECK(wm_Participant_Init(&A, &ca) == MKA_OK, "init A");
        CHECK(wm_Participant_Init(&B, &cb) == MKA_OK, "init B");

        for (tick = 0; tick < 12; tick++) {
            uint8_t f[512];
            size_t n;
            uint32_t t = (uint32_t)tick * MKA_HELLO_TIME_MS;
            wm_Participant_Run(&A, t, NULL);
            wm_Participant_Run(&B, t, NULL);
            while (wire_pop(&a2b, f, &n)) {
                wm_Participant_Receive(&B, f, n, t);
            }
            while (wire_pop(&b2a, f, &n)) {
                wm_Participant_Receive(&A, f, n, t);
            }
        }

        CHECK(wm_Participant_IsKeyServer(&A) == 1, "A is key server");
        CHECK(A.sak_cipher_suite == cases[c].expect_cs, cases[c].tag);
        CHECK(A.latest.sak_len == cases[c].expect_len, "A SAK length");
        CHECK(B.latest.sak_len == cases[c].expect_len, "B adopts SAK length");
        CHECK_EQ_MEM(A.latest.sak, B.latest.sak, cases[c].expect_len,
            "A and B agree on the SAK");
    }
}

/* The Key Server reduces the confidentiality offset (and drops to
 * integrity-only) to the lowest MACsec Capability in the CA. */
static void test_capability_negotiation(void)
{
    struct {
        const char* tag;
        uint8_t a_cap;
        uint8_t b_cap;
        uint8_t a_off;
        uint8_t expect_off;
        uint8_t expect_integ;
    } cases[] = {
        {"both offset-capable -> keep configured 50",
            (uint8_t)MKA_CAP_INTEGRITY_CONF_OFFSET,
            (uint8_t)MKA_CAP_INTEGRITY_CONF_OFFSET, (uint8_t)MKA_CONF_OFFSET_50,
            (uint8_t)MKA_CONF_OFFSET_50, 0},
        {"peer confidentiality-only -> reduce to offset 0",
            (uint8_t)MKA_CAP_INTEGRITY_CONF_OFFSET,
            (uint8_t)MKA_CAP_INTEGRITY_CONF, (uint8_t)MKA_CONF_OFFSET_50,
            (uint8_t)MKA_CONF_OFFSET_0, 0},
        {"peer integrity-only -> integrity-only (NONE)",
            (uint8_t)MKA_CAP_INTEGRITY_CONF_OFFSET,
            (uint8_t)MKA_CAP_INTEGRITY_ONLY, (uint8_t)MKA_CONF_OFFSET_50,
            (uint8_t)MKA_CONF_OFFSET_NONE, 1},
    };
    size_t c;

    printf("MACsec capability / confidentiality-offset negotiation:\n");

    for (c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
        Wire a2b, b2a;
        Secy secy_a, secy_b;
        MkaParticipant A, B;
        MkaParticipantConfig ca, cb;
        int tick;

        memset(&a2b, 0, sizeof a2b);
        memset(&b2a, 0, sizeof b2a);
        memset(&secy_a, 0, sizeof secy_a);
        memset(&secy_b, 0, sizeof secy_b);

        cfg_part(&ca, &secy_a, &a2b, send_a, 0x0A, 10); /* A: Key Server */
        ca.macsec_capability = cases[c].a_cap;
        ca.confidentiality_offset = cases[c].a_off;

        cfg_part(&cb, &secy_b, &b2a, send_b, 0x0B, 20); /* B: peer */
        cb.macsec_capability = cases[c].b_cap;

        CHECK(wm_Participant_Init(&A, &ca) == MKA_OK, "init A");
        CHECK(wm_Participant_Init(&B, &cb) == MKA_OK, "init B");

        for (tick = 0; tick < 12; tick++) {
            uint8_t f[512];
            size_t n;
            uint32_t t = (uint32_t)tick * MKA_HELLO_TIME_MS;
            wm_Participant_Run(&A, t, NULL);
            wm_Participant_Run(&B, t, NULL);
            while (wire_pop(&a2b, f, &n)) {
                wm_Participant_Receive(&B, f, n, t);
            }
            while (wire_pop(&b2a, f, &n)) {
                wm_Participant_Receive(&A, f, n, t);
            }
        }

        CHECK(wm_Participant_IsKeyServer(&A) == 1, "A is key server");
        /* conf_offset is written only by secy_set_cs at SAK install, so a SAK
         * must actually have been distributed for the offset checks to mean
         * anything - otherwise the offset-0 case is indistinguishable from "no
         * SAK installed" (conf_offset keeps its memset-zero value). */
        CHECK(wm_Participant_HasSak(&A) && wm_Participant_HasSak(&B),
            "both ends installed a SAK");
        CHECK_EQ_MEM(A.latest.sak, B.latest.sak, 16, "A and B agree on SAK");
        CHECK(secy_a.conf_offset == cases[c].expect_off, cases[c].tag);
        CHECK(secy_b.conf_offset == cases[c].expect_off,
            "member SecY offset matches");
        /* A live peer below INTEGRITY_CONF forces the whole CA to
         * integrity-only (case 3); cases 1-2 keep confidentiality. This asserts
         * the true state, not just the false one. */
        CHECK(A.sak_integrity_only == cases[c].expect_integ,
            "integrity-only flag matches lowest peer capability");
    }
}

/* Edge cases that drive the negotiation decisions to full MC/DC: invalid
 * preference lists, skipped preference entries (zero / unsupported suite), and
 * a valid-but-not-live peer present when the Key Server selects the suite. */
static void test_negotiation_edge_cases(void)
{
    static const uint64_t prefs_ok[2] = {MKA_CIPHER_GCM_AES_256,
        MKA_CIPHER_GCM_AES_128};
    /* A zero entry and an unknown suite precede the valid ones; both must be
     * skipped by mka_select_cipher_suite. */
    static const uint64_t prefs_skip[4] = {0U, 0x0080C20001000099ULL,
        MKA_CIPHER_GCM_AES_256, MKA_CIPHER_GCM_AES_128};
    static const uint64_t prefs_over[5] = {MKA_CIPHER_GCM_AES_128,
        MKA_CIPHER_GCM_AES_128, MKA_CIPHER_GCM_AES_128, MKA_CIPHER_GCM_AES_128,
        MKA_CIPHER_GCM_AES_128};
    Wire a2b, b2a;
    Secy secy_a, secy_b;
    MkaParticipant A, B;
    MkaParticipantConfig ca, cb;
    int tick;
    size_t i;
    int slot = -1;

    printf("cipher negotiation edge cases (pref-list validation, skipped "
           "entries, not-live peer):\n");

    /* mka_cfg_valid: a non-empty preference list with a NULL pointer. */
    cfg_part(&ca, &secy_a, &a2b, send_a, 0x0A, 10);
    ca.cipher_prefs = NULL;
    ca.cipher_pref_count = 1;
    CHECK(wm_Participant_Init(&A, &ca) == MKA_ERR_BAD_ARG,
        "NULL preference list rejected");

    /* mka_cfg_valid: a preference list longer than MKA_MAX_CIPHER_SUITES. */
    cfg_part(&ca, &secy_a, &a2b, send_a, 0x0A, 10);
    ca.cipher_prefs = prefs_over;
    ca.cipher_pref_count = 5; /* > MKA_MAX_CIPHER_SUITES (4) */
    CHECK(wm_Participant_Init(&A, &ca) == MKA_ERR_BAD_ARG,
        "over-long preference list rejected");

    /* mka_select_cipher_suite: skip the zero and unknown entries, pick 256. */
    memset(&a2b, 0, sizeof a2b);
    memset(&b2a, 0, sizeof b2a);
    memset(&secy_a, 0, sizeof secy_a);
    memset(&secy_b, 0, sizeof secy_b);

    cfg_part(&ca, &secy_a, &a2b, send_a, 0x0A, 10); /* A: Key Server */
    ca.cipher_suite = 0;
    ca.cipher_prefs = prefs_skip;
    ca.cipher_pref_count = 4;
    ca.announce_cipher_suites = 1;

    cfg_part(&cb, &secy_b, &b2a, send_b, 0x0B, 20); /* B: peer, accepts 256 */
    cb.cipher_suite = 0;
    cb.cipher_prefs = prefs_ok;
    cb.cipher_pref_count = 2;
    cb.announce_cipher_suites = 1;

    CHECK(wm_Participant_Init(&A, &ca) == MKA_OK, "init A");
    CHECK(wm_Participant_Init(&B, &cb) == MKA_OK, "init B");
    for (tick = 0; tick < 12; tick++) {
        uint8_t f[512];
        size_t n;
        uint32_t t = (uint32_t)tick * MKA_HELLO_TIME_MS;
        wm_Participant_Run(&A, t, NULL);
        wm_Participant_Run(&B, t, NULL);
        while (wire_pop(&a2b, f, &n)) {
            wm_Participant_Receive(&B, f, n, t);
        }
        while (wire_pop(&b2a, f, &n)) {
            wm_Participant_Receive(&A, f, n, t);
        }
    }
    CHECK(wm_Participant_IsKeyServer(&A) == 1, "A is key server");
    CHECK(A.sak_cipher_suite == MKA_CIPHER_GCM_AES_256,
        "zero and unknown entries skipped -> 256");

    /* mka_select_cipher_suite / mka_min_capability: a peer that is present
     * (valid) but not live must not constrain selection. Inject one into a free
     * slot of the Key Server's table, then re-key. */
    for (i = 0U; i < MKA_MAX_PEERS; i++) {
        if (!A.peers[i].valid) {
            slot = (int)i;
            break;
        }
    }
    CHECK(slot >= 0, "free peer slot available");
    A.peers[slot].valid = true;
    A.peers[slot].live = false; /* potential, not live */
    A.peers[slot].macsec_capability = (uint8_t)MKA_CAP_INTEGRITY_ONLY;
    /* Advertise only GCM-AES-128 (not 256) so that, were this not-live peer
     * wrongly counted, suite selection would downgrade to 128 and
     * min-capability would force integrity-only - both detectable by the
     * assertions below. */
    A.peers[slot].adv_suites[0] = MKA_CIPHER_GCM_AES_128;
    A.peers[slot].adv_count = 1;
    CHECK(wm_Participant_Rekey(&A) == MKA_OK, "re-key with a not-live peer");
    CHECK(A.sak_cipher_suite == MKA_CIPHER_GCM_AES_256,
        "not-live peer ignored in suite selection");
    CHECK(A.sak_integrity_only == 0,
        "not-live integrity-only peer did not force integrity-only");
}

/* Drive A (Key Server, priority 10) and B (peer) from their preference lists to
 * convergence, and return the cipher suite A selected. */
static uint64_t nego_run(const uint64_t* aprefs, uint8_t an, const uint64_t* bp,
    uint8_t bn)
{
    Wire a2b, b2a;
    Secy sa, sb;
    MkaParticipant A, B;
    MkaParticipantConfig ca, cb;
    int tick;

    memset(&a2b, 0, sizeof a2b);
    memset(&b2a, 0, sizeof b2a);
    memset(&sa, 0, sizeof sa);
    memset(&sb, 0, sizeof sb);

    cfg_part(&ca, &sa, &a2b, send_a, 0x0A, 10);
    ca.cipher_suite = 0;
    ca.cipher_prefs = aprefs;
    ca.cipher_pref_count = an;
    ca.announce_cipher_suites = 1;

    cfg_part(&cb, &sb, &b2a, send_b, 0x0B, 20);
    cb.cipher_suite = 0;
    cb.cipher_prefs = bp;
    cb.cipher_pref_count = bn;
    cb.announce_cipher_suites = 1;

    wm_Participant_Init(&A, &ca);
    wm_Participant_Init(&B, &cb);
    for (tick = 0; tick < 12; tick++) {
        uint8_t f[512];
        size_t n;
        uint32_t t = (uint32_t)tick * MKA_HELLO_TIME_MS;
        wm_Participant_Run(&A, t, NULL);
        wm_Participant_Run(&B, t, NULL);
        while (wire_pop(&a2b, f, &n)) {
            wm_Participant_Receive(&B, f, n, t);
        }
        while (wire_pop(&b2a, f, &n)) {
            wm_Participant_Receive(&A, f, n, t);
        }
    }
    return A.sak_cipher_suite;
}

/* Selection extremes: an XPN suite is selectable, and a preference list with no
 * commonly-acceptable suite exhausts and falls back to mandatory GCM-AES-128.
 */
static void test_negotiation_select_extremes(void)
{
    static const uint64_t xpn[2] = {MKA_CIPHER_GCM_AES_XPN_256,
        MKA_CIPHER_GCM_AES_XPN_128};
    static const uint64_t only256[1] = {MKA_CIPHER_GCM_AES_256};
    static const uint64_t only128[1] = {MKA_CIPHER_GCM_AES_128};

    printf("cipher negotiation extremes (XPN selection, pref-list "
           "exhaustion):\n");

    /* Both prefer XPN-256 -> it is negotiated (covers the XPN-256 match). */
    CHECK(nego_run(xpn, 2, xpn, 2) == MKA_CIPHER_GCM_AES_XPN_256,
        "XPN-256 negotiated");
    /* KS offers only 256, peer accepts only 128 -> no preference qualifies, so
     * the list exhausts and the mandatory GCM-AES-128 is used. */
    CHECK(nego_run(only256, 1, only128, 1) == MKA_CIPHER_GCM_AES_128,
        "exhausted preference list falls back to GCM-AES-128");
}
#endif /* WOLFMKA_CIPHER_NEGOTIATION */

/* The MKA version announced in the Basic Parameter Set is a build-time choice
 * (WOLFMKA_MKA_VERSION): 1 for 802.1X-2010, 3 for 802.1X-2020, which the OPEN
 * Alliance Automotive profile requires. Whatever it is set to must reach the
 * wire. */
static void test_mka_version_announced(void)
{
    Wire tx;
    Secy s;
    MkaParticipant A;
    MkaParticipantConfig ca;
    MkaPdu out;
    uint8_t f[512];
    size_t n = sizeof f;

    printf("announced MKA version reaches the wire:\n");
    memset(&tx, 0, sizeof tx);
    memset(&s, 0, sizeof s);
    cfg_part(&ca, &s, &tx, send_a, 0x0A, 10);
    CHECK(wm_Participant_Init(&A, &ca) == MKA_OK, "init A");

    CHECK(wm_Participant_BuildMkpdu(&A, f, sizeof f, &n) == MKA_OK,
        "build MKPDU");
    memset(&out, 0, sizeof out);
    CHECK(wm_Pdu_Decode(g_cmac, f, n, A.keys.ick, A.keys.ick_len, &out) ==
              MKA_OK,
        "decode own MKPDU");
    CHECK(out.basic.version == (uint8_t)WOLFMKA_MKA_VERSION,
        "Basic Parameter Set carries WOLFMKA_MKA_VERSION");
}

/* wm_Participant_AutomotiveDefaults fills only the fields the OPEN Alliance
 * profile fixes and leaves the caller's own configuration alone. */
static void test_automotive_defaults(void)
{
    MkaParticipantConfig c;
    Secy s;
    Wire tx;

    printf("automotive profile defaults:\n");
    memset(&s, 0, sizeof s);
    memset(&tx, 0, sizeof tx);
    CHECK(wm_Participant_AutomotiveDefaults(NULL) == MKA_ERR_BAD_ARG,
        "NULL config rejected");

    cfg_part(&c, &s, &tx, send_a, 0x0A, 33);
    CHECK(c.immediate_response == 0, "immediate response off by default");
    CHECK(wm_Participant_AutomotiveDefaults(&c) == MKA_OK, "defaults applied");
    CHECK(c.immediate_response == 1, "immediate response enabled");
#ifndef WOLFMKA_NO_RETRY
    CHECK(c.retry_base_ms == MKA_AUTOMOTIVE_RETRY_BASE_MS,
        "retry ramp starts at the automotive base");
    CHECK(c.retry_cyclic_ms == MKA_HELLO_TIME_MS,
        "retry ramp tops out at the Hello Time");
#endif
    /* Nothing else is touched. */
    CHECK(c.priority == 33, "caller's priority preserved");
    CHECK(c.sak_len == 16, "caller's SAK length preserved");
    CHECK(c.send == send_a, "caller's transmit hook preserved");
}

/* With immediate_response a peer-list change is answered on the next Run
 * instead of at the next Hello Time; without it the cadence stays periodic.
 * Both settings are exercised so each operand of the transmit condition is
 * shown to decide the outcome on its own. */
static void test_immediate_response(void)
{
    Wire a2b, b2a;
    Secy sa, sb;
    MkaParticipant A, B;
    MkaParticipantConfig ca, cb;
    uint8_t f[512];
    size_t n = 0U;
    bool sent;

    printf("immediate response to a peer-list change:\n");
    memset(&a2b, 0, sizeof a2b);
    memset(&b2a, 0, sizeof b2a);
    memset(&sa, 0, sizeof sa);
    memset(&sb, 0, sizeof sb);
    cfg_part(&ca, &sa, &a2b, send_a, 0x0A, 10);
    cfg_part(&cb, &sb, &b2a, send_b, 0x0B, 20);
    cb.immediate_response = 1; /* B answers at once, A does not */
    CHECK(wm_Participant_Init(&A, &ca) == MKA_OK, "init A");
    CHECK(wm_Participant_Init(&B, &cb) == MKA_OK, "init B");

    /* Both send their first MKPDU at t=0 (the started-yet check). */
    wm_Participant_Run(&A, 0U, NULL);
    wm_Participant_Run(&B, 0U, NULL);
    while (wire_pop(&b2a, f, &n)) {
        /* discard B's opening frame; this test watches A -> B */
    }

    /* A's frame reaches B at t=1 ms, adding a peer to B's Potential list. */
    CHECK(wire_pop(&a2b, f, &n) == 1, "A transmitted at t=0");
    CHECK(wm_Participant_Receive(&B, f, n, 1U) == MKA_OK, "B receives A");

    /* immediate_response && new_info -> B transmits far inside the Hello
     * Time. */
    sent = false;
    wm_Participant_Run(&B, 1U, &sent);
    CHECK(sent, "B answered the peer-list change immediately");

    /* immediate_response && !new_info -> nothing more until the interval. */
    sent = false;
    wm_Participant_Run(&B, 2U, &sent);
    CHECK(!sent, "B stays quiet once the change is announced");

    /* !immediate_response && new_info -> A waits for the interval even though
     * B's opening frame gave it a new peer. */
    while (wire_pop(&b2a, f, &n))
        CHECK(wm_Participant_Receive(&A, f, n, 2U) == MKA_OK, "A receives B");
    CHECK(A.new_info == 1, "A recorded the peer-list change");
    sent = false;
    wm_Participant_Run(&A, 3U, &sent);
    CHECK(!sent, "A defers to the periodic cadence");
}

/* The automotive profile's point: with its defaults a two-party CA reaches an
 * installed SAK in a few tens of milliseconds rather than several Hello Times.
 * Driven at a 1 ms tick so the measured figure is the protocol's, not the
 * harness's. */
static void test_automotive_fast_startup(void)
{
    Wire a2b, b2a;
    Secy sa, sb;
    MkaParticipant A, B;
    MkaParticipantConfig ca, cb;
    uint32_t t;
    uint32_t settled = 0U;

    printf("automotive profile startup time:\n");
    memset(&a2b, 0, sizeof a2b);
    memset(&b2a, 0, sizeof b2a);
    memset(&sa, 0, sizeof sa);
    memset(&sb, 0, sizeof sb);
    cfg_part(&ca, &sa, &a2b, send_a, 0x0A, 10);
    cfg_part(&cb, &sb, &b2a, send_b, 0x0B, 20);
    CHECK(wm_Participant_AutomotiveDefaults(&ca) == MKA_OK, "A profile cfg");
    CHECK(wm_Participant_AutomotiveDefaults(&cb) == MKA_OK, "B profile cfg");
    CHECK(wm_Participant_Init(&A, &ca) == MKA_OK, "init A");
    CHECK(wm_Participant_Init(&B, &cb) == MKA_OK, "init B");

    for (t = 0U; t < MKA_HELLO_TIME_MS; t++) {
        uint8_t f[512];
        size_t n;
        wm_Participant_Run(&A, t, NULL);
        wm_Participant_Run(&B, t, NULL);
        while (wire_pop(&a2b, f, &n))
            wm_Participant_Receive(&B, f, n, t);
        while (wire_pop(&b2a, f, &n))
            wm_Participant_Receive(&A, f, n, t);
        if ((settled == 0U) && sa.tx_enabled && sb.tx_enabled) {
            settled = t;
        }
    }

    CHECK(wm_Participant_HasSak(&A) && wm_Participant_HasSak(&B),
        "both ends hold the SAK");
    CHECK(sa.tx_enabled && sb.tx_enabled, "MACsec transmitting both ends");
    /* Well inside one Hello Time - i.e. the ramp and the immediate response,
     * not the periodic cadence, are what drove convergence. */
    CHECK(settled < (MKA_HELLO_TIME_MS / 4U), "MACsec up in well under a Hello "
                                              "Time");
    printf("  (MACsec up at t=%u ms)\n", (unsigned)settled);
}

/* A peer that resets returns with the same SCI but a fresh MI. Its old entry
 * must survive until the new MI proves liveness (so a forged MI cannot evict a
 * working peer) and must be retired the moment it does — not left to age out at
 * the Life Time (OPEN Alliance AutoMKA-03006). */
static void test_peer_reset_new_mi(void)
{
    Wire a2b, b2a;
    Secy sa, sb;
    MkaParticipant A, B;
    MkaParticipantConfig ca, cb;
    uint8_t old_mi[MKA_MI_LEN];
    uint8_t f[512];
    size_t n;
    uint32_t t;
    uint32_t seen_two = 0U;

    printf("peer reset (same SCI, new MI):\n");
    memset(&a2b, 0, sizeof a2b);
    memset(&b2a, 0, sizeof b2a);
    memset(&sa, 0, sizeof sa);
    memset(&sb, 0, sizeof sb);
    cfg_part(&ca, &sa, &a2b, send_a, 0x0A, 10);
    cfg_part(&cb, &sb, &b2a, send_b, 0x0B, 20);
    CHECK(wm_Participant_AutomotiveDefaults(&ca) == MKA_OK, "A profile cfg");
    CHECK(wm_Participant_AutomotiveDefaults(&cb) == MKA_OK, "B profile cfg");
    CHECK(wm_Participant_Init(&A, &ca) == MKA_OK, "init A");
    CHECK(wm_Participant_Init(&B, &cb) == MKA_OK, "init B");

    /* Converge normally first. */
    for (t = 0U; t < 200U; t++) {
        wm_Participant_Run(&A, t, NULL);
        wm_Participant_Run(&B, t, NULL);
        while (wire_pop(&a2b, f, &n))
            wm_Participant_Receive(&B, f, n, t);
        while (wire_pop(&b2a, f, &n))
            wm_Participant_Receive(&A, f, n, t);
    }
    CHECK(wm_Participant_PeerCount(&A) == 1U, "A tracks one peer");
    CHECK(wm_Participant_LivePeerCount(&A) == 1U, "that peer is live");
    memcpy(old_mi, B.actor_mi, MKA_MI_LEN);

    /* B resets: same CAK, same SCI, a fresh MI. */
    memset(&sb, 0, sizeof sb);
    CHECK(wm_Participant_Init(&B, &cb) == MKA_OK, "re-init B after reset");
    CHECK(memcmp(old_mi, B.actor_mi, MKA_MI_LEN) != 0, "reset produced a new "
                                                       "MI");

    /* Well inside the Life Time, so anything observed here is the reset
     * handling and not an expiry. */
    for (t = 200U; t < 400U; t++) {
        wm_Participant_Run(&A, t, NULL);
        wm_Participant_Run(&B, t, NULL);
        while (wire_pop(&a2b, f, &n))
            wm_Participant_Receive(&B, f, n, t);
        while (wire_pop(&b2a, f, &n))
            wm_Participant_Receive(&A, f, n, t);
        /* Both incarnations coexist until the new MI is proven live. */
        if (wm_Participant_PeerCount(&A) == 2U) {
            seen_two = t;
            CHECK(wm_Participant_LivePeerCount(&A) == 1U,
                "only the old incarnation is live while the new one is "
                "unproven");
        }
    }
    CHECK(t < MKA_LIFE_TIME_MS, "test stayed inside the MKA Life Time");
    CHECK(seen_two != 0U, "the new MI was admitted alongside the old entry");

    CHECK(wm_Participant_PeerCount(&A) == 1U, "stale MI retired once the new "
                                              "one went live");
    CHECK(wm_Participant_LivePeerCount(&A) == 1U, "the surviving peer is live");
    CHECK(memcmp(A.peers[0].valid ? A.peers[0].mi : A.peers[1].mi, B.actor_mi,
              MKA_MI_LEN) == 0,
        "the surviving peer is the new incarnation");
    CHECK(sa.tx_enabled && sb.tx_enabled, "MACsec recovered after the reset");
}

/* Build an MKPDU from a fixed fake peer that echoes the victim's MI with
 * Message Number `echo_mn`, in the Live Peer List when `live` is set and the
 * Potential list otherwise. `sender_mn` is the fake peer's own Message Number,
 * which must strictly increase to clear the replay guard. */
static size_t craft_echo(uint8_t* f, size_t cap, const MkaParticipant* v,
    uint32_t echo_mn, bool live, uint32_t sender_mn)
{
    static const uint8_t fake_sci[8] = {0, 0, 0, 0, 0, 0x5A, 0, 1};
    MkaPdu in;
    MkaPeerList* list;
    size_t n = cap;

    memset(&in, 0, sizeof in);
    in.basic.priority = 200; /* never outranks the victim for Key Server */
    in.basic.macsec_desired = 1;
    in.basic.algo_agility = MKA_ALGO_AGILITY_DEFAULT;
    memcpy(in.basic.ckn, v->cfg.cak.ckn, v->cfg.cak.ckn_len);
    in.basic.ckn_len = v->cfg.cak.ckn_len;
    memcpy(in.basic.sci, fake_sci, 8);
    memset(in.basic.mi, 0xE5, MKA_MI_LEN);
    in.basic.mn = sender_mn;

    list = live ? &in.live_peers : &in.potential_peers;
    list->present = 1;
    list->count = 1;
    memcpy(list->peers[0].mi, v->actor_mi, MKA_MI_LEN);
    list->peers[0].mn = echo_mn;

    CHECK(wm_Pdu_Encode(g_cmac, &in, v->keys.ick, v->keys.ick_len, f, cap,
              &n) == MKA_OK,
        "encode echo frame");
    return n;
}

/* Liveness requires the peer to quote a Message Number we recently emitted, not
 * just our MI (802.1X 9.4.3; OPEN Alliance AutoMKA-03005). A peer that reports
 * us live on a stale number is not evidence of anything current, so its MKPDU
 * is discarded without refreshing the Life timer (AutoMKA-04004). */
static void test_mn_recency_window(void)
{
    Wire tx;
    Secy s;
    MkaParticipant A;
    MkaParticipantConfig ca;
    uint8_t f[512];
    size_t n;
    uint32_t newest;
    uint32_t stale_seen;
    int i;

    printf("Message Number recency window:\n");
    memset(&tx, 0, sizeof tx);
    memset(&s, 0, sizeof s);
    cfg_part(&ca, &s, &tx, send_a, 0x0A, 10);
    CHECK(wm_Participant_Init(&A, &ca) == MKA_OK, "init A");

    /* Before anything has been emitted there is no number a peer could
     * legitimately quote back, so no MKPDU can prove liveness. */
    n = craft_echo(f, sizeof f, &A, 0U, false, 1U);
    CHECK(wm_Participant_Receive(&A, f, n, 1U) == MKA_OK,
        "pre-transmit MKPDU accepted");
    CHECK(wm_Participant_LivePeerCount(&A) == 0U,
        "nothing is live before we have emitted a Message Number");
    memset(&A, 0, sizeof A);
    CHECK(wm_Participant_Init(&A, &ca) == MKA_OK, "re-init A");

    /* Emit several MKPDUs so the Message Number is well clear of the window. */
    for (i = 0; i < 8; i++) {
        size_t drop;
        wm_Participant_Run(&A, (uint32_t)i * MKA_HELLO_TIME_MS, NULL);
        while (wire_pop(&tx, f, &drop)) {
            /* discard: nothing is listening */
        }
    }
    newest = A.actor_mn - 1U;
    CHECK(newest > MKA_MN_RECENT_WINDOW, "actor MN advanced past the window");

    /* The newest emitted MN, in the Live list: accepted and live. */
    n = craft_echo(f, sizeof f, &A, newest, true, 1U);
    CHECK(wm_Participant_Receive(&A, f, n, 1000U) == MKA_OK,
        "newest echoed MN accepted");
    CHECK(wm_Participant_LivePeerCount(&A) == 1U, "peer is live on newest MN");

    /* The oldest MN still inside the window: also live. */
    n = craft_echo(f, sizeof f, &A, newest - (MKA_MN_RECENT_WINDOW - 1U), true,
        2U);
    CHECK(wm_Participant_Receive(&A, f, n, 1100U) == MKA_OK,
        "window-edge MN accepted");
    CHECK(wm_Participant_LivePeerCount(&A) == 1U, "peer stays live at the "
                                                  "window edge");
    CHECK(A.peers[0].last_seen_ms == 1100U, "Life timer refreshed by a valid "
                                            "MKPDU");
    stale_seen = A.peers[0].last_seen_ms;

    /* One step outside the window, still in the Live list: the MKPDU is
     * invalid — rejected, and it must not refresh the Life timer. */
    n = craft_echo(f, sizeof f, &A, newest - MKA_MN_RECENT_WINDOW, true, 3U);
    CHECK(wm_Participant_Receive(&A, f, n, 1200U) == MKA_ERR_REPLAY,
        "stale echoed MN rejects the MKPDU");
    CHECK(A.peers[0].last_seen_ms == stale_seen,
        "rejected MKPDU did not refresh the Life timer");

    /* The same stale number in the Potential list is not an error — the peer is
     * only reporting what it last heard — but it does not prove liveness. */
    n = craft_echo(f, sizeof f, &A, newest - MKA_MN_RECENT_WINDOW, false, 4U);
    CHECK(wm_Participant_Receive(&A, f, n, 1300U) == MKA_OK,
        "stale MN in the Potential list is accepted");
    CHECK(wm_Participant_LivePeerCount(&A) == 0U,
        "stale MN in the Potential list does not prove liveness");
    CHECK(A.peers[0].last_seen_ms == 1300U, "accepted MKPDU refreshed the Life "
                                            "timer");

    /* A recent number in the Potential list does prove it. */
    n = craft_echo(f, sizeof f, &A, A.actor_mn - 1U, false, 5U);
    CHECK(wm_Participant_Receive(&A, f, n, 1400U) == MKA_OK,
        "recent MN in the Potential list accepted");
    CHECK(wm_Participant_LivePeerCount(&A) == 1U,
        "recent MN in the Potential list proves liveness");

    /* An MKPDU echoing an MI that is not ours at all leaves us not live. */
    n = craft_echo(f, sizeof f, &A, A.actor_mn - 1U, true, 6U);
    memset(&A.actor_mi, 0x11, MKA_MI_LEN); /* white box: change our identity */
    CHECK(wm_Participant_Receive(&A, f, n, 1500U) == MKA_OK,
        "MKPDU not echoing our MI is accepted");
    CHECK(wm_Participant_LivePeerCount(&A) == 0U,
        "a peer that does not echo our MI is not live");
}

/* --- SecY statistics shim (OPEN Alliance AutoMKA-07009) ------------------ */

static int g_stats_fail;

static int stats_secy(void* c, MkaSecyStats* out)
{
    (void)c;
    if (g_stats_fail != 0) {
        return -1;
    }
    out->out_pkts_untagged = 11U;
    out->in_octets_decrypted = 22U;
    return 0;
}

static int stats_tx_sc(void* c, const uint8_t* sci, MkaTxScStats* out)
{
    (void)c;
    if (g_stats_fail != 0) {
        return -1;
    }
    /* echo the low SCI octet so the test can tell which channel was asked for
     */
    out->out_pkts_protected = sci[5];
    out->out_pkts_encrypted = 33U;
    return 0;
}

static int stats_rx_sc(void* c, const uint8_t* sci, MkaRxScStats* out)
{
    (void)c;
    if (g_stats_fail != 0) {
        return -1;
    }
    out->in_pkts_ok = sci[5];
    out->in_pkts_late = 44U;
    return 0;
}

/* The MACsec counters belong to the SecY; wolfMKA only routes a management
 * caller to them, and reports honestly when there is nothing to route to. */
static void test_macsec_statistics(void)
{
    Wire a2b, b2a;
    Secy sa, sb;
    MkaParticipant A, B;
    MkaParticipantConfig ca, cb;
    MkaSecyStats sy;
    MkaTxScStats tx;
    MkaRxScStats rx;

    printf("MACsec statistics pass-through:\n");
    memset(&a2b, 0, sizeof a2b);
    memset(&b2a, 0, sizeof b2a);
    memset(&sa, 0, sizeof sa);
    memset(&sb, 0, sizeof sb);
    g_stats_fail = 0;
    cfg_part(&ca, &sa, &a2b, send_a, 0x0A, 10);
    cfg_part(&cb, &sb, &b2a, send_b, 0x0B, 20);
    CHECK(wm_Participant_Init(&A, &ca) == MKA_OK, "init A");
    CHECK(wm_Participant_Init(&B, &cb) == MKA_OK, "init B");

    /* No hooks configured: say so rather than inventing zeroes. */
    CHECK(wm_Participant_GetSecyStats(&A, &sy) == MKA_ERR_STATE,
        "no SecY stats hook -> STATE");
    CHECK(wm_Participant_GetTxScStats(&A, &tx) == MKA_ERR_STATE,
        "no Tx SC stats hook -> STATE");
    CHECK(wm_Participant_GetRxScStats(&A, 0U, &rx) == MKA_ERR_STATE,
        "no Rx SC stats hook -> STATE");

    /* Invalid arguments at each pointer position. */
    CHECK(wm_Participant_GetSecyStats(NULL, &sy) == MKA_ERR_BAD_ARG, "secy "
                                                                     "NULL p");
    CHECK(wm_Participant_GetSecyStats(&A, NULL) == MKA_ERR_BAD_ARG, "secy NULL "
                                                                    "out");
    CHECK(wm_Participant_GetTxScStats(NULL, &tx) == MKA_ERR_BAD_ARG, "tx NULL "
                                                                     "p");
    CHECK(wm_Participant_GetTxScStats(&A, NULL) == MKA_ERR_BAD_ARG, "tx NULL "
                                                                    "out");
    CHECK(wm_Participant_GetRxScStats(NULL, 0U, &rx) == MKA_ERR_BAD_ARG,
        "rx NULL p");
    CHECK(wm_Participant_GetRxScStats(&A, 0U, NULL) == MKA_ERR_BAD_ARG,
        "rx NULL out");

    /* Now wire the hooks up and converge so there is a peer to index. */
    ca.secy.get_secy_stats = stats_secy;
    ca.secy.get_tx_sc_stats = stats_tx_sc;
    ca.secy.get_rx_sc_stats = stats_rx_sc;
    CHECK(wm_Participant_Init(&A, &ca) == MKA_OK, "re-init A with stats hooks");
    run_pair(&A, &B, &a2b, &b2a, 12, NULL);
    CHECK(wm_Participant_PeerCount(&A) == 1U, "A has a peer to index");

    CHECK(wm_Participant_GetSecyStats(&A, &sy) == MKA_OK, "SecY stats read");
    CHECK(sy.out_pkts_untagged == 11U && sy.in_octets_decrypted == 22U,
        "SecY counters passed through unchanged");

    CHECK(wm_Participant_GetTxScStats(&A, &tx) == MKA_OK, "Tx SC stats read");
    CHECK(tx.out_pkts_protected == 0x0AU, "Tx SC asked for our own SCI");
    CHECK(tx.out_pkts_encrypted == 33U, "Tx SC counters passed through");

    CHECK(wm_Participant_GetRxScStats(&A, 0U, &rx) == MKA_OK, "Rx SC stats "
                                                              "read");
    CHECK(rx.in_pkts_ok == 0x0BU, "Rx SC asked for the peer's SCI");
    CHECK(rx.in_pkts_late == 44U, "Rx SC counters passed through");

    /* Past the last peer. */
    CHECK(wm_Participant_GetRxScStats(&A, 5U, &rx) == MKA_ERR_NO_PEER,
        "Rx SC index past the last peer -> NO_PEER");

    /* A hook that fails is reported, not silently zeroed. */
    g_stats_fail = 1;
    CHECK(wm_Participant_GetSecyStats(&A, &sy) == MKA_ERR_INTERNAL,
        "failing SecY stats hook -> INTERNAL");
    CHECK(wm_Participant_GetTxScStats(&A, &tx) == MKA_ERR_INTERNAL,
        "failing Tx SC stats hook -> INTERNAL");
    CHECK(wm_Participant_GetRxScStats(&A, 0U, &rx) == MKA_ERR_INTERNAL,
        "failing Rx SC stats hook -> INTERNAL");
    g_stats_fail = 0;
}

/* One call collapsing the participant's state into the management view the
 * OPEN Alliance profile asks for (AutoMKA-07008). Every state it can report is
 * driven here. */
static void test_pae_status(void)
{
    Wire a2b, b2a;
    Secy sa, sb;
    MkaParticipant A, B;
    MkaParticipantConfig ca, cb;
    MkaPaeStatus st;
    uint8_t f[512];
    size_t n;
    static const uint8_t zero_sci[MKA_SCI_LEN] = {0};

    printf("PAE status summary:\n");
    memset(&a2b, 0, sizeof a2b);
    memset(&b2a, 0, sizeof b2a);
    memset(&sa, 0, sizeof sa);
    memset(&sb, 0, sizeof sb);
    cfg_part(&ca, &sa, &a2b, send_a, 0x0A, 10);
    cfg_part(&cb, &sb, &b2a, send_b, 0x0B, 20);

    CHECK(wm_Participant_GetPaeStatus(NULL, &st) == MKA_ERR_BAD_ARG, "NULL p");
    CHECK(wm_Participant_Init(&A, &ca) == MKA_OK, "init A");
    CHECK(wm_Participant_GetPaeStatus(&A, NULL) == MKA_ERR_BAD_ARG, "NULL out");

    /* Nothing heard from yet. */
    CHECK(wm_Participant_GetPaeStatus(&A, &st) == MKA_OK, "status read");
    CHECK(st.state == MKA_PAE_WAITING_FOR_PEER, "fresh participant is waiting "
                                                "for a peer");
    CHECK(st.ckn_len == ca.cak.ckn_len, "CKN in use reported");
    CHECK_EQ_MEM(st.peer_sci, zero_sci, MKA_SCI_LEN, "no peer SCI yet");
    CHECK(st.cipher_suite == 0U, "no cipher suite before a SAK");

    /* MKPDUs arriving that do not authenticate: a different CAK at the far
     * end, which is not the same thing as silence. */
    memset(f, 0, sizeof f);
    n = sizeof f;
    CHECK(wm_Participant_BuildMkpdu(&A, f, sizeof f, &n) == MKA_OK, "build");
    f[n - 1U] ^= 0xFFU; /* corrupt the ICV */
    CHECK(wm_Participant_Receive(&A, f, n, 0U) == MKA_ERR_ICV, "ICV rejected");
    CHECK(wm_Participant_GetPaeStatus(&A, &st) == MKA_OK, "status read");
    CHECK(st.state == MKA_PAE_AUTH_FAIL_UNKNOWN_PEER,
        "unauthenticated traffic reported as an auth failure");

    /* A peer is known but the session is not up yet. */
    CHECK(wm_Participant_Init(&A, &ca) == MKA_OK, "re-init A");
    CHECK(wm_Participant_Init(&B, &cb) == MKA_OK, "init B");
    wm_Participant_Run(&B, 0U, NULL);
    CHECK(wire_pop(&b2a, f, &n) == 1, "B transmitted");
    CHECK(wm_Participant_Receive(&A, f, n, 0U) == MKA_OK, "A hears B");
    CHECK(wm_Participant_GetPaeStatus(&A, &st) == MKA_OK, "status read");
    CHECK(st.state == MKA_PAE_IN_PROGRESS, "peer known, session not yet up");
    CHECK_EQ_MEM(st.peer_sci, cb.sci, MKA_SCI_LEN, "peer SCI reported");

    /* A SAK is installed but transmit is still gated on the peer reporting it
     * receives: the session is not up yet, so it is still in progress. */
    {
        int gated_seen = 0;
        int tick;
        for (tick = 1; tick < 12; tick++) {
            uint32_t now = (uint32_t)tick * MKA_HELLO_TIME_MS;
            wm_Participant_Run(&A, now, NULL);
            wm_Participant_Run(&B, now, NULL);
            if (A.latest.valid && !A.latest.tx && (gated_seen == 0)) {
                CHECK(wm_Participant_GetPaeStatus(&A, &st) == MKA_OK,
                    "status read while gated");
                CHECK(st.state == MKA_PAE_IN_PROGRESS,
                    "SAK installed but transmit gated is still in progress");
                gated_seen = 1;
            }
            while (wire_pop(&a2b, f, &n))
                wm_Participant_Receive(&B, f, n, now);
            while (wire_pop(&b2a, f, &n))
                wm_Participant_Receive(&A, f, n, now);
        }
        CHECK(gated_seen == 1, "the gated state was observed");
    }

    /* Converged. */
    CHECK(wm_Participant_GetPaeStatus(&A, &st) == MKA_OK, "status read");
    CHECK(st.state == MKA_PAE_RUNNING, "MACsec running");
    CHECK(st.cipher_suite == A.sak_cipher_suite, "cipher suite in force "
                                                 "reported");
    CHECK_EQ_MEM(st.peer_sci, cb.sci, MKA_SCI_LEN, "live peer SCI reported");

    /* MACsec not desired on this participant at all. */
    ca.macsec_desired = 0;
    CHECK(wm_Participant_Init(&A, &ca) == MKA_OK, "re-init A without MACsec");
    CHECK(wm_Participant_GetPaeStatus(&A, &st) == MKA_OK, "status read");
    CHECK(st.state == MKA_PAE_UNDEFINED, "MACsec not desired -> undefined");
    CHECK(st.ckn_len == 0U, "undefined status carries no CKN");
}

/* A port may offer several CAKs to find one the far end also holds. Once one of
 * them brings MACsec up, the others have nobody to negotiate with and should
 * stop transmitting — and start again if the session drops (OPEN Alliance
 * AutoMKA-09001 / AutoMKA-09002). */
static void test_kay_quiesce_others(void)
{
    Wire a2b, b2a;
    Secy sa, sa2, sb;
    MkaKay kay;
    MkaParticipant B;
    MkaParticipantConfig ca, ca2, cb;
    uint8_t f[512];
    size_t n;
    uint32_t t;
    int idle;

    printf("losing CAs quiesce once one wins:\n");
    memset(&a2b, 0, sizeof a2b);
    memset(&b2a, 0, sizeof b2a);
    memset(&sa, 0, sizeof sa);
    memset(&sa2, 0, sizeof sa2);
    memset(&sb, 0, sizeof sb);

    CHECK(wm_Kay_SetQuiesceOthers(NULL, true) == MKA_ERR_BAD_ARG, "NULL kay");
    CHECK(wm_Kay_Init(&kay) == MKA_OK, "kay init");
    CHECK(wm_Kay_SetQuiesceOthers(&kay, true) == MKA_OK, "quiesce enabled");

    /* Two CAs on one port: the shared CKN B also holds, and a second one it
     * does not. */
    cfg_part(&ca, &sa, &a2b, send_a, 0x0A, 10);
    cfg_part(&ca2, &sa2, &a2b, send_a, 0x0A, 10);
    memcpy(ca2.cak.ckn, "other-ckn", 9);
    ca2.cak.ckn_len = 9;
    cfg_part(&cb, &sb, &b2a, send_b, 0x0B, 20);
    CHECK(wm_Kay_AddParticipant(&kay, &ca, NULL) == MKA_OK, "add CA 1");
    CHECK(wm_Kay_AddParticipant(&kay, &ca2, NULL) == MKA_OK, "add CA 2");
    CHECK(wm_Participant_Init(&B, &cb) == MKA_OK, "init B");

    for (t = 0U; t < 12U; t++) {
        uint32_t now = t * MKA_HELLO_TIME_MS;
        wm_Kay_Run(&kay, now);
        wm_Participant_Run(&B, now, NULL);
        while (wire_pop(&a2b, f, &n))
            wm_Participant_Receive(&B, f, n, now);
        while (wire_pop(&b2a, f, &n))
            wm_Kay_Receive(&kay, f, n, now);
    }
    CHECK(kay.parts[0].latest.tx, "the shared CA brought MACsec up");
    CHECK(kay.parts[1].quiesced, "the unmatched CA was quiesced");
    CHECK(!kay.parts[0].quiesced, "the winner keeps transmitting");

    /* The quiesced CA must now be silent across a full interval. */
    while (wire_pop(&a2b, f, &n)) {
        /* drain */
    }
    idle = 1;
    for (t = 12U; t < 16U; t++) {
        uint32_t now = t * MKA_HELLO_TIME_MS;
        uint32_t before = kay.parts[1].actor_mn;
        wm_Kay_Run(&kay, now);
        if (kay.parts[1].actor_mn != before) {
            idle = 0;
        }
        while (wire_pop(&a2b, f, &n)) {
            /* the winner's own MKPDUs; discarded */
        }
    }
    CHECK(idle == 1, "the quiesced CA emitted nothing");

    /* Drop the session: every CA resumes the search. */
    kay.parts[0].latest.valid = false;
    kay.parts[0].latest.tx = false;
    wm_Kay_Run(&kay, 16U * MKA_HELLO_TIME_MS);
    CHECK(!kay.parts[1].quiesced, "the loser resumes when the session drops");

    /* Turning the policy off releases anything still held. */
    kay.parts[1].quiesced = true;
    CHECK(wm_Kay_SetQuiesceOthers(&kay, false) == MKA_OK, "quiesce disabled");
    CHECK(!kay.parts[1].quiesced, "disabling the policy releases the loser");
    wm_Kay_Free(&kay);
}

#ifdef WOLFMKA_AUTOMOTIVE_PROFILE
/* Under the automotive profile the Key Server priority values are absolute:
 * 255 means never Key Server, so two participants both set to it must not
 * elect one between them, and 0 means always (OPEN Alliance AutoMKA-03007). */
static void test_ks_priority_extremes(void)
{
    Wire a2b, b2a;
    Secy sa, sb;
    MkaParticipant A, B;
    MkaParticipantConfig ca, cb;

    printf("Key Server priority 0 / 255 are absolute:\n");

    /* Both "never": nobody serves, so no SAK is ever agreed. */
    memset(&a2b, 0, sizeof a2b);
    memset(&b2a, 0, sizeof b2a);
    memset(&sa, 0, sizeof sa);
    memset(&sb, 0, sizeof sb);
    cfg_part(&ca, &sa, &a2b, send_a, 0x0A, MKA_PRIORITY_NEVER_KS);
    cfg_part(&cb, &sb, &b2a, send_b, 0x0B, MKA_PRIORITY_NEVER_KS);
    CHECK(wm_Participant_Init(&A, &ca) == MKA_OK, "init A");
    CHECK(wm_Participant_Init(&B, &cb) == MKA_OK, "init B");
    run_pair(&A, &B, &a2b, &b2a, 12, NULL);
    CHECK(wm_Participant_LivePeerCount(&A) == 1U, "peers still discover each "
                                                  "other");
    CHECK(!wm_Participant_IsKeyServer(&A) && !wm_Participant_IsKeyServer(&B),
        "neither 255-priority participant serves");
    CHECK(!wm_Participant_HasSak(&A) && !wm_Participant_HasSak(&B),
        "no SAK without a Key Server");

    /* One "never", one ordinary: the ordinary one serves. */
    memset(&a2b, 0, sizeof a2b);
    memset(&b2a, 0, sizeof b2a);
    memset(&sa, 0, sizeof sa);
    memset(&sb, 0, sizeof sb);
    cfg_part(&ca, &sa, &a2b, send_a, 0x0A, MKA_PRIORITY_NEVER_KS);
    cfg_part(&cb, &sb, &b2a, send_b, 0x0B, 20);
    CHECK(wm_Participant_Init(&A, &ca) == MKA_OK, "init A");
    CHECK(wm_Participant_Init(&B, &cb) == MKA_OK, "init B");
    run_pair(&A, &B, &a2b, &b2a, 12, NULL);
    CHECK(!wm_Participant_IsKeyServer(&A), "the 255 participant still "
                                           "declines");
    CHECK(wm_Participant_IsKeyServer(&B), "the eligible peer serves");
    CHECK(wm_Participant_HasSak(&A) && wm_Participant_HasSak(&B),
        "the CA still reaches a SAK");

    /* Priority 0 outranks an ordinary priority: it is the lowest value, so the
     * standard comparison already makes it always win. */
    memset(&a2b, 0, sizeof a2b);
    memset(&b2a, 0, sizeof b2a);
    memset(&sa, 0, sizeof sa);
    memset(&sb, 0, sizeof sb);
    cfg_part(&ca, &sa, &a2b, send_a, 0x0A, 20);
    cfg_part(&cb, &sb, &b2a, send_b, 0x0B, MKA_PRIORITY_ALWAYS_KS);
    CHECK(wm_Participant_Init(&A, &ca) == MKA_OK, "init A");
    CHECK(wm_Participant_Init(&B, &cb) == MKA_OK, "init B");
    run_pair(&A, &B, &a2b, &b2a, 12, NULL);
    CHECK(wm_Participant_IsKeyServer(&B), "priority 0 always serves");
    CHECK(!wm_Participant_IsKeyServer(&A), "the higher priority yields");
}
#endif /* WOLFMKA_AUTOMOTIVE_PROFILE */

/* Build an MKPDU carrying `peer`'s identity towards `victim`, with the MACsec
 * SAK Use shaped by `mode`: 0 = none, 1 = present but empty, 2 = present naming
 * an unknown Key Number, 3 = present and correctly naming the key in force,
 * 4 = transmitting on the key in force but not yet receiving on it. */
static size_t craft_sak_use(uint8_t* f, size_t cap, MkaParticipant* victim,
    const MkaParticipant* peer, int mode, uint32_t sender_mn)
{
    MkaPdu in;
    size_t n = cap;

    memset(&in, 0, sizeof in);
    in.basic.priority = peer->cfg.priority;
    in.basic.macsec_desired = 1;
    in.basic.algo_agility = MKA_ALGO_AGILITY_DEFAULT;
    memcpy(in.basic.ckn, victim->cfg.cak.ckn, victim->cfg.cak.ckn_len);
    in.basic.ckn_len = victim->cfg.cak.ckn_len;
    memcpy(in.basic.sci, peer->cfg.sci, MKA_SCI_LEN);
    memcpy(in.basic.mi, peer->actor_mi, MKA_MI_LEN);
    in.basic.mn = sender_mn;
    in.live_peers.present = 1;
    in.live_peers.count = 1;
    memcpy(in.live_peers.peers[0].mi, victim->actor_mi, MKA_MI_LEN);
    in.live_peers.peers[0].mn = echo_mn(victim);

    if (mode != 0) {
        in.sak_use.present = 1;
        if (mode == 4) {
            MKA_SAK_USE_SET_LATEST_TX(&in.sak_use);
            in.sak_use.latest_kn = victim->latest.kn;
        }
        else if (mode >= 2) {
            MKA_SAK_USE_SET_LATEST_RX(&in.sak_use);
            in.sak_use.latest_kn =
                (mode == 3) ? victim->latest.kn : (victim->latest.kn + 100U);
        }
        else {
            /* mode 1: present, but reporting no key in use */
        }
    }
    CHECK(wm_Pdu_Encode(g_cmac, &in, victim->keys.ick, victim->keys.ick_len, f,
              cap, &n) == MKA_OK,
        "encode SAK-Use frame");
    return n;
}

/* A peer whose MACsec SAK Use goes missing, empty or unrecognisable has lost
 * the key; nothing recovers it but a fresh SAK, so the Key Server rekeys
 * (OPEN Alliance AutoMKA-03011). */
static void test_rekey_on_lost_sak_use(void)
{
    Wire a2b, b2a;
    Secy sa, sb;
    MkaParticipant A, B;
    MkaParticipantConfig ca, cb;
    uint8_t f[512];
    size_t n;
    uint32_t kn_before;
    uint32_t mn = 1U;
    int mode;
    uint32_t t = 100U;

    printf("Key Server rekeys when a peer loses the SAK:\n");
    for (mode = 0; mode <= 2; mode++) {
        memset(&a2b, 0, sizeof a2b);
        memset(&b2a, 0, sizeof b2a);
        memset(&sa, 0, sizeof sa);
        memset(&sb, 0, sizeof sb);
        cfg_part(&ca, &sa, &a2b, send_a, 0x0A, 10);
        cfg_part(&cb, &sb, &b2a, send_b, 0x0B, 20);
        CHECK(wm_Participant_Init(&A, &ca) == MKA_OK, "init A");
        CHECK(wm_Participant_Init(&B, &cb) == MKA_OK, "init B");
        run_pair(&A, &B, &a2b, &b2a, 12, NULL);
        CHECK(wm_Participant_IsKeyServer(&A), "A is Key Server");
        CHECK(A.peers[0].sak_use_seen, "A saw B using the SAK");
        kn_before = A.latest.kn;

        /* B stops reporting the key it was using. */
        mn = B.actor_mn + 1U;
        n = craft_sak_use(f, sizeof f, &A, &B, mode, mn);
        CHECK(wm_Participant_Receive(&A, f, n, t) == MKA_OK, "degraded SAK Use "
                                                             "accepted");
        CHECK(!A.peers[0].sak_use_seen, "A no longer counts B as using it");
        wm_Participant_Run(&A, t + 1U, NULL);
        CHECK(A.latest.kn == (kn_before + 1U), "the Key Server rekeyed");

        /* Only once: a second such MKPDU must not rekey again, or a peer stuck
         * without a key would drive an endless rekey storm. */
        kn_before = A.latest.kn;
        n = craft_sak_use(f, sizeof f, &A, &B, mode, mn + 1U);
        CHECK(wm_Participant_Receive(&A, f, n, t + 2U) == MKA_OK, "second "
                                                                  "accepted");
        wm_Participant_Run(&A, t + 3U, NULL);
        CHECK(A.latest.kn == kn_before, "no second rekey from the same loss");
    }

    /* A peer that reports the key correctly keeps it: no rekey. */
    kn_before = A.latest.kn;
    n = craft_sak_use(f, sizeof f, &A, &B, 3, mn + 2U);
    CHECK(wm_Participant_Receive(&A, f, n, t + 4U) == MKA_OK, "good SAK Use "
                                                              "accepted");
    CHECK(A.peers[0].sak_use_seen, "A counts B as using the key again");
    wm_Participant_Run(&A, t + 5U, NULL);
    CHECK(A.latest.kn == kn_before, "a peer using the key prompts no rekey");

    /* Transmitting on the key but not yet receiving on it still counts as
     * using it, so it prompts no rekey either. */
    kn_before = A.latest.kn;
    n = craft_sak_use(f, sizeof f, &A, &B, 4, mn + 3U);
    CHECK(wm_Participant_Receive(&A, f, n, t + 6U) == MKA_OK, "tx-only SAK Use "
                                                              "accepted");
    CHECK(A.peers[0].sak_use_seen, "transmitting counts as using the key");
    wm_Participant_Run(&A, t + 7U, NULL);
    CHECK(A.latest.kn == kn_before, "tx-only report prompts no rekey");

    /* A peer that never reported using a key cannot lose one. */
    memset(&a2b, 0, sizeof a2b);
    memset(&b2a, 0, sizeof b2a);
    memset(&sa, 0, sizeof sa);
    memset(&sb, 0, sizeof sb);
    cfg_part(&ca, &sa, &a2b, send_a, 0x0A, 10);
    cfg_part(&cb, &sb, &b2a, send_b, 0x0B, 20);
    CHECK(wm_Participant_Init(&A, &ca) == MKA_OK, "re-init A");
    CHECK(wm_Participant_Init(&B, &cb) == MKA_OK, "re-init B");
    wm_Participant_Run(&A, 0U, NULL);
    wm_Participant_Run(&B, 0U, NULL);
    while (wire_pop(&b2a, f, &n))
        wm_Participant_Receive(&A, f, n, 0U);
    CHECK(!A.sak_lost, "a peer that never held a key raises no loss");
}

/* --- ordering probe for distribute-before-install (AutoMKA-03010) --------- */

static int g_seq;
static int g_seq_frame_out; /* when the MKPDU carrying the SAK was sent */
static int g_seq_tx_sa;     /* when the transmit SA was programmed */

static int ord_send(void* ctx, const uint8_t* f, size_t n)
{
    g_seq++;
    /* Only the frame that actually carries a Distributed SAK matters; it is the
     * long one, since the wrapped key adds a 40-octet parameter set. */
    if ((n > 100U) && (g_seq_frame_out == 0)) {
        g_seq_frame_out = g_seq;
    }
    wire_push((Wire*)ctx, f, n);
    return 0;
}

static int ord_install_tx(void* c, const uint8_t* sci, uint8_t an, uint32_t kn,
    const uint8_t* sak, size_t len)
{
    (void)c;
    (void)sci;
    (void)an;
    (void)kn;
    (void)sak;
    (void)len;
    g_seq++;
    if (g_seq_tx_sa == 0) {
        g_seq_tx_sa = g_seq;
    }
    return 0;
}

/* With distribute_before_install the Key Server puts a new SAK on the wire
 * before programming its own data plane, so a peer behind a slow SecY starts
 * installing at the same moment rather than after (OPEN Alliance
 * AutoMKA-03010). The default order is the reverse, and both must reach a
 * working session. */
static void test_distribute_before_install(void)
{
    int before;

    printf("distribute-before-install ordering:\n");
    for (before = 0; before <= 1; before++) {
        Wire a2b, b2a;
        Secy sa, sb;
        MkaParticipant A, B;
        MkaParticipantConfig ca, cb;

        memset(&a2b, 0, sizeof a2b);
        memset(&b2a, 0, sizeof b2a);
        memset(&sa, 0, sizeof sa);
        memset(&sb, 0, sizeof sb);
        g_seq = 0;
        g_seq_frame_out = 0;
        g_seq_tx_sa = 0;

        cfg_part(&ca, &sa, &a2b, send_a, 0x0A, 10);
        cfg_part(&cb, &sb, &b2a, send_b, 0x0B, 20);
        ca.send = ord_send; /* A is Key Server; watch its order */
        ca.send_ctx = &a2b;
        ca.secy.install_tx_sa = ord_install_tx;
        ca.distribute_before_install = (before != 0);
        CHECK(wm_Participant_Init(&A, &ca) == MKA_OK, "init A");
        CHECK(wm_Participant_Init(&B, &cb) == MKA_OK, "init B");

        run_pair(&A, &B, &a2b, &b2a, 12, NULL);

        CHECK(g_seq_frame_out != 0, "the Distributed SAK went out");
        CHECK(g_seq_tx_sa != 0, "the transmit SA was programmed");
        if (before != 0) {
            CHECK(g_seq_frame_out < g_seq_tx_sa,
                "key distributed before the SecY was programmed");
        }
        else {
            CHECK(g_seq_tx_sa < g_seq_frame_out,
                "default order programs the SecY first");
        }
        /* Either way the session must come up. */
        CHECK(wm_Participant_HasSak(&A) && wm_Participant_HasSak(&B),
            "both ends hold the SAK");
        CHECK(A.latest.tx && B.latest.tx, "MACsec transmitting both ends");
        CHECK(!A.sak_program_pending, "nothing left pending");
        /* Once programmed, the receive claim is made. */
        {
            uint8_t g[512];
            size_t gn = sizeof g;
            MkaPdu out;
            CHECK(wm_Participant_BuildMkpdu(&A, g, sizeof g, &gn) == MKA_OK,
                "build after programming");
            memset(&out, 0, sizeof out);
            CHECK(wm_Pdu_Decode(g_cmac, g, gn, A.keys.ick, A.keys.ick_len,
                      &out) == MKA_OK,
                "decode it");
            CHECK(MKA_SAK_USE_IS_LATEST_RX(&out.sak_use),
                "receive claimed once the SecY holds the key");
        }
        /* Only the Key Server defers; a member with the same setting programs
         * its data plane straight away, since it has nothing to distribute and
         * withholding its receive claim would look like a lost key. */
        CHECK(!wm_Participant_IsKeyServer(&B), "B is the member");
        CHECK(!B.sak_program_pending, "the member never defers");
    }
}

/* A rekey with the full automotive configuration on both ends must advance the
 * Key Number exactly once. The Key Server withholds its receive claim while it
 * programs, and a member must not read that - or its own install - as a lost
 * key, or the two features would answer each other indefinitely. */
static void test_profile_rekey_is_single(void)
{
    Wire a2b, b2a;
    Secy sa, sb;
    MkaParticipant A, B;
    MkaParticipantConfig ca, cb;
    uint8_t f[512];
    size_t n;
    uint32_t t;
    uint32_t kn_before;

    printf("automotive rekey does not cascade:\n");
    memset(&a2b, 0, sizeof a2b);
    memset(&b2a, 0, sizeof b2a);
    memset(&sa, 0, sizeof sa);
    memset(&sb, 0, sizeof sb);
    cfg_part(&ca, &sa, &a2b, send_a, 0x0A, 10);
    cfg_part(&cb, &sb, &b2a, send_b, 0x0B, 20);
    CHECK(wm_Participant_AutomotiveDefaults(&ca) == MKA_OK, "A profile cfg");
    CHECK(wm_Participant_AutomotiveDefaults(&cb) == MKA_OK, "B profile cfg");
    CHECK(wm_Participant_Init(&A, &ca) == MKA_OK, "init A");
    CHECK(wm_Participant_Init(&B, &cb) == MKA_OK, "init B");

    for (t = 0U; t < 400U; t++) {
        wm_Participant_Run(&A, t, NULL);
        wm_Participant_Run(&B, t, NULL);
        while (wire_pop(&a2b, f, &n))
            wm_Participant_Receive(&B, f, n, t);
        while (wire_pop(&b2a, f, &n))
            wm_Participant_Receive(&A, f, n, t);
    }
    CHECK(A.latest.tx && B.latest.tx, "MACsec up before the rekey");
    kn_before = A.latest.kn;

    CHECK(wm_Participant_Rekey(&A) == MKA_OK, "rekey");
    for (t = 400U; t < 900U; t++) {
        wm_Participant_Run(&A, t, NULL);
        wm_Participant_Run(&B, t, NULL);
        while (wire_pop(&a2b, f, &n))
            wm_Participant_Receive(&B, f, n, t);
        while (wire_pop(&b2a, f, &n))
            wm_Participant_Receive(&A, f, n, t);
    }
    CHECK(A.latest.kn == (kn_before + 1U), "exactly one rekey, no cascade");
    CHECK(B.latest.kn == A.latest.kn, "the member followed to the same key");
    CHECK(A.latest.tx && B.latest.tx, "MACsec up again after the rekey");
    CHECK(!A.old.valid && !B.old.valid, "the old key retired on both ends");
}

/* A send that fails must not leave the key programmed but unannounced: the
 * install stays pending until an MKPDU carrying it actually goes out. */
static void test_deferred_install_send_failure(void)
{
    Wire a2b, b2a;
    Secy sa, sb;
    MkaParticipant A, B;
    MkaParticipantConfig ca, cb;
    uint8_t f[512];
    size_t n;
    uint32_t t;

    printf("deferred install survives a failing send:\n");
    memset(&a2b, 0, sizeof a2b);
    memset(&b2a, 0, sizeof b2a);
    memset(&sa, 0, sizeof sa);
    memset(&sb, 0, sizeof sb);
    cfg_part(&ca, &sa, &a2b, send_a, 0x0A, 10);
    cfg_part(&cb, &sb, &b2a, send_b, 0x0B, 20);
    ca.distribute_before_install = 1;
    CHECK(wm_Participant_Init(&A, &ca) == MKA_OK, "init A");
    CHECK(wm_Participant_Init(&B, &cb) == MKA_OK, "init B");

    /* Bring B live so A generates a SAK on its next run. */
    for (t = 0U; t < 4U; t++) {
        uint32_t now = t * MKA_HELLO_TIME_MS;
        wm_Participant_Run(&A, now, NULL);
        wm_Participant_Run(&B, now, NULL);
        while (wire_pop(&a2b, f, &n))
            wm_Participant_Receive(&B, f, n, now);
        while (wire_pop(&b2a, f, &n))
            wm_Participant_Receive(&A, f, n, now);
    }
    CHECK(wm_Participant_HasSak(&A), "A generated a SAK");
    CHECK(!A.sak_program_pending, "and programmed it once sent");

    /* Force a rekey with the transmit path broken. */
    A.cfg.send = send_fail;
    CHECK(wm_Participant_Rekey(&A) == MKA_OK, "rekey requested");
    CHECK(A.sak_program_pending, "the new key waits to be announced");
    CHECK(sa.tx_kn != A.latest.kn, "the SecY has not been told the new key");
    wm_Participant_Run(&A, 5U * MKA_HELLO_TIME_MS, NULL);
    CHECK(A.sak_program_pending, "a failed send leaves it pending");

    /* While programming is outstanding the participant must not advertise that
     * it is receiving on the key: a peer takes that as leave to send protected
     * frames, which the data plane could not yet decrypt. */
    {
        uint8_t g[512];
        size_t gn = sizeof g;
        MkaPdu out;
        CHECK(wm_Participant_BuildMkpdu(&A, g, sizeof g, &gn) == MKA_OK,
            "build while programming is pending");
        memset(&out, 0, sizeof out);
        CHECK(wm_Pdu_Decode(g_cmac, g, gn, A.keys.ick, A.keys.ick_len, &out) ==
                  MKA_OK,
            "decode it");
        CHECK(!MKA_SAK_USE_IS_LATEST_RX(&out.sak_use),
            "no receive claim while the SecY lacks the key");
    }

    /* Restore the wire: the next transmit both announces and programs it. */
    A.cfg.send = send_a;
    wm_Participant_Run(&A, 6U * MKA_HELLO_TIME_MS, NULL);
    CHECK(!A.sak_program_pending, "the retry announced and programmed it");
    CHECK(sa.tx_kn == A.latest.kn, "the SecY now holds the new key");

    /* With no transmit callback at all there is nothing to wait for, so the
     * key is programmed straight away rather than deferred forever. */
    memset(&sa, 0, sizeof sa);
    ca.send = NULL;
    ca.distribute_before_install = 1;
    CHECK(wm_Participant_Init(&A, &ca) == MKA_OK, "re-init A without a wire");
    A.peers[0].valid = 1; /* white box: a live peer to key */
    A.peers[0].live = 1;
    A.peer_count = 1;
    A.is_key_server = 1;
    A.elected = 1;
    CHECK(wm_Participant_Rekey(&A) == MKA_OK, "rekey with no transmit hook");
    CHECK(!A.sak_program_pending, "nothing deferred without a wire");
    CHECK(sa.tx_installed, "the SecY was programmed immediately");
}

void run_kay_tests(void)
{
    printf("\n== kay ==\n");
    test_two_party_agreement();
    test_non_ks_capable();
    test_election_tie_break();
    test_peer_expiry();
    test_kay_errors();
    test_kay_foreign_ckn();
    test_replay_protection();
    test_tx_gating();
    test_async_secy();
    test_rekey();
    test_free();
    test_rekey_churn();
    test_rekey_kn_wrap();
#ifndef WOLFMKA_NO_XPN
    test_xpn_ssci();
#endif
#ifndef WOLFMKA_NO_DELAY_PROTECT
    test_delay_protection();
#endif
    test_kay_misc();
    test_kay_manager();
    test_kay_negative();
    test_kay_ckn_mismatch();
    test_peer_table_full();
    test_kay_plain_dist_sak();
    test_kay_dist_sak_bad_len();
    test_dist_sak_only_from_key_server();
    test_kay_dist_sak_bad_offset();
#ifndef WOLFMKA_NO_XPN
    test_xpn_ssci_membership_change();
    #ifndef WOLFMKA_NO_DELAY_PROTECT
    test_xpn_delay_protect_lpn64();
    #endif
#endif
    test_kay_introspection();
    test_kay_events();
    test_kay_event_ks_change();
    test_kay_cb_failures();
    test_kay_drop_no_sak();
    test_kay_join_no_rekey();
    test_kay_no_secy_hooks();
    test_kay_macsec_undesired();
    test_kay_no_retransmit();
    test_kay_cipher_variants();
    test_kay_branch_combos();
    test_kay_peer_state_combos();
    test_fixed_role_and_auto_rekey();
#ifndef WOLFMKA_NO_RETRY
    test_retry_backoff();
#endif
#ifndef WOLFMKA_NO_XPN
    test_xpn_param_set_kay();
#endif
#ifndef WOLFMKA_NO_ANNOUNCEMENTS
    test_announce_emission();
#endif
#ifndef WOLFMKA_NO_AUTO_REKEY
    test_pn32_exhaustion_rekey();
#endif
    test_pn_hook_failures();
#ifndef WOLFMKA_NO_RETRY
    test_retry_backoff_edges();
#endif
    test_fixed_peer_election_scan();
    test_autorekey_not_due();
    test_mka_version_announced();
    test_automotive_defaults();
    test_immediate_response();
    test_automotive_fast_startup();
    test_peer_reset_new_mi();
    test_mn_recency_window();
    test_macsec_statistics();
    test_pae_status();
    test_kay_quiesce_others();
    test_rekey_on_lost_sak_use();
    test_distribute_before_install();
    test_deferred_install_send_failure();
    test_profile_rekey_is_single();
#ifdef WOLFMKA_AUTOMOTIVE_PROFILE
    test_ks_priority_extremes();
#endif
#ifndef WOLFMKA_NO_XPN
    test_xpn_old_key_pn_fail();
    test_xpn_old_key_pn_emit();
#endif
#ifdef WOLFMKA_DISTRIBUTED_CAK
    test_distributed_cak();
#endif
#ifdef WOLFMKA_KMD
    test_kmd_propagation();
#endif
#ifdef WOLFMKA_SUSPENSION
    test_suspension();
#endif
#ifdef WOLFMKA_CIPHER_NEGOTIATION
    test_cipher_negotiation();
    test_capability_negotiation();
    test_negotiation_edge_cases();
    test_negotiation_select_extremes();
#endif

    /* No test must have overflowed the cross-wire ring or pushed an over-size
     * frame; either would have silently dropped a frame and could mask a
     * regression. */
    CHECK(g_wire_errors == 0, "cross-wire never dropped or overwrote a frame");
}
