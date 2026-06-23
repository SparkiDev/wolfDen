/* test_fault.c - fault injection: force wolfSSL primitives to fail so the
 * otherwise-unreachable MKA_ERR_CRYPTO branches are exercised.
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
 * These tests only do anything when the suite is built with
 * -DWOLFMKA_FAULT_INJECT (see `make test-fault`). In a normal build the hook
 * macro MKA_FI is a no-op, so run_fault_tests() is an empty stub and the
 * library carries no injection code at all. */

#include "test_util.h"

#ifdef WOLFMKA_FAULT_INJECT

    #include "wolfmka/internal/mka_fault.h"
    #include "wolfmka/mka_crypto.h"
    #include "wolfmka/mka_kay.h"
    #include "wolfmka/mka_pdu.h"

/* ---- the injection hook the library calls through MKA_FI ---------------- */
static int g_armed_site = MKA_FI_NONE;
static int g_armed_code;

/* A windowed arm: fail a contiguous run of calls at one site - skip the first
 * `skip`, fail the next `count`, then pass. Lets a test fail specific calls
 * (e.g. the 2nd and 3rd of four). */
static int g_win_site = MKA_FI_NONE;
static unsigned g_win_skip;
static unsigned g_win_count;
static unsigned g_win_seen;
static int g_win_code;

int wm_Fault_Eval(int site, int real_value)
{
    if ((site != MKA_FI_NONE) && (site == g_win_site)) {
        unsigned idx = g_win_seen;
        g_win_seen++;
        if ((idx >= g_win_skip) && (idx < (g_win_skip + g_win_count))) {
            return g_win_code;
        }
        return real_value;
    }
    if ((site != MKA_FI_NONE) && (site == g_armed_site)) {
        g_armed_site = MKA_FI_NONE; /* one-shot */
        return g_armed_code;
    }
    return real_value;
}
void wm_Fault_Arm(int site, int code)
{
    g_armed_site = site;
    g_armed_code = code;
}
void wm_Fault_Reset(void)
{
    g_armed_site = MKA_FI_NONE;
    g_win_site = MKA_FI_NONE;
    g_win_seen = 0U;
}
static void mka_fault_arm_window(int site, unsigned skip, unsigned count,
    int code)
{
    g_win_site = site;
    g_win_skip = skip;
    g_win_count = count;
    g_win_seen = 0U;
    g_win_code = code;
}

/* ---- per-primitive failure paths ---------------------------------------- */
static void test_fault_crypto_paths(void)
{
    MkaCakPair cak;
    MkaDerivedKeys keys;
    uint8_t kek[16], sak[16], wrapped[24], out[32];
    uint8_t icv[MKA_DEFAULT_ICV_LEN];
    size_t wlen, olen;

    printf("fault injection: crypto failure branches:\n");

    memset(&cak, 0, sizeof cak);
    memset(kek, 0x11, sizeof kek);
    memset(sak, 0x22, sizeof sak);
    memcpy(cak.cak, kek, 16);
    cak.cak_len = 16;
    memcpy(cak.ckn, "ckn", 3);
    cak.ckn_len = 3;

    /* CMAC failure inside the KDF -> key derivation reports MKA_ERR_CRYPTO. */
    wm_Fault_Arm(MKA_FI_CMAC, -1);
    CHECK(wm_Crypto_DeriveKeys(g_cmac, &cak, &keys) == MKA_ERR_CRYPTO,
        "KDF CMAC failure -> CRYPTO");

    /* CMAC failure in the ICV path. */
    wm_Fault_Arm(MKA_FI_CMAC, -1);
    CHECK(wm_Crypto_IcvCompute(g_cmac, kek, 16, sak, 16, icv) == MKA_ERR_CRYPTO,
        "ICV CMAC failure -> CRYPTO");

    /* Per-call RNG init failure (NULL rng) -> SAK generation reports CRYPTO. */
    wm_Fault_Arm(MKA_FI_RNG_INIT, -1);
    CHECK(wm_Crypto_GenerateSak(NULL, sak, 16) == MKA_ERR_CRYPTO,
        "RNG init failure -> CRYPTO");

    /* Pool RNG init failure -> RandomInit returns NULL (no slot handed out).
     * First prove a slot is actually free (an un-armed init succeeds and is
     * returned), so the NULL below is caused by the injected fault and not by
     * pool exhaustion - which would return NULL for an unrelated reason. */
    {
        MkaRandom* r = wm_Crypto_RandomInit();
        CHECK(r != NULL, "pool slot free before the fault is armed");
        wm_Crypto_RandomFree(r);
    }
    wm_Fault_Arm(MKA_FI_RNG_INIT, -1);
    CHECK(wm_Crypto_RandomInit() == NULL, "pool RNG init failure -> NULL");

    /* RNG block-generation failure. */
    wm_Fault_Arm(MKA_FI_RNG_GEN, -1);
    CHECK(wm_Crypto_GenerateSak(NULL, sak, 16) == MKA_ERR_CRYPTO,
        "RNG generate failure -> CRYPTO");

    /* AES Key Wrap failure. */
    wlen = sizeof wrapped;
    wm_Fault_Arm(MKA_FI_KEYWRAP, -1);
    CHECK(wm_Crypto_WrapSak(kek, 16, sak, 16, wrapped, &wlen) == MKA_ERR_CRYPTO,
        "key wrap failure -> CRYPTO");

    /* AES Key Unwrap failure: first produce a valid wrap, then fail unwrap. */
    wlen = sizeof wrapped;
    CHECK(wm_Crypto_WrapSak(kek, 16, sak, 16, wrapped, &wlen) == MKA_OK,
        "wrap ok for unwrap test");
    olen = sizeof out;
    wm_Fault_Arm(MKA_FI_KEYUNWRAP, -1);
    CHECK(wm_Crypto_UnwrapSak(kek, 16, wrapped, wlen, out, &olen) ==
              MKA_ERR_CRYPTO,
        "key unwrap failure -> CRYPTO");

    /* Hook auto-disarms: the next call must succeed normally. */
    olen = sizeof out;
    CHECK(wm_Crypto_UnwrapSak(kek, 16, wrapped, wlen, out, &olen) == MKA_OK,
        "hook is one-shot (auto-disarms)");

    wm_Fault_Reset();
}

static int fault_send(void* ctx, const uint8_t* f, size_t n)
{
    (void)ctx;
    (void)f;
    (void)n;
    return 0;
}

/* The CMAC-failure paths reached through higher layers: MKPDU ICV computation
 * during encode, and a participant transmit driven by the KaY manager. */
static void test_fault_layered_paths(void)
{
    uint8_t ick[16], buf[256];
    size_t out_len = sizeof buf;
    MkaPdu pdu;
    MkaKay kay;
    MkaParticipantConfig cfg;
    int rc;

    printf("fault injection: ICV/encode and manager run paths:\n");
    memset(ick, 0x33, sizeof ick);
    memset(&pdu, 0, sizeof pdu);
    pdu.basic.version = 1;
    pdu.basic.algo_agility = MKA_ALGO_AGILITY_DEFAULT;
    memcpy(pdu.basic.ckn, "ckn", 3);
    pdu.basic.ckn_len = 3;

    /* ICV computation failure inside wm_Pdu_Encode. */
    wm_Fault_Arm(MKA_FI_CMAC, -1);
    CHECK(wm_Pdu_Encode(g_cmac, &pdu, ick, 16, buf, sizeof buf, &out_len) ==
              MKA_ERR_CRYPTO,
        "encode ICV failure -> CRYPTO");

    /* Force the EAPOL body-length overflow guard (a real frame is far below
     * the 16-bit limit, so this branch is otherwise unreachable). */
    out_len = sizeof buf;
    wm_Fault_Arm(MKA_FI_BODY_LEN, 1);
    CHECK(wm_Pdu_Encode(g_cmac, &pdu, ick, 16, buf, sizeof buf, &out_len) ==
              MKA_ERR_BUFFER,
        "body length overflow -> BUFFER");

    /* A participant whose periodic transmit fails (ICV) makes wm_Kay_Run
     * surface the first participant error. */
    CHECK(wm_Kay_Init(&kay) == MKA_OK, "kay init");
    memset(&cfg, 0, sizeof cfg);
    memset(cfg.cak.cak, 0xCA, 16);
    cfg.cak.cak_len = 16;
    memcpy(cfg.cak.ckn, "ckn", 3);
    cfg.cak.ckn_len = 3;
    cfg.sak_len = 16;
    cfg.send = fault_send;
    cfg.cmac = g_cmac;
    CHECK(wm_Kay_AddParticipant(&kay, &cfg, NULL) == MKA_OK, "add CA");
    wm_Fault_Arm(MKA_FI_CMAC, -1); /* fail the build's ICV */
    rc = wm_Kay_Run(&kay, 0);
    CHECK(rc == MKA_ERR_CRYPTO,
        "kay_run surfaces the participant CMAC failure");

    wm_Fault_Reset();
}

/* Error arms of the `if (rc == MKA_OK)` sequences in init, rekey, SAK
 * distribution and MKPDU build - each reachable only when a primitive fails at
 * that specific step. */
static void test_fault_sequence_paths(void)
{
    MkaParticipant A, B;
    MkaParticipantConfig ca, cb;
    MkaKay kay;
    uint8_t f[512];
    size_t n = sizeof f;

    printf("fault injection: mid-sequence error arms:\n");

    memset(&ca, 0, sizeof ca);
    memset(ca.cak.cak, 0xCA, 16);
    ca.cak.cak_len = 16;
    memcpy(ca.cak.ckn, "ckn", 3);
    ca.cak.ckn_len = 3;
    ca.sak_len = 16;
    ca.macsec_desired = 1;
    ca.key_server_capable = 1;
    ca.cmac = g_cmac;

    /* init: key derivation (CMAC) fails -> init aborts. */
    wm_Fault_Arm(MKA_FI_CMAC, -1);
    CHECK(wm_Participant_Init(&A, &ca) == MKA_ERR_CRYPTO,
        "init: key derivation failure");

    /* init: MI generation (RNG) fails after keys derive cleanly. */
    wm_Fault_Arm(MKA_FI_RNG_INIT, -1);
    CHECK(wm_Participant_Init(&A, &ca) == MKA_ERR_CRYPTO,
        "init: MI generation failure");

    /* A clean participant for the remaining cases. */
    CHECK(wm_Participant_Init(&A, &ca) == MKA_OK, "init clean");

    /* rekey: SAK generation (RNG) fails. */
    A.is_key_server = 1;
    wm_Fault_Arm(MKA_FI_RNG_GEN, -1);
    CHECK(wm_Participant_Rekey(&A) == MKA_ERR_CRYPTO,
        "rekey: SAK generation failure");

    /* build MKPDU as Key Server with a SAK: the Distributed-SAK wrap fails,
     * which the build surfaces (covers the wrap and build error arms). */
    A.is_key_server = 1;
    A.latest.valid = 1;
    A.latest.sak_len = 16;
    A.latest.kn = 1;
    A.latest.an = 0;
    memset(A.latest.sak, 0x11, 16);
    A.sak_cipher_suite = MKA_CIPHER_GCM_AES_128;
    n = sizeof f;
    wm_Fault_Arm(MKA_FI_KEYWRAP, -1);
    CHECK(wm_Participant_BuildMkpdu(&A, f, sizeof f, &n) == MKA_ERR_CRYPTO,
        "build: distributed-SAK wrap failure");

    #ifdef WOLFMKA_DISTRIBUTED_CAK
    /* build MKPDU as Key Server with a staged group CAK but no SAK: now the
     * Distributed-CAK wrap is the failing one, surfaced by the build (covers
     * mka_build_dist_cak's error arm). */
    A.latest.valid = 0; /* no SAK -> dist-SAK skipped, dist-CAK reached */
    {
        static const uint8_t gc[16] = {0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
            0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51};
        CHECK(wm_Participant_DistributeCak(&A, gc, 16, gc, 6) == MKA_OK,
            "stage group CAK for fault");
    }
    n = sizeof f;
    wm_Fault_Arm(MKA_FI_KEYWRAP, -1);
    CHECK(wm_Participant_BuildMkpdu(&A, f, sizeof f, &n) == MKA_ERR_CRYPTO,
        "build: distributed-CAK wrap failure");
    #endif

    /* mka_install_from_dist: a non-Key-Server receives a wrapped SAK whose
     * unwrap fails. Build a real wrap with B's KEK, then fail the unwrap on
     * recv. */
    memset(&cb, 0, sizeof cb);
    memset(cb.cak.cak, 0xCA, 16);
    cb.cak.cak_len = 16;
    memcpy(cb.cak.ckn, "ckn", 3);
    cb.cak.ckn_len = 3;
    cb.sak_len = 16;
    cb.macsec_desired = 1;
    cb.key_server_capable = 0;
    cb.cmac = g_cmac;
    CHECK(wm_Participant_Init(&B, &cb) == MKA_OK, "init non-KS B");
    {
        uint8_t sak[16], wrapped[40];
        size_t wlen = sizeof wrapped;
        MkaPdu in;
        memset(sak, 0x55, sizeof sak);
        CHECK(wm_Crypto_WrapSak(B.keys.kek, B.keys.kek_len, sak, 16, wrapped,
                  &wlen) == MKA_OK,
            "wrap for dist frame");
        memset(&in, 0, sizeof in);
        in.basic.version = 1;
        in.basic.algo_agility = MKA_ALGO_AGILITY_DEFAULT;
        memcpy(in.basic.ckn, "ckn", 3);
        in.basic.ckn_len = 3;
        memset(in.basic.mi, 0x77, MKA_MI_LEN);
        in.basic.mn = 1;
        /* Make the sender B's elected Key Server (B is non-KS-capable):
         * advertise MACsec desire and echo B's MI so the peer is live and wins
         * election in this Receive(), so B acts on the distributed SAK. */
        in.basic.macsec_desired = 1;
        in.live_peers.present = 1;
        in.live_peers.count = 1;
        memcpy(in.live_peers.peers[0].mi, B.actor_mi, MKA_MI_LEN);
        in.live_peers.peers[0].mn = 1;
        in.dist_sak.present = 1;
        in.dist_sak.kn = 1;
        in.dist_sak.distributed_an = 0;
        memcpy(in.dist_sak.wrapped_sak, wrapped, wlen);
        in.dist_sak.wrapped_len = wlen;
        n = sizeof f;
        CHECK(wm_Pdu_Encode(g_cmac, &in, B.keys.ick, B.keys.ick_len, f,
                  sizeof f, &n) == MKA_OK,
            "encode dist frame");
        wm_Fault_Arm(MKA_FI_KEYUNWRAP, -1);
        CHECK(wm_Participant_Receive(&B, f, n, 0) == MKA_ERR_CRYPTO,
            "mka_install_from_dist: unwrap failure");
    }

    /* wm_Kay_AddParticipant: the participant init it performs fails. */
    CHECK(wm_Kay_Init(&kay) == MKA_OK, "kay init");
    wm_Fault_Arm(MKA_FI_CMAC, -1);
    CHECK(wm_Kay_AddParticipant(&kay, &ca, NULL) == MKA_ERR_CRYPTO,
        "add_participant: init failure");
    CHECK(wm_Kay_ParticipantCount(&kay) == 0, "no CA added on failure");

    wm_Fault_Reset();
}

/* wm_Kay_Run's first-failure accumulator:
 *     if ((s != MKA_OK) && (rc == MKA_OK)) rc = s;
 * Drive four participants whose runs return, in order, OK / fail / fail / OK so
 * that every (s, rc) combination of that condition is evaluated:
 *   p0: s==OK, rc==OK   -> s!=OK false                  (no record)
 *   p1: s!=OK, rc==OK   -> both true                    (record first failure)
 *   p2: s!=OK, rc!=OK   -> s!=OK true,  rc==OK false     (keep first failure)
 *   p3: s==OK, rc!=OK   -> s!=OK false (rc==OK not eval) (no change)
 * A participant's run fails when its MKPDU ICV (one CMAC per run) fails; a
 * windowed CMAC fault skipping call 0 and failing calls 1-2 gives the order. */
static void test_fault_kay_run_accumulate(void)
{
    MkaKay kay;
    MkaParticipantConfig c;
    int i;

    printf("fault injection: wm_Kay_Run first-failure accumulation:\n");

    CHECK(wm_Kay_Init(&kay) == MKA_OK, "kay init");
    for (i = 0; i < 4; i++) {
        char ckn[4];
        memset(&c, 0, sizeof c);
        memset(c.cak.cak, 0xCA, 16);
        c.cak.cak_len = 16;
        ckn[0] = 'c';
        ckn[1] = 'a';
        ckn[2] = (char)('0' + i);
        ckn[3] = '\0';
        memcpy(c.cak.ckn, ckn, 4);
        c.cak.ckn_len = 4;
        c.sak_len = 16;
        c.macsec_desired = 1;
        c.key_server_capable = 1;
        c.send = fault_send;
        c.cmac = g_cmac;
        CHECK(wm_Kay_AddParticipant(&kay, &c, NULL) == MKA_OK, "add CA");
    }

    /* Arm AFTER init (init's key derivation uses CMAC too): of the four
     * per-participant ICV CMAC calls during the run, fail calls 1 and 2. */
    mka_fault_arm_window(MKA_FI_CMAC, 1U, 2U, -1);
    CHECK(wm_Kay_Run(&kay, 0) == MKA_ERR_CRYPTO,
        "kay_run returns the first participant failure");

    wm_Fault_Reset();

    /* Sanity: with no fault armed every participant runs cleanly. */
    CHECK(wm_Kay_Run(&kay, MKA_HELLO_TIME_MS) == MKA_OK,
        "kay_run OK when all participants succeed");
}

/* wm_Participant_Run surfacing an in-run SAK-generation failure: as Key
 * Server with a live peer the run generates a SAK; when that fails, run
 * advances the handover and then returns the error (the `if (rc != MKA_OK)
 * return rc;`). */
static void test_fault_run_sak_gen(void)
{
    MkaParticipant A;
    MkaParticipantConfig c;

    printf("fault injection: run() surfaces in-run SAK-gen failure:\n");
    memset(&c, 0, sizeof c);
    memset(c.cak.cak, 0xCA, 16);
    c.cak.cak_len = 16;
    memcpy(c.cak.ckn, "ckn", 3);
    c.cak.ckn_len = 3;
    c.sak_len = 16;
    c.macsec_desired = 1;
    c.key_server_capable = 1;
    c.send = fault_send;
    c.cmac = g_cmac;
    CHECK(wm_Participant_Init(&A, &c) == MKA_OK, "init");

    /* Force Key-Server status with a live peer so run() must generate a SAK. */
    A.is_key_server = 1;
    A.peers[0].valid = 1;
    A.peers[0].live = 1;
    A.peer_count = 1;

    wm_Fault_Arm(MKA_FI_RNG_INIT, -1); /* SAK generation fails */
    CHECK(wm_Participant_Run(&A, 0, NULL) == MKA_ERR_CRYPTO,
        "run returns the SAK-generation failure");
    CHECK(wm_Participant_HasSak(&A) == 0, "no SAK installed on failure");

    wm_Fault_Reset();
}

void run_fault_tests(void)
{
    printf("\n== fault injection ==\n");
    test_fault_crypto_paths();
    test_fault_layered_paths();
    test_fault_sequence_paths();
    test_fault_kay_run_accumulate();
    test_fault_run_sak_gen();
}

#else /* fault injection compiled out */

void run_fault_tests(void)
{
    /* no-op: build with -DWOLFMKA_FAULT_INJECT (make test-fault) to enable */
}

#endif /* WOLFMKA_FAULT_INJECT */
