/* test_autosar.c
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
 * Exercises the AUTOSAR Mka API (Mka.h) over wolfMKA for full line, branch and
 * decision coverage of src/autosar/Mka.c. The Mka module is a singleton, so the
 * test re-initialises it between phases:
 *
 *   A  pre-init rejection and the void notification/no-op entry points
 *   B  argument validation and the simple setters/getters
 *   C  status transitions: UNDEFINED -> WAITING_PEER_LINK -> WAITING_PEER ->
 *      MACSEC_RUNNING, plus IN_PROGRESS (two peers, no Key Server)
 *   D  send-bridge failure paths and the StartPae add-participant failure
 *   E  the CKN bound, the SetCknStatus running-add path and async statistics
 *   F  asynchronous SecY: transmit gated until Mka_MacSecAddTxSaNotification,
 *      and per-notification completion granularity across two keying CKNs
 */
#include "test_util.h"
#include "wolfmka/autosar/Mka.h"
#include "wolfmka/mka_crypto.h"

int g_tests_run = 0;
int g_tests_failed = 0;

/* ---- cross-wire: a queue of frames tagged by destination RxPduId ---- */
typedef struct {
    PduIdType dst;
    uint8 data[600];
    uint16 len;
} Frame;

static Frame g_queue[16];
static int g_qhead;
static int g_qtail;

static Std_ReturnType test_transmit(PduIdType TxPduId, const uint8* f, uint16 n)
{
    Frame* slot;
    if (((g_qtail + 1) % 16) == g_qhead) {
        return E_NOT_OK;
    }
    slot = &g_queue[g_qtail];
    slot->dst = TxPduId;
    (void)memcpy(slot->data, f, n);
    slot->len = n;
    g_qtail = (g_qtail + 1) % 16;
    return E_OK;
}

/* A transmit that always fails (exercises the bridge's failure return). The
 * call counter lets a test prove the transmit path was actually entered rather
 * than skipped. */
static int g_fail_tx_calls;
static Std_ReturnType test_transmit_fail(PduIdType id, const uint8* f, uint16 n)
{
    (void)id;
    (void)f;
    (void)n;
    g_fail_tx_calls++;
    return E_NOT_OK;
}

static void drain(void)
{
    while (g_qhead != g_qtail) {
        Frame* fr = &g_queue[g_qhead];
        PduInfoType pdu;
        pdu.SduDataPtr = fr->data;
        pdu.SduLength = fr->len;
        pdu.MetaDataPtr = NULL;
        Mka_RxIndication(fr->dst, &pdu);
        g_qhead = (g_qhead + 1) % 16;
    }
}

static void queue_reset(void)
{
    g_qhead = 0;
    g_qtail = 0;
}

/* ---- shared keys ---- */
static const uint8 g_cak[16] = {0xCA, 0xCA, 0xCA, 0xCA, 0xCA, 0xCA, 0xCA, 0xCA,
    0xCA, 0xCA, 0xCA, 0xCA, 0xCA, 0xCA, 0xCA, 0xCA};
static const uint8 g_ckn[8] = {'a', 'u', 't', 'o', '-', 'c', 'k', 'n'};

static void run_cycles(int n)
{
    int i;
    for (i = 0; i < n; i++) {
        Mka_MainFunction();
        drain();
    }
}

/* ------------------------------------------------------------------ */
static void phase_pre_init(void)
{
    uint8 buf[8] = {0};
    PduInfoType pdu;
    Mka_PaeStatusType st;
    Mka_Stats_SecYType stats;
    Std_VersionInfoType ver;
    boolean en;

    printf("pre-init: API rejected, notifications are no-ops:\n");
    pdu.SduDataPtr = buf;
    pdu.SduLength = 8;
    pdu.MetaDataPtr = NULL;

    /* Scheduled / callback entry points tolerate the un-initialised module. */
    Mka_MainFunction();
    Mka_RxIndication(0, &pdu);
    Mka_TxConfirmation(0, E_OK);
    Mka_GetMacSecStatisticsNotification(0, E_OK);
    Mka_MacSecUpdateSecYNotification(0, E_OK);
    Mka_MacSecAddTxSaNotification(0, E_OK);
    Mka_MacSecAddRxSaNotification(0, E_OK);

    CHECK(Mka_SetEnable(0, TRUE) == E_NOT_OK, "SetEnable pre-init");
    CHECK(Mka_GetEnable(0, &en) == E_NOT_OK, "GetEnable pre-init");
    CHECK(Mka_GetPaeStatus(0, &st) == E_NOT_OK, "GetPaeStatus pre-init");
    CHECK(Mka_SetCknStatus(0, TRUE, g_ckn, 8) == E_NOT_OK, "SetCkn pre-init");
    CHECK(Mka_GetCknStatus(0, g_ckn, 8, &en) == E_NOT_OK, "GetCkn pre-init");
    CHECK(Mka_SetPaePermissiveMode(0, MKA_PERMISSIVE_MODE_NEVER) == E_NOT_OK,
        "SetPermissive pre-init");
    CHECK(Mka_StartPae(0) == E_NOT_OK, "StartPae pre-init");
    CHECK(Mka_GetMacSecStatistics(0, &stats) == E_NOT_OK, "GetStats pre-init");
    CHECK(Mka_LinkStateChange(0, ETHTRCV_LINK_STATE_ACTIVE) == E_NOT_OK,
        "LinkStateChange pre-init");

    /* Init with a NULL config leaves the module un-initialised. */
    Mka_Init(NULL);
    CHECK(Mka_SetEnable(0, TRUE) == E_NOT_OK, "still un-init after NULL");
    Mka_GetVersionInfo(NULL); /* NULL-tolerant */
    (void)ver;
}

/* ------------------------------------------------------------------ */
static void fill_pae(Mka_PaeConfigType* p, const Mka_CknConfigType* ckns,
    uint8 cknCount, PduIdType rx, PduIdType tx, uint8 lastSci, MkaRole role,
    Mka_TransmitFnType tx_fn, uint8 sakLen)
{
    memset(p, 0, sizeof *p);
    p->RxPduId = rx;
    p->TxPduId = tx;
    p->Sci[5] = lastSci;
    p->Sci[7] = 1;
    p->Priority = (role == MKA_ROLE_KEY_SERVER) ? 10U : 20U;
    p->Role = role;
    p->SakLength = sakLen;
    p->Transmit = tx_fn;
    p->Ckns = ckns;
    p->CknCount = cknCount;
}

static void phase_args(void)
{
    Mka_CknConfigType ckn = {g_cak, 16, g_ckn, 8, TRUE};
    Mka_PaeConfigType pae;
    Mka_ConfigType cfg;
    Mka_PaeStatusType st;
    Mka_Stats_SecYType stats;
    Std_VersionInfoType ver;
    boolean en;
    uint8 wrongckn[8] = {'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x'};

    printf("argument validation and simple setters:\n");
    fill_pae(&pae, &ckn, 1, 20, 21, 0x0A, MKA_ROLE_KEY_SERVER, test_transmit,
        16);
    cfg.Paes = &pae;
    cfg.PaeCount = 1;
    cfg.MainFunctionPeriodMs = 100;
    Mka_Init(&cfg);

    Mka_GetVersionInfo(&ver);
    CHECK(ver.sw_major_version == MKA_SW_MAJOR_VERSION, "version info");

    /* Bad index / NULL pointer for every accessor. */
    CHECK(Mka_SetEnable(9, TRUE) == E_NOT_OK, "SetEnable bad idx");
    CHECK(Mka_GetEnable(9, &en) == E_NOT_OK, "GetEnable bad idx");
    CHECK(Mka_GetEnable(0, NULL) == E_NOT_OK, "GetEnable null");
    CHECK(Mka_GetPaeStatus(9, &st) == E_NOT_OK, "GetPaeStatus bad idx");
    CHECK(Mka_GetPaeStatus(0, NULL) == E_NOT_OK, "GetPaeStatus null");
    CHECK(Mka_SetCknStatus(0, TRUE, NULL, 8) == E_NOT_OK, "SetCkn null");
    CHECK(Mka_SetCknStatus(0, TRUE, wrongckn, 8) == E_NOT_OK, "SetCkn nomatch");
    CHECK(Mka_SetCknStatus(0, TRUE, g_ckn, 3) == E_NOT_OK, "SetCkn bad len");
    CHECK(Mka_GetCknStatus(0, NULL, 8, &en) == E_NOT_OK, "GetCkn null ckn");
    CHECK(Mka_GetCknStatus(0, g_ckn, 8, NULL) == E_NOT_OK, "GetCkn null out");
    CHECK(Mka_GetCknStatus(0, wrongckn, 8, &en) == E_NOT_OK, "GetCkn no match");
    CHECK(Mka_SetPaePermissiveMode(9, MKA_PERMISSIVE_MODE_NEVER) == E_NOT_OK,
        "SetPermissive bad idx");
    CHECK(Mka_StartPae(9) == E_NOT_OK, "StartPae bad idx");
    CHECK(Mka_GetMacSecStatistics(9, &stats) == E_NOT_OK, "GetStats bad idx");
    CHECK(Mka_GetMacSecStatistics(0, NULL) == E_NOT_OK, "GetStats null");
    CHECK(Mka_LinkStateChange(9, ETHTRCV_LINK_STATE_ACTIVE) == E_NOT_OK,
        "LinkStateChange bad idx");

    /* Notifications with a bad index are silent no-ops. */
    Mka_GetMacSecStatisticsNotification(9, E_OK);
    Mka_MacSecUpdateSecYNotification(9, E_OK);
    Mka_MacSecAddTxSaNotification(9, E_OK);
    Mka_MacSecAddRxSaNotification(9, E_OK);

    /* Valid simple setters. */
    CHECK(Mka_SetPaePermissiveMode(0, MKA_PERMISSIVE_MODE_TIMEOUT) == E_OK,
        "SetPermissive ok");
    CHECK(Mka_SetEnable(0, TRUE) == E_OK, "enable");
    CHECK(Mka_GetEnable(0, &en) == E_OK && en == TRUE, "get enable");
    CHECK(Mka_SetEnable(0, FALSE) == E_OK, "disable");
    CHECK(Mka_SetCknStatus(0, FALSE, g_ckn, 8) == E_OK, "ckn disable pre");
    CHECK(Mka_SetCknStatus(0, TRUE, g_ckn, 8) == E_OK, "ckn enable pre-start");
    CHECK(Mka_GetCknStatus(0, g_ckn, 8, &en) == E_OK && en == TRUE, "get ckn");

    /* RxIndication with an unknown PDU id and with no payload. */
    {
        uint8 b[8] = {0};
        PduInfoType pdu;
        pdu.SduDataPtr = b;
        pdu.SduLength = 8;
        pdu.MetaDataPtr = NULL;
        Mka_RxIndication(999, &pdu); /* no PAE owns this id */
        pdu.SduDataPtr = NULL;
        Mka_RxIndication(20, &pdu); /* null payload */
        Mka_RxIndication(20, NULL); /* null PduInfo */
    }
}

/* ------------------------------------------------------------------ */
static void phase_status(void)
{
    Mka_CknConfigType ckn_a = {g_cak, 16, g_ckn, 8, TRUE};
    Mka_CknConfigType ckn_b = {g_cak, 16, g_ckn, 8, TRUE};
    Mka_PaeConfigType paes[2];
    Mka_ConfigType cfg;
    Mka_PaeStatusType st;

    printf("status transitions and convergence:\n");
    queue_reset();
    fill_pae(&paes[0], &ckn_a, 1, 20, 21, 0x0A, MKA_ROLE_KEY_SERVER,
        test_transmit, 16);
    fill_pae(&paes[1], &ckn_b, 1, 21, 20, 0x0B, MKA_ROLE_PEER, test_transmit,
        16);
    cfg.Paes = paes;
    cfg.PaeCount = 2;
    cfg.MainFunctionPeriodMs = MKA_HELLO_TIME_MS;
    Mka_Init(&cfg);

    /* Disabled -> UNDEFINED. */
    CHECK(Mka_GetPaeStatus(0, &st) == E_OK &&
              st.MkaStatus == MKA_STATUS_UNDEFINED,
        "disabled -> UNDEFINED");

    Mka_SetEnable(0, TRUE);
    Mka_SetEnable(1, TRUE);
    /* Enabled, link down -> WAITING_PEER_LINK. */
    CHECK(Mka_GetPaeStatus(0, &st) == E_OK &&
              st.MkaStatus == MKA_STATUS_WAITING_PEER_LINK,
        "link down -> waiting");

    Mka_LinkStateChange(0, ETHTRCV_LINK_STATE_ACTIVE);
    Mka_LinkStateChange(1, ETHTRCV_LINK_STATE_ACTIVE);
    Mka_StartPae(0);
    Mka_StartPae(1);

    /* Started, link up, no peers yet -> WAITING_PEER. */
    CHECK(Mka_GetPaeStatus(0, &st) == E_OK &&
              st.MkaStatus == MKA_STATUS_WAITING_PEER,
        "no peer -> WAITING_PEER");

    run_cycles(16);
    CHECK(Mka_GetPaeStatus(0, &st) == E_OK &&
              st.MkaStatus == MKA_STATUS_MACSEC_RUNNING,
        "converged -> RUNNING");
    CHECK(Mka_GetPaeStatus(1, &st) == E_OK &&
              st.MkaStatus == MKA_STATUS_MACSEC_RUNNING,
        "peer -> RUNNING");
}

/* A frame that routes to a participant by CKN but fails ICV verification (built
 * with the same CKN under a different CAK) latches MKA_STATUS_AUTH_FAIL; a link
 * transition clears it. */
static void phase_auth_fail(void)
{
    static const uint8 other_cak[16] = {0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A,
        0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A};
    Mka_CknConfigType ckn = {g_cak, 16, g_ckn, 8, TRUE};
    Mka_PaeConfigType pae;
    Mka_ConfigType cfg;
    Mka_PaeStatusType st;
    MkaParticipant intruder;
    MkaParticipantConfig ic;
    uint8 frame[256];
    size_t flen = sizeof frame;
    PduInfoType pdu;

    printf("ICV failure reported as AUTH_FAIL:\n");
    queue_reset();
    fill_pae(&pae, &ckn, 1, 70, 71, 0x30, MKA_ROLE_KEY_SERVER, test_transmit,
        16);
    cfg.Paes = &pae;
    cfg.PaeCount = 1;
    cfg.MainFunctionPeriodMs = 100;
    Mka_Init(&cfg);
    Mka_SetEnable(0, TRUE);
    Mka_LinkStateChange(0, ETHTRCV_LINK_STATE_ACTIVE);
    CHECK(Mka_StartPae(0) == E_OK, "start auth-fail PAE");

    /* Same CKN, different CAK => routes to our participant but the ICV (keyed
     * by the real CAK's ICK) will not verify. */
    memset(&ic, 0, sizeof ic);
    memcpy(ic.cak.cak, other_cak, 16);
    ic.cak.cak_len = 16;
    memcpy(ic.cak.ckn, g_ckn, 8);
    ic.cak.ckn_len = 8;
    ic.sci[5] = 0x99;
    ic.sci[7] = 1;
    ic.priority = 99;
    ic.macsec_desired = 1;
    ic.macsec_capability = (uint8)MKA_CAP_INTEGRITY_CONF;
    ic.key_server_capable = 1;
    ic.sak_len = 16;
    /* This raw forging participant lives outside the AUTOSAR layer, so it needs
     * its own CMAC workspace (the layer's is private to Mka.c). */
    ic.cmac = wm_Crypto_CmacInit();
    CHECK(ic.cmac != NULL, "intruder cmac");
    CHECK(wm_Participant_Init(&intruder, &ic) == MKA_OK, "init intruder");
    CHECK(wm_Participant_BuildMkpdu(&intruder, frame, sizeof frame, &flen) ==
              MKA_OK,
        "build foreign-CAK frame");

    pdu.SduDataPtr = frame;
    pdu.SduLength = (uint16)flen;
    pdu.MetaDataPtr = NULL;
    Mka_RxIndication(70, &pdu); /* delivered to PAE 0, fails ICV */

    CHECK(Mka_GetPaeStatus(0, &st) == E_OK &&
              st.MkaStatus == MKA_STATUS_AUTH_FAIL_UNKNOWN_PEER,
        "ICV failure -> AUTH_FAIL_UNKNOWN_PEER");

    /* A link transition restarts authentication and clears the latch. */
    Mka_LinkStateChange(0, ETHTRCV_LINK_STATE_ACTIVE);
    CHECK(Mka_GetPaeStatus(0, &st) == E_OK &&
              st.MkaStatus == MKA_STATUS_WAITING_PEER,
        "AUTH_FAIL cleared after link change");

    wm_Participant_Free(&intruder);
    wm_Crypto_CmacFree(ic.cmac); /* release the standalone CMAC slot */
}

static void phase_in_progress(void)
{
    Mka_CknConfigType ckn_a = {g_cak, 16, g_ckn, 8, TRUE};
    Mka_CknConfigType ckn_b = {g_cak, 16, g_ckn, 8, TRUE};
    Mka_PaeConfigType paes[2];
    Mka_ConfigType cfg;
    Mka_PaeStatusType st;

    printf("two peers, no Key Server -> IN_PROGRESS:\n");
    queue_reset();
    /* Both configured as peers: liveness is reached but no SAK is agreed. */
    fill_pae(&paes[0], &ckn_a, 1, 30, 31, 0x0C, MKA_ROLE_PEER, test_transmit,
        16);
    fill_pae(&paes[1], &ckn_b, 1, 31, 30, 0x0D, MKA_ROLE_PEER, test_transmit,
        16);
    cfg.Paes = paes;
    cfg.PaeCount = 2;
    cfg.MainFunctionPeriodMs = MKA_HELLO_TIME_MS;
    Mka_Init(&cfg);
    Mka_SetEnable(0, TRUE);
    Mka_SetEnable(1, TRUE);
    Mka_LinkStateChange(0, ETHTRCV_LINK_STATE_ACTIVE);
    Mka_LinkStateChange(1, ETHTRCV_LINK_STATE_ACTIVE);
    Mka_StartPae(0);
    Mka_StartPae(1);
    run_cycles(8);

    CHECK(Mka_GetPaeStatus(0, &st) == E_OK &&
              st.MkaStatus == MKA_STATUS_IN_PROGRESS,
        "live peer, no SAK -> IN_PROGRESS");
}

/* ------------------------------------------------------------------ */
static void phase_failures(void)
{
    Mka_CknConfigType ckn0 = {g_cak, 16, g_ckn, 8, TRUE};
    Mka_CknConfigType ckn1 = {g_cak, 16, g_ckn, 8, TRUE};
    Mka_CknConfigType cknBad = {g_cak, 16, g_ckn, 8, TRUE};
    Mka_PaeConfigType paes[3];
    Mka_ConfigType cfg;

    printf("send-bridge failure and StartPae add failure:\n");
    queue_reset();
    /* PAE 0 transmits to a NULL transceiver; PAE 1's transmit always fails;
     * PAE 2 has an invalid SAK length so adding its participant fails. */
    fill_pae(&paes[0], &ckn0, 1, 40, 41, 0x0E, MKA_ROLE_KEY_SERVER, NULL, 16);
    fill_pae(&paes[1], &ckn1, 1, 41, 42, 0x0F, MKA_ROLE_KEY_SERVER,
        test_transmit_fail, 16);
    fill_pae(&paes[2], &cknBad, 1, 43, 44, 0x11, MKA_ROLE_KEY_SERVER,
        test_transmit, 0 /* invalid SAK length */);
    cfg.Paes = paes;
    cfg.PaeCount = 3;
    cfg.MainFunctionPeriodMs = MKA_HELLO_TIME_MS;
    Mka_Init(&cfg);
    Mka_SetEnable(0, TRUE);
    Mka_SetEnable(1, TRUE);
    Mka_SetEnable(2, TRUE);
    Mka_LinkStateChange(0, ETHTRCV_LINK_STATE_ACTIVE);
    Mka_LinkStateChange(1, ETHTRCV_LINK_STATE_ACTIVE);
    Mka_LinkStateChange(2, ETHTRCV_LINK_STATE_ACTIVE);

    CHECK(Mka_StartPae(0) == E_OK, "start (null transmit)");
    CHECK(Mka_StartPae(1) == E_OK, "start (failing transmit)");
    CHECK(Mka_StartPae(2) == E_NOT_OK, "start fails (bad SAK length)");

    /* PAE 0 and 1 both transmit, hitting the bridge's two failure returns. PAE
     * 2 never got a participant (the bad SAK length failed the add), so it
     * holds no SAK; and the transmit failures do not produce a peer/SAK on 0
     * or 1. */
    g_fail_tx_calls = 0;
    run_cycles(3);
    {
        Mka_PaeStatusType st;
        CHECK(Mka_GetPaeStatus(2, &st) == E_OK &&
                  st.MkaStatus == MKA_STATUS_WAITING_PEER,
            "PAE 2 (failed add) has no SAK");
        CHECK(Mka_GetPaeStatus(0, &st) == E_OK &&
                  st.MkaStatus == MKA_STATUS_WAITING_PEER,
            "PAE 0 reaches no peer despite transmitting");
        /* PAE 1's failing transmit must actually have been invoked, proving the
         * bridge's E_NOT_OK return path was exercised (not merely that PAE 1
         * stayed peerless, which a never-transmitting PAE would also do). */
        CHECK(g_fail_tx_calls > 0, "failing transmit bridge path entered");
    }
}

/* ------------------------------------------------------------------ */
static void phase_ckn_bound_and_async(void)
{
    /* Five CKNs (> MKA_MAX_PARTICIPANTS) to exercise the participant bound. The
     * last one is disabled by default so it can be added at runtime. */
    static const uint8 cknA[8] = {'c', 'k', 'n', '-', 'a', 'a', 'a', 'a'};
    static const uint8 cknB[8] = {'c', 'k', 'n', '-', 'b', 'b', 'b', 'b'};
    static const uint8 cknC[8] = {'c', 'k', 'n', '-', 'c', 'c', 'c', 'c'};
    static const uint8 cknD[8] = {'c', 'k', 'n', '-', 'd', 'd', 'd', 'd'};
    static const uint8 cknE[8] = {'c', 'k', 'n', '-', 'e', 'e', 'e', 'e'};
    Mka_CknConfigType ckns[5] = {{g_cak, 16, cknA, 8, TRUE},
        {g_cak, 16, cknB, 8, TRUE}, {g_cak, 16, cknC, 8, TRUE},
        {g_cak, 16, cknD, 8, FALSE}, {g_cak, 16, cknE, 8, TRUE}};
    Mka_PaeConfigType pae;
    Mka_ConfigType cfg;
    Mka_Stats_SecYType stats;

    printf("CKN bound, runtime CKN add, async statistics:\n");
    queue_reset();
    fill_pae(&pae, ckns, 5, 50, 51, 0x12, MKA_ROLE_KEY_SERVER, test_transmit,
        16);
    cfg.Paes = &pae;
    cfg.PaeCount = 1;
    cfg.MainFunctionPeriodMs = 100;
    Mka_Init(&cfg);
    Mka_SetEnable(0, TRUE);
    Mka_LinkStateChange(0, ETHTRCV_LINK_STATE_ACTIVE);
    CHECK(Mka_StartPae(0) == E_OK, "start 5-CKN PAE");

    /* Re-enable an already-running CKN: the participant already exists. */
    CHECK(Mka_SetCknStatus(0, TRUE, cknA, 8) == E_OK, "re-enable running ckn");
    /* Enable a not-yet-added CKN while running: it is instantiated now (D is
     * the 4th participant, filling the table). */
    CHECK(Mka_SetCknStatus(0, TRUE, cknD, 8) == E_OK, "runtime CKN add");
    /* The 5th CKN is beyond the participant bound and is never tracked. */
    CHECK(Mka_SetCknStatus(0, TRUE, cknE, 8) == E_NOT_OK, "ckn beyond bound");

    /* 8.3.10 / 8.4.1 asynchronous statistics handshake. */
    CHECK(Mka_GetMacSecStatistics(0, &stats) == E_OK, "stats request");
    CHECK(Mka_GetMacSecStatistics(0, &stats) == E_NOT_OK, "stats busy");
    Mka_GetMacSecStatisticsNotification(0, E_OK);
    CHECK(Mka_GetMacSecStatistics(0, &stats) == E_OK, "stats request again");
    Mka_GetMacSecStatisticsNotification(0, E_OK);

    /* SecY SA notifications for a valid PAE. */
    Mka_MacSecUpdateSecYNotification(0, E_OK);
    Mka_MacSecAddTxSaNotification(0, E_OK);
    Mka_MacSecAddRxSaNotification(0, E_OK);
}

/* ------------------------------------------------------------------ */
/* Drive the short-circuit operand halves: a PAE enabled but not started, a
 * started PAE with the link down, a disabled PAE, StartPae twice, and a CKN
 * disabled while running. */
static void phase_partial_states(void)
{
    Mka_CknConfigType ckn_a = {g_cak, 16, g_ckn, 8, TRUE};
    Mka_CknConfigType ckn_b = {g_cak, 16, g_ckn, 8, TRUE};
    Mka_PaeConfigType paes[2];
    Mka_ConfigType cfg;
    uint8 b[8] = {0};
    PduInfoType pdu;

    printf("partial PAE states (operand coverage):\n");
    queue_reset();
    fill_pae(&paes[0], &ckn_a, 1, 60, 61, 0x20, MKA_ROLE_KEY_SERVER,
        test_transmit, 16);
    fill_pae(&paes[1], &ckn_b, 1, 61, 60, 0x21, MKA_ROLE_PEER, test_transmit,
        16);
    cfg.Paes = paes;
    cfg.PaeCount = 2;
    cfg.MainFunctionPeriodMs = 100;
    Mka_Init(&cfg);
    pdu.SduDataPtr = b;
    pdu.SduLength = 8;
    pdu.MetaDataPtr = NULL;

    Mka_SetEnable(0, TRUE);
    Mka_SetEnable(1, TRUE); /* enabled but never started */
    Mka_LinkStateChange(0, ETHTRCV_LINK_STATE_ACTIVE);
    CHECK(Mka_StartPae(0) == E_OK, "start PAE 0");
    CHECK(Mka_StartPae(0) == E_OK, "re-start PAE 0 (participant exists)");

    /* MainFunction skips a PAE that is not started, link-down, or disabled. */
    Mka_MainFunction(); /* PAE 1 not started -> skip */
    Mka_LinkStateChange(0, ETHTRCV_LINK_STATE_DOWN);
    Mka_MainFunction(); /* PAE 0 link down -> skip */
    Mka_SetEnable(0, FALSE);
    Mka_MainFunction(); /* PAE 0 disabled -> skip */
    Mka_SetEnable(0, TRUE);
    Mka_LinkStateChange(0, ETHTRCV_LINK_STATE_ACTIVE);

    /* RxIndication to a found PAE that is not started, then disabled. The frame
     * must be skipped, not processed: PAE 1 is enabled with no active link, so
     * it sits at WAITING_PEER_LINK and the not-started RxIndication leaves it
     * there; only the subsequent SetEnable(FALSE) moves it to UNDEFINED (which
     * proves the disable, not the RxIndication, changed the state). */
    {
        Mka_PaeStatusType st;
        CHECK(Mka_GetPaeStatus(1, &st) == E_OK &&
                  st.MkaStatus == MKA_STATUS_WAITING_PEER_LINK,
            "PAE 1 awaits link before skipped RxIndication");
        Mka_RxIndication(61, &pdu); /* PAE 1 not started -> skip */
        CHECK(Mka_GetPaeStatus(1, &st) == E_OK &&
                  st.MkaStatus == MKA_STATUS_WAITING_PEER_LINK,
            "not-started RxIndication left PAE 1 unchanged");
        Mka_SetEnable(1, FALSE);
        Mka_RxIndication(61, &pdu); /* PAE 1 disabled -> skip */
        CHECK(Mka_GetPaeStatus(1, &st) == E_OK &&
                  st.MkaStatus == MKA_STATUS_UNDEFINED,
            "disabled RxIndication left PAE 1 inert");
    }

    /* SetCknStatus with Enable == FALSE on a started PAE tears the participant
     * down; the stored enable flag flips to FALSE (proving the teardown branch
     * ran, not just that the call returned E_OK). */
    CHECK(Mka_SetCknStatus(0, FALSE, g_ckn, 8) == E_OK, "ckn disable running");
    {
        boolean en = TRUE;
        CHECK(Mka_GetCknStatus(0, g_ckn, 8, &en) == E_OK && en == FALSE,
            "disabled CKN flag cleared");
    }
}

static int queue_depth(void)
{
    return (g_qtail - g_qhead + 16) % 16;
}

/* Run one isolated PAE (no peer, so it never establishes and keeps retrying)
 * for `ticks` 100 ms cycles, never routing the frames back. Returns the number
 * of MKPDUs transmitted; *first_len gets the first frame's length (0 if none).
 */
static int run_solo(Mka_PaeConfigType* pae, int ticks, uint16* first_len)
{
    Mka_ConfigType cfg;
    int i;
    int n = 0;

    *first_len = 0;
    queue_reset();
    cfg.Paes = pae;
    cfg.PaeCount = 1;
    cfg.MainFunctionPeriodMs = 100U;
    Mka_Init(&cfg);
    Mka_SetEnable(0, TRUE);
    Mka_LinkStateChange(0, ETHTRCV_LINK_STATE_ACTIVE);
    Mka_StartPae(0);
    for (i = 0; i < ticks; i++) {
        Mka_MainFunction();
        while (queue_depth() > 0) {
            if (n == 0) {
                *first_len = g_queue[g_qhead].len;
            }
            n++;
            g_qhead = (g_qhead + 1) % 16;
        }
    }
    return n;
}

/* The retry back-off (CP_SWS_Mka_00012) and cipher-suite Announcement
 * (CP_SWS_Mka_00009) are exposed through Mka_PaeConfigType; prove both reach
 * the core engine. */
static void phase_retry_announce(void)
{
    Mka_CknConfigType ckn = {g_cak, 16, g_ckn, 8, TRUE};
    Mka_PaeConfigType pae;
    uint16 len_cfg = 0;
    uint16 len_plain = 0;
    int tx_cfg;
    int tx_plain;

    printf("AUTOSAR retry back-off + announcement plumbing:\n");

    fill_pae(&pae, &ckn, 1, 60, 61, 0x20, MKA_ROLE_KEY_SERVER, test_transmit,
        16);
#ifndef WOLFMKA_NO_RETRY
    pae.RetryBaseMs = 200U;
    pae.RetryCyclicMs = 2000U;
#endif
#ifndef WOLFMKA_NO_ANNOUNCEMENTS
    pae.AnnounceCipherSuites = TRUE;
#endif
    tx_cfg = run_solo(&pae, 20, &len_cfg); /* 2000 ms window */

    /* Control: defaults (no retry, no announcement). */
    fill_pae(&pae, &ckn, 1, 60, 61, 0x20, MKA_ROLE_KEY_SERVER, test_transmit,
        16);
    tx_plain = run_solo(&pae, 19, &len_plain); /* 1900 ms < Hello Time */

    CHECK(tx_plain == 1, "no retry: a single transmit within the Hello Time");
#ifndef WOLFMKA_NO_RETRY
    CHECK(tx_cfg >= 3, "RetryBaseMs drives multiple pre-peer retransmits");
#else
    (void)tx_cfg;
#endif
#ifndef WOLFMKA_NO_ANNOUNCEMENTS
    CHECK((len_cfg > len_plain) && (len_plain > 0U),
        "AnnounceCipherSuites adds a parameter set to the MKPDU");
#else
    (void)len_cfg;
    (void)len_plain;
#endif
}

/* A lone Key Server never agrees a SAK, so it stays unsecured: NEVER mode keeps
 * the port blocked even long past the permissive timeout; switching to TIMEOUT
 * reports plaintext-permitted once PermissiveTimeoutMs of unsecured time
 * elapses; losing activity (disable) resets that timer. */
static void permissive_lone_ks(void)
{
    Mka_CknConfigType ckn = {g_cak, 16, g_ckn, 8, TRUE};
    Mka_PaeConfigType pae;
    Mka_ConfigType cfg;
    Mka_PaeStatusType st;
    int i;

    fill_pae(&pae, &ckn, 1, 70, 71, 0x30, MKA_ROLE_KEY_SERVER, test_transmit,
        16);
    pae.PermissiveTimeoutMs = 300U;
    cfg.Paes = &pae;
    cfg.PaeCount = 1;
    cfg.MainFunctionPeriodMs = 100U;
    Mka_Init(&cfg);
    Mka_SetEnable(0, TRUE);
    Mka_LinkStateChange(0, ETHTRCV_LINK_STATE_ACTIVE);
    Mka_StartPae(0);

    /* NEVER (the default) never opens, even long past the timeout. */
    for (i = 0; i < 8; i++) {
        Mka_MainFunction();
    }
    CHECK(Mka_GetPaeStatus(0, &st) == E_OK && st.PermissivePlaintext == FALSE,
        "NEVER: stays blocked past the timeout");

    /* TIMEOUT opens once the unsecured time reaches PermissiveTimeoutMs. */
    Mka_SetPaePermissiveMode(0, MKA_PERMISSIVE_MODE_TIMEOUT);
    Mka_MainFunction();
    CHECK(Mka_GetPaeStatus(0, &st) == E_OK && st.PermissivePlaintext == TRUE,
        "TIMEOUT: opens after the unsecured timeout");

    /* Losing activity (disable) clears the permissive timer. */
    Mka_SetEnable(0, FALSE);
    Mka_MainFunction();
    Mka_SetEnable(0, TRUE);
    Mka_MainFunction();
    CHECK(Mka_GetPaeStatus(0, &st) == E_OK && st.PermissivePlaintext == FALSE,
        "disable resets the unsecured timer");
}

/* Establishing MACsec clears permissive plaintext even in TIMEOUT mode: two
 * PAEs that agree a SAK report MACSEC_RUNNING with PermissivePlaintext clear.
 */
static void permissive_secured_clears(void)
{
    Mka_CknConfigType ckn = {g_cak, 16, g_ckn, 8, TRUE};
    Mka_CknConfigType ckn_b = {g_cak, 16, g_ckn, 8, TRUE};
    Mka_PaeConfigType paes[2];
    Mka_ConfigType cfg;
    Mka_PaeStatusType st;

    queue_reset();
    fill_pae(&paes[0], &ckn, 1, 72, 73, 0x31, MKA_ROLE_KEY_SERVER,
        test_transmit, 16);
    fill_pae(&paes[1], &ckn_b, 1, 73, 72, 0x32, MKA_ROLE_PEER, test_transmit,
        16);
    paes[0].PermissiveTimeoutMs = 1U;
    paes[1].PermissiveTimeoutMs = 1U;
    cfg.Paes = paes;
    cfg.PaeCount = 2;
    cfg.MainFunctionPeriodMs = MKA_HELLO_TIME_MS;
    Mka_Init(&cfg);
    Mka_SetEnable(0, TRUE);
    Mka_SetEnable(1, TRUE);
    Mka_LinkStateChange(0, ETHTRCV_LINK_STATE_ACTIVE);
    Mka_LinkStateChange(1, ETHTRCV_LINK_STATE_ACTIVE);
    Mka_SetPaePermissiveMode(0, MKA_PERMISSIVE_MODE_TIMEOUT);
    Mka_StartPae(0);
    Mka_StartPae(1);
    run_cycles(16);
    CHECK(Mka_GetPaeStatus(0, &st) == E_OK &&
              st.MkaStatus == MKA_STATUS_MACSEC_RUNNING &&
              st.PermissivePlaintext == FALSE,
        "secured: permissive plaintext stays clear");
}

/* Permissive mode (8.2.9): the lone-Key-Server timer behaviour, then that a
 * successfully established SAK keeps the port clear. */
static void phase_permissive(void)
{
    printf("permissive mode timeout:\n");
    permissive_lone_ks();
    permissive_secured_clears();
}

/* --- async SecY through the AUTOSAR notification path (FM-19) --- */
static int g_async_tx_enabled;
static int g_async_install_tx_calls;
static int g_async_enable_count; /* number of transmit-enable events */

static int async_install_tx(void* c, const uint8_t* sci, uint8_t an,
    uint32_t kn, const uint8_t* sak, size_t len)
{
    (void)c;
    (void)sci;
    (void)an;
    (void)kn;
    (void)sak;
    (void)len;
    g_async_install_tx_calls++;
    /* Accept now; completion arrives via Mka_MacSecAddTxSaNotification. */
    return MKA_SECY_PENDING;
}

static int async_enable_tx(void* c, uint8_t an, bool en)
{
    (void)c;
    (void)an;
    if (en != 0) {
        g_async_enable_count++;
    }
    g_async_tx_enabled = en;
    return 0;
}

static MkaSecyOps make_async_secy(void)
{
    MkaSecyOps ops;
    memset(&ops, 0, sizeof ops);
    ops.install_tx_sa = async_install_tx;
    ops.enable_transmit = async_enable_tx;
    return ops;
}

/* A MacSec module that programs the transmit SA asynchronously returns
 * MKA_SECY_PENDING; the KaY holds the transmit gate until
 * Mka_MacSecAddTxSaNotification reports completion, which Mka_PaeSecyComplete
 * routes to the single participant with an operation outstanding (FM-19). */
static void phase_async_secy(void)
{
    Mka_CknConfigType ckn_a = {g_cak, 16, g_ckn, 8, TRUE};
    Mka_CknConfigType ckn_b = {g_cak, 16, g_ckn, 8, TRUE};
    Mka_PaeConfigType paes[2];
    Mka_ConfigType cfg;
    Mka_PaeStatusType st;

    printf("async SecY: transmit gated until AddTxSa notification:\n");
    g_async_tx_enabled = 0;
    g_async_install_tx_calls = 0;
    queue_reset();
    fill_pae(&paes[0], &ckn_a, 1, 24, 25, 0x0A, MKA_ROLE_KEY_SERVER,
        test_transmit, 16);
    fill_pae(&paes[1], &ckn_b, 1, 25, 24, 0x0B, MKA_ROLE_PEER, test_transmit,
        16);
    paes[0].Secy = make_async_secy(); /* the Key Server's data plane is async */
    cfg.Paes = paes;
    cfg.PaeCount = 2;
    cfg.MainFunctionPeriodMs = MKA_HELLO_TIME_MS;
    Mka_Init(&cfg);
    Mka_SetEnable(0, TRUE);
    Mka_SetEnable(1, TRUE);
    Mka_LinkStateChange(0, ETHTRCV_LINK_STATE_ACTIVE);
    Mka_LinkStateChange(1, ETHTRCV_LINK_STATE_ACTIVE);
    Mka_StartPae(0);
    Mka_StartPae(1);
    run_cycles(16);

    /* SAK agreed (MACsec running), but the asynchronous tx-SA install is still
     * outstanding, so transmit protection has not been enabled. */
    CHECK(Mka_GetPaeStatus(0, &st) == E_OK &&
              st.MkaStatus == MKA_STATUS_MACSEC_RUNNING,
        "KS reached MACSEC_RUNNING");
    CHECK(g_async_install_tx_calls > 0, "async install_tx_sa was called");
    CHECK(g_async_tx_enabled == 0,
        "transmit gated while tx-SA install pending");

    /* The MacSec module reports the add-Tx-SA complete: the adapter routes the
     * completion to the keying participant and the transmit gate releases. */
    Mka_MacSecAddTxSaNotification(0, E_OK);
    CHECK(g_async_tx_enabled != 0,
        "transmit enabled after AddTxSa notification");
}

/* Completion granularity (FM-19): a PAE carrying two keying CKNs has two
 * participants, each with an outstanding tx-SA install. One AddTxSa
 * notification acknowledges ONE SA operation, so it must release the transmit
 * gate of exactly one participant - not both - which a second notification then
 * releases. (The earlier defect forwarded each notification to every
 * participant, releasing both gates at once.) */
static void phase_async_secy_multi(void)
{
    static const uint8 ckn2[8] = {'a', 'u', 't', 'o', '-', 'c', 'k', '2'};
    Mka_CknConfigType ckns_a[2] = {{g_cak, 16, g_ckn, 8, TRUE},
        {g_cak, 16, ckn2, 8, TRUE}};
    Mka_CknConfigType ckns_b[2] = {{g_cak, 16, g_ckn, 8, TRUE},
        {g_cak, 16, ckn2, 8, TRUE}};
    Mka_PaeConfigType paes[2];
    Mka_ConfigType cfg;

    printf("async SecY granularity: one notification releases one CKN:\n");
    g_async_tx_enabled = 0;
    g_async_install_tx_calls = 0;
    g_async_enable_count = 0;
    queue_reset();
    fill_pae(&paes[0], ckns_a, 2, 26, 27, 0x0A, MKA_ROLE_KEY_SERVER,
        test_transmit, 16);
    fill_pae(&paes[1], ckns_b, 2, 27, 26, 0x0B, MKA_ROLE_PEER, test_transmit,
        16);
    paes[0].Secy = make_async_secy(); /* the Key Server's data plane is async */
    cfg.Paes = paes;
    cfg.PaeCount = 2;
    cfg.MainFunctionPeriodMs = MKA_HELLO_TIME_MS;
    Mka_Init(&cfg);
    Mka_SetEnable(0, TRUE);
    Mka_SetEnable(1, TRUE);
    Mka_LinkStateChange(0, ETHTRCV_LINK_STATE_ACTIVE);
    Mka_LinkStateChange(1, ETHTRCV_LINK_STATE_ACTIVE);
    Mka_StartPae(0);
    Mka_StartPae(1);
    run_cycles(20);

    /* Both CKNs agreed a SAK and both tx-SA installs are pending, so neither
     * participant has enabled transmit. */
    CHECK(g_async_install_tx_calls >= 2, "both CKNs installed a tx SA");
    CHECK(g_async_enable_count == 0, "both CKNs gated while installs pending");

    /* One notification releases exactly one CKN's gate. */
    Mka_MacSecAddTxSaNotification(0, E_OK);
    CHECK(g_async_enable_count == 1,
        "one notification enables exactly one CKN");

    /* The second notification releases the other. */
    Mka_MacSecAddTxSaNotification(0, E_OK);
    CHECK(g_async_enable_count == 2,
        "second notification enables the other CKN");
}

int main(void)
{
    printf("\n== autosar Mka ==\n");
    phase_pre_init();
    phase_args();
    phase_status();
    phase_auth_fail();
    phase_in_progress();
    phase_failures();
    phase_ckn_bound_and_async();
    phase_partial_states();
    phase_retry_announce();
    phase_permissive();
    phase_async_secy();
    phase_async_secy_multi();

    printf("\n------------------\n");
    printf("checks: %d, failures: %d => %s\n", g_tests_run, g_tests_failed,
        (g_tests_failed == 0) ? "PASS" : "FAIL");
    return (g_tests_failed == 0) ? 0 : 1;
}
