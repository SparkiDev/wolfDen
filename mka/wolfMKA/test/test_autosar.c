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
 * Exercises the AUTOSAR Mka API (Mka.h) over wolfMKA. `make coverage-autosar`
 * enforces 100% line, decision and MC/DC coverage of src/autosar/Mka.c from
 * this suite - the claim is measured and gated, not asserted here. The Mka
 * module is a singleton, so the test re-initialises it between phases:
 *
 *   A  an exhausted crypto-workspace pool at init, then pre-init rejection and
 *      the void notification / no-op entry points
 *   B  argument validation and the simple setters/getters
 *   C  status transitions: UNDEFINED -> WAITING_PEER_LINK -> WAITING_PEER ->
 *      MACSEC_RUNNING, plus IN_PROGRESS (two peers, no Key Server), and
 *      AUTH_FAIL_UNKNOWN_PEER
 *   D  send-bridge failure paths, the StartPae add-participant failure, and a
 *      PAE that ends up with no runnable CA
 *   E  the CKN bound, the SetCknStatus running-add path and async statistics
 *   F  configuration bounds refused at Mka_Init/Mka_StartPae (oversized
 *      CAK/CKN, a PaeCount beyond the static array, a NULL Ckns array) and
 *      partially-configured PAEs
 *   G  the retry back-off and cipher-suite Announcement config, permissive
 *      mode (8.2.9) including the re-init teardown and mode-switch retraction
 *   H  asynchronous SecY: transmit gated until Mka_MacSecAddTxSaNotification,
 *      and per-notification completion granularity across two keying CKNs
 *   I  a Connectivity Association failing inside Mka_MainFunction
 *      (fault-injection builds only)
 *   J  development-error reporting: the exact (service ID, error ID) pair for
 *      every rejection (MKA_DEV_ERROR_DETECT == STD_ON builds only)
 *
 * Phase A runs first, and must: each workspace is acquired once and never
 * released, so the pool-exhaustion paths close for good after the first
 * successful Mka_Init.
 */
#include "test_util.h"
#include "wolfmka/autosar/Mka.h"
#include "wolfmka/mka_crypto.h"

#ifdef WOLFMKA_FAULT_INJECT
    /* Lets this suite drive a wolfSSL failure, which is the only way to make a
     * Connectivity Association fail inside Mka_MainFunction. Coverage builds
     * define WOLFMKA_FAULT_INJECT; the delivered ones do not, and MKA_FI is
     * then a no-op. */
    #include "fault_impl.h"
#endif

#if (MKA_DEV_ERROR_DETECT == STD_ON)
/* ---- captured Det reports (see test/Det.h) ---- */
typedef struct {
    uint8 api;
    uint8 err;
} DetRec;

static DetRec g_det[32];
static size_t g_det_n;
static uint16 g_det_module = 0xFFFFU;
static uint8 g_det_instance = 0xFFU;

Std_ReturnType Det_ReportError(uint16 ModuleId, uint8 InstanceId, uint8 ApiId,
    uint8 ErrorId)
{
    /* Recorded rather than asserted here: this runs on every reported error in
     * the whole suite, and a CHECK per call would bury the count. phase_det
     * asserts the identification once. */
    g_det_module = ModuleId;
    g_det_instance = InstanceId;
    if (g_det_n < (sizeof g_det / sizeof g_det[0])) {
        g_det[g_det_n].api = ApiId;
        g_det[g_det_n].err = ErrorId;
        g_det_n++;
    }
    return E_OK;
}

static void det_reset(void)
{
    g_det_n = 0U;
}

/* Whether exactly one report was made, naming this API and this error. */
static int det_is(uint8 api, uint8 err)
{
    return (g_det_n == 1U) && (g_det[0].api == api) && (g_det[0].err == err);
}
#endif /* MKA_DEV_ERROR_DETECT */

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

    /* Scheduled / callback entry points tolerate the un-initialised module. The
     * main function is called twice: it reports the condition once and is
     * silent thereafter, so both halves of that need driving. */
    Mka_MainFunction();
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

/* ------------------------------------------------------------------ */
/* Must run before anything else: Mka_Init acquires the shared CMAC workspace on
 * first use and holds it for the life of the module (there is no Mka_DeInit),
 * so the "pool exhausted" path is only reachable while that static is still
 * NULL. The same applies to the RNG workspace, exercised second. An undersized
 * WOLFMKA_CMAC_POOL_SIZE or WOLFMKA_RANDOM_POOL_SIZE is a real integration
 * mistake, and the module must fail closed on it rather than come up without
 * the workspace. */
static void phase_cmac_pool_exhausted(void)
{
    Mka_CknConfigType ckn = {g_cak, 16, g_ckn, 8, TRUE};
    Mka_PaeConfigType pae;
    Mka_ConfigType cfg;
    Mka_PaeStatusType st;
    MkaCmacCtx* hog[16];
    size_t n = 0U;

    printf("CMAC pool exhausted at init:\n");
    while (n < (sizeof hog / sizeof hog[0])) {
        MkaCmacCtx* c = wm_Crypto_CmacInit();
        if (c == NULL) {
            break;
        }
        hog[n] = c;
        n++;
    }
    CHECK(n > 0U, "the pool had workspaces to take");
    CHECK(wm_Crypto_CmacInit() == NULL, "and is now empty");

    fill_pae(&pae, &ckn, 1, 10, 11, 0x01, MKA_ROLE_KEY_SERVER, test_transmit,
        16);
    cfg.Paes = &pae;
    cfg.PaeCount = 1;
    cfg.MainFunctionPeriodMs = 100;
    Mka_Init(&cfg);
    CHECK(Mka_GetPaeStatus(0, &st) == E_NOT_OK,
        "with no CMAC workspace the module stays uninitialised");

    while (n > 0U) {
        n--;
        wm_Crypto_CmacFree(hog[n]);
    }

    /* The same for the RNG. It is required for the same reason - wolfSSL's
     * WC_RNG never lives on wolfMKA's stack or heap either - so an undersized
     * WOLFMKA_RANDOM_POOL_SIZE, or a seeding failure, must also leave the
     * module down rather than up-but-unable-to-create-a-participant. Taken
     * after the CMAC block above, so the CMAC workspace is available and this
     * is the only thing missing. */
    {
        MkaRandom* rhog[16];
        size_t r = 0U;

        printf("RNG pool exhausted at init:\n");
        while (r < (sizeof rhog / sizeof rhog[0])) {
            MkaRandom* q = wm_Crypto_RandomInit();
            if (q == NULL) {
                break;
            }
            rhog[r] = q;
            r++;
        }
        CHECK(r > 0U, "the RNG pool had objects to take");
        CHECK(wm_Crypto_RandomInit() == NULL, "and is now empty");

        Mka_Init(&cfg);
        CHECK(Mka_GetPaeStatus(0, &st) == E_NOT_OK,
            "with no RNG workspace the module stays uninitialised too");

        while (r > 0U) {
            r--;
            wm_Crypto_RandomFree(rhog[r]);
        }
    }
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
    ic.rng = wm_Crypto_RandomInit();
    CHECK(ic.rng != NULL, "intruder rng");
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

    /* The status now comes from the KaY's own ladder, which reports the
     * authentication failure while no MKPDU has ever verified - so a link
     * transition on its own does not clear it. Nothing about a link bounce
     * fixes a CAK mismatch; the first MKPDU that authenticates does, and until
     * then AUTH_FAIL is the more accurate answer than WAITING_PEER. */
    Mka_LinkStateChange(0, ETHTRCV_LINK_STATE_ACTIVE);
    CHECK(Mka_GetPaeStatus(0, &st) == E_OK &&
              st.MkaStatus == MKA_STATUS_AUTH_FAIL_UNKNOWN_PEER,
        "a link change alone does not clear AUTH_FAIL");

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
    /* One CKN that instantiates and one that cannot: an over-long CAK is
     * rejected by mka_add_ckn before anything is copied. */
    static const uint8 ckn_b[8] = {'s', 'e', 'c', 'o', 'n', 'd', '-', 'b'};
    Mka_CknConfigType cknMixed[2] = {{g_cak, 16, g_ckn, 8, TRUE},
        {g_cak, (uint8)(MKA_MAX_CAK_LEN + 1U), ckn_b, 8, TRUE}};
    Mka_PaeConfigType paes[4];
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
    /* A real timeout, so the permissive latch below is actually reachable: with
     * PermissiveTimeoutMs left at zero the port fails closed whatever `started`
     * says, and the check would prove nothing. */
    paes[2].PermissiveTimeoutMs = 4000U;
    /* PAE 3 runs one of its two CKNs. */
    fill_pae(&paes[3], cknMixed, 2, 45, 46, 0x12, MKA_ROLE_KEY_SERVER,
        test_transmit, 16);
    cfg.Paes = paes;
    cfg.PaeCount = 4;
    cfg.MainFunctionPeriodMs = MKA_HELLO_TIME_MS;
    Mka_Init(&cfg);
    Mka_SetEnable(0, TRUE);
    Mka_SetEnable(1, TRUE);
    Mka_SetEnable(2, TRUE);
    Mka_LinkStateChange(0, ETHTRCV_LINK_STATE_ACTIVE);
    Mka_LinkStateChange(1, ETHTRCV_LINK_STATE_ACTIVE);
    Mka_LinkStateChange(2, ETHTRCV_LINK_STATE_ACTIVE);
    Mka_SetEnable(3, TRUE);
    Mka_LinkStateChange(3, ETHTRCV_LINK_STATE_ACTIVE);

    CHECK(Mka_StartPae(0) == E_OK, "start (null transmit)");
    CHECK(Mka_StartPae(1) == E_OK, "start (failing transmit)");
    CHECK(Mka_StartPae(2) == E_NOT_OK, "start fails (bad SAK length)");
    CHECK(Mka_StartPae(3) == E_NOT_OK, "start reports the one CKN that failed");

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

    /* PAE 2's only CKN could not be instantiated, so the PAE has no CA to run.
     * It must not count as started: an "active" PAE with no SAK accumulates
     * unsecured time and, under MKA_PERMISSIVE_MODE_TIMEOUT, latches the
     * controlled port open in plaintext - opening the port on a configuration
     * fault rather than on a peer that could not be reached. */
    {
        Mka_PaeStatusType st;
        boolean en = FALSE;

        CHECK(Mka_SetPaePermissiveMode(2, MKA_PERMISSIVE_MODE_TIMEOUT) == E_OK,
            "PAE 2 is put into permissive timeout mode");
        run_cycles(10);
        CHECK(Mka_GetPaeStatus(2, &st) == E_OK, "PAE 2 status readable");
        CHECK(st.PermissivePlaintext == FALSE,
            "a PAE with no runnable CA never opens the port in plaintext");

        /* And its CKN does not report itself enabled: the enable flag is the
         * request, kept so Mka_StartPae can be retried, but the status has to
         * answer for what is running. PAE 0, whose add succeeded, still does
         * report enabled. */
        /* PAE 3 did start - one of its two CKNs is running - so its CKN
         * status has to answer for each of them separately. Mka_StartPae
         * leaves both enable flags set so it can be retried, which is exactly
         * why the status cannot be read off those flags. */
        CHECK(Mka_GetCknStatus(3, g_ckn, 8, &en) == E_OK, "CKN status read");
        CHECK(en == TRUE, "the CKN that instantiated reads enabled");
        CHECK(Mka_GetCknStatus(3, ckn_b, 8, &en) == E_OK, "CKN status read");
        CHECK(en == FALSE, "the one whose add failed does not");
        CHECK(Mka_GetCknStatus(0, g_ckn, 8, &en) == E_OK, "CKN status read");
        CHECK(en == TRUE, "and a plain running CKN reads enabled");
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
    /* Five CKNs against MKA_MAX_PARTICIPANTS of four: the surplus one cannot be
     * instantiated, and that is reported rather than silently skipped. The four
     * within the bound still run - a port serving some of its CAs beats one
     * serving none. */
    CHECK(Mka_StartPae(0) == E_NOT_OK,
        "a CknCount beyond the build's bound is reported, not truncated");

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
/* The two configuration guards no functional phase reaches: an oversized
 * CAK/CKN in a Mka_CknConfigType, and a PaeCount larger than the static PAE
 * array. Both are rejections of a generated configuration, which is exactly the
 * kind of thing no happy path exercises. Plus the re-initialisation contract:
 * Mka_Init over a running module must leave nothing of the old one behind. */
/* A data plane that exposes its 802.1AE counters. Without one,
 * Mka_GetMacSecStatistics can only ever hand back zeros. */
static int g_stats_overflow;

static int bounds_get_secy_stats(void* c, MkaSecyStats* out)
{
    (void)c;
    memset(out, 0, sizeof *out);
    out->in_pkts_untagged = 11U;
    out->in_pkts_no_tag = 22U;
    out->in_pkts_bad_tag = 33U;
    out->in_pkts_overrun = 44U;
    out->out_pkts_untagged = 55U;
    out->out_pkts_too_long = 66U;
    if (g_stats_overflow != 0) {
        /* Past what a uint32 can hold, so the narrowing into
         * Mka_Stats_SecYType is exercised in its saturating direction. */
        out->in_pkts_untagged = (uint64_t)0x1234567890ULL;
        out->out_pkts_too_long = (uint64_t)0x100000000ULL;
    }
    return 0;
}

static void phase_config_bounds(void)
{
    static const uint8 big_cak[MKA_MAX_CAK_LEN + 1] = {0};
    static const uint8 big_ckn[MKA_MAX_CKN_LEN + 1] = {0};
    Mka_CknConfigType ckn_ok = {g_cak, 16, g_ckn, 8, TRUE};
    Mka_CknConfigType ckn_big_cak = {big_cak, MKA_MAX_CAK_LEN + 1U, g_ckn, 8,
        TRUE};
    Mka_CknConfigType ckn_big_ckn = {g_cak, 16, big_ckn, MKA_MAX_CKN_LEN + 1U,
        TRUE};
    Mka_PaeConfigType pae;
    Mka_PaeConfigType paes[MKA_MAX_PAES + 1U];
    Mka_ConfigType cfg;
    Mka_PaeStatusType st;
    uint8 i;

    printf("configuration bounds and re-initialisation:\n");
    queue_reset();

    /* An oversized CAK is refused when the participant is instantiated, so the
     * PAE starts with no participant at all. wm_Participant_Init would reject
     * the length too, so this pins the guard's branch rather than an outcome
     * only it can produce - the point of checking in mka_add_ckn is that it
     * happens before the copy into the fixed-size pc.cak.cak, which would
     * otherwise overrun into its neighbouring fields. */
    fill_pae(&pae, &ckn_big_cak, 1, 60, 61, 0x40, MKA_ROLE_KEY_SERVER,
        test_transmit, 16);
    cfg.Paes = &pae;
    cfg.PaeCount = 1;
    cfg.MainFunctionPeriodMs = 100;
    Mka_Init(&cfg);
    Mka_SetEnable(0, TRUE);
    Mka_LinkStateChange(0, ETHTRCV_LINK_STATE_ACTIVE);
    CHECK(Mka_StartPae(0) == E_NOT_OK, "an oversized CAK is refused");

    /* And an oversized CKN, on the same guard. */
    fill_pae(&pae, &ckn_big_ckn, 1, 60, 61, 0x41, MKA_ROLE_KEY_SERVER,
        test_transmit, 16);
    Mka_Init(&cfg);
    Mka_SetEnable(0, TRUE);
    Mka_LinkStateChange(0, ETHTRCV_LINK_STATE_ACTIVE);
    CHECK(Mka_StartPae(0) == E_NOT_OK, "an oversized CKN is refused");

    /* A PaeCount beyond the static array is refused outright, not clamped:
     * clamping left the ECU looking healthy while controlled ports the
     * configuration says are protected silently never ran MKA. */
    for (i = 0U; i < (uint8)(MKA_MAX_PAES + 1U); i++) {
        fill_pae(&paes[i], &ckn_ok, 1, (PduIdType)(80U + i),
            (PduIdType)(90U + i), (uint8)(0x50U + i), MKA_ROLE_KEY_SERVER,
            test_transmit, 16);
    }
    cfg.Paes = paes;
    cfg.PaeCount = (uint8)(MKA_MAX_PAES + 1U);
    Mka_Init(&cfg);
    CHECK(Mka_GetPaeStatus(0, &st) == E_NOT_OK,
        "an over-large PaeCount leaves the module uninitialised");
    /* Exactly the bound is fine. */
    cfg.PaeCount = (uint8)MKA_MAX_PAES;
    Mka_Init(&cfg);
    CHECK(Mka_GetPaeStatus((uint8)(MKA_MAX_PAES - 1U), &st) == E_OK,
        "a PaeCount of exactly MKA_MAX_PAES is accepted");
    CHECK(Mka_GetPaeStatus((uint8)MKA_MAX_PAES, &st) == E_NOT_OK,
        "and nothing beyond it exists");
    cfg.PaeCount = 1;

    /* A CKN entry whose Cak or Ckn pointer is NULL is refused rather than
     * dereferenced: the pointer and its length are separate fields, so a
     * generator can emit a length with no array. */
    {
        Mka_CknConfigType ckn_null_cak = {NULL, 16, g_ckn, 8, TRUE};
        Mka_CknConfigType ckn_null_ckn = {g_cak, 16, NULL, 8, TRUE};

        fill_pae(&pae, &ckn_null_cak, 1, 60, 61, 0x48, MKA_ROLE_KEY_SERVER,
            test_transmit, 16);
        cfg.Paes = &pae;
        cfg.PaeCount = 1;
        Mka_Init(&cfg);
        Mka_SetEnable(0, TRUE);
        Mka_LinkStateChange(0, ETHTRCV_LINK_STATE_ACTIVE);
        CHECK(Mka_StartPae(0) == E_NOT_OK, "a NULL CAK pointer is refused");

        fill_pae(&pae, &ckn_null_ckn, 1, 60, 61, 0x49, MKA_ROLE_KEY_SERVER,
            test_transmit, 16);
        Mka_Init(&cfg);
        Mka_SetEnable(0, TRUE);
        Mka_LinkStateChange(0, ETHTRCV_LINK_STATE_ACTIVE);
        CHECK(Mka_StartPae(0) == E_NOT_OK, "and so is a NULL CKN pointer");
    }

    /* A zero main-function period would pin the KaY's clock, so it is refused
     * outright - the module stays uninitialised rather than coming up dead. */
    cfg.Paes = &pae;
    cfg.PaeCount = 1;
    fill_pae(&pae, &ckn_ok, 1, 60, 61, 0x43, MKA_ROLE_KEY_SERVER, test_transmit,
        16);
    cfg.MainFunctionPeriodMs = 0;
    Mka_Init(&cfg);
    CHECK(Mka_GetPaeStatus(0, &st) == E_NOT_OK,
        "a zero main-function period leaves the module uninitialised");
    cfg.MainFunctionPeriodMs = 100;

    /* Re-initialising a running module discards its state: the PAE that was
     * enabled, started and linked comes back disabled and unstarted. */
    cfg.Paes = &pae;
    cfg.PaeCount = 1;
    fill_pae(&pae, &ckn_ok, 1, 60, 61, 0x42, MKA_ROLE_KEY_SERVER, test_transmit,
        16);
    Mka_Init(&cfg);
    Mka_SetEnable(0, TRUE);
    Mka_LinkStateChange(0, ETHTRCV_LINK_STATE_ACTIVE);
    CHECK(Mka_StartPae(0) == E_OK, "start before re-init");
    Mka_Init(&cfg);
    {
        boolean en = TRUE;
        CHECK(Mka_GetEnable(0, &en) == E_OK && en == FALSE,
            "re-init cleared the enable");
    }
    CHECK(Mka_GetPaeStatus(0, &st) == E_OK &&
              st.ConnectionStatus == ETHTRCV_LINK_STATE_DOWN,
        "and its link state is back down");
    CHECK(Mka_GetPaeStatus(1, &st) == E_NOT_OK,
        "the surplus PAEs from the wider config are gone");

    /* A PaeCount without a Paes array would be dereferenced; the configuration
     * is refused rather than trusted. */
    cfg.Paes = NULL;
    cfg.PaeCount = 1;
    Mka_Init(&cfg);
    CHECK(Mka_GetPaeStatus(0, &st) == E_NOT_OK,
        "a PaeCount with no Paes array leaves the module uninitialised");

    /* A PAE that declares CKNs but supplies no array contributes none, rather
     * than walking a NULL pointer. */
    fill_pae(&pae, NULL, 3, 60, 61, 0x44, MKA_ROLE_KEY_SERVER, test_transmit,
        16);
    cfg.Paes = &pae;
    cfg.PaeCount = 1;
    Mka_Init(&cfg);
    Mka_SetEnable(0, TRUE);
    Mka_LinkStateChange(0, ETHTRCV_LINK_STATE_ACTIVE);
    CHECK(Mka_StartPae(0) == E_OK, "a PAE with no CKN array still starts");
    CHECK(Mka_GetPaeStatus(0, &st) == E_OK &&
              st.MkaStatus == MKA_STATUS_WAITING_PEER,
        "and simply has no participant to run");
    /* ...and the CKN lookups agree it has none, rather than walking the NULL
     * array behind a non-zero CknCount. Mka_Init accepts this configuration, so
     * every reader has to survive it: before the fix these two segfaulted. */
    {
        boolean cs = TRUE;
        CHECK(Mka_GetCknStatus(0, g_ckn, 8, &cs) == E_NOT_OK,
            "a CKN lookup on a NULL Ckns array finds nothing");
        CHECK(Mka_SetCknStatus(0, TRUE, g_ckn, 8) == E_NOT_OK,
            "and so does enabling one");
    }

    /* MKA_PERMISSIVE_MODE_TIMEOUT with a zero timeout is an unset timeout, not
     * an instruction to run plaintext from the first tick. */
    fill_pae(&pae, &ckn_ok, 1, 60, 61, 0x45, MKA_ROLE_KEY_SERVER, test_transmit,
        16);
    pae.PermissiveTimeoutMs = 0U;
    Mka_Init(&cfg);
    Mka_SetEnable(0, TRUE);
    Mka_LinkStateChange(0, ETHTRCV_LINK_STATE_ACTIVE);
    Mka_StartPae(0);
    Mka_SetPaePermissiveMode(0, MKA_PERMISSIVE_MODE_TIMEOUT);
    for (i = 0U; i < 5U; i++) {
        Mka_MainFunction();
    }
    CHECK(Mka_GetPaeStatus(0, &st) == E_OK && st.PermissivePlaintext == FALSE,
        "a zero permissive timeout never opens the controlled port");

    /* Statistics come from the SecY when the data plane exposes them; without a
     * get_secy_stats hook the buffer could only ever be zeros. */
    {
        Mka_Stats_SecYType stats;

        fill_pae(&pae, &ckn_ok, 1, 60, 61, 0x46, MKA_ROLE_KEY_SERVER,
            test_transmit, 16);
        pae.Secy.get_secy_stats = bounds_get_secy_stats;
        Mka_Init(&cfg);
        Mka_SetEnable(0, TRUE);
        Mka_LinkStateChange(0, ETHTRCV_LINK_STATE_ACTIVE);
        CHECK(Mka_StartPae(0) == E_OK, "start the PAE with a counter source");
        memset(&stats, 0xFF, sizeof stats);
        CHECK(Mka_GetMacSecStatistics(0, &stats) == E_OK, "stats request");
        CHECK(stats.InPktsUntagged == 11U && stats.InPktsNoTag == 22U &&
                  stats.InPktsBadTag == 33U && stats.InPktsOverrun == 44U,
            "the receive counters come from the SecY");
        CHECK(stats.OutPktsUntagged == 55U && stats.OutPktsTooLong == 66U,
            "and so do the transmit ones");
        /* Answered synchronously, so the request is complete: no notification
         * is owed, and a second request must work rather than report busy
         * forever. */
        CHECK(Mka_GetMacSecStatistics(0, &stats) == E_OK,
            "a synchronous answer leaves nothing pending");
        CHECK(Mka_GetMacSecStatistics(0, &stats) == E_OK,
            "and keeps working, rather than wedging on a latch");

        /* A counter past 2^32 pegs rather than wrapping: 0xFFFFFFFF reads as
         * "at least this many", where a wrapped value reads as a wrong number
         * and the counter appears to run backwards. */
        g_stats_overflow = 1;
        memset(&stats, 0, sizeof stats);
        CHECK(Mka_GetMacSecStatistics(0, &stats) == E_OK, "stats request");
        CHECK(stats.InPktsUntagged == 0xFFFFFFFFU,
            "a 64-bit counter past 2^32 saturates");
        CHECK(stats.OutPktsTooLong == 0xFFFFFFFFU,
            "including one exactly at 2^32");
        CHECK(stats.InPktsNoTag == 22U,
            "while one that still fits is passed through");
        g_stats_overflow = 0;
    }

    /* A PaeCount of zero is a valid (if inert) configuration, not a rejected
     * one: the NULL-Paes guard only bites when PAEs are actually declared. */
    cfg.Paes = &pae;
    cfg.PaeCount = 0;
    Mka_Init(&cfg);
    CHECK(Mka_GetPaeStatus(0, &st) == E_NOT_OK, "a zero-PAE config has no PAE");
    CHECK(Mka_SetEnable(0, TRUE) == E_NOT_OK, "and nothing to enable");
    cfg.PaeCount = 1;

    /* Statistics on a PAE with no participant: nothing to read them from, so
     * the buffer stays as the SWS handshake left it rather than being filled
     * from a participant that does not exist. */
    {
        Mka_Stats_SecYType stats;

        fill_pae(&pae, NULL, 0, 60, 61, 0x47, MKA_ROLE_KEY_SERVER,
            test_transmit, 16);
        Mka_Init(&cfg);
        Mka_SetEnable(0, TRUE);
        Mka_LinkStateChange(0, ETHTRCV_LINK_STATE_ACTIVE);
        Mka_StartPae(0);
        memset(&stats, 0xFF, sizeof stats);
        CHECK(Mka_GetMacSecStatistics(0, &stats) == E_OK, "stats request");
        CHECK(stats.InPktsUntagged == 0U && stats.OutPktsTooLong == 0U,
            "with no participant the counters stay zeroed");
        Mka_GetMacSecStatisticsNotification(0, E_OK);
    }

    /* A permissive mode outside the enumeration is refused, not stored: with no
     * Det to report it, silently behaving as NEVER would hide the typo. */
    CHECK(Mka_SetPaePermissiveMode(0, MKA_PERMISSIVE_MODE_NEVER) == E_OK,
        "NEVER accepted");
    CHECK(Mka_SetPaePermissiveMode(0, MKA_PERMISSIVE_MODE_TIMEOUT) == E_OK,
        "TIMEOUT accepted");
    CHECK(Mka_SetPaePermissiveMode(0, (Mka_PermissiveModeType)7) == E_NOT_OK,
        "an unknown permissive mode is refused");

    /* Same for the other entry point taking an enumerated value. Storing an
     * unrecognised link state would at least fail closed, but the value is
     * handed straight back out as ConnectionStatus, so a typo'd constant would
     * round-trip through the module unflagged. */
    CHECK(Mka_LinkStateChange(0, ETHTRCV_LINK_STATE_DOWN) == E_OK,
        "both real link states are accepted");
    CHECK(Mka_LinkStateChange(0, ETHTRCV_LINK_STATE_ACTIVE) == E_OK,
        "in either direction");
    CHECK(Mka_LinkStateChange(0, (EthTrcv_LinkStateType)9) == E_NOT_OK,
        "and an unknown one is refused");
    {
        Mka_PaeStatusType st;
        CHECK(Mka_GetPaeStatus(0, &st) == E_OK, "status still readable");
        CHECK(st.ConnectionStatus == ETHTRCV_LINK_STATE_ACTIVE,
            "leaving the link state it was already holding untouched");
    }
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
    /* Disabling tore the PAE down, so re-enabling alone leaves it with no
     * participants; it has to be started again. The CKN-disable case below
     * needs one to tear down. */
    CHECK(Mka_StartPae(0) == E_OK, "re-start PAE 0 after the disable");

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
/* Switching away from TIMEOUT must retract a latch already set: any other mode
 * keeps the controlled port closed, so continuing to report plaintext as
 * permitted contradicts Mka.h 8.3.8 (skoll F: permissiveOpen never cleared). */
static void permissive_mode_switch_retracts(void)
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

    /* Latch it open: a lone Key Server never agrees a SAK, so it stays
     * unsecured past the timeout. */
    Mka_SetPaePermissiveMode(0, MKA_PERMISSIVE_MODE_TIMEOUT);
    for (i = 0; i < 5; i++) {
        Mka_MainFunction();
    }
    CHECK(Mka_GetPaeStatus(0, &st) == E_OK && st.PermissivePlaintext == TRUE,
        "TIMEOUT latched open");

    /* Switching back to NEVER retracts it immediately, without waiting for the
     * next main function. */
    Mka_SetPaePermissiveMode(0, MKA_PERMISSIVE_MODE_NEVER);
    CHECK(Mka_GetPaeStatus(0, &st) == E_OK && st.PermissivePlaintext == FALSE,
        "NEVER retracts the latch at once");
    Mka_MainFunction();
    CHECK(Mka_GetPaeStatus(0, &st) == E_OK && st.PermissivePlaintext == FALSE,
        "and it stays retracted while the mode is NEVER");
}

/* --- SecY install/delete accounting for the re-init teardown check --- */
static int g_teardown_installs;
static int g_teardown_deletes;

static int teardown_install_tx(void* c, const uint8_t* sci, uint8_t an,
    uint32_t kn, const uint8_t* sak, size_t len)
{
    (void)c;
    (void)sci;
    (void)an;
    (void)kn;
    (void)sak;
    (void)len;
    g_teardown_installs++;
    return 0;
}

static int teardown_delete_sa(void* c, const uint8_t* sci, uint8_t an)
{
    (void)c;
    (void)sci;
    (void)an;
    g_teardown_deletes++;
    return 0;
}

/* Re-initialising must tear the old configuration down. Without it the data
 * plane keeps every SAK it was programmed with while the control plane forgets
 * them, and there is no Mka_DeInit that could ever delete them (skoll F:
 * Mka_Init does not tear down). */
static void permissive_reinit_tears_down(void)
{
    Mka_CknConfigType ckn = {g_cak, 16, g_ckn, 8, TRUE};
    Mka_PaeConfigType paes[2];
    Mka_ConfigType cfg;
    Mka_PaeStatusType st;
    int deletes_before;
    int i;

    printf("re-init tears down the previous configuration:\n");
    g_teardown_installs = 0;
    g_teardown_deletes = 0;
    queue_reset();

    /* Two PAEs that key each other over the shared queue, so a SAK really is
     * installed - a lone Key Server never agrees one. */
    fill_pae(&paes[0], &ckn, 1, 24, 25, 0x0A, MKA_ROLE_KEY_SERVER,
        test_transmit, 16);
    fill_pae(&paes[1], &ckn, 1, 25, 24, 0x0B, MKA_ROLE_PEER, test_transmit, 16);
    for (i = 0; i < 2; i++) {
        paes[i].Secy.install_tx_sa = teardown_install_tx;
        paes[i].Secy.delete_sa = teardown_delete_sa;
    }
    cfg.Paes = paes;
    cfg.PaeCount = 2;
    cfg.MainFunctionPeriodMs = MKA_HELLO_TIME_MS;
    Mka_Init(&cfg);
    for (i = 0; i < 2; i++) {
        Mka_SetEnable((uint8)i, TRUE);
        Mka_LinkStateChange((uint8)i, ETHTRCV_LINK_STATE_ACTIVE);
        Mka_StartPae((uint8)i);
    }
    run_cycles(16);
    CHECK(g_teardown_installs > 0, "the SecY was programmed before re-init");
    deletes_before = g_teardown_deletes;

    /* Re-init with a smaller PaeCount: the SAs of both old PAEs must go, and
     * the surplus PAE must not survive into the new configuration. */
    cfg.PaeCount = 1;
    Mka_Init(&cfg);
    CHECK(g_teardown_deletes > deletes_before,
        "re-init deleted the SAs the old configuration installed");
    CHECK(Mka_GetPaeStatus(1, &st) == E_NOT_OK,
        "the surplus PAE is out of range for the new configuration");

    /* Growing back must start it clean rather than resuming stale state. */
    cfg.PaeCount = 2;
    Mka_Init(&cfg);
    CHECK(Mka_GetPaeStatus(1, &st) == E_OK &&
              (st.MkaStatus == MKA_STATUS_UNDEFINED),
        "the PAE comes back idle, not still running the old session");

    /* Disabling a PAE tears it down too: the connection is no longer viable, so
     * leaving its SAKs programmed would let the controlled port keep protecting
     * traffic with a key whose control plane has stopped - and the far end
     * eventually rekeys away from it. */
    for (i = 0U; i < 2U; i++) {
        Mka_SetEnable((uint8)i, TRUE);
        Mka_LinkStateChange((uint8)i, ETHTRCV_LINK_STATE_ACTIVE);
        Mka_StartPae((uint8)i);
    }
    run_cycles(16);
    CHECK(g_teardown_installs > 0, "the SecY was programmed");
    deletes_before = g_teardown_deletes;
    CHECK(Mka_SetEnable(0, TRUE) == E_OK, "enabling an enabled PAE is a no-op");
    CHECK(g_teardown_deletes == deletes_before, "and tears nothing down");
    CHECK(Mka_SetEnable(0, FALSE) == E_OK, "disable the PAE");
    CHECK(g_teardown_deletes > deletes_before,
        "which deletes the SAs it had installed");
    CHECK(Mka_GetPaeStatus(0, &st) == E_OK &&
              st.MkaStatus == MKA_STATUS_UNDEFINED,
        "and the PAE reports itself down");
    /* A link bounce, by contrast, leaves the other PAE's CA intact. */
    deletes_before = g_teardown_deletes;
    Mka_LinkStateChange(1, ETHTRCV_LINK_STATE_DOWN);
    Mka_LinkStateChange(1, ETHTRCV_LINK_STATE_ACTIVE);
    CHECK(g_teardown_deletes == deletes_before,
        "a link transition tears nothing down");

    /* An Mka_Init that is *refused* must tear down just the same. Returning
     * early used to strand the previous configuration's SAs in the data plane
     * for good: the module went un-initialised, so the next Mka_Init saw
     * wasInit == FALSE and skipped the teardown too, and there is no
     * Mka_DeInit that could ever remove them. */
    for (i = 0U; i < 2U; i++) {
        Mka_SetEnable((uint8)i, TRUE);
        Mka_LinkStateChange((uint8)i, ETHTRCV_LINK_STATE_ACTIVE);
        Mka_StartPae((uint8)i);
    }
    run_cycles(16);
    CHECK(g_teardown_installs > 0, "the SecY was programmed again");
    deletes_before = g_teardown_deletes;
    Mka_Init(NULL);
    CHECK(g_teardown_deletes > deletes_before,
        "a refused Mka_Init still deletes the SAs it leaves behind");
    CHECK(Mka_GetPaeStatus(0, &st) == E_NOT_OK, "and leaves the module down");

    /* And the configuration that follows it starts from nothing. */
    deletes_before = g_teardown_deletes;
    cfg.PaeCount = 2;
    Mka_Init(&cfg);
    CHECK(g_teardown_deletes == deletes_before,
        "with nothing stranded, the next init has nothing left to delete");
}

static void phase_permissive(void)
{
    printf("permissive mode timeout:\n");
    permissive_lone_ks();
    permissive_secured_clears();
    permissive_mode_switch_retracts();
    permissive_reinit_tears_down();
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
 * Mka_MacSecAddTxSaNotification reports completion, which mka_pae_secy_complete
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

    /* A SAK is agreed, but the asynchronous tx-SA install is still outstanding,
     * so transmit protection has not been enabled - and MACSEC_RUNNING means
     * protection is running, not merely that a key was agreed. Reporting it
     * here would tell an integrator to open the controlled port while frames
     * would still leave unprotected. */
    CHECK(Mka_GetPaeStatus(0, &st) == E_OK &&
              st.MkaStatus == MKA_STATUS_IN_PROGRESS,
        "still IN_PROGRESS while the tx-SA install is outstanding");
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

#ifdef WOLFMKA_FAULT_INJECT
/* ------------------------------------------------------------------ */
/* A Connectivity Association that fails inside Mka_MainFunction. The status
 * wm_Kay_Run returns used to be discarded, leaving the PAE at WAITING_PEER with
 * nothing to say why; it is now reported to Det - once, on the transition into
 * failure, so a persistent fault does not fill the log. Only a wolfSSL failure
 * can produce it, hence the injected one. */
static void phase_kay_run_failure(void)
{
    Mka_CknConfigType ckn = {g_cak, 16, g_ckn, 8, TRUE};
    Mka_PaeConfigType pae;
    Mka_ConfigType cfg;
    int i;
    int reported = 0;

    printf("a CA failing inside the main function:\n");
    queue_reset();
    fill_pae(&pae, &ckn, 1, 70, 71, 0x60, MKA_ROLE_KEY_SERVER, test_transmit,
        16);
    cfg.Paes = &pae;
    cfg.PaeCount = 1;
    /* One Hello Time per tick, so every tick has an MKPDU to build and the
     * armed fault lands on each of them. With a shorter period the transmit
     * cadence - which advances on a failed build as well as a successful one -
     * would leave most ticks with nothing to do, and a run that fails, then
     * succeeds, then fails is never the persistent failure this exercises. */
    cfg.MainFunctionPeriodMs = MKA_HELLO_TIME_MS;
    Mka_Init(&cfg);
    Mka_SetEnable(0, TRUE);
    Mka_LinkStateChange(0, ETHTRCV_LINK_STATE_ACTIVE);
    CHECK(Mka_StartPae(0) == E_OK, "PAE started");

    /* A healthy tick first, so the failure below is a transition into failure
     * rather than the initial state. */
    Mka_MainFunction();
    #if (MKA_DEV_ERROR_DETECT == STD_ON)
    det_reset();
    #endif

    /* The arm is one-shot and a tick only reaches the CMAC when it has an
     * MKPDU to build, so re-arm each tick until one does. */
    for (i = 0; (i < 60) && (reported == 0); i++) {
        wm_Fault_Arm(MKA_FI_CMAC, -1);
        Mka_MainFunction();
    #if (MKA_DEV_ERROR_DETECT == STD_ON)
        reported = (g_det_n > 0U) ? 1 : 0;
    #endif
    }
    #if (MKA_DEV_ERROR_DETECT == STD_ON)
    CHECK(reported == 1, "the failing CA reached Det");
    CHECK(det_is(MKA_SID_MAIN_FUNCTION, MKA_E_KAY_RUN_FAILED),
        "reported against the main function as a run failure");
    det_reset();
    #endif

    /* Still failing every tick: the edge-trigger keeps it to the one report. */
    for (i = 0; i < 20; i++) {
        wm_Fault_Arm(MKA_FI_CMAC, -1);
        Mka_MainFunction();
    }
    #if (MKA_DEV_ERROR_DETECT == STD_ON)
    CHECK(g_det_n == 0U, "a persistent failure is not reported every tick");
    #endif

    /* Recovered - a clean run clears the latch - then failing again. */
    wm_Fault_Reset();
    for (i = 0; i < 40; i++) {
        Mka_MainFunction();
    }
    #if (MKA_DEV_ERROR_DETECT == STD_ON)
    det_reset();
    #endif
    reported = 0;
    for (i = 0; (i < 60) && (reported == 0); i++) {
        wm_Fault_Arm(MKA_FI_CMAC, -1);
        Mka_MainFunction();
    #if (MKA_DEV_ERROR_DETECT == STD_ON)
        reported = (g_det_n > 0U) ? 1 : 0;
    #endif
    }
    #if (MKA_DEV_ERROR_DETECT == STD_ON)
    CHECK(reported == 1, "a fresh failure after a recovery is reported again");
    #endif
    wm_Fault_Reset();
    Mka_MainFunction();
}
#endif /* WOLFMKA_FAULT_INJECT */

#if (MKA_DEV_ERROR_DETECT == STD_ON)
/* ------------------------------------------------------------------ */
/* Development-error reporting (SWS section 7). Every condition the module
 * rejects is also reported to Det, naming the API that was called and which of
 * the errors it was - the whole value being that "uninitialised", "bad PAE
 * index" and "NULL pointer" are different mistakes with different fixes.
 * Detection is unchanged by the switch; only the reporting is added, so each
 * case below also asserts the return value is what the Det-off build gives. */
static void phase_det(void)
{
    Mka_CknConfigType ckn = {g_cak, 16, g_ckn, 8, TRUE};
    Mka_PaeConfigType pae;
    Mka_ConfigType cfg;
    Mka_PaeStatusType st;
    PduInfoType pdu;
    uint8 buf[8] = {0};
    boolean en;
    int i;

    printf("Det development-error reporting:\n");
    fill_pae(&pae, &ckn, 1, 60, 61, 0x50, MKA_ROLE_KEY_SERVER, test_transmit,
        16);
    cfg.Paes = &pae;
    cfg.PaeCount = 1;
    cfg.MainFunctionPeriodMs = 100;

    /* Reports carry this module's identification, which is what lets Det
     * attribute them. */
    det_reset();
    Mka_Init(NULL);
    CHECK(det_is(MKA_SID_INIT, MKA_E_PARAM_POINTER),
        "a NULL configuration is a pointer error against Mka_Init");
    CHECK(g_det_module == (uint16)MKA_MODULE_ID, "reported as this module");
    CHECK(g_det_instance == (uint8)MKA_INSTANCE_ID, "and this instance");

    /* Configurations Mka_Init refuses. A count with no array is a pointer
     * mistake; a zero main-function period is a value that cannot work. */
    det_reset();
    cfg.Paes = NULL;
    Mka_Init(&cfg);
    CHECK(det_is(MKA_SID_INIT, MKA_E_PARAM_POINTER),
        "a PaeCount with no Paes array is a pointer error");
    cfg.Paes = &pae;

    det_reset();
    cfg.MainFunctionPeriodMs = 0;
    Mka_Init(&cfg);
    CHECK(det_is(MKA_SID_INIT, MKA_E_INIT_FAILED),
        "a zero main-function period fails the init");
    cfg.MainFunctionPeriodMs = 100;

    /* That last Mka_Init left the module uninitialised, so the API is now in
     * the pre-init state without needing a separate fixture. */
    det_reset();
    CHECK(Mka_GetEnable(0, &en) == E_NOT_OK, "pre-init call rejected");
    CHECK(det_is(MKA_SID_GET_ENABLE, MKA_E_UNINIT),
        "and reported against the API that was called");

    det_reset();
    pdu.SduDataPtr = buf;
    pdu.SduLength = sizeof buf;
    pdu.MetaDataPtr = NULL;
    Mka_RxIndication(60, &pdu);
    CHECK(det_is(MKA_SID_RX_INDICATION, MKA_E_UNINIT),
        "a frame arriving before init is reported too");

    det_reset();
    Mka_TxConfirmation(61, E_OK);
    CHECK(det_is(MKA_SID_TX_CONFIRMATION, MKA_E_UNINIT),
        "and so is a transmit confirmation");

    /* Mka_MainFunction is the exception: a BSW scheduler calls it every tick,
     * and the module can stay uninitialised for good (this one just refused a
     * configuration), so it reports once for the period rather than once per
     * call. The one report still catches an integration that schedules the main
     * function and never calls Mka_Init at all. */
    det_reset();
    Mka_MainFunction();
    CHECK(det_is(MKA_SID_MAIN_FUNCTION, MKA_E_UNINIT),
        "the scheduled main function reports running without a module");
    det_reset();
    for (i = 0; i < 20; i++) {
        Mka_MainFunction();
    }
    CHECK(g_det_n == 0U, "but only once, however long the scheduler runs");

    /* Now a working module: the remaining errors are per-call mistakes. */
    Mka_Init(&cfg);
    Mka_SetEnable(0, TRUE);
    Mka_LinkStateChange(0, ETHTRCV_LINK_STATE_ACTIVE);
    CHECK(Mka_StartPae(0) == E_OK, "PAE started");

    det_reset();
    CHECK(Mka_GetPaeStatus((uint8)MKA_MAX_PAES, &st) == E_NOT_OK,
        "an out-of-range PAE index is rejected");
    CHECK(det_is(MKA_SID_GET_PAE_STATUS, MKA_E_INVALID_PAE_IDX),
        "and reported as a bad index, not as uninitialised");

    det_reset();
    CHECK(Mka_GetPaeStatus(0, NULL) == E_NOT_OK, "a NULL out-parameter too");
    CHECK(det_is(MKA_SID_GET_PAE_STATUS, MKA_E_PARAM_POINTER),
        "reported as a pointer error from the same API");

    det_reset();
    Mka_GetVersionInfo(NULL);
    CHECK(det_is(MKA_SID_GET_VERSION_INFO, MKA_E_PARAM_POINTER),
        "a void API reports its pointer errors as well");

    det_reset();
    CHECK(Mka_SetCknStatus(0, TRUE, NULL, 0) == E_NOT_OK, "NULL CKN rejected");
    CHECK(det_is(MKA_SID_SET_CKN_STATUS, MKA_E_PARAM_POINTER),
        "against Mka_SetCknStatus");

    /* Configurations beyond the build's static limits are reported as
     * out-of-range parameters rather than silently truncated. */
    {
        Mka_PaeConfigType many[MKA_MAX_PAES + 1U];
        Mka_CknConfigType ckn5[MKA_MAX_PARTICIPANTS + 1U];
        uint8 j;

        for (j = 0U; j < (uint8)(MKA_MAX_PAES + 1U); j++) {
            fill_pae(&many[j], &ckn, 1, (PduIdType)(120U + j),
                (PduIdType)(130U + j), (uint8)(0x70U + j), MKA_ROLE_KEY_SERVER,
                test_transmit, 16);
        }
        det_reset();
        cfg.Paes = many;
        cfg.PaeCount = (uint8)(MKA_MAX_PAES + 1U);
        Mka_Init(&cfg);
        CHECK(det_is(MKA_SID_INIT, MKA_E_PARAM_INVALID),
            "too many PAEs is an out-of-range parameter, not a clamp");

        for (j = 0U; j < (uint8)(MKA_MAX_PARTICIPANTS + 1U); j++) {
            ckn5[j] = ckn;
        }
        cfg.Paes = &pae;
        cfg.PaeCount = 1;
        fill_pae(&pae, ckn5, (uint8)(MKA_MAX_PARTICIPANTS + 1U), 60, 61, 0x51,
            MKA_ROLE_KEY_SERVER, test_transmit, 16);
        Mka_Init(&cfg);
        Mka_SetEnable(0, TRUE);
        Mka_LinkStateChange(0, ETHTRCV_LINK_STATE_ACTIVE);
        det_reset();
        CHECK(Mka_StartPae(0) == E_NOT_OK, "too many CKNs is refused");
        CHECK(det_is(MKA_SID_START_PAE, MKA_E_PARAM_INVALID),
            "and reported against Mka_StartPae");
    }

    /* Restore a workable module for the cases below. */
    fill_pae(&pae, &ckn, 1, 60, 61, 0x52, MKA_ROLE_KEY_SERVER, test_transmit,
        16);
    cfg.Paes = &pae;
    cfg.PaeCount = 1;
    Mka_Init(&cfg);
    Mka_SetEnable(0, TRUE);
    Mka_LinkStateChange(0, ETHTRCV_LINK_STATE_ACTIVE);
    CHECK(Mka_StartPae(0) == E_OK, "PAE restarted for the remaining cases");

    det_reset();
    CHECK(Mka_SetPaePermissiveMode(0, (Mka_PermissiveModeType)7) == E_NOT_OK,
        "an unknown permissive mode is rejected");
    CHECK(det_is(MKA_SID_SET_PAE_PERMISSIVE_MODE, MKA_E_PARAM_INVALID),
        "and reported as an out-of-range value, not a pointer");

    /* The same for the other entry point taking an enumerated value. An
     * unrecognised link state would otherwise be stored verbatim and handed
     * back out as Mka_PaeStatusType::ConnectionStatus. */
    det_reset();
    CHECK(Mka_LinkStateChange(0, (EthTrcv_LinkStateType)9) == E_NOT_OK,
        "an unknown transceiver link state is rejected");
    CHECK(det_is(MKA_SID_LINK_STATE_CHANGE, MKA_E_PARAM_INVALID),
        "and reported as an out-of-range value");

    /* A successful Mka_Init re-arms that report, so a configuration refused
     * later gets its own rather than being masked by the earlier one. */
    det_reset();
    cfg.MainFunctionPeriodMs = 0;
    Mka_Init(&cfg);
    CHECK(det_is(MKA_SID_INIT, MKA_E_INIT_FAILED), "the second refusal");
    det_reset();
    Mka_MainFunction();
    CHECK(det_is(MKA_SID_MAIN_FUNCTION, MKA_E_UNINIT),
        "and the main function reports the new uninitialised period");
    cfg.MainFunctionPeriodMs = 100;
    Mka_Init(&cfg);
    Mka_SetEnable(0, TRUE);
    Mka_LinkStateChange(0, ETHTRCV_LINK_STATE_ACTIVE);
    CHECK(Mka_StartPae(0) == E_OK, "PAE restarted");

    /* Every API must report against its own service ID - that is the whole
     * point of having eighteen of them, and asserting a handful proves only
     * that those few are wired up. The thirteen that take a PAE index are
     * driven uniformly with an out-of-range one; the remaining five have no
     * index and are covered by their own cases above and below. */
    {
        static const struct {
            uint8 sid;
            const char* name;
        } indexed[] = {
            {MKA_SID_SET_ENABLE, "Mka_SetEnable"},
            {MKA_SID_GET_ENABLE, "Mka_GetEnable"},
            {MKA_SID_SET_CKN_STATUS, "Mka_SetCknStatus"},
            {MKA_SID_GET_CKN_STATUS, "Mka_GetCknStatus"},
            {MKA_SID_START_PAE, "Mka_StartPae"},
            {MKA_SID_GET_PAE_STATUS, "Mka_GetPaeStatus"},
            {MKA_SID_SET_PAE_PERMISSIVE_MODE, "Mka_SetPaePermissiveMode"},
            {MKA_SID_GET_MACSEC_STATISTICS, "Mka_GetMacSecStatistics"},
            {MKA_SID_LINK_STATE_CHANGE, "Mka_LinkStateChange"},
            {MKA_SID_GET_MACSEC_STATISTICS_NOTIF,
                "Mka_GetMacSecStatisticsNotification"},
            {MKA_SID_MACSEC_UPDATE_SECY_NOTIF,
                "Mka_MacSecUpdateSecYNotification"},
            {MKA_SID_MACSEC_ADD_TX_SA_NOTIF, "Mka_MacSecAddTxSaNotification"},
            {MKA_SID_MACSEC_ADD_RX_SA_NOTIF, "Mka_MacSecAddRxSaNotification"},
        };
        const uint8 bad = (uint8)MKA_MAX_PAES;
        Mka_Stats_SecYType bad_stats;
        size_t k;

        for (k = 0U; k < (sizeof indexed / sizeof indexed[0]); k++) {
            det_reset();
            switch (indexed[k].sid) {
                case MKA_SID_SET_ENABLE: (void)Mka_SetEnable(bad, TRUE); break;
                case MKA_SID_GET_ENABLE: (void)Mka_GetEnable(bad, &en); break;
                case MKA_SID_SET_CKN_STATUS:
                    (void)Mka_SetCknStatus(bad, TRUE, g_ckn, 8);
                    break;
                case MKA_SID_GET_CKN_STATUS:
                    (void)Mka_GetCknStatus(bad, g_ckn, 8, &en);
                    break;
                case MKA_SID_START_PAE: (void)Mka_StartPae(bad); break;
                case MKA_SID_GET_PAE_STATUS:
                    (void)Mka_GetPaeStatus(bad, &st);
                    break;
                case MKA_SID_SET_PAE_PERMISSIVE_MODE:
                    (void)Mka_SetPaePermissiveMode(bad,
                        MKA_PERMISSIVE_MODE_NEVER);
                    break;
                case MKA_SID_GET_MACSEC_STATISTICS:
                    (void)Mka_GetMacSecStatistics(bad, &bad_stats);
                    break;
                case MKA_SID_LINK_STATE_CHANGE:
                    (void)Mka_LinkStateChange(bad, ETHTRCV_LINK_STATE_ACTIVE);
                    break;
                case MKA_SID_GET_MACSEC_STATISTICS_NOTIF:
                    Mka_GetMacSecStatisticsNotification(bad, E_OK);
                    break;
                case MKA_SID_MACSEC_UPDATE_SECY_NOTIF:
                    Mka_MacSecUpdateSecYNotification(bad, E_OK);
                    break;
                case MKA_SID_MACSEC_ADD_TX_SA_NOTIF:
                    Mka_MacSecAddTxSaNotification(bad, E_OK);
                    break;
                default: Mka_MacSecAddRxSaNotification(bad, E_OK); break;
            }
            CHECK(det_is(indexed[k].sid, MKA_E_INVALID_PAE_IDX),
                indexed[k].name);
        }
    }

    /* Calls that succeed report nothing - including the ones whose only
     * development error is the pre-init case. */
    det_reset();
    CHECK(Mka_GetPaeStatus(0, &st) == E_OK, "a valid call succeeds");
    Mka_TxConfirmation(61, E_OK);
    Mka_MainFunction();
    CHECK(g_det_n == 0U, "and reports nothing");
}
#endif /* MKA_DEV_ERROR_DETECT */

int main(void)
{
    printf("\n== autosar Mka ==\n");
    phase_cmac_pool_exhausted();
    phase_pre_init();
    phase_args();
    phase_status();
    phase_auth_fail();
    phase_in_progress();
    phase_failures();
    phase_ckn_bound_and_async();
    phase_config_bounds();
    phase_partial_states();
    phase_retry_announce();
    phase_permissive();
    phase_async_secy();
    phase_async_secy_multi();
#ifdef WOLFMKA_FAULT_INJECT
    phase_kay_run_failure();
#endif
#if (MKA_DEV_ERROR_DETECT == STD_ON)
    phase_det();
#endif

    printf("\n------------------\n");
    printf("checks: %d, failures: %d => %s\n", g_tests_run, g_tests_failed,
        (g_tests_failed == 0) ? "PASS" : "FAIL");
    return (g_tests_failed == 0) ? 0 : 1;
}
