/**
 * @file Mka.c
 * AUTOSAR Mka module (Document ID 1066) implemented over wolfMKA.
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
 * Module state is a fixed array of PAE runtime blocks, each wrapping a wolfMKA
 * MkaKay (so one PAE carries several CKN participants). Per-participant
 * transmit is bridged from the wolfMKA send callback to the PAE's configured
 * Mka_TransmitFnType. See Mka.h for the API and AUTOSAR.md for the mapping.
 *
 * This is a shim, not a re-implementation: everything about MKA itself - the
 * state ladder Mka_GetPaeStatus reports, the counters
 * Mka_GetMacSecStatistics returns, the timers Mka_MainFunction steps - is read
 * back out of the KaY rather than derived here a second time. What genuinely
 * belongs to the binding is the part wolfMKA has no view of: link state, the
 * enable flags, permissive mode, and the asynchronous SecY handshakes the SWS
 * defines (Mka_MacSecAddTxSaNotification and friends).
 *
 * Development-error reporting (SWS section 7) is behind MKA_DEV_ERROR_DETECT,
 * which defaults to STD_OFF so this builds and links with no generated Det.
 * Detection does not depend on that switch: every condition is checked, and
 * rejected with E_NOT_OK, either way - the switch only decides whether the
 * rejection is also reported, so turning it off cannot change behaviour. Two
 * reports are edge-triggered rather than per-call, because a BSW scheduler
 * calls Mka_MainFunction forever and both conditions can persist: see the
 * comments at those sites, and AUTOSAR.md for the error and service IDs.
 */
#include "wolfmka/autosar/Mka.h"
#include "wolfmka/mka_crypto.h"

/** Per-PAE runtime state (one controlled port). */
typedef struct {
    /** the KaY running this PAE's CKNs */
    MkaKay kay;
    /** this PAE's configuration */
    const Mka_PaeConfigType* cfg;
    /** Mka_SetEnable state */
    boolean enabled;
    /** Mka_StartPae has run */
    boolean started;
    /** last reported link state */
    EthTrcv_LinkStateType link;
    /** Mka_SetPaePermissiveMode state */
    Mka_PermissiveModeType permissive;
    /** last wm_Kay_Run reported a failure: edge-trigger for the Det report.
     *  Kept in both MKA_DEV_ERROR_DETECT settings so the runtime struct - a
     *  static array - has the same layout either way. */
    boolean runFailed;
    /** time active without a SAK */
    uint32 unsecuredMs;
    /** permissive plaintext now allowed */
    boolean permissiveOpen;
    /** per-CKN */
    boolean cknEnabled[MKA_MAX_PARTICIPANTS];
    /* Asynchronous SecY/statistics handshake (8.4). */
    /** pending stats buffer */
    Mka_Stats_SecYType* statsPtr;
    /** stats request in flight */
    boolean statsPending;
    /** Last SecY/statistics notification result. Diagnostic only: nothing in
     *  the module reads it and Mka.h exposes no accessor, so it is not shadow
     *  state that any decision depends on. The KaY is deliberately told nothing
     *  about a failed SecY operation either - wm_Participant_SecyComplete takes
     *  no result, because the core has no recovery path for one, and FMEA FM-06
     *  assigns SecY error handling to the integrator. Kept because a debugger
     *  or a memory dump is where this value is useful. */
    Std_ReturnType lastSecyResult;
} Mka_PaeRtType;

static Mka_PaeRtType Mka_Pae[MKA_MAX_PAES];
static const Mka_ConfigType* Mka_Cfg;
static uint8 Mka_PaeCount;
static boolean Mka_Initialized = FALSE;

/* Whether the "main function running without a module" report has been made for
 * the current uninitialised period. Re-armed by a successful Mka_Init, so a
 * later configuration that is refused can report again. */
static boolean Mka_UninitReported = FALSE;
static uint32 Mka_TimeMs;
/* One CMAC workspace shared by every participant: AUTOSAR BSW is single
 * threaded and a participant's CMAC operations do not nest, so the contexts are
 * used sequentially. Acquired once in Mka_Init. */
static MkaCmacCtx* Mka_Cmac;
/* One seeded RNG for every participant: seeding is the expensive step, which
 * is why wolfMKA offers a pool at all. Without this every MI and SAK draw
 * would seed a throwaway generator. Acquired once on the first Mka_Init and
 * held for the life of the module - there is no Mka_DeInit in the SWS, so it is
 * never released, and re-acquiring on each Mka_Init would exhaust the pool. */
static MkaRandom* Mka_Rng;

/**
 * Bridge wolfMKA's send callback to the PAE's transmit function.
 * @param[in] ctx    The PAE runtime block (set as the participant's send
 *                   context).
 * @param[in] frame  The complete EAPOL-MKA frame to transmit.
 * @param[in] len    Frame length in octets.
 * @return 0 if the frame was accepted by the lower layer, else -1.
 */
static int mka_send_bridge(void* ctx, const uint8_t* frame, size_t len)
{
    const Mka_PaeRtType* pae = (const Mka_PaeRtType*)ctx;
    Std_ReturnType ret;

    /* ctx is always a PAE whose cfg is set by Mka_Init. */
    if (pae->cfg->Transmit == NULL) {
        return -1;
    }
    ret = pae->cfg->Transmit(pae->cfg->TxPduId, frame, (uint16)len);
    return (ret == E_OK) ? 0 : -1;
}

/**
 * Add one CKN to a PAE as a wolfMKA participant.
 *
 * Translates the PAE/CKN configuration into an MkaParticipantConfig (wiring the
 * send bridge and SecY hooks) and creates the participant in the PAE's KaY.
 * @param[in,out] pae  The PAE runtime block.
 * @param[in]     ckn  The CKN/CAK to instantiate.
 * @return E_OK if the participant was created, else E_NOT_OK.
 */
static Std_ReturnType mka_add_ckn(Mka_PaeRtType* pae,
    const Mka_CknConfigType* ckn)
{
    const Mka_PaeConfigType* c = pae->cfg;
    MkaParticipantConfig pc;
    MkaStatus status;

    /* Reject a misconfigured CKN before copying into the fixed-size buffers. */
    if ((ckn->CakLength > MKA_MAX_CAK_LEN) ||
        (ckn->CknLength > MKA_MAX_CKN_LEN)) {
        return E_NOT_OK;
    }
    /* Length and pointer are separate configuration fields, so a generator can
     * emit one without the other. Both are copied unconditionally below, and a
     * NULL with a non-zero length would be dereferenced - the same shape as the
     * NULL Ckns array mka_ckn_count() guards against, one level down. */
    if ((ckn->Cak == NULL) || (ckn->Ckn == NULL)) {
        return E_NOT_OK;
    }

    (void)WOLFMKA_MEMSET(&pc, 0, sizeof pc);
    (void)WOLFMKA_MEMCPY(pc.cak.cak, ckn->Cak, ckn->CakLength);
    pc.cak.cak_len = ckn->CakLength;
    (void)WOLFMKA_MEMCPY(pc.cak.ckn, ckn->Ckn, ckn->CknLength);
    pc.cak.ckn_len = ckn->CknLength;
    (void)WOLFMKA_MEMCPY(pc.sci, c->Sci, MKA_SCI_LEN);
    pc.priority = c->Priority;
    pc.macsec_desired = TRUE;
    pc.macsec_capability = (uint8)MKA_CAP_INTEGRITY_CONF;
    pc.key_server_capable = (c->Role != MKA_ROLE_PEER) ? TRUE : FALSE;
    pc.sak_len = c->SakLength;
    pc.confidentiality_offset = c->ConfidentialityOffset;
    pc.delay_protect = c->DelayProtect;
    pc.cipher_suite = c->CipherSuite;
    pc.role = c->Role;
    pc.sak_rekey_time_ms = c->SakRekeyTimeMs;
#ifndef WOLFMKA_NO_RETRY
    pc.retry_base_ms = c->RetryBaseMs;
    pc.retry_cyclic_ms = c->RetryCyclicMs;
#endif
#ifndef WOLFMKA_NO_ANNOUNCEMENTS
    pc.announce_cipher_suites = c->AnnounceCipherSuites;
#endif
    pc.secy = c->Secy;
    pc.events = c->Events;
    pc.send = mka_send_bridge;
    pc.send_ctx = pae;
    pc.cmac = Mka_Cmac;
    pc.rng = Mka_Rng;

    status = wm_Kay_AddParticipant(&pae->kay, &pc, NULL);
    /* pc carried the plaintext CAK into the participant; it is a stack object,
     * so leaving it is leaving key material on the stack. */
    wm_Crypto_ForceZero(&pc, sizeof pc);
    return (status == MKA_OK) ? E_OK : E_NOT_OK;
}

/**
 * Find a PAE by its receive PDU id.
 * @param[in] id  The receive PDU id to match.
 * @return The matching PAE runtime block, or NULL if none matches.
 */
static Mka_PaeRtType* mka_find_by_rx_pdu(PduIdType id)
{
    uint8 i;

    for (i = 0U; i < Mka_PaeCount; i++) {
        if (Mka_Pae[i].cfg->RxPduId == id) {
            return &Mka_Pae[i];
        }
    }
    return NULL;
}

/**
 * How many CKNs a PAE actually has.
 *
 * CknCount and Ckns are separate configuration fields, so a generator can emit
 * a count with no array. Mka_Init accepts that rather than refusing the whole
 * PAE - the port still runs, it just has no participant - which means every
 * other reader has to agree that such a PAE has zero CKNs. Reading CknCount
 * directly and indexing Ckns is a NULL dereference on a configuration the
 * module itself declared valid.
 * @param[in] pae  the PAE runtime block.
 * @return the number of usable entries in pae->cfg->Ckns.
 */
static uint8 mka_ckn_count(const Mka_PaeRtType* pae)
{
    return (pae->cfg->Ckns != NULL) ? pae->cfg->CknCount : 0U;
}

/**
 * Find a configured CKN index within a PAE.
 *
 * A PAE runs at most MKA_MAX_PARTICIPANTS participants, so CKNs configured
 * beyond that bound are not tracked (keeping the index within cknEnabled[]).
 * @param[in] pae  The PAE runtime block.
 * @param[in] ckn  The CAK Name to match.
 * @param[in] len  Length of @p ckn in octets.
 * @return The CKN index (0 .. MKA_MAX_PARTICIPANTS-1), or -1 if not found.
 */
static int mka_find_ckn(const Mka_PaeRtType* pae, const uint8* ckn, uint8 len)
{
    uint8 i;
    uint8 cknCount = mka_ckn_count(pae);

    for (i = 0U; (i < cknCount) && (i < (uint8)MKA_MAX_PARTICIPANTS); i++) {
        const Mka_CknConfigType* k = &pae->cfg->Ckns[i];
        if ((k->CknLength == len) && (WOLFMKA_MEMCMP(k->Ckn, ckn, len) == 0)) {
            return (int)i;
        }
    }
    return -1;
}

/**
 * Validate that the module is initialised and @p idx names a PAE, reporting the
 * specific development error to Det when it does not.
 *
 * The two conditions are separated rather than tested as one expression because
 * they are different diagnoses: an API called before Mka_Init is a sequencing
 * mistake, an index past PaeCount is a configuration one, and telling them
 * apart is the whole value of the report. Order matters - an index cannot be
 * judged against a PaeCount the module does not have yet - so uninitialised is
 * checked first, which is also the order the previous single expression
 * short-circuited in.
 * @param[in] idx  The PAE index to check.
 * @param[in] sid  API service ID of the caller, for the Det report.
 * @return TRUE if usable, FALSE otherwise.
 */
static boolean mka_pae_ok_det(uint8 idx, uint8 sid)
{
    boolean ok = TRUE;

    if (!Mka_Initialized) {
        MKA_DET_REPORT_ERROR(sid, MKA_E_UNINIT);
        ok = FALSE;
    }
    else if (idx >= Mka_PaeCount) {
        MKA_DET_REPORT_ERROR(sid, MKA_E_INVALID_PAE_IDX);
        ok = FALSE;
    }
    else {
        /* initialised and in range */
    }
    return ok;
}

/**
 * Validate a required pointer argument, reporting MKA_E_PARAM_POINTER when it
 * is NULL.
 * @param[in] ptr  The pointer to check.
 * @param[in] sid  API service ID of the caller, for the Det report.
 * @return TRUE if non-NULL, FALSE otherwise.
 */
static boolean mka_ptr_ok_det(const void* ptr, uint8 sid)
{
    boolean ok = TRUE;

    if (ptr == NULL) {
        MKA_DET_REPORT_ERROR(sid, MKA_E_PARAM_POINTER);
        ok = FALSE;
    }
    return ok;
}

/**
 * Whether any of a PAE's participants has an installed SAK (MACsec is up).
 * @param[in] pae  The PAE runtime block.
 * @return TRUE if at least one participant has a SAK, else FALSE.
 */
static boolean mka_pae_has_sak(const Mka_PaeRtType* pae)
{
    size_t i;

    for (i = 0U; i < pae->kay.count; i++) {
        if (wm_Participant_HasSak(&pae->kay.parts[i])) {
            return TRUE;
        }
    }
    return FALSE;
}

/**
 * Advance the permissive-mode timer for one PAE (8.2.9). While the PAE is
 * active (enabled, started, link up) but has no SAK, the unsecured time counts
 * up; in MKA_PERMISSIVE_MODE_TIMEOUT it latches permissiveOpen once the
 * configured PermissiveTimeoutMs is reached, telling the integrator the
 * controlled port may run in plaintext. Establishing a SAK or losing
 * activity clears both. MKA_PERMISSIVE_MODE_NEVER never opens.
 * @param[in,out] pae       The PAE runtime block.
 * @param[in]     periodMs  The Mka_MainFunction period in milliseconds.
 */
static void mka_permissive_update(Mka_PaeRtType* pae, uint32 periodMs)
{
    boolean active = ((pae->enabled != FALSE) && (pae->started != FALSE) &&
                         (pae->link == ETHTRCV_LINK_STATE_ACTIVE))
                         ? TRUE
                         : FALSE;

    if ((active == FALSE) || (mka_pae_has_sak(pae) != FALSE)) {
        pae->unsecuredMs = 0U;
        pae->permissiveOpen = FALSE;
        return;
    }
    /* Active but unsecured: count toward the timeout (capped so it cannot
     * wrap), then open in plaintext only when configured to time out. */
    if (pae->unsecuredMs < pae->cfg->PermissiveTimeoutMs) {
        uint32 room = pae->cfg->PermissiveTimeoutMs - pae->unsecuredMs;
        pae->unsecuredMs += (periodMs < room) ? periodMs : room;
    }
    if (pae->permissive == MKA_PERMISSIVE_MODE_TIMEOUT) {
        /* A zero timeout is an unset one, not an instruction to run plaintext
         * from the first tick: fail closed rather than open. */
        if ((pae->cfg->PermissiveTimeoutMs > 0U) &&
            (pae->unsecuredMs >= pae->cfg->PermissiveTimeoutMs)) {
            pae->permissiveOpen = TRUE;
        }
    }
    else {
        /* Any other mode keeps the controlled port closed, so a latch set while
         * the mode was TIMEOUT must not survive a switch away from it - the
         * status would otherwise keep reporting that plaintext is permitted. */
        pae->permissiveOpen = FALSE;
    }
}

/* Reset every PAE, clamp the PAE count to the static array, and give each an
 * empty KaY with its per-CKN enables seeded from the configuration. */
void Mka_Init(const Mka_ConfigType* ConfigPtr)
{
    uint8 i;
    boolean wasInit = Mka_Initialized;
    uint8 oldCount = Mka_PaeCount;

    Mka_Initialized = FALSE;

    /* Tear down whatever the previous configuration left running - and do it
     * before validating this one, so that *every* exit below leaves the module
     * genuinely down rather than merely flagged down. wm_Kay_Free deletes the
     * SecY SAs each participant installed and wipes its key material; skip it
     * and the data plane keeps every SAK it was programmed with while the
     * control plane forgets them. There is no Mka_DeInit, so nothing later can
     * recover: a rejected Mka_Init that returned early used to strand the
     * previous configuration's SAs for the life of the ECU, and the next
     * Mka_Init then saw wasInit == FALSE and skipped the teardown for good. */
    if (wasInit != FALSE) {
        for (i = 0U; i < oldCount; i++) {
            wm_Kay_Free(&Mka_Pae[i].kay);
        }
    }
    /* Clear every slot, not only the ones the new configuration uses: a smaller
     * PaeCount would otherwise leave the surplus PAEs holding their CAK,
     * derived keys and a dangling cfg pointer for the lifetime of the ECU. */
    (void)WOLFMKA_MEMSET(Mka_Pae, 0, sizeof Mka_Pae);
    /* Nothing of the old configuration survives a refused new one either. */
    Mka_PaeCount = 0U;
    Mka_Cfg = NULL;

    if (ConfigPtr == NULL) {
        MKA_DET_REPORT_ERROR(MKA_SID_INIT, MKA_E_PARAM_POINTER);
        return;
    }
    /* Acquire the two shared crypto workspaces once. Both are required by the
     * KaY - wolfSSL's Cmac context and its WC_RNG never live on wolfMKA's stack
     * or heap, so neither can be substituted - and both are acquired here
     * rather than per participant, since every CA on every PAE can share them
     * in this single-threaded binding. */
    if (Mka_Cmac == NULL) {
        Mka_Cmac = wm_Crypto_CmacInit();
    }
    if (Mka_Cmac == NULL) {
        /* Sized by WOLFMKA_CMAC_POOL_SIZE; with none free no participant can
         * compute an ICV. Refused before the RNG is touched, so a refusal does
         * not leave a pool object claimed by a module that never came up. */
        MKA_DET_REPORT_ERROR(MKA_SID_INIT, MKA_E_INIT_FAILED);
        return;
    }
    if (Mka_Rng == NULL) {
        Mka_Rng = wm_Crypto_RandomInit();
    }
    if (Mka_Rng == NULL) {
        /* Sized by WOLFMKA_RANDOM_POOL_SIZE, and it can also fail to seed.
         * Required for the same reason as the CMAC workspace, so the same
         * answer: the module stays down and says why, rather than coming up
         * "initialised" and then failing every Mka_StartPae for a reason the
         * integrator would have to infer. */
        MKA_DET_REPORT_ERROR(MKA_SID_INIT, MKA_E_INIT_FAILED);
        return;
    }

    if ((ConfigPtr->PaeCount > 0U) && (ConfigPtr->Paes == NULL)) {
        /* A count without an array would be dereferenced below; refuse the
         * configuration instead, leaving the module uninitialised. */
        MKA_DET_REPORT_ERROR(MKA_SID_INIT, MKA_E_PARAM_POINTER);
        return;
    }
    if (ConfigPtr->MainFunctionPeriodMs == 0U) {
        /* Mka_MainFunction advances the KaY's clock by this period, so a zero
         * pins time at 0 and no hello, retry or rekey timer ever fires - MKA
         * runs, transmits its first MKPDU and then sits there for the lifetime
         * of the ECU. It is also what a memset-ed Mka_ConfigType holds, so
         * refuse it rather than come up dead. */
        MKA_DET_REPORT_ERROR(MKA_SID_INIT, MKA_E_INIT_FAILED);
        return;
    }

    Mka_Cfg = ConfigPtr;
    Mka_TimeMs = 0U;
    /* Honour the configured PAE count, but never exceed the static array. */
    if (ConfigPtr->PaeCount > (uint8)MKA_MAX_PAES) {
        /* Refused, not clamped. Clamping left the ECU looking healthy while the
         * surplus controlled ports never ran MKA at all - ports the
         * configuration says are protected, silently absent. A configuration
         * that asks for more PAEs than the build was compiled for is a
         * mismatch between the generator and MKA_MAX_PAES, and the integrator
         * has to know. */
        MKA_DET_REPORT_ERROR(MKA_SID_INIT, MKA_E_PARAM_INVALID);
        return;
    }
    Mka_PaeCount = ConfigPtr->PaeCount;

    for (i = 0U; i < Mka_PaeCount; i++) {
        Mka_PaeRtType* pae = &Mka_Pae[i];
        uint8 j;
        uint8 cknCount;

        /* Every slot was cleared above; give this one its configuration and an
         * empty KaY. */
        pae->cfg = &ConfigPtr->Paes[i];
        pae->enabled = FALSE;
        pae->started = FALSE;
        pae->link = ETHTRCV_LINK_STATE_DOWN;
        pae->permissive = MKA_PERMISSIVE_MODE_NEVER;
        (void)wm_Kay_Init(&pae->kay);

        cknCount = mka_ckn_count(pae);
        /* Seed each CKN's enabled state from its configured default. */
        for (j = 0U; (j < cknCount) && (j < (uint8)MKA_MAX_PARTICIPANTS); j++) {
            pae->cknEnabled[j] = pae->cfg->Ckns[j].DefaultEnabled;
        }
    }
    Mka_Initialized = TRUE;
    /* Re-arm: a future configuration that is refused, or a shutdown that leaves
     * the module down, gets its own report rather than being masked by this
     * one's. */
    Mka_UninitReported = FALSE;
}

/* Copy the compile-time vendor/module/version constants into the caller's
 * buffer. */
void Mka_GetVersionInfo(Std_VersionInfoType* VersionInfoPtr)
{
    if (VersionInfoPtr == NULL) {
        MKA_DET_REPORT_ERROR(MKA_SID_GET_VERSION_INFO, MKA_E_PARAM_POINTER);
        return;
    }
    VersionInfoPtr->vendorID = MKA_VENDOR_ID;
    VersionInfoPtr->moduleID = MKA_MODULE_ID;
    VersionInfoPtr->sw_major_version = MKA_SW_MAJOR_VERSION;
    VersionInfoPtr->sw_minor_version = MKA_SW_MINOR_VERSION;
    VersionInfoPtr->sw_patch_version = MKA_SW_PATCH_VERSION;
}

/* Record the CKN's enable flag; on an already-started PAE, instantiate the
 * participant on enable or tear it down on disable. */
Std_ReturnType Mka_SetCknStatus(uint8 MkaPaeIdx, boolean Enable,
    const uint8* Ckn, uint8 CknLength)
{
    Mka_PaeRtType* pae;
    int idx;

    if (!mka_pae_ok_det(MkaPaeIdx, MKA_SID_SET_CKN_STATUS) ||
        !mka_ptr_ok_det(Ckn, MKA_SID_SET_CKN_STATUS)) {
        return E_NOT_OK;
    }
    pae = &Mka_Pae[MkaPaeIdx];
    idx = mka_find_ckn(pae, Ckn, CknLength);
    if (idx < 0) {
        return E_NOT_OK;
    }
    pae->cknEnabled[idx] = (Enable != FALSE) ? TRUE : FALSE;

    if (Enable != FALSE) {
        /* If already running, instantiate the participant on enable. */
        if (pae->started && (wm_Kay_Find(&pae->kay, Ckn, CknLength) == NULL)) {
            return mka_add_ckn(pae, &pae->cfg->Ckns[idx]);
        }
    }
    else {
        /* Disable: tear down the running participant so MKA actually stops for
         * this CKN (its SecY SAs are deleted and key material wiped). */
        if (wm_Kay_Find(&pae->kay, Ckn, CknLength) != NULL) {
            (void)wm_Kay_RemoveParticipant(&pae->kay, Ckn, CknLength);
        }
    }
    return E_OK;
}

/* Look up the CKN and return its stored enable flag. */
Std_ReturnType Mka_GetCknStatus(uint8 MkaPaeIdx, const uint8* Ckn,
    uint8 CknLength, boolean* EnablePtr)
{
    /* Not const: wm_Kay_Find takes a mutable MkaKay, since it hands back a
     * participant the caller may drive. */
    Mka_PaeRtType* pae;
    int idx;

    if (!mka_pae_ok_det(MkaPaeIdx, MKA_SID_GET_CKN_STATUS) ||
        !mka_ptr_ok_det(Ckn, MKA_SID_GET_CKN_STATUS) ||
        !mka_ptr_ok_det(EnablePtr, MKA_SID_GET_CKN_STATUS)) {
        return E_NOT_OK;
    }
    pae = &Mka_Pae[MkaPaeIdx];
    idx = mka_find_ckn(pae, Ckn, CknLength);
    if (idx < 0) {
        return E_NOT_OK;
    }
    /* Once the PAE is running, report what is running rather than what was
     * asked for. cknEnabled is the integrator's request - Mka_StartPae and
     * Mka_SetCknStatus both leave it set when the instantiation fails, so that
     * a later call can retry - and reporting it back on a started PAE would
     * claim a CKN is enabled when the KaY holds no participant for it. Reading
     * the KaY keeps this on the same footing as Mka_GetPaeStatus: the binding
     * is a shim over one state machine, not a second one. */
    if (pae->started != FALSE) {
        *EnablePtr =
            (wm_Kay_Find(&pae->kay, Ckn, CknLength) != NULL) ? TRUE : FALSE;
    }
    else {
        *EnablePtr = pae->cknEnabled[idx];
    }
    return E_OK;
}

/* Store the PAE's enable flag. */
Std_ReturnType Mka_SetEnable(uint8 MkaPaeIdx, boolean Enable)
{
    if (!mka_pae_ok_det(MkaPaeIdx, MKA_SID_SET_ENABLE)) {
        return E_NOT_OK;
    }
    /* Normalised like Mka_SetCknStatus: boolean is a uint8, so storing the
     * caller's value verbatim would let Mka_GetEnable hand back something that
     * is neither TRUE nor FALSE. */
    Mka_Pae[MkaPaeIdx].enabled = (Enable != FALSE) ? TRUE : FALSE;

    if (Enable == FALSE) {
        Mka_PaeRtType* pae = &Mka_Pae[MkaPaeIdx];

        /* Disabling a PAE means the connection is no longer viable, so tear it
         * down rather than merely stop ticking it. wm_Kay_Free deletes every
         * SecY SA its participants installed and wipes their key material.
         *
         * Without this the flag stopped Mka_MainFunction stepping the KaY and
         * Mka_RxIndication routing to it, while every SAK stayed programmed:
         * the controlled port went on protecting traffic with a key whose
         * control plane was no longer running, the far end eventually expired
         * this member and rekeyed, and the port was left encrypting with a key
         * nobody else held. It is the same argument Mka_Init makes for its own
         * teardown, and it is why Mka_SetCknStatus(..., FALSE, ...) already
         * removes the participant for a single CKN.
         *
         * `started` is cleared with it: the PAE must be started again, which is
         * what re-instantiates the enabled CKNs. A link bounce is deliberately
         * *not* treated this way - see Mka_LinkStateChange. */
        wm_Kay_Free(&pae->kay);
        pae->started = FALSE;
    }
    return E_OK;
}

/* Return the PAE's stored enable flag. */
Std_ReturnType Mka_GetEnable(uint8 MkaPaeIdx, boolean* EnablePtr)
{
    if (!mka_pae_ok_det(MkaPaeIdx, MKA_SID_GET_ENABLE) ||
        !mka_ptr_ok_det(EnablePtr, MKA_SID_GET_ENABLE)) {
        return E_NOT_OK;
    }
    *EnablePtr = Mka_Pae[MkaPaeIdx].enabled;
    return E_OK;
}

/**
 * Translate one participant's MkaPaeState into the AUTOSAR status enumeration.
 *
 * The KaY already computes this ladder (wm_Participant_GetPaeStatus), and the
 * binding is a shim: deriving it a second time from wm_Participant_HasSak and
 * wm_Participant_LivePeerCount gave two state machines answering one question,
 * and they had already drifted apart. MKA_PAE_WAITING_FOR_LINK_UP is never
 * returned by the KaY - link state is the binding's own - so it has no case
 * here; Mka_GetPaeStatus reports WAITING_PEER_LINK from pae->link before this
 * is reached.
 * @param[in] st  the participant's state.
 * @return the corresponding Mka_MkaStatusType.
 */
static Mka_MkaStatusType mka_status_from_pae(MkaPaeState st)
{
    Mka_MkaStatusType out;

    switch (st) {
        case MKA_PAE_RUNNING: out = MKA_STATUS_MACSEC_RUNNING; break;
        case MKA_PAE_IN_PROGRESS: out = MKA_STATUS_IN_PROGRESS; break;
        case MKA_PAE_AUTH_FAIL_UNKNOWN_PEER:
            out = MKA_STATUS_AUTH_FAIL_UNKNOWN_PEER;
            break;
        case MKA_PAE_WAITING_FOR_PEER:
        case MKA_PAE_WAITING_FOR_LINK_UP:
        case MKA_PAE_UNDEFINED:
        default: out = MKA_STATUS_WAITING_PEER; break;
    }
    return out;
}

/**
 * Rank of a status for the cross-participant aggregate.
 *
 * Ordered by how much the integrator can act on, which for the first three is
 * the same as how far the CA has got: running beats in-progress beats waiting.
 * The exception is AUTH_FAIL_UNKNOWN_PEER, ranked above WAITING_PEER because it
 * is the more informative of the two - one CA failing to authenticate is a
 * configured CAK that does not match, which is worth reporting even while
 * another CA on the same PAE is merely quiet.
 * @param[in] st  the status to rank.
 * @return a rank; the highest across a PAE's CAs is the one reported.
 */
static uint8 mka_status_rank(Mka_MkaStatusType st)
{
    uint8 rank;

    switch (st) {
        case MKA_STATUS_MACSEC_RUNNING: rank = 3U; break;
        case MKA_STATUS_IN_PROGRESS: rank = 2U; break;
        case MKA_STATUS_AUTH_FAIL_UNKNOWN_PEER: rank = 1U; break;
        default: rank = 0U; break;
    }
    return rank;
}

/**
 * Aggregate the KaY's state across a PAE's participants.
 *
 * A PAE runs one CA per configured CKN, and the AUTOSAR status is per PAE, so
 * the most advanced state any CA has reached is the one reported - the same
 * "any participant" rule the previous SAK/live-peer aggregate used.
 * @param[in] pae  the PAE runtime block.
 * @return the aggregated status for an enabled, linked PAE.
 */
static Mka_MkaStatusType mka_active_status(const Mka_PaeRtType* pae)
{
    Mka_MkaStatusType best = MKA_STATUS_WAITING_PEER;
    size_t i;

    for (i = 0U; i < pae->kay.count; i++) {
        MkaPaeStatus ps;
        Mka_MkaStatusType st;

        /* Seeded rather than tested for: wm_Participant_GetPaeStatus fails only
         * on a NULL argument, and neither of these can be NULL, so branching on
         * its return would add an outcome no test could ever reach. UNDEFINED
         * maps to the lowest-ranked status, so a hypothetical failure loses to
         * every real one instead of winning. */
        ps.state = MKA_PAE_UNDEFINED;
        (void)wm_Participant_GetPaeStatus(&pae->kay.parts[i], &ps);
        st = mka_status_from_pae(ps.state);
        if (mka_status_rank(st) > mka_status_rank(best)) {
            best = st;
        }
    }
    return best;
}

Std_ReturnType Mka_GetPaeStatus(uint8 MkaPaeIdx,
    Mka_PaeStatusType* PaeStatusPtr)
{
    const Mka_PaeRtType* pae;

    if (!mka_pae_ok_det(MkaPaeIdx, MKA_SID_GET_PAE_STATUS) ||
        !mka_ptr_ok_det(PaeStatusPtr, MKA_SID_GET_PAE_STATUS)) {
        return E_NOT_OK;
    }
    pae = &Mka_Pae[MkaPaeIdx];
    PaeStatusPtr->ConnectionStatus = pae->link;
    PaeStatusPtr->PermissivePlaintext = FALSE;

    /* A disabled PAE reports no status; without link there is no peer yet. */
    if (!pae->enabled) {
        PaeStatusPtr->MkaStatus = MKA_STATUS_UNDEFINED;
        return E_OK;
    }
    if (pae->link != ETHTRCV_LINK_STATE_ACTIVE) {
        PaeStatusPtr->MkaStatus = MKA_STATUS_WAITING_PEER_LINK;
        return E_OK;
    }

    PaeStatusPtr->PermissivePlaintext = pae->permissiveOpen;
    PaeStatusPtr->MkaStatus = mka_active_status(pae);
    return E_OK;
}

/* Store the PAE's permissive mode. Rejects a value outside the enumeration
 * rather than storing it: with no Det to report the misuse, silently treating
 * an unknown mode as NEVER would leave an integrator who passed the wrong
 * constant with no indication of it. */
Std_ReturnType Mka_SetPaePermissiveMode(uint8 MkaPaeIdx,
    Mka_PermissiveModeType PermissiveMode)
{
    if (!mka_pae_ok_det(MkaPaeIdx, MKA_SID_SET_PAE_PERMISSIVE_MODE)) {
        return E_NOT_OK;
    }
    if ((PermissiveMode != MKA_PERMISSIVE_MODE_NEVER) &&
        (PermissiveMode != MKA_PERMISSIVE_MODE_TIMEOUT)) {
        MKA_DET_REPORT_ERROR(MKA_SID_SET_PAE_PERMISSIVE_MODE,
            MKA_E_PARAM_INVALID);
        return E_NOT_OK;
    }
    Mka_Pae[MkaPaeIdx].permissive = PermissiveMode;
    if (PermissiveMode != MKA_PERMISSIVE_MODE_TIMEOUT) {
        /* Take effect at once rather than at the next Mka_MainFunction, so a
         * status read in between cannot still report plaintext as permitted. */
        Mka_Pae[MkaPaeIdx].permissiveOpen = FALSE;
    }
    return E_OK;
}

/* Instantiate every enabled CKN not already running as a participant, then mark
 * the PAE started; report failure if any participant could not be created. */
Std_ReturnType Mka_StartPae(uint8 MkaPaeIdx)
{
    Mka_PaeRtType* pae;
    uint8 j;
    uint8 cknCount;
    Std_ReturnType rc = E_OK;

    if (!mka_pae_ok_det(MkaPaeIdx, MKA_SID_START_PAE)) {
        return E_NOT_OK;
    }
    pae = &Mka_Pae[MkaPaeIdx];
    cknCount = mka_ckn_count(pae);
    if (cknCount > (uint8)MKA_MAX_PARTICIPANTS) {
        /* As the PAE count: silently stopping at the bound would leave the
         * surplus CAKs uninstantiated while this still returned E_OK, so not
         * even the return value carried a signal. Report it and refuse - the
         * CKNs within the bound are still instantiated below, since a port
         * running some of its CAs beats a port running none. */
        MKA_DET_REPORT_ERROR(MKA_SID_START_PAE, MKA_E_PARAM_INVALID);
        rc = E_NOT_OK;
        cknCount = (uint8)MKA_MAX_PARTICIPANTS;
    }
    /* Instantiate every enabled CKN that is not already a participant. */
    for (j = 0U; j < cknCount; j++) {
        if (pae->cknEnabled[j] && (wm_Kay_Find(&pae->kay, pae->cfg->Ckns[j].Ckn,
                                       pae->cfg->Ckns[j].CknLength) == NULL)) {
            if (mka_add_ckn(pae, &pae->cfg->Ckns[j]) != E_OK) {
                /* keep going; report failure at the end */
                rc = E_NOT_OK;
            }
        }
    }
    /* Started means "this PAE has a Certificate Authority it can actually run".
     * A PAE whose every CKN failed to instantiate has none, and marking it
     * started anyway would make it "active" for mka_permissive_update: it would
     * accumulate unsecured time it can never end and, under
     * MKA_PERMISSIVE_MODE_TIMEOUT, latch the controlled port open in plaintext.
     * Permissive mode answers "MKA could not establish a Secure Channel with
     * the peer", not "this ECU's own configuration is broken" - so this fails
     * closed, as the zero-timeout case above does. The enable flags are left
     * alone, so calling Mka_StartPae again retries the instantiation. */
    if (wm_Kay_ParticipantCount(&pae->kay) > (size_t)0) {
        pae->started = TRUE;
    }
    return rc;
}

/* Record an asynchronous statistics request (rejected if one is already in
 * flight); the SecY fills the buffer and confirms via the notification. */
/**
 * Narrow a 64-bit SecY counter into the 32-bit AUTOSAR statistic.
 *
 * MkaSecyStats counts in uint64 and Mka_Stats_SecYType in uint32 (SWS 8.2.10),
 * so the value has to lose its top half somewhere. It is pegged rather than
 * wrapped: a diagnostic reader can act on 0xFFFFFFFF, which says "at least this
 * many", but a wrapped value is simply a wrong number, and the counter appears
 * to run backwards with nothing to say why. On a sustained gigabit link of
 * small frames a packet counter reaches 2^32 in about a day.
 * @param[in] v  the 64-bit counter.
 * @return v, or UINT32_MAX if it does not fit.
 */
static uint32 mka_sat32(uint64_t v)
{
    return (v > (uint64_t)0xFFFFFFFFU) ? (uint32)0xFFFFFFFFU : (uint32)v;
}

Std_ReturnType Mka_GetMacSecStatistics(uint8 MkaPaeIdx,
    Mka_Stats_SecYType* MacSecStatsPtr)
{
    Mka_PaeRtType* pae;

    if (!mka_pae_ok_det(MkaPaeIdx, MKA_SID_GET_MACSEC_STATISTICS) ||
        !mka_ptr_ok_det(MacSecStatsPtr, MKA_SID_GET_MACSEC_STATISTICS)) {
        return E_NOT_OK;
    }
    pae = &Mka_Pae[MkaPaeIdx];
    if (pae->statsPending != FALSE) {
        /* a request is already in flight */
        return E_NOT_OK;
    }
    /* Counters live in the data plane, so the buffer starts cleared. */
    (void)WOLFMKA_MEMSET(MacSecStatsPtr, 0, sizeof *MacSecStatsPtr);

    /* Where the data plane exposes its counters through the SecY hook, the
     * request is answered here and now. */
    if (pae->kay.count > 0U) {
        MkaSecyStats st;
        if (wm_Participant_GetSecyStats(&pae->kay.parts[0], &st) == MKA_OK) {
            MacSecStatsPtr->InPktsUntagged = mka_sat32(st.in_pkts_untagged);
            MacSecStatsPtr->InPktsNoTag = mka_sat32(st.in_pkts_no_tag);
            MacSecStatsPtr->InPktsBadTag = mka_sat32(st.in_pkts_bad_tag);
            MacSecStatsPtr->InPktsOverrun = mka_sat32(st.in_pkts_overrun);
            MacSecStatsPtr->OutPktsUntagged = mka_sat32(st.out_pkts_untagged);
            MacSecStatsPtr->OutPktsTooLong = mka_sat32(st.out_pkts_too_long);
            /* Answered synchronously, so no notification will follow and the
             * pending latch must not be set. Setting it used to wedge the API
             * permanently against wolfMKA's own SecY, which is synchronous:
             * nothing would ever call Mka_GetMacSecStatisticsNotification, and
             * every later request returned E_NOT_OK for the life of the ECU. */
            pae->statsPtr = NULL;
            return E_OK;
        }
    }

    /* Otherwise the SWS asynchronous handshake (8.3.10): record the request,
     * and let a MacSec module that fills the buffer itself confirm through
     * Mka_GetMacSecStatisticsNotification. */
    pae->statsPtr = MacSecStatsPtr;
    pae->statsPending = TRUE;
    return E_OK;
}

/* Store the new link state. Authentication state itself lives in the KaY and is
 * not reset here: a link transition does not change which CAK the far end
 * holds. */
Std_ReturnType Mka_LinkStateChange(uint8 MkaPaeIdx,
    EthTrcv_LinkStateType TransceiverLinkState)
{
    if (!mka_pae_ok_det(MkaPaeIdx, MKA_SID_LINK_STATE_CHANGE)) {
        return E_NOT_OK;
    }
    /* Same argument as Mka_SetPaePermissiveMode: silently storing an
     * unrecognised value would leave an integrator who passed the wrong
     * constant with no indication of it. Treating it as no-link would at least
     * fail closed, but the value is also handed straight back out as
     * Mka_PaeStatusType::ConnectionStatus, so a typo would round-trip through
     * the module unflagged. */
    if ((TransceiverLinkState != ETHTRCV_LINK_STATE_DOWN) &&
        (TransceiverLinkState != ETHTRCV_LINK_STATE_ACTIVE)) {
        MKA_DET_REPORT_ERROR(MKA_SID_LINK_STATE_CHANGE, MKA_E_PARAM_INVALID);
        return E_NOT_OK;
    }
    Mka_Pae[MkaPaeIdx].link = TransceiverLinkState;
    return E_OK;
}

/* Route a received frame to the owning PAE's KaY, when that PAE is live. */
void Mka_RxIndication(PduIdType RxPduId, const PduInfoType* PduInfoPtr)
{
    Mka_PaeRtType* pae;

    if (!Mka_Initialized) {
        MKA_DET_REPORT_ERROR(MKA_SID_RX_INDICATION, MKA_E_UNINIT);
        return;
    }
    if ((PduInfoPtr == NULL) || (PduInfoPtr->SduDataPtr == NULL)) {
        MKA_DET_REPORT_ERROR(MKA_SID_RX_INDICATION, MKA_E_PARAM_POINTER);
        return;
    }
    /* Route the frame to its PAE's KaY, but only once that PAE is live. */
    pae = mka_find_by_rx_pdu(RxPduId);
    if ((pae != NULL) && pae->enabled && pae->started) {
        /* The outcome needs no tracking here: the KaY counts ICV failures and
         * verified MKPDUs itself, and Mka_GetPaeStatus reads its ladder rather
         * than deriving a second one. */
        (void)wm_Kay_Receive(&pae->kay, PduInfoPtr->SduDataPtr,
            PduInfoPtr->SduLength, Mka_TimeMs);
    }
}

/* No-op: wolfMKA transmits synchronously through the send callback, so there is
 * nothing to confirm asynchronously. */
void Mka_TxConfirmation(PduIdType TxPduId, Std_ReturnType result)
{
    (void)TxPduId;
    (void)result;
    /* Nothing to confirm - wolfMKA transmits synchronously - but a call before
     * Mka_Init is still a sequencing mistake worth reporting. The behaviour is
     * a no-op either way. */
    if (!Mka_Initialized) {
        MKA_DET_REPORT_ERROR(MKA_SID_TX_CONFIRMATION, MKA_E_UNINIT);
    }
}

/* Release the pending statistics request and record the SecY's outcome. */
void Mka_GetMacSecStatisticsNotification(uint8 MkaPaeIdx, Std_ReturnType Result)
{
    Mka_PaeRtType* pae;

    if (!mka_pae_ok_det(MkaPaeIdx, MKA_SID_GET_MACSEC_STATISTICS_NOTIF)) {
        return;
    }
    /* The SecY has filled the buffer handed to Mka_GetMacSecStatistics; release
     * the pending request and record the outcome. */
    pae = &Mka_Pae[MkaPaeIdx];
    pae->statsPending = FALSE;
    pae->statsPtr = NULL;
    pae->lastSecyResult = Result;
}

/* Route one AUTOSAR MacSec completion to the right wolfMKA participant.
 *
 * Each MacSec notification acknowledges exactly ONE SA operation, but it names
 * only the PAE (controlled port), not the CKN. The completion is therefore
 * delivered to a single participant - the one with an operation outstanding -
 * and clears exactly one pending op, so a PAE carrying several CKNs no longer
 * over-decrements the participants the notification was not for. At most one
 * participant on a PAE installs SAs at a time (the active CA); if more than one
 * had work outstanding the per-PAE notification could not disambiguate them, so
 * the first is chosen. wolfMKA's own SecY adapter is synchronous (never returns
 * MKA_SECY_PENDING), so secy_pending is zero everywhere and this is a no-op
 * today; it wires the path for an asynchronous MacSec module.
 */
static void mka_pae_secy_complete(Mka_PaeRtType* pae)
{
    size_t i;
    boolean done = FALSE;

    for (i = 0U; (i < pae->kay.count) && !done; i++) {
        if (pae->kay.parts[i].secy_pending > 0U) {
            (void)wm_Participant_SecyComplete(&pae->kay.parts[i]);
            done = TRUE;
        }
    }
}

/* SecY configuration update acknowledged: record the outcome and release any
 * transmit gate held for an asynchronous MacSec module. */
void Mka_MacSecUpdateSecYNotification(uint8 MkaPaeIdx, Std_ReturnType Result)
{
    if (mka_pae_ok_det(MkaPaeIdx, MKA_SID_MACSEC_UPDATE_SECY_NOTIF) != FALSE) {
        Mka_Pae[MkaPaeIdx].lastSecyResult = Result;
        mka_pae_secy_complete(&Mka_Pae[MkaPaeIdx]);
    }
}

/* Add-transmit-SA acknowledged: record the outcome and release the transmit
 * gate for an asynchronous MacSec module. */
void Mka_MacSecAddTxSaNotification(uint8 MkaPaeIdx, Std_ReturnType Result)
{
    if (mka_pae_ok_det(MkaPaeIdx, MKA_SID_MACSEC_ADD_TX_SA_NOTIF) != FALSE) {
        Mka_Pae[MkaPaeIdx].lastSecyResult = Result;
        mka_pae_secy_complete(&Mka_Pae[MkaPaeIdx]);
    }
}

/* Add-receive-SA acknowledged: record the outcome and release any transmit gate
 * held for an asynchronous MacSec module. */
void Mka_MacSecAddRxSaNotification(uint8 MkaPaeIdx, Std_ReturnType Result)
{
    if (mka_pae_ok_det(MkaPaeIdx, MKA_SID_MACSEC_ADD_RX_SA_NOTIF) != FALSE) {
        Mka_Pae[MkaPaeIdx].lastSecyResult = Result;
        mka_pae_secy_complete(&Mka_Pae[MkaPaeIdx]);
    }
}

/* Advance the permissive timer for every PAE, tick each live PAE's KaY, then
 * advance the shared MKA millisecond clock. */
void Mka_MainFunction(void)
{
    uint8 i;

    if (!Mka_Initialized) {
        /* Reported once per uninitialised period, not once per call.
         *
         * A BSW scheduler calls main functions cyclically and unconditionally.
         * If Mka_Init has not run - or ran and refused the configuration, which
         * leaves Mka_Initialized FALSE for good - the scheduler keeps calling
         * this forever, so reporting every time would be one message per tick,
         * indefinitely, at whatever rate the task is configured for. The first
         * one already says everything the rest would.
         *
         * It is still worth that one: an integration that schedules the main
         * function but never calls Mka_Init, and calls no other API, has
         * nothing else to tell it so. The other entry points report on every
         * call instead, because they are called by code that chose the moment -
         * there one report answers one mistake. */
        if (!Mka_UninitReported) {
            Mka_UninitReported = TRUE;
            MKA_DET_REPORT_ERROR(MKA_SID_MAIN_FUNCTION, MKA_E_UNINIT);
        }
        return;
    }
    /* Tick every PAE that is live, advance the permissive timer for all, then
     * advance the shared MKA clock. */
    for (i = 0U; i < Mka_PaeCount; i++) {
        Mka_PaeRtType* pae = &Mka_Pae[i];
        mka_permissive_update(pae, Mka_Cfg->MainFunctionPeriodMs);
        if (pae->enabled && pae->started &&
            (pae->link == ETHTRCV_LINK_STATE_ACTIVE)) {
            /* A per-CA failure - a crypto error during SAK generation, say -
             * used to be discarded here, leaving the PAE sitting at
             * WAITING_PEER with nothing to say why. Report it, but only on the
             * transition into failure: the condition usually persists, and one
             * Det message per tick would bury the rest of the log. The run
             * continues either way, so one CA's failure cannot stall the
             * others. */
            if (wm_Kay_Run(&pae->kay, Mka_TimeMs) != MKA_OK) {
                if (!pae->runFailed) {
                    pae->runFailed = TRUE;
                    MKA_DET_REPORT_ERROR(MKA_SID_MAIN_FUNCTION,
                        MKA_E_KAY_RUN_FAILED);
                }
            }
            else {
                pae->runFailed = FALSE;
            }
        }
    }
    Mka_TimeMs += Mka_Cfg->MainFunctionPeriodMs;
}
