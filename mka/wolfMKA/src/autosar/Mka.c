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
 */
#include "wolfmka/autosar/Mka.h"
#include "wolfmka/mka_crypto.h"

#include <string.h>

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
    /** time active without a SAK */
    uint32 unsecuredMs;
    /** permissive plaintext now allowed */
    boolean permissiveOpen;
    /** last RX failed ICV verification */
    boolean authFailed;
    /** per-CKN */
    boolean cknEnabled[MKA_MAX_PARTICIPANTS];
    /* Asynchronous SecY/statistics handshake (8.4). */
    /** pending stats buffer */
    Mka_Stats_SecYType* statsPtr;
    /** stats request in flight */
    boolean statsPending;
    /** last SecY result */
    Std_ReturnType lastSecyResult;
} Mka_PaeRtType;

static Mka_PaeRtType Mka_Pae[MKA_MAX_PAES];
static const Mka_ConfigType* Mka_Cfg;
static uint8 Mka_PaeCount;
static boolean Mka_Initialized = FALSE;
static uint32 Mka_TimeMs;
/* One CMAC workspace shared by every participant: AUTOSAR BSW is single
 * threaded and a participant's CMAC operations do not nest, so the contexts are
 * used sequentially. Acquired once in Mka_Init. */
static MkaCmacCtx* Mka_Cmac;

/**
 * Bridge wolfMKA's send callback to the PAE's transmit function.
 * @param[in] ctx    The PAE runtime block (set as the participant's send
 *                   context).
 * @param[in] frame  The complete EAPOL-MKA frame to transmit.
 * @param[in] len    Frame length in octets.
 * @return 0 if the frame was accepted by the lower layer, else -1.
 */
static int Mka_SendBridge(void* ctx, const uint8_t* frame, size_t len)
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
static Std_ReturnType Mka_AddCkn(Mka_PaeRtType* pae,
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

    (void)memset(&pc, 0, sizeof pc);
    (void)memcpy(pc.cak.cak, ckn->Cak, ckn->CakLength);
    pc.cak.cak_len = ckn->CakLength;
    (void)memcpy(pc.cak.ckn, ckn->Ckn, ckn->CknLength);
    pc.cak.ckn_len = ckn->CknLength;
    (void)memcpy(pc.sci, c->Sci, MKA_SCI_LEN);
    pc.priority = c->Priority;
    pc.macsec_desired = TRUE;
    pc.macsec_capability = (uint8)MKA_CAP_INTEGRITY_CONF;
    pc.key_server_capable = (boolean)(c->Role != MKA_ROLE_PEER);
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
    pc.send = Mka_SendBridge;
    pc.send_ctx = pae;
    pc.cmac = Mka_Cmac;

    status = wm_Kay_AddParticipant(&pae->kay, &pc, NULL);
    return (status == MKA_OK) ? E_OK : E_NOT_OK;
}

/**
 * Find a PAE by its receive PDU id.
 * @param[in] id  The receive PDU id to match.
 * @return The matching PAE runtime block, or NULL if none matches.
 */
static Mka_PaeRtType* Mka_FindByRxPdu(PduIdType id)
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
 * Find a configured CKN index within a PAE.
 *
 * A PAE runs at most MKA_MAX_PARTICIPANTS participants, so CKNs configured
 * beyond that bound are not tracked (keeping the index within cknEnabled[]).
 * @param[in] pae  The PAE runtime block.
 * @param[in] ckn  The CAK Name to match.
 * @param[in] len  Length of @p ckn in octets.
 * @return The CKN index (0 .. MKA_MAX_PARTICIPANTS-1), or -1 if not found.
 */
static int Mka_FindCkn(const Mka_PaeRtType* pae, const uint8* ckn, uint8 len)
{
    uint8 i;
    uint8 cknCount = pae->cfg->CknCount;

    for (i = 0U; (i < cknCount) && (i < (uint8)MKA_MAX_PARTICIPANTS); i++) {
        const Mka_CknConfigType* k = &pae->cfg->Ckns[i];
        if ((k->CknLength == len) && (memcmp(k->Ckn, ckn, len) == 0)) {
            return (int)i;
        }
    }
    return -1;
}

/**
 * Validate that the module is initialised and @p idx names a PAE.
 * @param[in] idx  The PAE index to check.
 * @return TRUE if usable, FALSE otherwise.
 */
static boolean Mka_PaeOk(uint8 idx)
{
    return (boolean)(Mka_Initialized && (idx < Mka_PaeCount));
}

/**
 * Whether any of a PAE's participants has an installed SAK (MACsec is up).
 * @param[in] pae  The PAE runtime block.
 * @return TRUE if at least one participant has a SAK, else FALSE.
 */
static boolean Mka_PaeHasSak(const Mka_PaeRtType* pae)
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
static void Mka_PermissiveUpdate(Mka_PaeRtType* pae, uint32 periodMs)
{
    boolean active = (boolean)(pae->enabled && pae->started &&
                               (pae->link == ETHTRCV_LINK_STATE_ACTIVE));

    if (!active || Mka_PaeHasSak(pae)) {
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
    if ((pae->permissive == MKA_PERMISSIVE_MODE_TIMEOUT) &&
        (pae->unsecuredMs >= pae->cfg->PermissiveTimeoutMs)) {
        pae->permissiveOpen = TRUE;
    }
}

/* Reset every PAE, clamp the PAE count to the static array, and give each an
 * empty KaY with its per-CKN enables seeded from the configuration. */
void Mka_Init(const Mka_ConfigType* ConfigPtr)
{
    uint8 i;

    Mka_Initialized = FALSE;
    if (ConfigPtr == NULL) {
        return;
    }
    /* Acquire the shared CMAC workspace once (the CMAC-consuming API requires a
     * caller-supplied one); without it no participant can run. */
    if (Mka_Cmac == NULL) {
        Mka_Cmac = wm_Crypto_CmacInit();
    }
    if (Mka_Cmac == NULL) {
        return;
    }
    Mka_Cfg = ConfigPtr;
    Mka_TimeMs = 0U;
    /* Honour the configured PAE count, but never exceed the static array. */
    Mka_PaeCount = (ConfigPtr->PaeCount < (uint8)MKA_MAX_PAES)
                       ? ConfigPtr->PaeCount
                       : (uint8)MKA_MAX_PAES;

    for (i = 0U; i < Mka_PaeCount; i++) {
        Mka_PaeRtType* pae = &Mka_Pae[i];
        uint8 j;
        uint8 cknCount;

        /* Reset the PAE to a known idle state and give it an empty KaY. */
        (void)memset(pae, 0, sizeof *pae);
        pae->cfg = &ConfigPtr->Paes[i];
        pae->enabled = FALSE;
        pae->started = FALSE;
        pae->link = ETHTRCV_LINK_STATE_DOWN;
        pae->permissive = MKA_PERMISSIVE_MODE_NEVER;
        (void)wm_Kay_Init(&pae->kay);

        cknCount = pae->cfg->CknCount;
        /* Seed each CKN's enabled state from its configured default. */
        for (j = 0U; (j < cknCount) && (j < (uint8)MKA_MAX_PARTICIPANTS); j++) {
            pae->cknEnabled[j] = pae->cfg->Ckns[j].DefaultEnabled;
        }
    }
    Mka_Initialized = TRUE;
}

/* Copy the compile-time vendor/module/version constants into the caller's
 * buffer. */
void Mka_GetVersionInfo(Std_VersionInfoType* VersionInfoPtr)
{
    if (VersionInfoPtr == NULL) {
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

    if (!Mka_PaeOk(MkaPaeIdx) || (Ckn == NULL)) {
        return E_NOT_OK;
    }
    pae = &Mka_Pae[MkaPaeIdx];
    idx = Mka_FindCkn(pae, Ckn, CknLength);
    if (idx < 0) {
        return E_NOT_OK;
    }
    pae->cknEnabled[idx] = (boolean)(Enable != FALSE);

    if (Enable != FALSE) {
        /* If already running, instantiate the participant on enable. */
        if (pae->started && (wm_Kay_Find(&pae->kay, Ckn, CknLength) == NULL)) {
            return Mka_AddCkn(pae, &pae->cfg->Ckns[idx]);
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
    const Mka_PaeRtType* pae;
    int idx;

    if (!Mka_PaeOk(MkaPaeIdx) || (Ckn == NULL) || (EnablePtr == NULL)) {
        return E_NOT_OK;
    }
    pae = &Mka_Pae[MkaPaeIdx];
    idx = Mka_FindCkn(pae, Ckn, CknLength);
    if (idx < 0) {
        return E_NOT_OK;
    }
    *EnablePtr = pae->cknEnabled[idx];
    return E_OK;
}

/* Store the PAE's enable flag. */
Std_ReturnType Mka_SetEnable(uint8 MkaPaeIdx, boolean Enable)
{
    if (!Mka_PaeOk(MkaPaeIdx)) {
        return E_NOT_OK;
    }
    Mka_Pae[MkaPaeIdx].enabled = Enable;
    return E_OK;
}

/* Return the PAE's stored enable flag. */
Std_ReturnType Mka_GetEnable(uint8 MkaPaeIdx, boolean* EnablePtr)
{
    if (!Mka_PaeOk(MkaPaeIdx) || (EnablePtr == NULL)) {
        return E_NOT_OK;
    }
    *EnablePtr = Mka_Pae[MkaPaeIdx].enabled;
    return E_OK;
}

/* Derive the reported status from the link state plus the PAE's aggregated
 * SAK / live-peer / ICV-failure state. */
/**
 * Aggregate state across a PAE's participants.
 * @param[in]  pae      the PAE runtime block.
 * @param[out] hasSak   set TRUE if any participant has an installed SAK.
 * @param[out] hasPeer  set TRUE if any participant has a live peer.
 */
static void mka_pae_aggregate(const Mka_PaeRtType* pae, boolean* hasSak,
    boolean* hasPeer)
{
    size_t i;

    *hasSak = FALSE;
    *hasPeer = FALSE;
    for (i = 0U; i < pae->kay.count; i++) {
        const MkaParticipant* p = &pae->kay.parts[i];
        if (wm_Participant_HasSak(p)) {
            *hasSak = TRUE;
        }
        if (wm_Participant_LivePeerCount(p) > 0U) {
            *hasPeer = TRUE;
        }
    }
}

/**
 * Map an enabled, linked PAE's aggregated state to its MKA status.
 * @param[in] pae      the PAE runtime block (for the auth-failure flag).
 * @param[in] hasSak   whether any participant has an installed SAK.
 * @param[in] hasPeer  whether any participant has a live peer.
 * @return MACSEC_RUNNING / IN_PROGRESS / AUTH_FAIL_UNKNOWN_PEER / WAITING_PEER.
 */
static Mka_MkaStatusType mka_active_status(const Mka_PaeRtType* pae,
    boolean hasSak, boolean hasPeer)
{
    Mka_MkaStatusType st;

    if (hasSak) {
        st = MKA_STATUS_MACSEC_RUNNING;
    }
    else if (hasPeer) {
        st = MKA_STATUS_IN_PROGRESS;
    }
    else if (pae->authFailed) {
        /* Frames are arriving but failing ICV verification (e.g. a CAK/CKN
         * mismatch with the peer), so authentication - not peer presence - is
         * the problem. */
        st = MKA_STATUS_AUTH_FAIL_UNKNOWN_PEER;
    }
    else {
        st = MKA_STATUS_WAITING_PEER;
    }
    return st;
}

Std_ReturnType Mka_GetPaeStatus(uint8 MkaPaeIdx,
    Mka_PaeStatusType* PaeStatusPtr)
{
    const Mka_PaeRtType* pae;
    boolean hasSak;
    boolean hasPeer;

    if (!Mka_PaeOk(MkaPaeIdx) || (PaeStatusPtr == NULL)) {
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
    mka_pae_aggregate(pae, &hasSak, &hasPeer);
    PaeStatusPtr->MkaStatus = mka_active_status(pae, hasSak, hasPeer);
    return E_OK;
}

/* Store the PAE's permissive mode. */
Std_ReturnType Mka_SetPaePermissiveMode(uint8 MkaPaeIdx,
    Mka_PermissiveModeType PermissiveMode)
{
    if (!Mka_PaeOk(MkaPaeIdx)) {
        return E_NOT_OK;
    }
    Mka_Pae[MkaPaeIdx].permissive = PermissiveMode;
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

    if (!Mka_PaeOk(MkaPaeIdx)) {
        return E_NOT_OK;
    }
    pae = &Mka_Pae[MkaPaeIdx];
    cknCount = pae->cfg->CknCount;
    /* Instantiate every enabled CKN that is not already a participant. */
    for (j = 0U; (j < cknCount) && (j < (uint8)MKA_MAX_PARTICIPANTS); j++) {
        if (pae->cknEnabled[j] && (wm_Kay_Find(&pae->kay, pae->cfg->Ckns[j].Ckn,
                                       pae->cfg->Ckns[j].CknLength) == NULL)) {
            if (Mka_AddCkn(pae, &pae->cfg->Ckns[j]) != E_OK) {
                /* keep going; report failure at the end */
                rc = E_NOT_OK;
            }
        }
    }
    pae->started = TRUE;
    return rc;
}

/* Record an asynchronous statistics request (rejected if one is already in
 * flight); the SecY fills the buffer and confirms via the notification. */
Std_ReturnType Mka_GetMacSecStatistics(uint8 MkaPaeIdx,
    Mka_Stats_SecYType* MacSecStatsPtr)
{
    Mka_PaeRtType* pae;

    if (!Mka_PaeOk(MkaPaeIdx) || (MacSecStatsPtr == NULL)) {
        return E_NOT_OK;
    }
    pae = &Mka_Pae[MkaPaeIdx];
    if (pae->statsPending) {
        /* a request is already in flight */
        return E_NOT_OK;
    }
    /* Asynchronous (8.3.10): record the request; the SecY fills the buffer and
     * confirms via Mka_GetMacSecStatisticsNotification. Counters live in the
     * data plane, so the buffer is cleared here as a starting point. */
    (void)memset(MacSecStatsPtr, 0, sizeof *MacSecStatsPtr);
    pae->statsPtr = MacSecStatsPtr;
    pae->statsPending = TRUE;
    return E_OK;
}

/* Store the new link state and clear the ICV-failure latch. */
Std_ReturnType Mka_LinkStateChange(uint8 MkaPaeIdx,
    EthTrcv_LinkStateType TransceiverLinkState)
{
    if (!Mka_PaeOk(MkaPaeIdx)) {
        return E_NOT_OK;
    }
    Mka_Pae[MkaPaeIdx].link = TransceiverLinkState;
    /* A link transition restarts authentication; clear any stale ICV-fail. */
    Mka_Pae[MkaPaeIdx].authFailed = FALSE;
    return E_OK;
}

/* Route a received frame to the owning PAE's KaY (when live) and latch any ICV
 * verification failure for status reporting. */
void Mka_RxIndication(PduIdType RxPduId, const PduInfoType* PduInfoPtr)
{
    Mka_PaeRtType* pae;

    if (!Mka_Initialized || (PduInfoPtr == NULL) ||
        (PduInfoPtr->SduDataPtr == NULL)) {
        return;
    }
    /* Route the frame to its PAE's KaY, but only once that PAE is live. */
    pae = Mka_FindByRxPdu(RxPduId);
    if ((pae != NULL) && pae->enabled && pae->started) {
        MkaStatus rc = wm_Kay_Receive(&pae->kay, PduInfoPtr->SduDataPtr,
            PduInfoPtr->SduLength, Mka_TimeMs);
        /* Track ICV authentication failures so Mka_GetPaeStatus can distinguish
         * "peer present but failing authentication" from "no peer yet". A frame
         * that verifies (or any non-ICV outcome) clears the latch. */
        if (rc == MKA_ERR_ICV) {
            pae->authFailed = TRUE;
        }
        else if (rc == MKA_OK) {
            pae->authFailed = FALSE;
        }
        else {
            /* other outcomes (parse, replay, foreign CKN) leave it unchanged */
        }
    }
}

/* No-op: wolfMKA transmits synchronously through the send callback, so there is
 * nothing to confirm asynchronously. */
void Mka_TxConfirmation(PduIdType TxPduId, Std_ReturnType result)
{
    (void)TxPduId;
    (void)result;
}

/* Release the pending statistics request and record the SecY's outcome. */
void Mka_GetMacSecStatisticsNotification(uint8 MkaPaeIdx, Std_ReturnType Result)
{
    Mka_PaeRtType* pae;

    if (!Mka_PaeOk(MkaPaeIdx)) {
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
static void Mka_PaeSecyComplete(Mka_PaeRtType* pae)
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
    if (Mka_PaeOk(MkaPaeIdx)) {
        Mka_Pae[MkaPaeIdx].lastSecyResult = Result;
        Mka_PaeSecyComplete(&Mka_Pae[MkaPaeIdx]);
    }
}

/* Add-transmit-SA acknowledged: record the outcome and release the transmit
 * gate for an asynchronous MacSec module. */
void Mka_MacSecAddTxSaNotification(uint8 MkaPaeIdx, Std_ReturnType Result)
{
    if (Mka_PaeOk(MkaPaeIdx)) {
        Mka_Pae[MkaPaeIdx].lastSecyResult = Result;
        Mka_PaeSecyComplete(&Mka_Pae[MkaPaeIdx]);
    }
}

/* Add-receive-SA acknowledged: record the outcome and release any transmit gate
 * held for an asynchronous MacSec module. */
void Mka_MacSecAddRxSaNotification(uint8 MkaPaeIdx, Std_ReturnType Result)
{
    if (Mka_PaeOk(MkaPaeIdx)) {
        Mka_Pae[MkaPaeIdx].lastSecyResult = Result;
        Mka_PaeSecyComplete(&Mka_Pae[MkaPaeIdx]);
    }
}

/* Advance the permissive timer for every PAE, tick each live PAE's KaY, then
 * advance the shared MKA millisecond clock. */
void Mka_MainFunction(void)
{
    uint8 i;

    if (!Mka_Initialized) {
        return;
    }
    /* Tick every PAE that is live, advance the permissive timer for all, then
     * advance the shared MKA clock. */
    for (i = 0U; i < Mka_PaeCount; i++) {
        Mka_PaeRtType* pae = &Mka_Pae[i];
        Mka_PermissiveUpdate(pae, Mka_Cfg->MainFunctionPeriodMs);
        if (pae->enabled && pae->started &&
            (pae->link == ETHTRCV_LINK_STATE_ACTIVE)) {
            (void)wm_Kay_Run(&pae->kay, Mka_TimeMs);
        }
    }
    Mka_TimeMs += Mka_Cfg->MainFunctionPeriodMs;
}
