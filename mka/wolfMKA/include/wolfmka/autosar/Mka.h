/**
 * @file Mka.h
 * AUTOSAR Classic Platform MACsec Key Agreement (Mka) API over wolfMKA.
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
 * Realises the AUTOSAR "Specification of MACsec Key Agreement" Mka module
 * (Document ID 1066) - its 8.2 types, 8.3 functions, 8.4 callbacks and 8.5 main
 * function - on top of the wolfMKA KaY (`mka_kay_*` / `mka_participant_*`). See
 * AUTOSAR.md for the conformance map.
 *
 * It is a portable library binding, not a generated AUTOSAR BSW module:
 * configuration is supplied as plain structs, and the lower-layer transmit
 * (EthIf) and the MACsec SecY are integrator-provided function pointers. The
 * mapping is: PAE -> MkaKay (one per controlled port), CKN -> MkaParticipant,
 * Mka_MainFunction -> wm_Kay_Run, Mka_RxIndication -> wm_Kay_Receive.
 */
#ifndef WOLFMKA_AUTOSAR_MKA_H
#define WOLFMKA_AUTOSAR_MKA_H

#include "wolfmka/autosar/Mka_Std.h"
#include "wolfmka/mka_kay.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Module / vendor identification (placeholders; set per integration). The
 * software version mirrors the library's WOLFMKA_VERSION_* (mka_types.h, pulled
 * in via mka_kay.h) so there is a single source of truth. */
#define MKA_VENDOR_ID        0U
#define MKA_MODULE_ID        0xFFU
#define MKA_SW_MAJOR_VERSION WOLFMKA_VERSION_MAJOR
#define MKA_SW_MINOR_VERSION WOLFMKA_VERSION_MINOR
#define MKA_SW_PATCH_VERSION WOLFMKA_VERSION_PATCH

/* Maximum number of PAEs (controlled ports) the module manages. */
#ifndef MKA_MAX_PAES
    #define MKA_MAX_PAES 4U
#endif

/** 8.2.12 Status of an MKA instance, reported by Mka_GetPaeStatus. */
typedef enum {
    /** SAK agreed; MACsec link up */
    MKA_STATUS_MACSEC_RUNNING = 0,
    /** waiting for link up */
    MKA_STATUS_WAITING_PEER_LINK = 1,
    /** waiting for a remote peer */
    MKA_STATUS_WAITING_PEER = 2,
    /** negotiation ongoing */
    MKA_STATUS_IN_PROGRESS = 3,
    /** peer ICVs invalid */
    MKA_STATUS_AUTH_FAIL_UNKNOWN_PEER = 4,
    /** PAE disabled / no status */
    MKA_STATUS_UNDEFINED = 0xFF
} Mka_MkaStatusType;

/** 8.2.9 Behaviour when a Secure Channel cannot be established. */
typedef enum {
    /** never enable without MACsec */
    MKA_PERMISSIVE_MODE_NEVER = 0,
    /** enable plaintext after a timeout */
    MKA_PERMISSIVE_MODE_TIMEOUT = 1
} Mka_PermissiveModeType;

/** 8.2.11 A PAE's link state and MKA status. */
typedef struct {
    /** transceiver link state */
    EthTrcv_LinkStateType ConnectionStatus;
    /** MKA instance status */
    Mka_MkaStatusType MkaStatus;
    /** controlled port may run plaintext: set in MKA_PERMISSIVE_MODE_TIMEOUT
     *  once the PermissiveTimeoutMs elapses unsecured */
    boolean PermissivePlaintext;
} Mka_PaeStatusType;

/** 8.2.10 Aggregate SecY statistics counters (minimal subset). */
typedef struct {
    /** received non-MACsec packets accepted */
    uint32 InPktsUntagged;
    /** received non-MACsec packets discarded */
    uint32 InPktsNoTag;
    /** received packets with an invalid SecTAG */
    uint32 InPktsBadTag;
    /** received packets dropped (rate limit) */
    uint32 InPktsOverrun;
    /** transmitted non-MACsec packets */
    uint32 OutPktsUntagged;
    /** transmitted packets discarded (too big) */
    uint32 OutPktsTooLong;
} Mka_Stats_SecYType;

/**
 * Lower-layer transmit callback (the EthIf abstraction).
 * @param[in] TxPduId  The PAE's configured transmit PDU id.
 * @param[in] Frame    The complete EAPOL-MKA frame to send.
 * @param[in] Length   Frame length in octets.
 * @return E_OK if the frame was accepted for transmission, else E_NOT_OK.
 */
typedef Std_ReturnType (
    *Mka_TransmitFnType)(PduIdType TxPduId, const uint8* Frame, uint16 Length);

/** One pre-shared CKN/CAK known to a PAE. */
typedef struct {
    /** the Connectivity Association Key */
    const uint8* Cak;
    /** CAK length in octets (16 or 32) */
    uint8 CakLength;
    /** the CAK Name */
    const uint8* Ckn;
    /** CKN length in octets (1..32) */
    uint8 CknLength;
    /** enabled at Mka_Init / Mka_StartPae */
    boolean DefaultEnabled;
} Mka_CknConfigType;

/** Configuration of one PAE (one controlled port). */
typedef struct {
    /** id of received MKA frames */
    PduIdType RxPduId;
    /** id passed to Transmit */
    PduIdType TxPduId;
    /** our Secure Channel Id */
    uint8 Sci[MKA_SCI_LEN];
    /** Key Server priority */
    uint8 Priority;
    /** AUTO or a fixed role */
    MkaRole Role;
    /** SAK size: 16 or 32 */
    uint8 SakLength;
    /** MkaConfidentialityOffset (0/30/50) */
    uint8 ConfidentialityOffset;
    /** 0 => default by SakLength */
    uint64_t CipherSuite;
    /** auto-rekey period; 0 => off */
    uint32 SakRekeyTimeMs;
    /** unsecured ms before plaintext */
    uint32 PermissiveTimeoutMs;
    /** enable delay protection */
    boolean DelayProtect;
#ifndef WOLFMKA_NO_RETRY
    /** MKA retry base delay; 0 => off */
    uint32 RetryBaseMs;
    /** MKA retry back-off ceiling */
    uint32 RetryCyclicMs;
#endif
#ifndef WOLFMKA_NO_ANNOUNCEMENTS
    /** emit cipher-suite Announcement (00009) */
    boolean AnnounceCipherSuites;
#endif
    /** data-plane (SecY) hooks */
    MkaSecyOps Secy;
    /** optional async event hooks */
    MkaEventOps Events;
    /** lower-layer transmit */
    Mka_TransmitFnType Transmit;
    /** the PAE's CKN/CAK table */
    const Mka_CknConfigType* Ckns;
    /** number of entries in Ckns */
    uint8 CknCount;
} Mka_PaeConfigType;

/** 8.2.13 The module post-build configuration. */
typedef struct {
    /** array of PAE configurations */
    const Mka_PaeConfigType* Paes;
    /** number of PAEs */
    uint8 PaeCount;
    /** Mka_MainFunction tick */
    uint32 MainFunctionPeriodMs;
} Mka_ConfigType;

/* ------------------------------------------------------------------------- */
/* 8.3 Function definitions                                                  */
/* ------------------------------------------------------------------------- */

/**
 * 8.3.1 Initialise the Mka module from its configuration.
 *
 * Stores the configuration, resets every PAE and creates an empty KaY per PAE.
 * A NULL @p ConfigPtr leaves the module un-initialised.
 * @param[in] ConfigPtr  The post-build configuration (must outlive the module).
 */
void Mka_Init(const Mka_ConfigType* ConfigPtr);

/**
 * 8.3.2 Return module version information.
 * @param[out] VersionInfoPtr  Out: receives the vendor/module/version fields;
 *                             ignored if NULL.
 */
void Mka_GetVersionInfo(Std_VersionInfoType* VersionInfoPtr);

/**
 * 8.3.3 Enable or disable a configured CKN on a PAE.
 *
 * When the PAE is already started, enabling instantiates the participant.
 * @param[in] MkaPaeIdx  Index of the PAE (0 .. PaeCount-1).
 * @param[in] Enable     TRUE to enable the CKN, FALSE to disable it.
 * @param[in] Ckn        CAK Name to match against the PAE's configured CKNs.
 * @param[in] CknLength  Length of @p Ckn in octets.
 * @return E_OK if the CKN was found and updated; E_NOT_OK otherwise (not
 *         initialised, bad index, NULL Ckn, no match, or add failure).
 */
Std_ReturnType Mka_SetCknStatus(uint8 MkaPaeIdx, boolean Enable,
    const uint8* Ckn, uint8 CknLength);

/**
 * 8.3.4 Read whether a configured CKN is enabled.
 * @param[in]  MkaPaeIdx  Index of the PAE (0 .. PaeCount-1).
 * @param[in]  Ckn        CAK Name to match.
 * @param[in]  CknLength  Length of @p Ckn in octets.
 * @param[out] EnablePtr  Out: receives the CKN's enabled state.
 * @return E_OK if the CKN was found; E_NOT_OK otherwise.
 */
Std_ReturnType Mka_GetCknStatus(uint8 MkaPaeIdx, const uint8* Ckn,
    uint8 CknLength, boolean* EnablePtr);

/**
 * 8.3.5 Enable or disable a PAE.
 * @param[in] MkaPaeIdx  Index of the PAE (0 .. PaeCount-1).
 * @param[in] Enable     TRUE to enable the PAE, FALSE to disable it.
 * @return E_OK on success; E_NOT_OK if not initialised or bad index.
 */
Std_ReturnType Mka_SetEnable(uint8 MkaPaeIdx, boolean Enable);

/**
 * 8.3.6 Read whether a PAE is enabled.
 * @param[in]  MkaPaeIdx  Index of the PAE (0 .. PaeCount-1).
 * @param[out] EnablePtr  Out: receives the PAE's enabled state.
 * @return E_OK on success; E_NOT_OK if not initialised, bad index, or NULL.
 */
Std_ReturnType Mka_GetEnable(uint8 MkaPaeIdx, boolean* EnablePtr);

/**
 * 8.3.7 Read a PAE's link and MKA status.
 * @param[in]  MkaPaeIdx     Index of the PAE (0 .. PaeCount-1).
 * @param[out] PaeStatusPtr  Out: receives the link state and MKA status.
 * @return E_OK on success; E_NOT_OK if not initialised, bad index, or NULL.
 */
Std_ReturnType Mka_GetPaeStatus(uint8 MkaPaeIdx,
    Mka_PaeStatusType* PaeStatusPtr);

/**
 * 8.3.8 Set a PAE's permissive mode (8.2.9).
 *
 * In MKA_PERMISSIVE_MODE_TIMEOUT, once the PAE has been active without a SAK
 * for PermissiveTimeoutMs, Mka_GetPaeStatus reports PermissivePlaintext = TRUE
 * so the integrator may open the controlled port in plaintext;
 * MKA_PERMISSIVE_MODE_NEVER keeps it blocked. Establishing MACsec clears it.
 * @param[in] MkaPaeIdx       Index of the PAE (0 .. PaeCount-1).
 * @param[in] PermissiveMode  The mode to apply.
 * @return E_OK on success; E_NOT_OK if not initialised or bad index.
 */
Std_ReturnType Mka_SetPaePermissiveMode(uint8 MkaPaeIdx,
    Mka_PermissiveModeType PermissiveMode);

/**
 * 8.3.9 Start MKA on a PAE, instantiating its enabled CKNs.
 * @param[in] MkaPaeIdx  Index of the PAE (0 .. PaeCount-1).
 * @return E_OK if all enabled CKNs were instantiated; E_NOT_OK if not
 *         initialised, bad index, or a participant could not be created.
 */
Std_ReturnType Mka_StartPae(uint8 MkaPaeIdx);

/**
 * 8.3.10 Request MACsec statistics for a PAE (asynchronous).
 *
 * Records the request; the SecY fills @p MacSecStatsPtr and confirms via
 * Mka_GetMacSecStatisticsNotification. Fails if a request is already pending.
 * @param[in]  MkaPaeIdx       Index of the PAE (0 .. PaeCount-1).
 * @param[out] MacSecStatsPtr  Out: buffer the SecY fills with the counters.
 * @return E_OK if the request was accepted; E_NOT_OK if not initialised, bad
 *         index, NULL, or a request is already in flight.
 */
Std_ReturnType Mka_GetMacSecStatistics(uint8 MkaPaeIdx,
    Mka_Stats_SecYType* MacSecStatsPtr);

/**
 * 8.3.11 Notify the module of a transceiver link-state change.
 * @param[in] MkaPaeIdx             Index of the PAE (0 .. PaeCount-1).
 * @param[in] TransceiverLinkState  The new link state.
 * @return E_OK on success; E_NOT_OK if not initialised or bad index.
 */
Std_ReturnType Mka_LinkStateChange(uint8 MkaPaeIdx,
    EthTrcv_LinkStateType TransceiverLinkState);

/* ------------------------------------------------------------------------- */
/* 8.4 Callback notifications                                                */
/*                                                                           */
/* The SecY/MacSec interface is asynchronous in AUTOSAR: the module requests */
/* an operation and the MacSec module calls one of the *Notification entry   */
/* points below on completion. The wolfMKA SecY (MkaSecyOps) is synchronous, */
/* so the SA/SecY notifications are acknowledgements here; the statistics     */
/* request is genuinely deferred (see Mka_GetMacSecStatistics).              */
/* ------------------------------------------------------------------------- */

/**
 * 8.4.1 Confirm an asynchronous Mka_GetMacSecStatistics request.
 * @param[in] MkaPaeIdx  Index of the PAE the request was issued for.
 * @param[in] Result     E_OK if the SecY gathered the statistics, else
 *                       E_NOT_OK.
 */
void Mka_GetMacSecStatisticsNotification(uint8 MkaPaeIdx,
    Std_ReturnType Result);

/**
 * 8.4.2 Indicate a received EAPOL-MKA frame to the module.
 * @param[in] RxPduId     The PDU id the frame arrived on (selects the PAE).
 * @param[in] PduInfoPtr  The received frame and its length.
 */
void Mka_RxIndication(PduIdType RxPduId, const PduInfoType* PduInfoPtr);

/**
 * 8.4.3 Confirm a previous transmit request completed.
 * @param[in] TxPduId  The transmitted PDU id.
 * @param[in] result   Transmission result (unused: the send is synchronous).
 */
void Mka_TxConfirmation(PduIdType TxPduId, Std_ReturnType result);

/**
 * 8.4.4 Confirm an asynchronous SecY configuration update.
 * @param[in] MkaPaeIdx  Index of the PAE.
 * @param[in] Result     Outcome of the SecY update.
 */
void Mka_MacSecUpdateSecYNotification(uint8 MkaPaeIdx, Std_ReturnType Result);

/**
 * 8.4.5 Confirm an asynchronous "add transmit SA" request.
 * @param[in] MkaPaeIdx  Index of the PAE.
 * @param[in] Result     Outcome of the add-transmit-SA operation.
 */
void Mka_MacSecAddTxSaNotification(uint8 MkaPaeIdx, Std_ReturnType Result);

/**
 * 8.4.6 Confirm an asynchronous "add receive SA" request.
 * @param[in] MkaPaeIdx  Index of the PAE.
 * @param[in] Result     Outcome of the add-receive-SA operation.
 */
void Mka_MacSecAddRxSaNotification(uint8 MkaPaeIdx, Std_ReturnType Result);

/* ------------------------------------------------------------------------- */
/* 8.5 Scheduled functions                                                   */
/* ------------------------------------------------------------------------- */

/** 8.5.1 Cyclic main function; advances every MKA instance. */
void Mka_MainFunction(void);

#ifdef __cplusplus
}
#endif

#endif /* WOLFMKA_AUTOSAR_MKA_H */
