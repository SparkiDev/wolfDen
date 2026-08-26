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

/**
 * @name Module identification
 * Reported by Mka_GetVersionInfo(), and used by Det to attribute a development
 * error to this module. The vendor and module IDs are placeholders: a real
 * integration overrides them with the values its BSW configuration assigns, or
 * Det reports arrive labelled as somebody else's module.
 * @{
 */
#ifndef MKA_VENDOR_ID
    /** Vendor ID; override to match the BSW configuration. */
    #define MKA_VENDOR_ID 0U
#endif
#ifndef MKA_MODULE_ID
    /** Module ID; override to match the BSW configuration. */
    #define MKA_MODULE_ID 0xFFU
#endif
#ifndef MKA_INSTANCE_ID
    /** Which instance of the module a report comes from. One instance is the
     *  norm - a single Mka module manages every PAE - so this stays 0 unless an
     *  integration runs more than one. */
    #define MKA_INSTANCE_ID 0U
#endif
/** Major version; mirrors the library's WOLFMKA_VERSION_MAJOR, so the module
 *  and the library it wraps cannot report different versions. */
#define MKA_SW_MAJOR_VERSION WOLFMKA_VERSION_MAJOR
/** Minor version; mirrors WOLFMKA_VERSION_MINOR. */
#define MKA_SW_MINOR_VERSION WOLFMKA_VERSION_MINOR
/** Patch version; mirrors WOLFMKA_VERSION_PATCH. */
#define MKA_SW_PATCH_VERSION WOLFMKA_VERSION_PATCH
/** @} */

/* ------------------------------------------------------------------------- */
/* Development error detection (SWS section 7)                               */
/* ------------------------------------------------------------------------- */

/**
 * @def MKA_DEV_ERROR_DETECT
 * Whether the module reports development errors to Det. STD_OFF by default, so
 * the binding builds and links with no Det present and the reporting compiles
 * away to nothing; set it to STD_ON in a build that has one.
 *
 * Detection itself does not depend on this switch. Every condition below is
 * checked, and rejected with E_NOT_OK, in both settings - the switch only
 * controls whether the rejection is also *reported*. So turning it off cannot
 * change what the module does, only what a developer gets told about it.
 */
#ifndef MKA_DEV_ERROR_DETECT
    #define MKA_DEV_ERROR_DETECT STD_OFF
#endif

/**
 * @def MKA_DET_REPORT_ERROR(sid, err)
 * How a development error reaches Det: `MKA_DET_REPORT_ERROR(sid,
 * err)`.
 *
 * With MKA_DEV_ERROR_DETECT == STD_ON - the definition shown here - it
 * is the standard `Det_ReportError(MKA_MODULE_ID, MKA_INSTANCE_ID, sid,
 * err)`, and `Det.h` is included for it. Define this macro yourself
 * before including Mka.h to route reports somewhere else (a project Det
 * wrapper, a trace buffer, a test double); `Det.h` is then not included
 * at all. With the switch STD_OFF it expands instead to a no-op that
 * still consumes both arguments, so neither goes unused.
 * @param sid  API service ID of the reporting function (MKA_SID_*).
 * @param err  development error ID (MKA_E_*).
 */
#if (MKA_DEV_ERROR_DETECT == STD_ON)
    #ifndef MKA_DET_REPORT_ERROR
        #include "Det.h"
        #define MKA_DET_REPORT_ERROR(sid, err)                                 \
            ((void)Det_ReportError((uint16)MKA_MODULE_ID,                      \
                (uint8)MKA_INSTANCE_ID, (uint8)(sid), (uint8)(err)))
    #endif
#else
    #ifndef MKA_DET_REPORT_ERROR
        #define MKA_DET_REPORT_ERROR(sid, err)                                 \
            do {                                                               \
                (void)(sid);                                                   \
                (void)(err);                                                   \
            } while (0)
    #endif
#endif

/* Development error IDs. The values follow the usual AUTOSAR numbering for
 * these conditions; each is overridable so an integration can align them with
 * the exact SWS revision or Det configuration it is built against. 0x80 and
 * above are vendor-specific. */
#ifndef MKA_E_UNINIT
    /** an API was called before Mka_Init, or after it refused a configuration
     */
    #define MKA_E_UNINIT 0x01U
#endif
#ifndef MKA_E_PARAM_POINTER
    /** a NULL pointer was passed where a buffer or configuration was required
     */
    #define MKA_E_PARAM_POINTER 0x02U
#endif
#ifndef MKA_E_INVALID_PAE_IDX
    /** MkaPaeIdx is outside 0 .. PaeCount-1 */
    #define MKA_E_INVALID_PAE_IDX 0x03U
#endif
#ifndef MKA_E_INIT_FAILED
    /** Mka_Init refused the configuration; the module is left uninitialised */
    #define MKA_E_INIT_FAILED 0x04U
#endif
#ifndef MKA_E_PARAM_INVALID
    /** a parameter was outside its permitted range or enumeration */
    #define MKA_E_PARAM_INVALID 0x05U
#endif
#ifndef MKA_E_KAY_RUN_FAILED
    /** vendor-specific: a Connectivity Association failed inside
     *  Mka_MainFunction (e.g. SAK generation hit a crypto error). Reported once
     *  on the transition into failure, not every tick it persists, and the
     *  remaining PAEs are still stepped. */
    #define MKA_E_KAY_RUN_FAILED 0x80U
#endif

/**
 * @name API service IDs
 * Which API a Det report came from, passed as Det_ReportError's ApiId. The
 * error IDs above are shared between several APIs, so on their own they would
 * not say where the mistake was made.
 * @{
 */
/** Mka_Init() */
#define MKA_SID_INIT                        0x01U
/** Mka_GetVersionInfo() */
#define MKA_SID_GET_VERSION_INFO            0x02U
/** Mka_MainFunction() */
#define MKA_SID_MAIN_FUNCTION               0x03U
/** Mka_SetEnable() */
#define MKA_SID_SET_ENABLE                  0x04U
/** Mka_GetEnable() */
#define MKA_SID_GET_ENABLE                  0x05U
/** Mka_SetCknStatus() */
#define MKA_SID_SET_CKN_STATUS              0x06U
/** Mka_GetCknStatus() */
#define MKA_SID_GET_CKN_STATUS              0x07U
/** Mka_StartPae() */
#define MKA_SID_START_PAE                   0x08U
/** Mka_GetPaeStatus() */
#define MKA_SID_GET_PAE_STATUS              0x09U
/** Mka_SetPaePermissiveMode() */
#define MKA_SID_SET_PAE_PERMISSIVE_MODE     0x0AU
/** Mka_GetMacSecStatistics() */
#define MKA_SID_GET_MACSEC_STATISTICS       0x0BU
/** Mka_LinkStateChange() */
#define MKA_SID_LINK_STATE_CHANGE           0x0CU
/** Mka_RxIndication() */
#define MKA_SID_RX_INDICATION               0x0DU
/** Mka_TxConfirmation() */
#define MKA_SID_TX_CONFIRMATION             0x0EU
/** Mka_GetMacSecStatisticsNotification() */
#define MKA_SID_GET_MACSEC_STATISTICS_NOTIF 0x0FU
/** Mka_MacSecUpdateSecYNotification() */
#define MKA_SID_MACSEC_UPDATE_SECY_NOTIF    0x10U
/** Mka_MacSecAddTxSaNotification() */
#define MKA_SID_MACSEC_ADD_TX_SA_NOTIF      0x11U
/** Mka_MacSecAddRxSaNotification() */
#define MKA_SID_MACSEC_ADD_RX_SA_NOTIF      0x12U
/** @} */

#ifndef MKA_MAX_PAES
    /** Maximum number of PAEs (controlled ports) the module manages. Sizes the
     *  static runtime array, so a configured PaeCount above it is clamped. */
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
    /** Confidentiality offset as the MkaConfidentialityOffset *encoding* -
     *  MKA_CONF_OFFSET_0 / _30 / _50, i.e. 0, 1 or 2 - not the octet count it
     *  names. The core rejects anything above MKA_CONF_OFFSET_50. */
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
    /** Mka_MainFunction tick in milliseconds; must be non-zero - it is what
     *  advances the KaY's clock, so a zero stops every timer */
    uint32 MainFunctionPeriodMs;
} Mka_ConfigType;

/* ------------------------------------------------------------------------- */
/* 8.3 Function definitions                                                  */
/* ------------------------------------------------------------------------- */

/**
 * 8.3.1 Initialise the Mka module from its configuration.
 *
 * Stores the configuration, resets every PAE and creates an empty KaY per PAE.
 * The module is left un-initialised, with no diagnostic, by a NULL
 * @p ConfigPtr, by a non-zero @c PaeCount with a NULL @c Paes, or by a zero
 * @c MainFunctionPeriodMs (which would pin the KaY's clock and stop every timer
 * firing). A @c PaeCount above @c MKA_MAX_PAES is clamped, not refused.
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
 *
 * Disabling tears the PAE down: every participant is freed, which deletes the
 * Secure Associations it installed in the SecY and wipes its key material. The
 * controlled port is therefore no longer protecting traffic when this returns -
 * disabling means the connection is not viable, not that MKA is paused. The PAE
 * must be started again with Mka_StartPae() to run, which re-instantiates its
 * enabled CKNs.
 *
 * Contrast Mka_LinkStateChange(), which deliberately leaves a CA intact: a link
 * bounce does not change whether the far end still holds the CAK.
 * @param[in] MkaPaeIdx  Index of the PAE (0 .. PaeCount-1).
 * @param[in] Enable     TRUE to enable the PAE, FALSE to disable and tear down.
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
 * @return E_OK on success; E_NOT_OK if not initialised, the index is bad, or
 *         PermissiveMode is not one of the Mka_PermissiveModeType values.
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
 * @param[in] TransceiverLinkState  The new link state; must be one of the
 *                                  EthTrcv_LinkStateType values.
 * @return E_OK on success; E_NOT_OK if not initialised, the index is out of
 *         range, or TransceiverLinkState is not one of the
 *         EthTrcv_LinkStateType values.
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
