/**
 * @file Mka_Std.h
 * Minimal AUTOSAR base types for building the Mka module standalone.
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
 * Provides just enough of the AUTOSAR base types (Std_ReturnType, PduInfoType,
 * EthTrcv_LinkStateType, the integer aliases, ...) so the Mka module builds
 * outside a full AUTOSAR stack. In a real integration the platform's
 * Std_Types.h and ComStack_Types.h provide these; define MKA_NO_STD_SHIM to
 * suppress this shim and use the platform headers instead.
 */
#ifndef WOLFMKA_AUTOSAR_MKA_STD_H
#define WOLFMKA_AUTOSAR_MKA_STD_H

#ifndef MKA_NO_STD_SHIM

    #include <stdint.h>
    #include <stddef.h>

/** AUTOSAR 8-bit unsigned integer. */
typedef uint8_t uint8;
/** AUTOSAR 16-bit unsigned integer. */
typedef uint16_t uint16;
/** AUTOSAR 32-bit unsigned integer. */
typedef uint32_t uint32;
/** AUTOSAR boolean; holds TRUE or FALSE. */
typedef uint8_t boolean;

    #ifndef TRUE
        /** AUTOSAR boolean true. */
        #define TRUE 1U
    #endif
    #ifndef FALSE
        /** AUTOSAR boolean false. */
        #define FALSE 0U
    #endif

/** AUTOSAR standard return type: E_OK or E_NOT_OK. */
typedef uint8 Std_ReturnType;
    #ifndef E_OK
        /** the request succeeded */
        #define E_OK 0x00U
    #endif
    #ifndef E_NOT_OK
        /** the request was rejected or failed */
        #define E_NOT_OK 0x01U
    #endif

    /* Configuration-switch values (AUTOSAR Std_Types.h). Guarded, so a real
     * Std_Types.h that already defines them wins. */
    #ifndef STD_ON
        #define STD_ON 0x01U
    #endif
    #ifndef STD_OFF
        #define STD_OFF 0x00U
    #endif

/** Module version information (AUTOSAR Std_VersionInfoType). */
typedef struct {
    /** vendor identifier */
    uint16 vendorID;
    /** module identifier */
    uint16 moduleID;
    /** software major version */
    uint8 sw_major_version;
    /** software minor version */
    uint8 sw_minor_version;
    /** software patch version */
    uint8 sw_patch_version;
} Std_VersionInfoType;

/** PDU identifier */
typedef uint16 PduIdType;
/** PDU length in octets */
typedef uint16 PduLengthType;

/** A PDU's payload and length (AUTOSAR PduInfoType). */
typedef struct {
    /** payload bytes */
    uint8* SduDataPtr;
    /** payload length */
    PduLengthType SduLength;
    /** metadata (unused) */
    uint8* MetaDataPtr;
} PduInfoType;

/** Ethernet transceiver link state, as reported to Mka_LinkStateChange(). */
typedef uint8 EthTrcv_LinkStateType;
    #ifndef ETHTRCV_LINK_STATE_DOWN
        /** no link on the port */
        #define ETHTRCV_LINK_STATE_DOWN 0U
    #endif
    #ifndef ETHTRCV_LINK_STATE_ACTIVE
        /** the port has link and can carry frames */
        #define ETHTRCV_LINK_STATE_ACTIVE 1U
    #endif

#endif /* MKA_NO_STD_SHIM */

#endif /* WOLFMKA_AUTOSAR_MKA_STD_H */
