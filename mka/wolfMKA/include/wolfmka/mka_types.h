/* mka_types.h
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
 * Core constants, enumerations and structures for the MACsec Key Agreement
 * (MKA) protocol as specified in IEEE Std 802.1X-2010, Clause 9 (the MKA
 * protocol) and Clause 11.11 (the MKPDU encoding).
 *
 * Part of wolfMKA - an MKA implementation using wolfSSL for cryptography.
 */

#ifndef WOLFMKA_TYPES_H
#define WOLFMKA_TYPES_H

/* wolfMKA release version. WOLFMKA_VERSION_HEX is a monotonic 0xMMmmpp value
 * for easy comparison, e.g. #if WOLFMKA_VERSION_HEX >= 0x010000U. The AUTOSAR
 * Mka module's MKA_SW_*_VERSION fields are derived from these (single source).
 */
#define WOLFMKA_VERSION_MAJOR  1U
#define WOLFMKA_VERSION_MINOR  0U
#define WOLFMKA_VERSION_PATCH  0U
#define WOLFMKA_VERSION_STRING "1.0.0"
#define WOLFMKA_VERSION_HEX                                                    \
    ((WOLFMKA_VERSION_MAJOR * 0x10000U) + (WOLFMKA_VERSION_MINOR * 0x100U) +   \
        WOLFMKA_VERSION_PATCH)

#include <stddef.h>

/* Boolean type: include <stdbool.h> when the toolchain provides it (all C99 and
 * many C89 toolchains); otherwise fall back to a typedef plus true/false macros
 * an integrator can override for an exotic pre-C99 target (pre-define them, or
 * set WOLFMKA_NO_STDBOOL). In C++, bool/true/false are language keywords, so
 * neither path is taken. */
#if !defined(__cplusplus)
    #if defined(WOLFMKA_NO_STDBOOL)
        #define WOLFMKA_USE_STDBOOL 0
    #elif defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L)
        #define WOLFMKA_USE_STDBOOL 1
    #elif defined(__has_include)
        #if __has_include(<stdbool.h>)
            #define WOLFMKA_USE_STDBOOL 1
        #else
            #define WOLFMKA_USE_STDBOOL 0
        #endif
    #else
        #define WOLFMKA_USE_STDBOOL 0
    #endif

    #if WOLFMKA_USE_STDBOOL
        #include <stdbool.h>
    #else
        /* No <stdbool.h>: a minimal equivalent. unsigned char holds 0/1 and is
         * adequate for wolfMKA, which uses bool only for true/false logic. */
        #ifndef bool
typedef unsigned char bool;
        #endif
        #ifndef true
            #define true 1
        #endif
        #ifndef false
            #define false 0
        #endif
    #endif
#endif

/* Fixed-width integer types: include <stdint.h> when the toolchain provides it
 * (all C99 and most C89 toolchains); otherwise fall back to typedefs an
 * integrator can override for an exotic target (pre-define them, or set
 * WOLFMKA_NO_STDINT). The fallback assumes a conventional target - 16-bit
 * short, 32-bit int, 64-bit long long; verify the widths on unusual hardware.
 */
#if defined(WOLFMKA_NO_STDINT)
    #define WOLFMKA_USE_STDINT 0
#elif defined(__has_include)
    #if __has_include(<stdint.h>)
        #define WOLFMKA_USE_STDINT 1
    #else
        #define WOLFMKA_USE_STDINT 0
    #endif
#elif defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L)
    #define WOLFMKA_USE_STDINT 1
#else
    #define WOLFMKA_USE_STDINT 0
#endif

#if WOLFMKA_USE_STDINT
    #include <stdint.h>
#else
    /* No <stdint.h>: pick an exact-width base type for each width from the
     * <limits.h> ranges. A matching *_MAX guarantees that many value bits with
     * no padding, so the selected type is exact; a width with no matching type
     * stops the build rather than silently using a wrong size. */
    #include <limits.h>

    #if UCHAR_MAX == 0xFF
typedef unsigned char uint8_t;
typedef signed char int8_t;
    #else
        #error "wolfMKA: no 8-bit integer type on this target"
    #endif

    #if USHRT_MAX == 0xFFFF
typedef unsigned short uint16_t;
typedef short int16_t;
    #elif UINT_MAX == 0xFFFF
typedef unsigned int uint16_t;
typedef int int16_t;
    #else
        #error "wolfMKA: no 16-bit integer type on this target"
    #endif

    #if UINT_MAX == 0xFFFFFFFF
typedef unsigned int uint32_t;
typedef int int32_t;
    #elif ULONG_MAX == 0xFFFFFFFF
typedef unsigned long uint32_t;
typedef long int32_t;
    #else
        #error "wolfMKA: no 32-bit integer type on this target"
    #endif

    #if ULONG_MAX == 0xFFFFFFFFFFFFFFFF
typedef unsigned long uint64_t;
typedef long int64_t;
    #elif defined(ULLONG_MAX) && (ULLONG_MAX == 0xFFFFFFFFFFFFFFFF)
typedef unsigned long long uint64_t;
typedef long long int64_t;
    #else
        #error "wolfMKA: no 64-bit integer type on this target"
    #endif
#endif

/* redefinable WOLFMKA_MEMCPY/MEMSET/... and alloc */
#include "mka_mem.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------- */
/* Portability                                                               */
/* ------------------------------------------------------------------------- */

/* 'inline' is C99; MKA_INLINE maps to the compiler's inline keyword, or to
 * nothing where none is available. An integrator may pre-define it to override
 * (e.g. to force or forbid inlining on a particular toolchain). */
#ifndef MKA_INLINE
    #if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L)
        #define MKA_INLINE inline
    #elif defined(__GNUC__)
        #define MKA_INLINE __inline__
    #elif defined(_MSC_VER)
        #define MKA_INLINE __inline
    #else
        /* no inline keyword available */
        #define MKA_INLINE
    #endif
#endif

/* ------------------------------------------------------------------------- */
/* Build profiles                                                            */
/* ------------------------------------------------------------------------- */

/*
 * Optional protocol features, each compiled out by its own WOLFMKA_NO_* flag:
 *   WOLFMKA_NO_EAP           - EAP-MSK CAK/CKN derivation (PSK-only build)
 *   WOLFMKA_NO_XPN           - XPN cipher suites + SSCI assignment
 *   WOLFMKA_NO_DELAY_PROTECT - delay-protection LPN handling
 *   WOLFMKA_NO_RETRY         - MKA retry exponential back-off
 *   WOLFMKA_NO_ANNOUNCEMENTS - Announcement (cipher-suite) emit/decode
 *   WOLFMKA_NO_AUTO_REKEY    - automatic SAK rekey (time span + PN exhaustion)
 *
 * WOLFMKA_AUTOSAR selects the feature set the AUTOSAR Mka binding
 * (src/autosar/Mka.c) needs. It keys MACsec from a pre-shared CAK and does not
 * use EAP-MSK derivation, so EAP is compiled out. The retry back-off
 * (CP_SWS_Mka_00012), Announcements (CP_SWS_Mka_00009), XPN and delay
 * protection all stay in - each is configurable through Mka_PaeConfigType.
 *
 * WOLFMKA_AUTOMOTIVE_PROFILE selects the feature set of the OPEN Alliance TC17
 * Automotive MKA profile (see OPEN-ALLIANCE.md for the requirement-by-
 * requirement map). The profile is built on IEEE Std 802.1X-2020, so version 3
 * MKPDUs are emitted, and it removes Secure Announcements and cipher-suite
 * negotiation. The remaining profile behaviour is runtime configuration -
 * wm_Participant_AutomotiveDefaults() fills a MkaParticipantConfig with the
 * recommended values.
 */
#ifdef WOLFMKA_AUTOSAR
    #ifndef WOLFMKA_NO_EAP
        #define WOLFMKA_NO_EAP
    #endif
#endif

#ifdef WOLFMKA_AUTOMOTIVE_PROFILE
    /* Automotive MKA removes Secure Announcements and cipher-suite negotiation
     * (they are an unnecessary attack surface on a statically designed
     * in-vehicle network). */
    #ifndef WOLFMKA_NO_ANNOUNCEMENTS
        #define WOLFMKA_NO_ANNOUNCEMENTS
    #endif
    /* Automotive MKA uses version 3 MKPDUs or above. */
    #ifndef WOLFMKA_MKA_VERSION
        #define WOLFMKA_MKA_VERSION 3U
    #endif
#endif

/* ------------------------------------------------------------------------- */
/* Host byte order                                                           */
/* ------------------------------------------------------------------------- */

/*
 * Exactly one of WOLFMKA_LITTLE_ENDIAN / WOLFMKA_BIG_ENDIAN ends up defined. A
 * project may force the result by defining either one on the command line (for
 * a compiler whose macros are not recognised below); otherwise the host byte
 * order is deduced from the standard compiler/architecture predefines. When it
 * cannot be determined the build stops with an #error rather than guessing.
 */
#if defined(WOLFMKA_LITTLE_ENDIAN) && defined(WOLFMKA_BIG_ENDIAN)
    #error "Define at most one of WOLFMKA_LITTLE_ENDIAN / WOLFMKA_BIG_ENDIAN"
#elif !defined(WOLFMKA_LITTLE_ENDIAN) && !defined(WOLFMKA_BIG_ENDIAN)
    #if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) &&         \
        defined(__ORDER_BIG_ENDIAN__)
        #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
            #define WOLFMKA_LITTLE_ENDIAN
        #elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
            #define WOLFMKA_BIG_ENDIAN
        #else
            #error "wolfMKA: unsupported __BYTE_ORDER__; define \
WOLFMKA_LITTLE_ENDIAN or WOLFMKA_BIG_ENDIAN"
        #endif
    #elif defined(__BIG_ENDIAN__) || defined(__ARMEB__) ||                     \
        defined(__THUMBEB__) || defined(__AARCH64EB__) ||                      \
        defined(__MIPSEB__) || defined(_MIPSEB) || defined(__sparc__) ||       \
        defined(__sparc)
        #define WOLFMKA_BIG_ENDIAN
    #elif defined(__LITTLE_ENDIAN__) || defined(__ARMEL__) ||                  \
        defined(__AARCH64EL__) || defined(__MIPSEL__) || defined(_MIPSEL) ||   \
        defined(_M_IX86) || defined(_M_X64) || defined(_M_ARM) ||              \
        defined(_M_ARM64) || defined(__i386__) || defined(__x86_64__) ||       \
        defined(__aarch64__) || defined(__arm__)
        #define WOLFMKA_LITTLE_ENDIAN
    #else
        #error "wolfMKA: cannot determine host byte order; define \
WOLFMKA_LITTLE_ENDIAN or WOLFMKA_BIG_ENDIAN"
    #endif
#endif

/* ------------------------------------------------------------------------- */
/* Fixed sizes (octets) from IEEE Std 802.1X-2010                            */
/* ------------------------------------------------------------------------- */

/* Sizes are unsigned (U suffix) so that arithmetic mixing them with size_t
 * stays within a single essential type category (MISRA C:2012 Rule 10.4). */
/* Member Identifier (9.4.1) */
#define MKA_MI_LEN           12U
/* Message Number, 32-bit */
#define MKA_MN_LEN           4U
/* Secure Channel Identifier (MAC+Port) */
#define MKA_SCI_LEN          8U
/* Ethernet MAC address */
#define MKA_MAC_LEN          6U
/* Algorithm Agility field */
#define MKA_ALGO_AGILITY_LEN 4U
/* Key Number, 32-bit */
#define MKA_KN_LEN           4U
/* AES-CMAC ICV length */
#define MKA_DEFAULT_ICV_LEN  16U
/* CAK Name maximum length (9.3.1) */
#define MKA_MAX_CKN_LEN      32U
/* 256-bit CAK maximum */
#define MKA_MAX_CAK_LEN      32U
/* KEK/ICK KDF context (CKN, padded) */
#define MKA_KEK_CONTEXT_LEN  16U

/* Key Numbers / Key Server priority limits */
#define MKA_KS_PRIORITY_DEFAULT 16U
#define MKA_KS_PRIORITY_MAX     255U

/* Algorithm Agility value identifying the default KDF/cipher family,
 * 0x0080C201 (IEEE Std 802.1X-2010, 11.11.1). */
#define MKA_ALGO_AGILITY_DEFAULT 0x0080C201UL

/* ------------------------------------------------------------------------- */
/* EAPOL framing (IEEE Std 802.1X-2010, 11.3 / 11.4)                         */
/* ------------------------------------------------------------------------- */

/* Protocol version for 802.1X-2010 */
#define EAPOL_VERSION_2010 3U
/* MKA protocol version announced in the Basic Parameter Set (11.11.1): 1 for
 * IEEE Std 802.1X-2010, 2 for 802.1Xbx-2014, 3 for 802.1X-2020. wolfMKA emits
 * the 802.1X-2010 value by default, since that is the base the wire format is
 * implemented to; the XPN and suspension parameter sets it also supports are
 * later amendments, so a build may advertise 2 or 3 instead. Receive is
 * unaffected either way - a peer's announced version is recorded and never used
 * to reject a frame. WOLFMKA_AUTOMOTIVE_PROFILE selects 3, which the OPEN
 * Alliance profile requires. */
#ifndef WOLFMKA_MKA_VERSION
    #define WOLFMKA_MKA_VERSION 1U
#endif
/* EAPOL-MKA packet type */
#define EAPOL_TYPE_MKA  5U
/* version + type + body length(2) */
#define EAPOL_HDR_LEN   4U
#define EAPOL_ETHERTYPE 0x888EU

/* PAE group destination address 01-80-C2-00-00-03 (used by transport). */
#define MKA_PAE_GROUP_ADDR {0x01, 0x80, 0xC2, 0x00, 0x00, 0x03}

/* ------------------------------------------------------------------------- */
/* MKPDU parameter-set types (IEEE Std 802.1X-2010, Table 11-6)              */
/* ------------------------------------------------------------------------- */

typedef enum {
    MKA_PS_LIVE_PEER_LIST = 1,
    MKA_PS_POTENTIAL_PEER = 2,
    MKA_PS_SAK_USE = 3,
    MKA_PS_DISTRIBUTED_SAK = 4,
    MKA_PS_DISTRIBUTED_CAK = 5,
    MKA_PS_KMD = 6,
    MKA_PS_ANNOUNCEMENT = 7,
    /** XPN extensions (802.1Xbx / 802.1X-2020) */
    MKA_PS_XPN = 8,
    MKA_PS_ICV_INDICATOR = 255
} MkaParamSetType;

/** MACsec Capability (Basic Parameter Set, 11.11.1) */
typedef enum {
    MKA_CAP_NOT_IMPLEMENTED = 0,
    MKA_CAP_INTEGRITY_ONLY = 1,
    /** + confidentiality, offset 0 */
    MKA_CAP_INTEGRITY_CONF = 2,
    /** + selectable confidentiality offset */
    MKA_CAP_INTEGRITY_CONF_OFFSET = 3
} MkaMacsecCapability;

/** Confidentiality offsets carried in the Distributed SAK parameter set
 * (Table 11-6). The field is two bits wide, so all four values are legal on
 * the wire; the enumeration is the offset selector, not the octet count it
 * names. */
typedef enum {
    /** no confidentiality: the cipher suite runs integrity-only */
    MKA_CONF_OFFSET_NONE = 0,
    /** confidentiality from octet 0 */
    MKA_CONF_OFFSET_0 = 1,
    /** confidentiality from octet 30 */
    MKA_CONF_OFFSET_30 = 2,
    /** confidentiality from octet 50 */
    MKA_CONF_OFFSET_50 = 3
} MkaConfidentialityOffset;

/* ------------------------------------------------------------------------- */
/* Return codes                                                              */
/* ------------------------------------------------------------------------- */

typedef enum {
    MKA_OK = 0,
    /** parameter is invalid */
    MKA_ERR_BAD_ARG = -1,
    /** underlying wolfSSL failure */
    MKA_ERR_CRYPTO = -2,
    /** output buffer too small */
    MKA_ERR_BUFFER = -3,
    /** malformed MKPDU */
    MKA_ERR_PARSE = -4,
    /** ICV verification failed */
    MKA_ERR_ICV = -5,
    /** unsupported EAPOL/MKA version */
    MKA_ERR_VERSION = -6,
    /** peer not found / not live */
    MKA_ERR_NO_PEER = -7,
    /** operation invalid in current state */
    MKA_ERR_STATE = -8,
    /** table full */
    MKA_ERR_FULL = -9,
    /** operation requires being Key Server */
    MKA_ERR_NOT_KS = -10,
    /** internal error */
    MKA_ERR_INTERNAL = -11,
    /** stale/replayed MKPDU (Message Number) */
    MKA_ERR_REPLAY = -12,
    /** the previous SAK has been adopted but has not reached the wire yet, so a
     *  second one cannot help. A make-before-break handover that is merely
     *  still running is *not* this: rekeying out of one is normal, and the
     *  packet-number-exhaustion rekey depends on being able to */
    MKA_ERR_REKEY_BUSY = -13
} MkaStatus;

/* Build a 64-bit unsigned constant from its high and low 32-bit halves. This
 * spells the protocol's 64-bit values (cipher-suite IDs, XPN PN thresholds)
 * without a C99 'ULL'-suffixed 64-bit literal, so they compile
 * -Wlong-long-clean even under a strict pre-C99 toolchain - needing only a
 * 64-bit uint64_t (the one long-long extension MACsec's 64-bit fields require).
 * It is an integer constant expression, usable in case labels and static
 * initializers. */
#define MKA_U64(hi, lo) (((uint64_t)(hi) << 32U) | (uint64_t)(lo))

/* MACsec Cipher Suites (IEEE Std 802.1AE-2018, Table 14-1). The XPN suites use
 * 64-bit packet numbering (IEEE Std 802.1Xbx-2014). */
#define MKA_CIPHER_GCM_AES_128     MKA_U64(0x0080C200U, 0x01000001U)
#define MKA_CIPHER_GCM_AES_256     MKA_U64(0x0080C200U, 0x01000002U)
#define MKA_CIPHER_GCM_AES_XPN_128 MKA_U64(0x0080C200U, 0x01000003U)
#define MKA_CIPHER_GCM_AES_XPN_256 MKA_U64(0x0080C200U, 0x01000004U)

/* ------------------------------------------------------------------------- */
/* Common value structs                                                      */
/* ------------------------------------------------------------------------- */

/** Opaque handle to one RNG object from the crypto layer's pool. Acquired with
 * wm_Crypto_RandomInit and passed to the random-consuming functions. */
typedef struct MkaRandom MkaRandom;

/** Opaque handle to one AES-CMAC context from the crypto layer's pool. Acquired
 * with wm_Crypto_CmacInit and passed (required, non-NULL) to the
 * CMAC-consuming functions so the ~1 KB wolfSSL Cmac object always lives in
 * wolfMKA-owned storage - never a wolfSSL stack frame or allocation. */
typedef struct MkaCmacCtx MkaCmacCtx;

/** Member Identifier + Message Number, the unit used in peer lists. */
typedef struct {
    /** Member Identifier: random per participant, redrawn on restart */
    uint8_t mi[MKA_MI_LEN];
    /** Message Number this member was last heard at */
    uint32_t mn;
} MkaPeerId;

/** The CAK / CKN pair identifying a Connectivity Association Key. */
typedef struct {
    /** the Connectivity Association Key itself */
    uint8_t cak[MKA_MAX_CAK_LEN];
    /** 16 or 32 */
    size_t cak_len;
    /** the CAK Name: identifies this CA on the wire, and selects the CAK a
     *  received MKPDU should be verified with */
    uint8_t ckn[MKA_MAX_CKN_LEN];
    /** 1..32 */
    size_t ckn_len;
} MkaCakPair;

/** Derived per-CA secret keys (KEK, ICK). */
typedef struct {
    /** Key Encrypting Key: wraps a distributed SAK */
    uint8_t kek[MKA_MAX_CAK_LEN];
    /** KEK length in octets (16 or 32) */
    size_t kek_len;
    /** Integrity Check Key: authenticates an MKPDU's ICV */
    uint8_t ick[MKA_MAX_CAK_LEN];
    /** ICK length in octets (16 or 32) */
    size_t ick_len;
} MkaDerivedKeys;

/**
 * Return a static human-readable name for an MkaStatus code.
 * @param[in] status  The status code to describe.
 * @return A pointer to a static, NUL-terminated string naming the code, or
 *         "MKA_ERR_UNKNOWN" for any value outside the MkaStatus enumeration.
 *         The returned string is never NULL and must not be freed or modified.
 */
const char* wm_Status_String(MkaStatus status);

#ifdef __cplusplus
}
#endif

#endif /* WOLFMKA_TYPES_H */
