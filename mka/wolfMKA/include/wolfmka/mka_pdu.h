/* mka_pdu.h
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
 * Encoding and decoding of MKA Protocol Data Units (MKPDUs) as specified in
 * IEEE Std 802.1X-2010, Clause 11.11. An MKPDU is carried as the body of an
 * EAPOL-MKA frame and is a sequence of parameter sets:
 *
 *   [EAPOL header]
 *   Basic Parameter Set            (always first)
 *   Live Peer List                 (optional)
 *   Potential Peer List            (optional)
 *   MACsec SAK Use                 (optional)
 *   Distributed SAK                (optional)
 *   ... (other sets ignored on decode)
 *   ICV Indicator + ICV            (always last)
 *
 * This module is purely about the wire format; the protocol logic lives in
 * mka_kay.[ch].
 */

#ifndef WOLFMKA_PDU_H
#define WOLFMKA_PDU_H

#include "mka_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Peers represented in one MKPDU. Override at build time if needed; a larger
 * value needs a correspondingly larger MKA_MKPDU_MAX_LEN to encode them all. */
#ifndef MKA_MAX_PEERS
    #define MKA_MAX_PEERS 32U
#endif

/* A peer-list parameter set carries its body length in a 12-bit field, and each
 * entry is 16 octets, so more than 255 peers cannot be encoded - the length
 * would wrap to a smaller value and the list would be silently truncated on the
 * wire rather than rejected. */
#if MKA_MAX_PEERS > 255U
    #error                                                                     \
        "MKA_MAX_PEERS cannot exceed 255: a peer list's 12-bit body length \
field cannot express more, and the list would be silently truncated."
#endif
/* every parameter set has a 4-octet hdr*/
#define MKA_PARAM_HDR_LEN   4U
/* 32-octet SAK + 8 (AES key wrap) */
#define MKA_MAX_WRAPPED_SAK 40U
/* Key Management Domain name (type 6) */
#define MKA_MAX_KMD_LEN     64U

/* The remaining fixed field widths of 11.11, named so the encode helper, its
 * mirror size helper and the decoder cannot drift apart: each appears in all
 * three, and wm_Pdu_Encode's writes are unchecked precisely because
 * wm_Pdu_EncodedSize is trusted to have computed the same total. */
/* Lowest Acceptable PN as carried in SAK Use: the low 32 bits, with the MSBs
 * riding in the XPN parameter set for an XPN cipher suite */
#define MKA_LPN_LEN             4U
/* MACsec SAK Use body (11.11.4): the Latest and Old keys, each named by
 * Key Server MI || Key Number || Lowest Acceptable PN */
#define MKA_SAK_USE_BODY_LEN    (2U * (MKA_MI_LEN + MKA_KN_LEN + MKA_LPN_LEN))
/* IEEE Std 802.1AE Cipher Suite reference number, on the wire */
#define MKA_CIPHER_SUITE_LEN    8U
/* a GCM-AES-128 SAK wrapped by AES Key Wrap: 16 + 8 */
#define MKA_WRAPPED_SAK_128_LEN 24U
/* Announcement TLV header: 1-octet type, 1-octet length */
#define MKA_ANN_TLV_HDR_LEN     2U

/** Basic Parameter Set (11.11.1). */
typedef struct {
    /** MKA version (1) */
    uint8_t version;
    /** Key Server priority */
    uint8_t priority;
    /** Key Server flag */
    bool key_server;
    /** MACsec Desired flag */
    bool macsec_desired;
    /** MkaMacsecCapability */
    uint8_t macsec_capability;
    /** actor SCI (MAC || port) */
    uint8_t sci[MKA_SCI_LEN];
    /** actor Member Identifier */
    uint8_t mi[MKA_MI_LEN];
    /** actor Message Number */
    uint32_t mn;
    /** Algorithm Agility (0x0080C201) */
    uint32_t algo_agility;
    /** CAK Name */
    uint8_t ckn[MKA_MAX_CKN_LEN];
    /** CAK Name length in octets */
    size_t ckn_len;
} MkaBasicParamSet;

/** Live or Potential Peer List (11.11.2 / 11.11.3). */
typedef struct {
    /** this parameter set is present in the MKPDU */
    bool present;
    /** the listed members, each an MI and the MN it was last heard at */
    MkaPeerId peers[MKA_MAX_PEERS];
    /** number of entries in @c peers */
    size_t count;
    /** Octet 2 of the parameter set. Reserved (0) except in a Live Peer List
     * sent by a Key Server distributing a SAK for an XPN Cipher Suite, where
     * it carries that Key Server's own SSCI (IEEE Std 802.1X-2020 11.11,
     * 9.10) - the value it transmits under, and equally the position it would
     * have occupied in this list. Only meaningful alongside an MKA Version
     * Identifier of 3 or above. */
    uint8_t ks_ssci;
} MkaPeerList;

/*
 * Key-in-use flags for MACsec SAK Use (11.11.4). The values are the on-wire
 * bit positions within octet 1 of the parameter set, so encode and decode are
 * a plain mask rather than four conditionals.
 */
#define MKA_SAK_USE_LATEST_TX 0x20U
#define MKA_SAK_USE_LATEST_RX 0x10U
#define MKA_SAK_USE_OLD_TX    0x02U
#define MKA_SAK_USE_OLD_RX    0x01U
/* All four key-in-use flags; the rest of octet 1 holds the AN fields. */
#define MKA_SAK_USE_KEY_MASK  0x33U

/*
 * Transmission-mode flags for MACsec SAK Use (11.11.4). The values are the
 * on-wire bit positions within octet 2 of the parameter set (the low nibble
 * holds the body length), so encode and decode are a plain mask.
 */
#define MKA_SAK_USE_PLAIN_TX      0x80U
#define MKA_SAK_USE_PLAIN_RX      0x40U
#define MKA_SAK_USE_DELAY_PROTECT 0x20U
/* All three mode flags; the rest of octet 2 holds body_len[11:8]. */
#define MKA_SAK_USE_MODE_MASK     0xE0U

/** MACsec SAK Use (11.11.4). */
typedef struct {
    /** this parameter set is present in the MKPDU */
    bool present;
    /** Latest Key Association Number */
    uint8_t latest_an;
    /** Old Key Association Number */
    uint8_t old_an;
    /** MKA_SAK_USE_* : Latest/Old Tx/Rx */
    uint8_t key_flags;
    /** MKA_SAK_USE_* : Plain Tx/Rx, Delay */
    uint8_t mode_flags;
    /** Member Identifier of the Key Server that issued the Latest key */
    uint8_t latest_ks_mi[MKA_MI_LEN];
    /** Latest Key Number */
    uint32_t latest_kn;
    /** Latest Lowest Acceptable PN */
    uint32_t latest_lpn;
    /** Member Identifier of the Key Server that issued the Old key */
    uint8_t old_ks_mi[MKA_MI_LEN];
    /** Key Number of the Old key */
    uint32_t old_kn;
    /** Lowest Acceptable PN the sender will accept on the Old key */
    uint32_t old_lpn;
} MkaSakUse;

/*
 * Boolean accessors for the SAK Use flag fields. Each yields true when the
 * corresponding bit is set in the matching octet-1 (key) or octet-2 (mode)
 * field of the parameter set above.
 */
#define MKA_SAK_USE_IS_LATEST_TX(su)                                           \
    (((su)->key_flags & MKA_SAK_USE_LATEST_TX) != 0U)
#define MKA_SAK_USE_IS_LATEST_RX(su)                                           \
    (((su)->key_flags & MKA_SAK_USE_LATEST_RX) != 0U)
#define MKA_SAK_USE_IS_OLD_TX(su) (((su)->key_flags & MKA_SAK_USE_OLD_TX) != 0U)
#define MKA_SAK_USE_IS_OLD_RX(su) (((su)->key_flags & MKA_SAK_USE_OLD_RX) != 0U)
#define MKA_SAK_USE_IS_PLAIN_TX(su)                                            \
    (((su)->mode_flags & MKA_SAK_USE_PLAIN_TX) != 0U)
#define MKA_SAK_USE_IS_PLAIN_RX(su)                                            \
    (((su)->mode_flags & MKA_SAK_USE_PLAIN_RX) != 0U)
#define MKA_SAK_USE_IS_DELAY_PROTECT(su)                                       \
    (((su)->mode_flags & MKA_SAK_USE_DELAY_PROTECT) != 0U)

/*
 * Setters for the SAK Use flag fields. Each sets the corresponding bit in the
 * matching octet-1 (key) or octet-2 (mode) field, leaving the others intact.
 */
#define MKA_SAK_USE_SET_LATEST_TX(su)                                          \
    ((su)->key_flags |= (uint8_t)MKA_SAK_USE_LATEST_TX)
#define MKA_SAK_USE_SET_LATEST_RX(su)                                          \
    ((su)->key_flags |= (uint8_t)MKA_SAK_USE_LATEST_RX)
#define MKA_SAK_USE_SET_OLD_TX(su)                                             \
    ((su)->key_flags |= (uint8_t)MKA_SAK_USE_OLD_TX)
#define MKA_SAK_USE_SET_OLD_RX(su)                                             \
    ((su)->key_flags |= (uint8_t)MKA_SAK_USE_OLD_RX)
#define MKA_SAK_USE_SET_PLAIN_TX(su)                                           \
    ((su)->mode_flags |= (uint8_t)MKA_SAK_USE_PLAIN_TX)
#define MKA_SAK_USE_SET_PLAIN_RX(su)                                           \
    ((su)->mode_flags |= (uint8_t)MKA_SAK_USE_PLAIN_RX)
#define MKA_SAK_USE_SET_DELAY_PROTECT(su)                                      \
    ((su)->mode_flags |= (uint8_t)MKA_SAK_USE_DELAY_PROTECT)

/** Distributed SAK (11.11.5). */
typedef struct {
    /** this parameter set is present in the MKPDU */
    bool present;
    /** Association Number for this SAK */
    uint8_t distributed_an;
    /** MkaConfidentialityOffset */
    uint8_t confidentiality_offset;
    /** Key Number */
    uint32_t kn;
    /** 0 => default GCM-AES-128 */
    uint64_t cipher_suite;
    /** the SAK wrapped with the CA's KEK (AES Key Wrap, RFC 3394) */
    uint8_t wrapped_sak[MKA_MAX_WRAPPED_SAK];
    /** 0 => plain (MACsec not in use) */
    size_t wrapped_len;
} MkaDistSak;

#ifdef WOLFMKA_DISTRIBUTED_CAK
/** Distributed CAK (parameter set type 5): an AES-Key-Wrapped CAK followed by
 * its CKN. The boundary between the wrapped CAK and the CKN is not carried on
 * the wire (both are variable length), so the body is captured raw here and the
 * KaY splits it using the receiving participant's CAK length - the wrapped CAK
 * is CAK length + 8 octets (RFC 3394), the remainder is the CKN. */
typedef struct {
    bool present;
    uint8_t
        /** wrapped CAK || CKN */
        body[MKA_MAX_WRAPPED_SAK + MKA_MAX_CKN_LEN];
    size_t body_len;
} MkaDistCak;
#endif /* WOLFMKA_DISTRIBUTED_CAK */

#ifdef WOLFMKA_KMD
/** Key Management Domain (parameter set type 6): a variable-length octet string
 * naming the key management domain the Key Server advertises. Carried verbatim;
 * no cryptography (the MKPDU ICV already authenticates it). */
typedef struct {
    bool present;
    uint8_t kmd[MKA_MAX_KMD_LEN];
    size_t kmd_len;
} MkaKmd;
#endif /* WOLFMKA_KMD */

/*
 * Announcement parameter set (IEEE Std 802.1X-2020, 11.12, Figure 11-15;
 * parameter set type 7). Carries EAPoL-MKA-Announcement TLVs (Figure 11-19: a
 * 7-bit type and 9-bit length). wolfMKA handles the MACsec Cipher Suites TLV
 * (type 112, 11.12.3, Figure 11-22), through which a Key Server learns the
 * suites a peer supports (AUTOSAR CP_SWS_Mka_00009).
 *
 * Per 11.12.3 each suite is a 10-octet entry: a 2-octet implementation
 * capability (only the two least-significant bits are meaningful - the MACsec
 * Capability of Table 11-6; the 14 more-significant bits are transmitted as 0
 * and ignored on receipt) followed by the 8-octet IEEE Std 802.1AE Cipher Suite
 * reference number. The TLV information string is a multiple of 10 octets.
 */
/* EAPoL-MKA-Announcement TLV type */
#define MKA_ANN_TLV_CIPHER_SUITES 112U
/* 2-octet cap + 8-octet suite */
#define MKA_CS_TLV_ENTRY_LEN      10U
/* suites advertised in one TLV */
#define MKA_MAX_CIPHER_SUITES     4U

#ifndef WOLFMKA_NO_ANNOUNCEMENTS
/** One entry of an Announcement's cipher-suite TLV: a suite the sender accepts,
 *  and the MACsec Capability it can offer with it. */
typedef struct {
    /** MACsec Capability in the low 2 bits */
    uint16_t capability;
    /** 64-bit cipher suite reference */
    uint64_t cipher_suite;
} MkaCipherSuiteEntry;

/** Announcement parameter set (type 7): the cipher suites the sender will
 * accept, in preference order (IEEE Std 802.1X-2010, 11.12). */
typedef struct {
    /** an Announcement carrying a cipher-suite TLV is present */
    bool present;
    /** the cipher suites this participant will accept, most preferred first */
    MkaCipherSuiteEntry suites[MKA_MAX_CIPHER_SUITES];
    /** number of entries in @c suites */
    size_t count;
} MkaAnnounce;
#endif /* WOLFMKA_NO_ANNOUNCEMENTS */

/*
 * MACsec XPN parameter set (IEEE Std 802.1X-2020, 11.11.6, Figure 11-16).
 *
 * The MACsec SAK Use set carries the 32 least-significant bits of each Lowest
 * Acceptable PN; this set supplies the 32 most-significant bits, so the full
 * 64-bit value can be reconstructed. The PN MSBs are transmitted as zero, and
 * ignored on receipt, when the cipher suite does not use XPN. Header octet 2 is
 * the MKA suspension time in seconds (suspendedWhile / suspendFor); wolfMKA
 * does not implement suspension, so it transmits 0. Body is a fixed 8 octets:
 * the Latest then the Old PN MSBs, big-endian.
 */
#define MKA_XPN_BODY_LEN 8U

/** XPN parameter set (type 8): the upper 32 bits of the Latest and Old key
 * packet numbers, for the extended-packet-number cipher suites (802.1Xbx). */
typedef struct {
    /** an XPN parameter set is present in the MKPDU */
    bool present;
    /** octet 2: suspension time (s) */
    uint8_t suspension_time;
    /** MSBs of Latest Key LPN */
    uint32_t latest_lpn_msb;
    /** MSBs of Old Key LPN */
    uint32_t old_lpn_msb;
} MkaXpn;

/** A decoded / to-be-encoded MKPDU (excluding the ICV, handled internally).
 *
 * Every parameter set is a fixed-size struct with a companion length or count,
 * so on the encode side those must not exceed the array they describe:
 * basic.ckn_len <= MKA_MAX_CKN_LEN, dist_sak.wrapped_len <=
 * MKA_MAX_WRAPPED_SAK, the peer-list counts <= MKA_MAX_PEERS, announce.count <=
 * MKA_MAX_CIPHER_SUITES, and dist_cak.body_len / kmd.kmd_len within their own
 * buffers. wm_Pdu_Encode and wm_Pdu_EncodedSize check this rather than trust
 * it. The decoder never produces an out-of-range value. */
typedef struct {
    /** Basic Parameter Set; mandatory, always first */
    MkaBasicParamSet basic;
    /** Live Peer List (type 1): members that have proven liveness */
    MkaPeerList live_peers;
    /** Potential Peer List (type 2): members heard but not yet live */
    MkaPeerList potential_peers;
    /** MACsec SAK Use (type 3): which keys the sender is using */
    MkaSakUse sak_use;
    /** Distributed SAK (type 4): a wrapped key from the Key Server */
    MkaDistSak dist_sak;
#ifdef WOLFMKA_DISTRIBUTED_CAK
    MkaDistCak dist_cak;
#endif
#ifdef WOLFMKA_KMD
    MkaKmd kmd;
#endif
#ifndef WOLFMKA_NO_ANNOUNCEMENTS
    /** Announcement (type 7): the cipher suites the sender accepts */
    MkaAnnounce announce;
#endif
    /** XPN (type 8): the upper 32 bits of the packet numbers */
    MkaXpn xpn;
} MkaPdu;

/**
 * Encode an MKPDU into a complete EAPOL-MKA frame (header through ICV).
 *
 * The ICV is computed with AES-CMAC over the encoded bytes using the ICK.
 *
 * @param[in]  cmac     CMAC workspace (wm_Crypto_CmacInit) for the ICV;
 * required (non-NULL).
 * @param[in]  pdu      The parameter sets to encode.
 * @param[in]  ick      The Integrity Check Key for the trailing ICV.
 * @param[in]  ick_len  ICK length in octets (16 or 32).
 * @param[out] out      Output buffer.
 * @param[in]  cap      Capacity of out in octets.
 * @param[out] out_len  Receives the number of octets written.
 * @return MKA_OK on success;
 *         MKA_ERR_BAD_ARG if cmac, pdu, ick, out or out_len is NULL, or a
 *         length field in pdu exceeds the array that backs it (ckn_len,
 *         wrapped_len, the peer-list and announcement counts, dist_cak.body_len
 *         and kmd.kmd_len);
 *         MKA_ERR_BUFFER if out is too small or the body exceeds 65535 octets;
 *         MKA_ERR_CRYPTO if ICV computation fails.
 */
MkaStatus wm_Pdu_Encode(MkaCmacCtx* cmac, const MkaPdu* pdu, const uint8_t* ick,
    size_t ick_len, uint8_t* out, size_t cap, size_t* out_len);

/**
 * Compute the exact encoded size (including the ICV) of an MKPDU.
 *
 * Returns the number of octets wm_Pdu_Encode would write for @p pdu, so a
 * caller can size or validate the output buffer up front.
 *
 * @param[in] pdu  The parameter sets that would be encoded.
 * @return The encoded size in octets, or 0 if pdu is NULL or any of its length
 *         fields exceeds the array that backs it.
 */
size_t wm_Pdu_EncodedSize(const MkaPdu* pdu);

/**
 * Decode and ICV-verify an EAPOL-MKA frame.
 *
 * The ICV is checked with the supplied ICK before any parameter-set content is
 * trusted.
 *
 * @param[in]  cmac     CMAC workspace (wm_Crypto_CmacInit) for the ICV;
 * required (non-NULL).
 * @param[in]  in       The received frame.
 * @param[in]  in_len   Length of the frame in octets.
 * @param[in]  ick      The Integrity Check Key used to verify the ICV.
 * @param[in]  ick_len  ICK length in octets (16 or 32).
 * @param[out] pdu      Out: the decoded parameter sets.
 * @return MKA_OK on success;
 *         MKA_ERR_BAD_ARG if cmac, in, ick or pdu is NULL;
 *         MKA_ERR_PARSE if the frame is malformed;
 *         MKA_ERR_VERSION if the EAPOL/MKA version is unsupported;
 *         MKA_ERR_ICV if ICV verification fails.
 */
MkaStatus wm_Pdu_Decode(MkaCmacCtx* cmac, const uint8_t* in, size_t in_len,
    const uint8_t* ick, size_t ick_len, MkaPdu* pdu);

/**
 * Recover the Basic Parameter Set without verifying the ICV.
 *
 * Lets a receiver look up which CAK (and therefore ICK) to use before it can
 * verify the ICV. Only the Basic Parameter Set is parsed.
 *
 * @param[in]  in      The received frame.
 * @param[in]  in_len  Length of the frame in octets.
 * @param[out] basic   Out: the decoded Basic Parameter Set.
 * @return MKA_OK on success;
 *         MKA_ERR_BAD_ARG if in or basic is NULL;
 *         MKA_ERR_PARSE if the frame is malformed;
 *         MKA_ERR_VERSION if the EAPOL/MKA version is unsupported.
 */
MkaStatus wm_Pdu_PeekBasic(const uint8_t* in, size_t in_len,
    MkaBasicParamSet* basic);

#ifdef __cplusplus
}
#endif

#endif /* WOLFMKA_PDU_H */
