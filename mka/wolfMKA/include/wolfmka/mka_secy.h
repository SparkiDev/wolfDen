/* mka_secy.h
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
 * Abstract SecY (MAC Security Entity) interface. MKA is the control plane; the
 * SecY is the data plane that actually performs MACsec encryption/integrity.
 * IEEE Std 802.1X-2010 (Clause 10) and 802.1AE define the operations MKA needs
 * to drive the SecY. wolfMKA keeps these abstract so the same KaY can sit on
 * top of a Linux kernel macsec device, a hardware offload, or a test shim.
 *
 * The KaY invokes these callbacks as a SAK is agreed and installed:
 *
 *   create_rx_sc / create_tx_sc   establish Secure Channels
 *   install_rx_sa / install_tx_sa install a SAK as a Secure Association
 *   enable_receive / enable_transmit
 *   delete_sa                     tear down an SA on rekey/teardown
 *
 * All callbacks return 0 on success, non-zero on failure.
 */

#ifndef WOLFMKA_SECY_H
#define WOLFMKA_SECY_H

#include "mka_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Returned by a SecY callback that programs the data plane asynchronously: the
 * operation has been accepted but is not yet complete. The integrator must
 * later report completion with wm_Participant_SecyComplete(); until every
 * outstanding operation completes, the KaY holds back enabling transmit
 * protection so it never sends on an SA the hardware has not yet installed. A
 * purely synchronous backend returns 0 and never uses this value.
 *
 * The value is a distinctive sentinel ('PEND' in ASCII), deliberately NOT 1, so
 * a backend that idiomatically does `return 1;` to mean success is treated as
 * synchronous-done rather than mistaken for an asynchronous deferral. Only this
 * exact value defers; any other non-negative return is synchronous success.
 */
#define MKA_SECY_PENDING 0x50454E44

/**
 * MACsec statistics kept by the SecY for the port as a whole (IEEE Std
 * 802.1AE-2018, 10.7.9/10.7.10 for the receive counters and 10.7.18/10.7.19 for
 * the transmit ones). Read through MkaSecyOps.get_secy_stats; wolfMKA never
 * maintains these itself - the data plane owns them.
 */
typedef struct {
    /** transmitted without a SecTAG because protection was off */
    uint64_t out_pkts_untagged;
    /** discarded on transmit: longer than the peer accepts */
    uint64_t out_pkts_too_long;
    /** user-data octets integrity-protected but not encrypted */
    uint64_t out_octets_protected;
    /** user-data octets encrypted as well as protected */
    uint64_t out_octets_encrypted;
    /** received without a SecTAG and accepted (validation permissive) */
    uint64_t in_pkts_untagged;
    /** received without a SecTAG and discarded (validation strict) */
    uint64_t in_pkts_no_tag;
    /** discarded: the SecTAG itself was malformed */
    uint64_t in_pkts_bad_tag;
    /** discarded: no Secure Association matched the SecTAG */
    uint64_t in_pkts_no_sa;
    /** received for an unknown Secure Association and accepted */
    uint64_t in_pkts_no_sa_error;
    /** discarded because the SecY validation rate limit was hit */
    uint64_t in_pkts_overrun;
    /** user-data octets whose integrity was checked, not decrypted */
    uint64_t in_octets_validated;
    /** user-data octets decrypted as well as validated */
    uint64_t in_octets_decrypted;
} MkaSecyStats;

/** Per-transmit-Secure-Channel statistics (802.1AE secyTxSCStatsEntry). */
typedef struct {
    /** transmitted with integrity protection only */
    uint64_t out_pkts_protected;
    /** transmitted encrypted as well as protected */
    uint64_t out_pkts_encrypted;
} MkaTxScStats;

/** Per-receive-Secure-Channel statistics (802.1AE secyRxSCStatsEntry). */
typedef struct {
    /** received and validated successfully */
    uint64_t in_pkts_ok;
    /** delivered without validation (validation disabled) */
    uint64_t in_pkts_unchecked;
    /** discarded: packet number below the replay window */
    uint64_t in_pkts_late;
    /** failed validation but were delivered anyway (permissive) */
    uint64_t in_pkts_invalid;
    /** failed validation and were discarded */
    uint64_t in_pkts_not_valid;
} MkaRxScStats;

/**
 * Data-plane (SecY) callbacks the KaY drives as a SAK is agreed.
 *
 * Every callback returns 0 on success and a negative value on failure, or the
 * exact MKA_SECY_PENDING sentinel to signal asynchronous completion (see
 * above). Optional callbacks may be left NULL; the KaY skips them.
 */
typedef struct MkaSecyOps {
    /** Create the transmit Secure Channel identified by our SCI. */
    int (*create_tx_sc)(void* ctx, const uint8_t sci[MKA_SCI_LEN]);

    /** Create a receive Secure Channel for a peer SCI. */
    int (*create_rx_sc)(void* ctx, const uint8_t sci[MKA_SCI_LEN]);

    /** Install the transmit SA (our SCI, association/key num, SAK). */
    int (*install_tx_sa)(void* ctx, const uint8_t sci[MKA_SCI_LEN], uint8_t an,
        uint32_t kn, const uint8_t* sak, size_t sak_len);

    /** Install a receive SA for a peer SCI. */
    int (*install_rx_sa)(void* ctx, const uint8_t sci[MKA_SCI_LEN], uint8_t an,
        uint32_t kn, const uint8_t* sak, size_t sak_len);

    /** Enable/disable the transmit SA (protect outbound traffic). */
    int (*enable_transmit)(void* ctx, uint8_t an, bool enable);

    /** Enable/disable a receive SA for a peer SCI. */
    int (*enable_receive)(void* ctx, const uint8_t sci[MKA_SCI_LEN], uint8_t an,
        bool enable);

    /** Delete an SA (transmit if sci == NULL, else the peer rx SA). */
    int (*delete_sa)(void* ctx, const uint8_t* sci, uint8_t an);

    /* --- Optional: delay/replay protection (802.1X-2010, 9.4.1) --- */

    /**
     * Read the transmit SA's next packet number (full 64 bits).
     *
     * Used to advertise the Lowest Acceptable PN: the low 32 bits travel in the
     * MACsec SAK Use set, and under an XPN cipher suite the high 32 bits travel
     * in the XPN parameter set (11.11.6). A 32-bit (non-XPN) data plane fills
     * the low 32 bits and leaves the high 32 as zero - mirroring set_lowest_pn,
     * which is likewise a single 64-bit hook regardless of suite width.
     */
    int (*get_next_pn)(void* ctx, uint8_t an, uint64_t* next_pn);

    /**
     * Advance a receive SA's replay-window lower bound.
     *
     * Set to the value a transmitting peer last advertised; enables delay
     * protection. @p lowest_pn is the full Lowest Acceptable PN: 32-bit for the
     * non-XPN suites, up to 64-bit for the XPN suites (a 32-bit-only data plane
     * uses the low 32 bits).
     */
    int (*set_lowest_pn)(void* ctx, const uint8_t sci[MKA_SCI_LEN], uint8_t an,
        uint64_t lowest_pn);

    /* --- Optional: Extended Packet Numbering (IEEE Std 802.1Xbx-2014) --- */

    /**
     * Configure the cipher suite, SSCI (for XPN) and confidentiality offset on
     * a channel.
     *
     * Called before the channel's SAs are installed. The Salt is derived by the
     * SecY from the SAK per 802.1AE-2018; it is not distributed by MKA.
     * @c confidentiality_offset is the in-force MkaConfidentialityOffset
     * selection - MKA_CONF_OFFSET_0/30/50, i.e. 0, 30 or 50 octets of cleartext
     * before encryption begins - chosen by the Key Server and adopted by every
     * member. Under WOLFMKA_CIPHER_NEGOTIATION it may instead be
     * MKA_CONF_OFFSET_NONE, meaning a member cannot do confidentiality, so the
     * cipher suite must run integrity-only (no encryption).
     */
    int (*set_cipher_suite)(void* ctx, const uint8_t sci[MKA_SCI_LEN],
        uint64_t cipher_suite, uint32_t ssci, uint8_t confidentiality_offset);

    /* --- Optional: MACsec statistics (802.1AE Clause 10.7) --------------- */

    /**
     * Read the port's MACsec statistics. Optional; leave NULL when the data
     * plane exposes no counters. The KaY never calls this on its own - it is
     * driven by wm_Participant_GetSecyStats() on behalf of a management or
     * diagnostics interface (OPEN Alliance AutoMKA-07009).
     */
    int (*get_secy_stats)(void* ctx, MkaSecyStats* out);
    /** Read one transmit Secure Channel's statistics. Optional. */
    int (*get_tx_sc_stats)(void* ctx, const uint8_t sci[MKA_SCI_LEN],
        MkaTxScStats* out);
    /** Read one receive Secure Channel's statistics. Optional. */
    int (*get_rx_sc_stats)(void* ctx, const uint8_t sci[MKA_SCI_LEN],
        MkaRxScStats* out);

    /** Opaque context passed to every callback. */
    void* ctx;
} MkaSecyOps;

#ifdef __cplusplus
}
#endif

#endif /* WOLFMKA_SECY_H */
