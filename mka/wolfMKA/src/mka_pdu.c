/* mka_pdu.c  -  MKPDU encode/decode (IEEE Std 802.1X-2010, 11.11).
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
 * Written to conform to MISRA C:2012 (see MISRA.md for the deviation record).
 */

#include "wolfmka/mka_pdu.h"
#include "wolfmka/mka_crypto.h"
#include "wolfmka/internal/mka_fault.h"
/* shared w_be16/32/48, rd_be16/32/48 */
#include "wolfmka/mka_bytes.h"

/* Offset of the sender SCI MAC within the EAPOL PDU: past the EAPOL header,
 * then the 4-octet Basic Parameter Set header that precedes the Actor SCI.
 */
#define MKA_L2_SCI_MAC_OFFSET (EAPOL_HDR_LEN + 4U)
/* Smallest EAPOL PDU this helper may be handed: it reads the six SCI MAC
 * octets at MKA_L2_SCI_MAC_OFFSET. */
#define MKA_L2_MIN_PDU_LEN    (MKA_L2_SCI_MAC_OFFSET + 6U)

/**
 * Build the L2 prefix the ICV covers: PAE group DA || sender SCI MAC || EAPOL
 * EtherType (MKA_ICV_L2_PREFIX_LEN octets).
 *
 * @p pdu_len is taken rather than assumed: the sender MAC is read from a fixed
 * offset inside the PDU, so the caller's guarantee that the PDU is long enough
 * is a real precondition and not an incidental property of the call sites. On
 * receive it holds because a frame short of an ICV has already been rejected;
 * on transmit because the frame is complete before the ICV is computed.
 * @param[out] l2         receives the prefix.
 * @param[in]  eapol_pdu  the EAPOL PDU the sender MAC is taken from.
 * @param[in]  pdu_len    its length; must be at least MKA_L2_MIN_PDU_LEN.
 */
static void mka_build_l2_prefix(uint8_t l2[MKA_ICV_L2_PREFIX_LEN],
    const uint8_t* eapol_pdu, size_t pdu_len)
{
    static const uint8_t pae_group[6] = MKA_PAE_GROUP_ADDR;

    WOLFMKA_ASSERT(pdu_len >= MKA_L2_MIN_PDU_LEN);
    (void)pdu_len;

    (void)WOLFMKA_MEMCPY(&l2[0], pae_group, sizeof pae_group);
    (void)WOLFMKA_MEMCPY(&l2[6], &eapol_pdu[MKA_L2_SCI_MAC_OFFSET], 6);
    l2[12] = (uint8_t)(EAPOL_ETHERTYPE >> 8);
    l2[13] = (uint8_t)(EAPOL_ETHERTYPE & 0xFFU);
}

/* ------------------------------------------------------------------------- */
/* Byte cursor helpers                                                       */
/* ------------------------------------------------------------------------- */

/* These wrap the raw byte-order primitives of mka_bytes.h (w_be16, rd_be32,
 * ...) with the cursor bookkeeping the encoders and decoders need. They carry
 * the file-static mka_ prefix like every other static here; the shared
 * primitives they call keep their own shorter names, so a call reads as
 * mka_w_be32(w, v) at the cursor and w_be32(p, v) at a raw address. */

/** Forward output cursor for MKPDU encoding: the byte-cursor helpers append to
 * buf and advance len. wm_Pdu_Encode sizes the whole frame up front, so the
 * writes need no runtime bounds checks; cap is consulted only by the
 * debug-build assertions. */
typedef struct {
    /** the output buffer being filled */
    uint8_t* buf;
    /** its capacity; used only by the debug-build bounds assertion */
    size_t cap;
    /** octets written so far, and so the next write offset */
    size_t len;
} MkaWriter;

/**
 * Append n octets to the writer.
 *
 * The total encoded size is checked once up front (wm_Pdu_Encode), so the
 * per-write path is unconditional; a debug build still asserts the bound.
 * @param[in,out] w  Output cursor.
 * @param[in]     p  Source bytes.
 * @param[in]     n  Number of octets to append.
 */
static MKA_INLINE void mka_w_bytes(MkaWriter* w, const uint8_t* p, size_t n)
{
    WOLFMKA_ASSERT((w->len + n) <= w->cap);
    (void)WOLFMKA_MEMCPY(&w->buf[w->len], p, n);
    w->len += n;
}

/**
 * Append a single octet (the low 8 bits of v).
 * @param[in,out] w  output cursor.
 * @param[in]     v  value whose low 8 bits are appended.
 */
static MKA_INLINE void mka_w_u8(MkaWriter* w, size_t v)
{
    WOLFMKA_ASSERT((w->len + 1U) <= w->cap);
    w->buf[w->len] = (uint8_t)v;
    w->len += 1U;
}

/**
 * Append a 16-bit value in big-endian order at the writer cursor.
 * @param[in,out] w  output cursor.
 * @param[in]     v  value to append.
 */
static MKA_INLINE void mka_w_be16(MkaWriter* w, uint16_t v)
{
    WOLFMKA_ASSERT((w->len + 2U) <= w->cap);
    w_be16(&w->buf[w->len], v);
    w->len += 2U;
}

/**
 * Append a 32-bit value in big-endian order at the writer cursor.
 * @param[in,out] w  output cursor.
 * @param[in]     v  value to append.
 */
static MKA_INLINE void mka_w_be32(MkaWriter* w, uint32_t v)
{
    WOLFMKA_ASSERT((w->len + 4U) <= w->cap);
    w_be32(&w->buf[w->len], v);
    w->len += 4U;
}

/**
 * Append a 64-bit value in big-endian order at the writer cursor.
 * @param[in,out] w  output cursor.
 * @param[in]     v  value to append.
 */
static MKA_INLINE void mka_w_be64(MkaWriter* w, uint64_t v)
{
    WOLFMKA_ASSERT((w->len + 8U) <= w->cap);
    w_be64(&w->buf[w->len], v);
    w->len += 8U;
}

/**
 * Pad with zero octets to the next 4-octet boundary.
 *
 * Capacity is verified once up front (wm_Pdu_Encode), so this is
 * unconditional; a debug build still asserts the bound.
 * @param[in,out] w  output cursor.
 */
static MKA_INLINE void mka_w_pad4(MkaWriter* w)
{
    size_t pad = (4U - (w->len & 3U)) & 3U;
    WOLFMKA_ASSERT((w->len + pad) <= w->cap);
    (void)WOLFMKA_MEMSET(&w->buf[w->len], 0, pad);
    w->len += pad;
}

/** Forward input cursor for MKPDU decoding: the byte-cursor helpers read from
 * buf at pos and advance it. Each decoder validates the parameter-set length
 * before reading, so the reads need no runtime bounds checks; cap is consulted
 * only by the debug-build assertions. */
typedef struct {
    /** the frame being read */
    const uint8_t* buf;
    /** its length; used only by the debug-build bounds assertion */
    size_t cap;
    /** octets consumed so far, and so the next read offset */
    size_t pos;
} MkaReader;

/**
 * Copy n octets out of the reader at the cursor, advancing past them.
 *
 * Each decoder validates the parameter-set length before reading, so the
 * per-read path is unconditional; a debug build still asserts the bound.
 * @param[in,out] r    input cursor.
 * @param[out]    dst  destination buffer.
 * @param[in]     n    number of octets to copy.
 */
static MKA_INLINE void mka_r_bytes(MkaReader* r, uint8_t* dst, size_t n)
{
    WOLFMKA_ASSERT((r->pos + n) <= r->cap);
    (void)WOLFMKA_MEMCPY(dst, &r->buf[r->pos], n);
    r->pos += n;
}

/**
 * Read a single octet at the reader cursor, advancing past it.
 * @param[in,out] r  input cursor.
 * @return the octet.
 */
static MKA_INLINE uint8_t mka_r_be8(MkaReader* r)
{
    uint8_t v;
    WOLFMKA_ASSERT((r->pos + 1U) <= r->cap);
    v = r->buf[r->pos];
    r->pos += 1U;
    return v;
}

/**
 * Read a 32-bit big-endian value at the reader cursor, advancing past it.
 * @param[in,out] r  input cursor.
 * @return the decoded value.
 */
static MKA_INLINE uint32_t mka_r_be32(MkaReader* r)
{
    uint32_t v;
    WOLFMKA_ASSERT((r->pos + 4U) <= r->cap);
    v = rd_be32(&r->buf[r->pos]);
    r->pos += 4U;
    return v;
}

/**
 * Read a 64-bit big-endian value at the reader cursor, advancing past it.
 * @param[in,out] r  input cursor.
 * @return the decoded value.
 */
static MKA_INLINE uint64_t mka_r_be64(MkaReader* r)
{
    uint64_t v;
    WOLFMKA_ASSERT((r->pos + 8U) <= r->cap);
    v = rd_be64(&r->buf[r->pos]);
    r->pos += 8U;
    return v;
}

/**
 * Extract a parameter-set body length (a 12-bit field).
 * @param[in] hdr  The 4-octet parameter-set header.
 * @return The body length: low nibble of octet 2, then octet 3.
 */
#define mka_param_body_len(hdr)                                                \
    ((uint16_t)((((uint16_t)(hdr)[2] & 0x0FU) << 8U) | (uint16_t)(hdr)[3]))

/**
 * Round a length up to the next 4-octet boundary.
 * @param[in] n  The length to round.
 * @return n rounded up to a multiple of 4.
 */
#define mka_align4(n) (((n) + 3U) & ~(size_t)3U)

/* ------------------------------------------------------------------------- */
/* Body lengths                                                              */
/* ------------------------------------------------------------------------- */

/* wm_Pdu_Encode's writes carry no runtime bounds check: the whole frame is
 * sized once up front by wm_Pdu_EncodedSize, and that total is trusted. The two
 * parameter sets whose body length is conditional therefore have exactly one
 * function each deciding it, called by both the encoder and the size helper -
 * hand-copied logic in the two places is the one way an encoder could come to
 * write more than the size function reported, and WOLFMKA_ASSERT is a no-op
 * outside a debug build. */

/**
 * Body length of the MACsec SAK Use parameter set (11.11.4).
 *
 * The body is present only when a key is actually in use; a "no key"
 * indication is the header alone. mka_decode_sak_use enforces the same rule in
 * the other direction.
 * @param[in] s  the parameter set.
 * @return MKA_SAK_USE_BODY_LEN, or 0 for a "no key" indication.
 */
static size_t mka_sak_use_body_len(const MkaSakUse* s)
{
    /* Not cast to size_t: MKA_SAK_USE_BODY_LEN is a composite expression, and
     * casting one to a wider type is MISRA Rule 10.8. The implicit widening of
     * an unsigned constant to the size_t return type is unsigned-to-unsigned
     * and value-preserving. */
    return ((s->key_flags & MKA_SAK_USE_KEY_MASK) != 0U) ? MKA_SAK_USE_BODY_LEN
                                                         : 0U;
}

/**
 * Whether a Distributed SAK carries an explicit MACsec Cipher Suite (11.11.5).
 *
 * The default GCM-AES-128 - cipher suite 0, a 16-octet SAK in a 24-octet wrap -
 * is implied and omitted; anything else is named on the wire.
 * @param[in] d  the parameter set.
 * @return true if the 8-octet cipher suite is emitted.
 */
static bool mka_dist_sak_explicit_cs(const MkaDistSak* d)
{
    return !((d->cipher_suite == 0U) &&
             (d->wrapped_len == (size_t)MKA_WRAPPED_SAK_128_LEN));
}

/**
 * Body length of the Distributed SAK parameter set (11.11.5).
 * @param[in] d  the parameter set.
 * @return the body length; 0 when no SAK is being distributed.
 */
static size_t mka_dist_sak_body_len(const MkaDistSak* d)
{
    size_t body = 0U;

    if (d->wrapped_len != 0U) {
        body = (size_t)MKA_KN_LEN + d->wrapped_len;
        if (mka_dist_sak_explicit_cs(d)) {
            body += (size_t)MKA_CIPHER_SUITE_LEN;
        }
    }
    return body;
}

/* ------------------------------------------------------------------------- */
/* Encode                                                                    */
/* ------------------------------------------------------------------------- */

/**
 * Encode the Basic Parameter Set (11.11.1) into the writer.
 * @param[in,out] w  output cursor.
 * @param[in]     b  the Basic Parameter Set to encode.
 */
static void mka_basic_encode(MkaWriter* w, const MkaBasicParamSet* b)
{
    size_t body_len = MKA_SCI_LEN + MKA_MI_LEN + MKA_MN_LEN +
                      MKA_ALGO_AGILITY_LEN + b->ckn_len;
    uint8_t octet2;

    /* MKA Version || Key Server Priority || {Key Server, MACsec Desired, MACsec
     * Capability, body length} || SCI || Actor MI || Actor Message Number ||
     * Algorithm Agility || CAK Name; padded to 4 octets (11.11.1). */
    mka_w_u8(w, b->version);
    mka_w_u8(w, b->priority);

    /* Octet 2: KS | MD | cap(2) | body_len[11:8]. */
    octet2 = (uint8_t)(((b->key_server ? 0x80U : 0U)) |
                       ((b->macsec_desired ? 0x40U : 0U)) |
                       (((uint32_t)b->macsec_capability & 0x3U) << 4U) |
                       ((body_len >> 8U) & 0x0FU));
    mka_w_u8(w, octet2);
    /* Octet 3: body_len[7:0] */
    mka_w_u8(w, body_len & 0xFFU);

    mka_w_bytes(w, b->sci, MKA_SCI_LEN);
    mka_w_bytes(w, b->mi, MKA_MI_LEN);
    mka_w_be32(w, b->mn);
    mka_w_be32(w, b->algo_agility);
    mka_w_bytes(w, b->ckn, b->ckn_len);
    mka_w_pad4(w);
}

/**
 * Encode a Live or Potential Peer List (type 1 or 2), if present and non-empty.
 * @param[in,out] w     output cursor.
 * @param[in]     pl    the peer list to encode (skipped if absent or empty).
 * @param[in]     type  the parameter-set type octet (Live or Potential).
 */
static void mka_peer_list_encode(MkaWriter* w, const MkaPeerList* pl,
    uint8_t type)
{
    if (pl->present && (pl->count != 0U)) {
        size_t body_len = pl->count * (MKA_MI_LEN + MKA_MN_LEN);
        size_t i;

        /* Parameter set type || {reserved, body length} || (Member Identifier
         * || Message Number) per peer; each entry is 16 octets, no pad
         * (11.11.2/11.11.3). */
        mka_w_u8(w, type);
        /* Octet 2: reserved, except that a Version 3 Key Server distributing
         * an XPN SAK puts its own SSCI here (11.11, 9.10). The KaY leaves it
         * zero everywhere else, including in every Potential Peer List. */
        mka_w_u8(w, pl->ks_ssci);
        mka_w_u8(w, (body_len >> 8U) & 0x0FU);
        mka_w_u8(w, body_len & 0xFFU);
        for (i = 0U; i < pl->count; i++) {
            mka_w_bytes(w, pl->peers[i].mi, MKA_MI_LEN);
            mka_w_be32(w, pl->peers[i].mn);
        }
        /* Header (4) + count * 16-octet entries is always a 4-octet multiple.
         */
        WOLFMKA_ASSERT((w->len & 3U) == 0U);
    }
}

/**
 * Encode the MACsec SAK Use parameter set (11.11.4), if present.
 * @param[in,out] w  output cursor.
 * @param[in]     s  the SAK Use parameter set to encode (skipped if absent).
 */
static void mka_sak_use_encode(MkaWriter* w, const MkaSakUse* s)
{
    if (s->present) {
        size_t body_len;
        uint8_t octet1;
        uint8_t octet2;

        /* Parameter set type || {Latest/Old Key AN, Tx, Rx, Plain Tx, Plain Rx,
         * Delay Protect, body length} || Latest Key Server MI || Latest Key
         * Number || Latest Lowest Acceptable PN || Old Key Server MI || Old Key
         * Number || Old Lowest Acceptable PN; fixed sizing, no pad (11.11.4).
         */

        body_len = mka_sak_use_body_len(s);

        octet1 = (uint8_t)((((uint32_t)s->latest_an & 0x3U) << 6U) |
                           (((uint32_t)s->old_an & 0x3U) << 2U) |
                           (s->key_flags & MKA_SAK_USE_KEY_MASK));
        octet2 = (uint8_t)((s->mode_flags & MKA_SAK_USE_MODE_MASK) |
                           ((body_len >> 8U) & 0x0FU));

        mka_w_u8(w, (uint32_t)MKA_PS_SAK_USE);
        mka_w_u8(w, octet1);
        mka_w_u8(w, octet2);
        mka_w_u8(w, body_len & 0xFFU);

        if (body_len != 0U) {
            mka_w_bytes(w, s->latest_ks_mi, MKA_MI_LEN);
            mka_w_be32(w, s->latest_kn);
            mka_w_be32(w, s->latest_lpn);
            mka_w_bytes(w, s->old_ks_mi, MKA_MI_LEN);
            mka_w_be32(w, s->old_kn);
            mka_w_be32(w, s->old_lpn);
        }
        /* Header (4) + body (0 or 40) is always a 4-octet multiple: no pad. */
        WOLFMKA_ASSERT((w->len & 3U) == 0U);
    }
}

/**
 * Encode the Distributed SAK parameter set (11.11.5), if present.
 * @param[in,out] w  output cursor.
 * @param[in]     d  the Distributed SAK parameter set to encode (skipped if
 *                   absent).
 */
static void mka_dist_sak_encode(MkaWriter* w, const MkaDistSak* d)
{
    if (d->present) {
        bool explicit_cs;
        size_t body_len;
        uint8_t octet1;

        /* Parameter set type || {Distributed AN, Confidentiality Offset, body
         * length} || Key Number || [MACsec Cipher Suite] || AES Key Wrap of
         * SAK; the cipher suite is omitted for the default GCM-AES-128; padded
         * (11.11.5). */

        body_len = mka_dist_sak_body_len(d);
        explicit_cs = (d->wrapped_len != 0U) && mka_dist_sak_explicit_cs(d);

        octet1 =
            (uint8_t)((((uint32_t)d->distributed_an & 0x3U) << 6U) |
                      (((uint32_t)d->confidentiality_offset & 0x3U) << 4U));

        mka_w_u8(w, (uint32_t)MKA_PS_DISTRIBUTED_SAK);
        mka_w_u8(w, octet1);
        mka_w_u8(w, (body_len >> 8U) & 0x0FU);
        mka_w_u8(w, body_len & 0xFFU);

        if (body_len != 0U) {
            mka_w_be32(w, d->kn);
            if (explicit_cs) {
                mka_w_be64(w, d->cipher_suite);
            }
            mka_w_bytes(w, d->wrapped_sak, d->wrapped_len);
        }
        mka_w_pad4(w);
    }
}

#ifdef WOLFMKA_DISTRIBUTED_CAK
/**
 * Encode the Distributed CAK parameter set (type 5), if present. The body
 * (wrapped CAK || CKN) is assembled by the KaY and carried opaquely here.
 * @param[in,out] w  output cursor.
 * @param[in]     d  the Distributed CAK parameter set to encode (skipped if
 *                   absent).
 */
static void mka_dist_cak_encode(MkaWriter* w, const MkaDistCak* d)
{
    if (d->present) {
        size_t body_len = d->body_len;

        mka_w_u8(w, (uint32_t)MKA_PS_DISTRIBUTED_CAK);
        mka_w_u8(w, 0U);
        mka_w_u8(w, (body_len >> 8U) & 0x0FU);
        mka_w_u8(w, body_len & 0xFFU);
        mka_w_bytes(w, d->body, body_len);
        mka_w_pad4(w);
    }
}
#endif /* WOLFMKA_DISTRIBUTED_CAK */

#ifdef WOLFMKA_KMD
/**
 * Encode the Key Management Domain parameter set (type 6), if present.
 * @param[in,out] w  output cursor.
 * @param[in]     k  the KMD parameter set to encode (skipped if absent).
 */
static void mka_kmd_encode(MkaWriter* w, const MkaKmd* k)
{
    if (k->present) {
        size_t body_len = k->kmd_len;

        /* Parameter set type || {reserved, body length} || Key Management
         * Domain; padded (type 6). */
        mka_w_u8(w, (uint32_t)MKA_PS_KMD);
        mka_w_u8(w, 0U);
        mka_w_u8(w, (body_len >> 8U) & 0x0FU);
        mka_w_u8(w, body_len & 0xFFU);
        mka_w_bytes(w, k->kmd, body_len);
        mka_w_pad4(w);
    }
}
#endif /* WOLFMKA_KMD */

#ifndef WOLFMKA_NO_ANNOUNCEMENTS
/**
 * Encode the Announcement parameter set (11.12), if present and non-empty.
 * @param[in,out] w  output cursor.
 * @param[in]     a  the announcement to encode (skipped if absent or empty).
 */
static void mka_announce_encode(MkaWriter* w, const MkaAnnounce* a)
{
    if (a->present && (a->count != 0U)) {
        size_t tlv_val_len = a->count * MKA_CS_TLV_ENTRY_LEN;
        /* one TLV: hdr + value */
        size_t body_len = MKA_ANN_TLV_HDR_LEN + tlv_val_len;

        /* Parameter set type || {reserved, body length} || Cipher Suites TLV
         * {type 112, length} || (Implementation Capability || MACsec Cipher
         * Suite) per suite; padded (11.12 / TLV 11.12.3, Figure 11-22). */
        size_t i;
        uint16_t tlv_hdr =
            (uint16_t)(((uint16_t)MKA_ANN_TLV_CIPHER_SUITES << 9U) |
                       (uint16_t)tlv_val_len);

        mka_w_u8(w, (uint32_t)MKA_PS_ANNOUNCEMENT);
        /* reserved */
        mka_w_u8(w, 0U);
        mka_w_u8(w, (body_len >> 8U) & 0x0FU);
        mka_w_u8(w, body_len & 0xFFU);

        /* MACsec Cipher Suites TLV: header, then one entry per suite. */
        mka_w_be16(w, tlv_hdr);
        for (i = 0U; i < a->count; i++) {
            mka_w_be16(w, a->suites[i].capability);
            mka_w_be64(w, a->suites[i].cipher_suite);
        }
        mka_w_pad4(w);
    }
}
#endif /* WOLFMKA_NO_ANNOUNCEMENTS */

/**
 * Encode the MACsec XPN parameter set (11.11.6), if present.
 * @param[in,out] w  output cursor.
 * @param[in]     x  the XPN parameter set to encode (skipped if absent).
 */
static void mka_xpn_encode(MkaWriter* w, const MkaXpn* x)
{
    if (x->present) {
        /* Parameter set type || {MKA Suspension Time, body length} || Latest
         * Lowest Acceptable PN (MSBs) || Old Lowest Acceptable PN (MSBs); the
         * fixed 12-octet set needs no padding (11.11.6). */
        mka_w_u8(w, (uint32_t)MKA_PS_XPN);
        /* MKA suspension time (s) */
        mka_w_u8(w, x->suspension_time);
        mka_w_u8(w, ((uint32_t)MKA_XPN_BODY_LEN >> 8U) & 0x0FU);
        mka_w_u8(w, MKA_XPN_BODY_LEN & 0xFFU);
        mka_w_be32(w, x->latest_lpn_msb);
        mka_w_be32(w, x->old_lpn_msb);
        /* Header (4) + fixed body (8) is always a 4-octet multiple: no pad. */
        WOLFMKA_ASSERT((w->len & 3U) == 0U);
    }
}

/** Encoded octet count of one parameter set: header + body, aligned. */
#define MKA_SET_SIZE(body) mka_align4(MKA_PARAM_HDR_LEN + (body))

/* Each mka_*_size() returns the encoded octet count its parameter set
 * contributes (0 when absent). It has to agree exactly with what the matching
 * mka_*_encode helper writes: wm_Pdu_Encode checks the total once and the
 * writes are then unbounded, so a size that under-reports would write past the
 * caller's capacity with nothing to catch it in a release build.
 *
 * The two sets whose body length is conditional - MACsec SAK Use and
 * Distributed SAK - get that agreement structurally: mka_sak_use_body_len and
 * mka_dist_sak_body_len are the single decision, called from both sides. The
 * rest are a fixed field list or a count times an entry size, where the encoder
 * emits exactly what the expression below names. */

/** Encoded size of the Basic Parameter Set (always present). */
static size_t mka_basic_size(const MkaBasicParamSet* b)
{
    return MKA_SET_SIZE(MKA_SCI_LEN + MKA_MI_LEN + MKA_MN_LEN +
                        MKA_ALGO_AGILITY_LEN + b->ckn_len);
}

/** Encoded size of a Live/Potential Peer List, or 0 if absent/empty. */
static size_t mka_peer_list_size(const MkaPeerList* pl)
{
    if (pl->present && (pl->count != 0U)) {
        return MKA_SET_SIZE(pl->count * (MKA_MI_LEN + MKA_MN_LEN));
    }
    return 0U;
}

/** Encoded size of the MACsec SAK Use set, or 0 if absent. */
static size_t mka_sak_use_size(const MkaSakUse* s)
{
    size_t body = 0U;

    if (!s->present) {
        return 0U;
    }
    body = mka_sak_use_body_len(s);
    return MKA_SET_SIZE(body);
}

/** Encoded size of the Distributed SAK set, or 0 if absent. */
static size_t mka_dist_sak_size(const MkaDistSak* d)
{
    size_t body = 0U;

    if (!d->present) {
        return 0U;
    }
    body = mka_dist_sak_body_len(d);
    return MKA_SET_SIZE(body);
}

#ifdef WOLFMKA_DISTRIBUTED_CAK
/** Encoded size of the Distributed CAK set, or 0 if absent. */
static size_t mka_dist_cak_size(const MkaDistCak* d)
{
    return d->present ? MKA_SET_SIZE(d->body_len) : 0U;
}
#endif

#ifdef WOLFMKA_KMD
/** Encoded size of the Key Management Domain set, or 0 if absent. */
static size_t mka_kmd_size(const MkaKmd* k)
{
    return k->present ? MKA_SET_SIZE(k->kmd_len) : 0U;
}
#endif

#ifndef WOLFMKA_NO_ANNOUNCEMENTS
/** Encoded size of the Announcement set, or 0 if absent/empty. */
static size_t mka_announce_size(const MkaAnnounce* a)
{
    if (a->present && (a->count != 0U)) {
        return MKA_SET_SIZE(
            MKA_ANN_TLV_HDR_LEN + (a->count * MKA_CS_TLV_ENTRY_LEN));
    }
    return 0U;
}
#endif

/** Encoded size of the XPN set, or 0 if absent. */
static size_t mka_xpn_size(const MkaXpn* x)
{
    return x->present ? MKA_SET_SIZE(MKA_XPN_BODY_LEN) : 0U;
}

/**
 * Whether every caller-filled length in an MkaPdu is within the fixed-size
 * array that backs it.
 *
 * wm_Pdu_Encode sizes the whole frame once and then writes without per-field
 * bounds checks, so a length larger than its array would be reported in the
 * size (making the capacity check pass) and then over-read the struct - e.g.
 * basic.ckn_len of 100 reads 68 octets past MkaBasicParamSet.ckn. Every
 * in-library caller fills these from state already bounded at participant
 * init, so this guards the public entry points against an integrator's own
 * MkaPdu.
 * @param[in] pdu  the parameter sets to check (non-NULL).
 * @return true if every length is in range, else false.
 */
static bool mka_pdu_lens_valid(const MkaPdu* pdu)
{
    bool ok = (pdu->basic.ckn_len <= (size_t)MKA_MAX_CKN_LEN) &&
              (pdu->live_peers.count <= (size_t)MKA_MAX_PEERS) &&
              (pdu->potential_peers.count <= (size_t)MKA_MAX_PEERS) &&
              (pdu->dist_sak.wrapped_len <= sizeof(pdu->dist_sak.wrapped_sak));
#ifdef WOLFMKA_DISTRIBUTED_CAK
    ok = ok && (pdu->dist_cak.body_len <= sizeof(pdu->dist_cak.body));
#endif
#ifdef WOLFMKA_KMD
    ok = ok && (pdu->kmd.kmd_len <= sizeof(pdu->kmd.kmd));
#endif
#ifndef WOLFMKA_NO_ANNOUNCEMENTS
    ok = ok && (pdu->announce.count <= (size_t)MKA_MAX_CIPHER_SUITES);
#endif
    return ok;
}

/* Mirrors the encode_* helpers exactly (EAPOL header + every present set, each
 * 4-octet aligned, + ICV Indicator + ICV) so a single up-front capacity check
 * can replace per-write bounds checks. A zero return means either no PDU or a
 * length field out of range for its array, which is what stops those unchecked
 * writes from over-reading the caller's struct. */
size_t wm_Pdu_EncodedSize(const MkaPdu* pdu)
{
    size_t n;

    if ((pdu == NULL) || (!mka_pdu_lens_valid(pdu))) {
        return 0U;
    }

    n = EAPOL_HDR_LEN;
    n += mka_basic_size(&pdu->basic);
    n += mka_peer_list_size(&pdu->live_peers);
    n += mka_peer_list_size(&pdu->potential_peers);
    n += mka_sak_use_size(&pdu->sak_use);
    n += mka_dist_sak_size(&pdu->dist_sak);
#ifdef WOLFMKA_DISTRIBUTED_CAK
    n += mka_dist_cak_size(&pdu->dist_cak);
#endif
#ifdef WOLFMKA_KMD
    n += mka_kmd_size(&pdu->kmd);
#endif
#ifndef WOLFMKA_NO_ANNOUNCEMENTS
    n += mka_announce_size(&pdu->announce);
#endif
    n += mka_xpn_size(&pdu->xpn);

    /* ICV Indicator parameter set (4 octets) plus the ICV itself. */
    n += MKA_PARAM_HDR_LEN + MKA_DEFAULT_ICV_LEN;
    return n;
}

/* Size the whole frame once; with capacity known the body-length field can be
 * written directly and the parameter sets emitted without per-write checks. */
MkaStatus wm_Pdu_Encode(MkaCmacCtx* cmac, const MkaPdu* pdu, const uint8_t* ick,
    size_t ick_len, uint8_t* out, size_t cap, size_t* out_len)
{
    MkaWriter w;
    size_t total;
    size_t body_len;
    size_t icv_off;
    uint8_t icv[MKA_DEFAULT_ICV_LEN];
    MkaStatus rc;
    uint8_t l2[MKA_ICV_L2_PREFIX_LEN];

    if ((cmac == NULL) || (pdu == NULL) || (ick == NULL) || (out == NULL) ||
        (out_len == NULL)) {
        return MKA_ERR_BAD_ARG;
    }

    /* Size the whole frame once; the writes then need no bounds checks. A zero
     * means a length field is out of range for the array behind it - the one
     * thing the sizing cannot express, and the one that would make those
     * unchecked writes over-read the caller's struct. */
    total = wm_Pdu_EncodedSize(pdu);
    if (total == 0U) {
        return MKA_ERR_BAD_ARG;
    }
    if (total > cap) {
        return MKA_ERR_BUFFER;
    }
    body_len = total - EAPOL_HDR_LEN;
    if (MKA_FI(MKA_FI_BODY_LEN, body_len > 0xFFFFU)) {
        return MKA_ERR_BUFFER;
    }

    w.buf = out;
    w.cap = cap;
    w.len = 0U;

    /* EAPOL header with the now-known body length. */
    mka_w_u8(&w, EAPOL_VERSION_2010);
    mka_w_u8(&w, EAPOL_TYPE_MKA);
    mka_w_be16(&w, (uint16_t)body_len);

    /* Each parameter set encodes itself only when present (the Basic set is
     * always emitted); absent sets are no-ops. */
    mka_basic_encode(&w, &pdu->basic);
    mka_peer_list_encode(&w, &pdu->live_peers, (uint8_t)MKA_PS_LIVE_PEER_LIST);
    mka_peer_list_encode(&w, &pdu->potential_peers,
        (uint8_t)MKA_PS_POTENTIAL_PEER);
    mka_sak_use_encode(&w, &pdu->sak_use);
    mka_dist_sak_encode(&w, &pdu->dist_sak);
#ifdef WOLFMKA_DISTRIBUTED_CAK
    mka_dist_cak_encode(&w, &pdu->dist_cak);
#endif
#ifdef WOLFMKA_KMD
    mka_kmd_encode(&w, &pdu->kmd);
#endif
#ifndef WOLFMKA_NO_ANNOUNCEMENTS
    mka_announce_encode(&w, &pdu->announce);
#endif
    mka_xpn_encode(&w, &pdu->xpn);

    /* ICV Indicator parameter set: type 255, body length = ICV length. */
    mka_w_u8(&w, (uint32_t)MKA_PS_ICV_INDICATOR);
    mka_w_u8(&w, 0U);
    mka_w_u8(&w, 0U);
    mka_w_u8(&w, MKA_DEFAULT_ICV_LEN);

    /* ICV = AES-CMAC(ICK, everything so far, i.e. through the ICV header). */
    icv_off = w.len;
    mka_build_l2_prefix(l2, out, icv_off);
    rc = wm_Crypto_IcvComputeL2(cmac, ick, ick_len, l2, sizeof l2, out, icv_off,
        icv);
    if (rc != MKA_OK) {
        return rc;
    }
    mka_w_bytes(&w, icv, MKA_DEFAULT_ICV_LEN);

    *out_len = w.len;
    return MKA_OK;
}

/* ------------------------------------------------------------------------- */
/* Decode                                                                    */
/* ------------------------------------------------------------------------- */

/**
 * Validate the EAPOL header and locate the MKPDU body.
 * @param[in]  in        Received frame.
 * @param[in]  in_len    Length of the frame in octets.
 * @param[out] body      Out: pointer to the parameter-set region.
 * @param[out] body_len  Out: length of that region.
 * @return MKA_OK, MKA_ERR_PARSE or MKA_ERR_VERSION.
 */
static MkaStatus mka_parse_eapol(const uint8_t* in, size_t in_len,
    const uint8_t** body, size_t* body_len)
{
    size_t declared;

    if (in_len < EAPOL_HDR_LEN) {
        return MKA_ERR_PARSE;
    }
    /* older versions never carry MKA */
    if (in[0] < EAPOL_VERSION_2010) {
        return MKA_ERR_VERSION;
    }
    if (in[1] != EAPOL_TYPE_MKA) {
        return MKA_ERR_PARSE;
    }

    declared = rd_be16(&in[2]);
    if ((EAPOL_HDR_LEN + declared) > in_len) {
        return MKA_ERR_PARSE;
    }

    *body = &in[EAPOL_HDR_LEN];
    *body_len = declared;
    return MKA_OK;
}

/**
 * Decode the Basic Parameter Set.
 * @param[in]  p         Parameter-set region.
 * @param[in]  avail     Length of that region in octets.
 * @param[out] b         Out: decoded basic fields.
 * @param[out] consumed  Out: octets occupied (4-octet aligned).
 * @return MKA_OK or MKA_ERR_PARSE.
 */
static MkaStatus mka_decode_basic(const uint8_t* p, size_t avail,
    MkaBasicParamSet* b, size_t* consumed)
{
    /* MKA Version || Key Server Priority || {Key Server, MACsec Desired, MACsec
     * Capability, body length} || SCI || Actor MI || Actor Message Number ||
     * Algorithm Agility || CAK Name (11.11.1). */
    const size_t fixed =
        MKA_SCI_LEN + MKA_MI_LEN + MKA_MN_LEN + MKA_ALGO_AGILITY_LEN;
    size_t body_len;
    size_t ckn_len;
    size_t total;
    uint8_t octet2;
    uint8_t octet3;
    MkaReader r;

    if (avail < MKA_PARAM_HDR_LEN) {
        return MKA_ERR_PARSE;
    }

    /* avail >= 4 is checked above, so the 4-octet header reads are in bounds;
     * the cap is tightened to the validated total before the body. */
    r.buf = p;
    r.cap = avail;
    r.pos = 0U;
    b->version = mka_r_be8(&r);
    b->priority = mka_r_be8(&r);
    octet2 = mka_r_be8(&r);
    octet3 = mka_r_be8(&r);
    b->key_server = ((octet2 & 0x80U) != 0U);
    b->macsec_desired = ((octet2 & 0x40U) != 0U);
    b->macsec_capability = (uint8_t)((octet2 >> 4U) & 0x3U);
    body_len = (((size_t)octet2 & 0x0FU) << 8U) | (size_t)octet3;

    if (body_len < fixed) {
        return MKA_ERR_PARSE;
    }
    ckn_len = body_len - fixed;
    if (ckn_len > MKA_MAX_CKN_LEN) {
        return MKA_ERR_PARSE;
    }

    total = mka_align4(MKA_PARAM_HDR_LEN + body_len);
    if (total > avail) {
        return MKA_ERR_PARSE;
    }

    r.cap = total;
    mka_r_bytes(&r, b->sci, MKA_SCI_LEN);
    mka_r_bytes(&r, b->mi, MKA_MI_LEN);
    b->mn = mka_r_be32(&r);
    b->algo_agility = mka_r_be32(&r);
    /* Ignore an MKPDU whose Algorithm Agility names a KDF/cipher family we do
     * not implement (11.11.1); only the default 0x0080C201 is supported. */
    if (b->algo_agility != MKA_ALGO_AGILITY_DEFAULT) {
        return MKA_ERR_PARSE;
    }
    mka_r_bytes(&r, b->ckn, ckn_len);
    b->ckn_len = ckn_len;

    *consumed = total;
    return MKA_OK;
}

/**
 * Decode a Live/Potential Peer List body into pl.
 * @param[in]  p         the parameter set (header + body).
 * @param[in]  body_len  the body length in octets.
 * @param[out] pl        out: the decoded peer list (clamped to MKA_MAX_PEERS).
 * @return MKA_OK on success, or MKA_ERR_PARSE if body_len is not a multiple of
 *         the per-peer entry size.
 */
static MkaStatus mka_decode_peer_list(const uint8_t* p, size_t body_len,
    MkaPeerList* pl)
{
    /* (Member Identifier || Message Number) per peer (11.11.2/11.11.3). */
    /* 16, a power of two */
    const size_t entry = MKA_MI_LEN + MKA_MN_LEN;
    size_t n;
    size_t i;
    MkaReader r;

    /* body_len % entry == 0 */
    if ((body_len & (entry - 1U)) != 0U) {
        return MKA_ERR_PARSE;
    }
    n = body_len / entry;
    if (n > MKA_MAX_PEERS) {
        /* clamp; extra peers ignored */
        n = MKA_MAX_PEERS;
    }

    pl->present = true;
    pl->count = n;
    /* Octet 2 of the header; reserved in every list but a Version 3 Key
     * Server's Live Peer List accompanying an XPN Distributed SAK. Recorded
     * rather than acted on: a receiver ranking SSCIs from this list is the
     * other half of 9.10 and is not implemented yet. */
    pl->ks_ssci = p[1];
    r.buf = p;
    r.cap = MKA_PARAM_HDR_LEN + body_len;
    r.pos = MKA_PARAM_HDR_LEN;
    for (i = 0U; i < n; i++) {
        mka_r_bytes(&r, pl->peers[i].mi, MKA_MI_LEN);
        pl->peers[i].mn = mka_r_be32(&r);
    }
    return MKA_OK;
}

/**
 * Decode the MACsec SAK Use parameter set into s.
 * @param[in]  p         the parameter set (header + body).
 * @param[in]  body_len  the body length in octets (0 for a "no key" set, else
 *                       40).
 * @param[out] s         out: the decoded SAK Use parameter set.
 * @return MKA_OK on success, or MKA_ERR_PARSE if body_len is neither 0 nor 40.
 */
static MkaStatus mka_decode_sak_use(const uint8_t* p, size_t body_len,
    MkaSakUse* s)
{
    /* {Latest/Old Key AN, Tx, Rx, Plain Tx, Plain Rx, Delay Protect} || Latest
     * Key Server MI || Latest Key Number || Latest Lowest Acceptable PN || Old
     * Key Server MI || Old Key Number || Old Lowest Acceptable PN; the body is
     * absent for a "no key" set (11.11.4). */
    uint8_t o1;
    uint8_t o2;
    MkaReader r;

    /* Octets 1 and 2 carry the flag fields; skip the type octet (already
     * dispatched). */
    r.buf = p;
    r.cap = MKA_PARAM_HDR_LEN + body_len;
    r.pos = 1U;
    o1 = mka_r_be8(&r);
    o2 = mka_r_be8(&r);

    s->present = true;
    s->latest_an = (uint8_t)((o1 >> 6U) & 0x3U);
    s->old_an = (uint8_t)((o1 >> 2U) & 0x3U);
    s->key_flags = (uint8_t)(o1 & MKA_SAK_USE_KEY_MASK);
    s->mode_flags = (uint8_t)(o2 & MKA_SAK_USE_MODE_MASK);

    if (body_len == 0U) {
        /* No body means no key in use, which is the same predicate the encoder
         * uses to decide whether to emit one (mka_sak_use_encode). Keeping the
         * flags here would decode to a peer transmitting or receiving under a
         * key whose Key Server MI, Key Number and Lowest Acceptable PN were
         * never on the wire, and re-encoding the result would not reproduce the
         * frame that was received. The Association Numbers go with them: they
         * index keys that this set does not name. */
        s->key_flags = 0U;
        s->latest_an = 0U;
        s->old_an = 0U;
        return MKA_OK;
    }
    if (body_len != MKA_SAK_USE_BODY_LEN) {
        return MKA_ERR_PARSE;
    }

    /* Advance past the body-length octet to the start of the body. */
    r.pos = MKA_PARAM_HDR_LEN;
    mka_r_bytes(&r, s->latest_ks_mi, MKA_MI_LEN);
    s->latest_kn = mka_r_be32(&r);
    s->latest_lpn = mka_r_be32(&r);
    mka_r_bytes(&r, s->old_ks_mi, MKA_MI_LEN);
    s->old_kn = mka_r_be32(&r);
    s->old_lpn = mka_r_be32(&r);
    return MKA_OK;
}

/**
 * Decode the Distributed SAK parameter set into d.
 * @param[in]  p         the parameter set (header + body).
 * @param[in]  body_len  the body length in octets (0 for a plain/keyless set).
 * @param[out] d         out: the decoded Distributed SAK parameter set.
 * @return MKA_OK on success, or MKA_ERR_PARSE if the body is too short or the
 *         wrapped-key length is invalid (over the maximum or not a multiple
 *         of 8).
 */
static MkaStatus mka_decode_dist_sak(const uint8_t* p, size_t body_len,
    MkaDistSak* d)
{
    /* {Distributed AN, Confidentiality Offset} || Key Number || [MACsec Cipher
     * Suite] || AES Key Wrap of SAK; the body is absent when no SAK is
     * distributed (11.11.5). */
    uint8_t o1;
    bool explicit_cs;
    size_t wrap_len;
    MkaReader r;

    /* Octet 1 carries the flag fields; skip the type octet (already
     * dispatched). */
    r.buf = p;
    r.cap = MKA_PARAM_HDR_LEN + body_len;
    r.pos = 1U;
    o1 = mka_r_be8(&r);

    d->present = true;
    d->distributed_an = (uint8_t)((o1 >> 6U) & 0x3U);
    d->confidentiality_offset = (uint8_t)((o1 >> 4U) & 0x3U);

    /* plain - MACsec not in use */
    if (body_len == 0U) {
        d->wrapped_len = 0U;
        return MKA_OK;
    }
    if (body_len < (MKA_KN_LEN + MKA_WRAPPED_SAK_128_LEN)) {
        return MKA_ERR_PARSE;
    }

    /* A body of exactly Key Number + a 24-octet wrap is the default suite and
     * carries no cipher-suite field. Otherwise the 8-octet MACsec Cipher Suite
     * precedes the wrapped SAK. Mirrors mka_dist_sak_explicit_cs on encode. */
    explicit_cs = (body_len != (MKA_KN_LEN + MKA_WRAPPED_SAK_128_LEN));
    wrap_len = body_len - MKA_KN_LEN -
               (explicit_cs ? (size_t)MKA_CIPHER_SUITE_LEN : 0U);
    if ((wrap_len > MKA_MAX_WRAPPED_SAK) || ((wrap_len & 0x7U) != 0U)) {
        return MKA_ERR_PARSE;
    }

    /* Advance past the body-length octets to the start of the body. */
    r.pos = MKA_PARAM_HDR_LEN;
    d->kn = mka_r_be32(&r);
    d->cipher_suite = 0U;
    if (explicit_cs) {
        d->cipher_suite = mka_r_be64(&r);
    }
    mka_r_bytes(&r, d->wrapped_sak, wrap_len);
    d->wrapped_len = wrap_len;
    return MKA_OK;
}

#ifdef WOLFMKA_DISTRIBUTED_CAK
/**
 * Decode the Distributed CAK parameter set (type 5) into d. The body (wrapped
 * CAK || CKN) is captured raw; the KaY splits and unwraps it using the
 * receiving participant's CAK length.
 * @param[in]  p         the parameter set (header + body).
 * @param[in]  body_len  the body length in octets.
 * @param[out] d         out: the decoded Distributed CAK parameter set.
 * @return MKA_OK, or MKA_ERR_PARSE if the body does not fit the buffer.
 */
static MkaStatus mka_decode_dist_cak(const uint8_t* p, size_t body_len,
    MkaDistCak* d)
{
    if (body_len > sizeof(d->body)) {
        return MKA_ERR_PARSE;
    }
    d->present = true;
    (void)WOLFMKA_MEMCPY(d->body, &p[MKA_PARAM_HDR_LEN], body_len);
    d->body_len = body_len;
    return MKA_OK;
}
#endif /* WOLFMKA_DISTRIBUTED_CAK */

#ifdef WOLFMKA_KMD
/**
 * Decode the Key Management Domain parameter set (type 6) into k.
 * @param[in]  p         the parameter set (header + body).
 * @param[in]  body_len  the body length in octets.
 * @param[out] k         out: the decoded KMD parameter set.
 * @return MKA_OK, or MKA_ERR_PARSE if the KMD exceeds the receive buffer.
 */
static MkaStatus mka_decode_kmd(const uint8_t* p, size_t body_len, MkaKmd* k)
{
    /* Key Management Domain (type 6). */
    if (body_len > sizeof(k->kmd)) {
        return MKA_ERR_PARSE;
    }
    k->present = true;
    (void)WOLFMKA_MEMCPY(k->kmd, &p[MKA_PARAM_HDR_LEN], body_len);
    k->kmd_len = body_len;
    return MKA_OK;
}
#endif /* WOLFMKA_KMD */

#ifndef WOLFMKA_NO_ANNOUNCEMENTS
/**
 * Decode the Announcement parameter set into a.
 *
 * Walks the announcement TLVs (Figure 11-19) and extracts the MACsec Cipher
 * Suites TLV (type 112); other TLVs are skipped.
 * @param[in]  p         the parameter set (header + body).
 * @param[in]  body_len  the body length in octets.
 * @param[out] a         out: the decoded announcement.
 * @return MKA_OK on success, or MKA_ERR_PARSE if a TLV runs past the body.
 */
static MkaStatus mka_decode_announce(const uint8_t* p, size_t body_len,
    MkaAnnounce* a)
{
    size_t pos = MKA_PARAM_HDR_LEN;
    size_t end = MKA_PARAM_HDR_LEN + body_len;
    bool seen_suites = false;

    /* Walk the TLVs in the body. */
    while ((pos + MKA_ANN_TLV_HDR_LEN) <= end) {
        /* TLV header: 7-bit type, 9-bit value length. */
        uint16_t hdr = rd_be16(&p[pos]);
        uint8_t type = (uint8_t)((hdr >> 9U) & 0x7FU);
        uint16_t vlen16 = (uint16_t)(hdr & 0x1FFU);
        size_t vlen = vlen16;

        pos += MKA_ANN_TLV_HDR_LEN;
        /* Reject a value that runs past the body. */
        if ((pos + vlen) > end) {
            return MKA_ERR_PARSE;
        }
        if (type == (uint8_t)MKA_ANN_TLV_CIPHER_SUITES) {
            /* One cipher-suites TLV per announcement. The walk below assigns
             * rather than merges, so a second one would replace the first
             * outright - the same shape as a repeated parameter set, and hidden
             * behind an extra level of nesting. Rejected on the same grounds:
             * an authenticated member could otherwise state a constraint and
             * then bury it under a permissive copy. */
            if (seen_suites) {
                return MKA_ERR_PARSE;
            }
            seen_suites = true;
            /* Read each (capability, cipher suite) entry, up to our limit.
             *
             * `present` is set only once an entry has actually been decoded. A
             * cipher-suites TLV too short to hold even one - a zero-length
             * body, or a truncated entry - expresses no constraint, and marking
             * it present would be read by the KaY as "this peer accepts
             * anything": mka_refresh_peer clears the peer's recorded suites on
             * any present announcement, and mka_peer_accepts_cs treats an empty
             * set as unconstrained. A CAK holder could then erase a peer's
             * stated 128-only constraint with one malformed frame and have a
             * 256-bit SAK distributed to it. Leaving `present` false keeps
             * whatever the peer last announced, which is the fail-safe
             * direction. */
            size_t off = pos;
            size_t got = 0U;
            while (((off + MKA_CS_TLV_ENTRY_LEN) <= (pos + vlen)) &&
                   (got < MKA_MAX_CIPHER_SUITES)) {
                /* Only the two LSbits (MACsec Capability) are meaningful. */
                a->suites[got].capability = (uint16_t)(rd_be16(&p[off]) & 0x3U);
                off += 2U;
                /* 8-octet cipher suite, network order. */
                a->suites[got].cipher_suite = rd_be64(&p[off]);
                off += MKA_CIPHER_SUITE_LEN;
                got++;
            }
            if (got > 0U) {
                a->present = true;
                a->count = got;
            }
        }
        /* Skip past this TLV to the next (unknown types ignored). */
        pos += vlen;
    }
    return MKA_OK;
}
#endif /* WOLFMKA_NO_ANNOUNCEMENTS */

/**
 * Decode the MACsec XPN parameter set into x.
 * @param[in]  p         the parameter set (header + body).
 * @param[in]  body_len  the body length in octets (must be at least 8).
 * @param[out] x         out: the decoded XPN parameter set.
 * @return MKA_OK on success, or MKA_ERR_PARSE if the body is too short.
 */
static MkaStatus mka_decode_xpn(const uint8_t* p, size_t body_len, MkaXpn* x)
{
    /* {MKA Suspension Time} || Latest Lowest Acceptable PN (MSBs) || Old Lowest
     * Acceptable PN (MSBs) (11.11.6). */
    MkaReader r;

    if (body_len < MKA_XPN_BODY_LEN) {
        return MKA_ERR_PARSE;
    }
    x->present = true;
    r.buf = p;
    r.cap = MKA_PARAM_HDR_LEN + body_len;
    /* octet 1 is the MKA Suspension Time; skip the type octet. */
    r.pos = 1U;
    x->suspension_time = mka_r_be8(&r);
    /* Advance past the body-length octets to the start of the body. */
    r.pos = MKA_PARAM_HDR_LEN;
    x->latest_lpn_msb = mka_r_be32(&r);
    x->old_lpn_msb = mka_r_be32(&r);
    return MKA_OK;
}

/* Parses only the Basic Parameter Set; the ICV is deliberately not checked
 * here, so the CKN can be read before the matching ICK is known. */
MkaStatus wm_Pdu_PeekBasic(const uint8_t* in, size_t in_len,
    MkaBasicParamSet* basic)
{
    const uint8_t* body;
    size_t body_len;
    size_t consumed;
    MkaStatus rc;

    if ((in == NULL) || (basic == NULL)) {
        return MKA_ERR_BAD_ARG;
    }
    (void)WOLFMKA_MEMSET(basic, 0, sizeof(*basic));

    rc = mka_parse_eapol(in, in_len, &body, &body_len);
    if ((rc == MKA_OK) && (body_len < MKA_DEFAULT_ICV_LEN)) {
        /* Every MKPDU ends in an ICV, so a body too short to hold one is
         * malformed however little of it we intend to read. */
        rc = MKA_ERR_PARSE;
    }
    if (rc == MKA_OK) {
        rc = mka_decode_basic(body, body_len - MKA_DEFAULT_ICV_LEN, basic,
            &consumed);
    }
    return rc;
}

/**
 * Dispatch one non-basic parameter set by type into the MkaPdu.
 *
 * Unknown/unsupported types are skipped (returns MKA_OK).
 * @param[in]     type  Parameter-set type octet.
 * @param[in]     p     Parameter set (header + body).
 * @param[in]     plen  Parameter-set body length.
 * @param[in,out] pdu   In/out: decoded result.
 * @return MKA_OK or MKA_ERR_PARSE.
 */
static MkaStatus mka_decode_one(uint8_t type, const uint8_t* p, uint16_t plen,
    MkaPdu* pdu)
{
    MkaStatus rc;

    switch (type) {
        case (uint8_t)MKA_PS_LIVE_PEER_LIST:
            rc = mka_decode_peer_list(p, plen, &pdu->live_peers);
            break;
        case (uint8_t)MKA_PS_POTENTIAL_PEER:
            rc = mka_decode_peer_list(p, plen, &pdu->potential_peers);
            break;
        case (uint8_t)MKA_PS_SAK_USE:
            rc = mka_decode_sak_use(p, plen, &pdu->sak_use);
            break;
        case (uint8_t)MKA_PS_DISTRIBUTED_SAK:
            rc = mka_decode_dist_sak(p, plen, &pdu->dist_sak);
            break;
#ifdef WOLFMKA_DISTRIBUTED_CAK
        case (uint8_t)MKA_PS_DISTRIBUTED_CAK:
            rc = mka_decode_dist_cak(p, plen, &pdu->dist_cak);
            break;
#endif
#ifdef WOLFMKA_KMD
        case (uint8_t)MKA_PS_KMD:
            rc = mka_decode_kmd(p, plen, &pdu->kmd);
            break;
#endif
#ifndef WOLFMKA_NO_ANNOUNCEMENTS
        case (uint8_t)MKA_PS_ANNOUNCEMENT:
            rc = mka_decode_announce(p, plen, &pdu->announce);
            break;
#endif
        case (uint8_t)MKA_PS_XPN:
            rc = mka_decode_xpn(p, plen, &pdu->xpn);
            break;
        default:
            /* unknown / unsupported set: skip */
            rc = MKA_OK;
            break;
    }
    return rc;
}

/**
 * Validate the frame and hand back its MKPDU body: parse the EAPOL header, then
 * verify the trailing-16-octet ICV (computed over the whole frame up to, but
 * not including, those octets) before any content is trusted.
 * @param[in]  cmac      CMAC workspace (non-NULL).
 * @param[in]  in        the EAPOL-MKA frame.
 * @param[in]  in_len    its length in octets.
 * @param[in]  ick       the ICK for ICV verification.
 * @param[in]  ick_len   its length in octets.
 * @param[out] body      receives the MKPDU body (after the EAPOL header).
 * @param[out] body_len  receives the body length in octets.
 * @return MKA_OK, MKA_ERR_PARSE on a malformed/short frame, or MKA_ERR_ICV.
 */
static MkaStatus mka_verify_frame(MkaCmacCtx* cmac, const uint8_t* in,
    size_t in_len, const uint8_t* ick, size_t ick_len, const uint8_t** body,
    size_t* body_len)
{
    size_t covered;
    MkaStatus rc;
    uint8_t l2[MKA_ICV_L2_PREFIX_LEN];

    rc = mka_parse_eapol(in, in_len, body, body_len);
    if (rc != MKA_OK) {
        return rc;
    }
    /* The ICV occupies the last MKA_DEFAULT_ICV_LEN octets of the *body*, so
     * the body itself must be at least that long. Measuring the frame instead
     * admits declared body lengths of 12..15, for which the authenticated
     * region shrinks to 0..3 octets and the "received ICV" starts inside the
     * EAPOL header. */
    if (*body_len < MKA_DEFAULT_ICV_LEN) {
        return MKA_ERR_PARSE;
    }
    covered = (EAPOL_HDR_LEN + *body_len) - MKA_DEFAULT_ICV_LEN;
    mka_build_l2_prefix(l2, in, in_len);
    return wm_Crypto_IcvVerifyL2(cmac, ick, ick_len, l2, sizeof l2, in, covered,
        &in[covered]);
}

/**
 * Walk the optional parameter sets after the Basic set, stopping at the ICV
 * Indicator (or the ICV region); the region ends where the ICV starts (body_len
 * >= 16 here as mka_decode_basic required a far larger body).
 * @param[in]     body      the MKPDU body.
 * @param[in]     body_len  its length in octets.
 * @param[in]     off       the first set's offset in body (after the Basic
 * set).
 * @param[in,out] pdu       the decoded result, updated per parameter set.
 * @return MKA_OK, or MKA_ERR_PARSE on a malformed set.
 */
static MkaStatus mka_decode_param_sets(const uint8_t* body, size_t body_len,
    size_t off, MkaPdu* pdu)
{
    size_t param_end = body_len - MKA_DEFAULT_ICV_LEN;
    size_t pos = off;
    /* One bit per parameter-set type this decoder stores state for; every such
     * type is below 16 (MKA_PS_XPN, the largest, is 8). Sets at or above 16 are
     * unknown to this decoder and are skipped without touching the MkaPdu, so
     * a repeat of one clobbers nothing and is not worth tracking. */
    uint32_t seen = 0U;

    while ((pos + MKA_PARAM_HDR_LEN) <= param_end) {
        const uint8_t* p = &body[pos];
        uint8_t type = p[0];
        uint16_t plen = mka_param_body_len(p);
        size_t total = mka_align4(MKA_PARAM_HDR_LEN + plen);
        MkaStatus rc;

        if (type == (uint8_t)MKA_PS_ICV_INDICATOR) {
            /* This set ends the walk, so a bogus one silently hides everything
             * after it. A real one sits immediately before the ICV and declares
             * its length; anything else is malformed. */
            if ((pos != (param_end - MKA_PARAM_HDR_LEN)) ||
                (plen != (uint16_t)MKA_DEFAULT_ICV_LEN)) {
                return MKA_ERR_PARSE;
            }
            break;
        }
        if ((pos + total) > param_end) {
            /* param_end, not body_len: the trailing ICV octets are not payload,
             * and a set declared long enough to swallow them would be handed to
             * a parameter-set decoder as if they were. */
            return MKA_ERR_PARSE;
        }
        if (type < 16U) {
            /* IEEE Std 802.1X-2010, 11.11 allows at most one parameter set of
             * each type per MKPDU, and every decoder here assigns rather than
             * merges - so a second set of a type overwrites the first outright.
             * An authenticated member could use that to hide a set behind a
             * later benign copy: two Live Peer Lists, the first proving our
             * liveness and the second naming an unrelated peer, would leave
             * this participant never seeing the proof it was actually sent.
             * The same trick buries a Distributed SAK or a SAK Use. */
            uint32_t bit = (uint32_t)1U << (uint32_t)type;
            if ((seen & bit) != 0U) {
                return MKA_ERR_PARSE;
            }
            seen |= bit;
        }
        rc = mka_decode_one(type, p, plen, pdu);
        if (rc != MKA_OK) {
            return rc;
        }
        pos += total;
    }
    return MKA_OK;
}

/* Verifies the trailing-16-octet ICV before trusting any content, then decodes
 * the mandatory Basic set and walks the rest, stopping at the ICV Indicator. */
MkaStatus wm_Pdu_Decode(MkaCmacCtx* cmac, const uint8_t* in, size_t in_len,
    const uint8_t* ick, size_t ick_len, MkaPdu* pdu)
{
    const uint8_t* body;
    size_t body_len;
    size_t consumed;
    MkaStatus rc;

    if ((cmac == NULL) || (in == NULL) || (ick == NULL) || (pdu == NULL)) {
        return MKA_ERR_BAD_ARG;
    }
    (void)WOLFMKA_MEMSET(pdu, 0, sizeof(*pdu));

    /* Authenticate the frame, decode the mandatory Basic set, then walk the
     * remaining parameter sets. */
    rc = mka_verify_frame(cmac, in, in_len, ick, ick_len, &body, &body_len);
    if (rc != MKA_OK) {
        return rc;
    }
    /* mka_verify_frame has established body_len >= MKA_DEFAULT_ICV_LEN, so the
     * subtraction is safe; the Basic set is bounded by where the ICV starts for
     * the same reason the walk below is. */
    rc = mka_decode_basic(body, body_len - MKA_DEFAULT_ICV_LEN, &pdu->basic,
        &consumed);
    if (rc != MKA_OK) {
        return rc;
    }
    return mka_decode_param_sets(body, body_len, consumed, pdu);
}
