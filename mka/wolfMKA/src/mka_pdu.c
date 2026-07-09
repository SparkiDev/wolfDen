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

#ifdef WOLFMKA_ICV_L2_ADDR
/* Offset of the sender SCI MAC within the EAPOL PDU: past the EAPOL header, then
 * the 4-octet Basic Parameter Set header that precedes the Actor SCI. */
#define MKA_L2_SCI_MAC_OFFSET (EAPOL_HDR_LEN + 4U)
/* Build the L2 prefix the ICV covers: PAE group DA || sender SCI MAC || EAPOL
 * EtherType (MKA_ICV_L2_PREFIX_LEN octets). */
static void mka_build_l2_prefix(uint8_t l2[MKA_ICV_L2_PREFIX_LEN],
                                const uint8_t* eapol_pdu)
{
    static const uint8_t pae_group[6] = MKA_PAE_GROUP_ADDR;
    (void)WOLFMKA_MEMCPY(&l2[0], pae_group, sizeof pae_group);
    (void)WOLFMKA_MEMCPY(&l2[6], &eapol_pdu[MKA_L2_SCI_MAC_OFFSET], 6);
    l2[12] = (uint8_t)(EAPOL_ETHERTYPE >> 8);
    l2[13] = (uint8_t)(EAPOL_ETHERTYPE & 0xFFU);
}
#endif /* WOLFMKA_ICV_L2_ADDR */

/* ------------------------------------------------------------------------- */
/* Byte cursor helpers                                                       */
/* ------------------------------------------------------------------------- */

/* Forward output cursor for MKPDU encoding: the byte-cursor helpers append to
 * buf and advance len. wm_Pdu_Encode sizes the whole frame up front, so the
 * writes need no runtime bounds checks; cap is consulted only by the
 * debug-build assertions. */
typedef struct {
    uint8_t* buf;
    /* used only by the debug-build bounds assertion */
    size_t cap;
    size_t len;
} Writer;

/**
 * Append n octets to the writer.
 *
 * The total encoded size is checked once up front (wm_Pdu_Encode), so the
 * per-write path is unconditional; a debug build still asserts the bound.
 * @param[in,out] w  Output cursor.
 * @param[in]     p  Source bytes.
 * @param[in]     n  Number of octets to append.
 */
static MKA_INLINE void w_bytes(Writer* w, const uint8_t* p, size_t n)
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
static MKA_INLINE void w_u8(Writer* w, size_t v)
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
static MKA_INLINE void wc_be16(Writer* w, uint16_t v)
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
static MKA_INLINE void wc_be32(Writer* w, uint32_t v)
{
    WOLFMKA_ASSERT((w->len + 4U) <= w->cap);
    w_be32(&w->buf[w->len], v);
    w->len += 4U;
}

/**
 * Pad with zero octets to the next 4-octet boundary.
 *
 * Capacity is verified once up front (wm_Pdu_Encode), so this is
 * unconditional; a debug build still asserts the bound.
 * @param[in,out] w  output cursor.
 */
static MKA_INLINE void w_pad4(Writer* w)
{
    size_t pad = (4U - (w->len & 3U)) & 3U;
    WOLFMKA_ASSERT((w->len + pad) <= w->cap);
    (void)WOLFMKA_MEMSET(&w->buf[w->len], 0, pad);
    w->len += pad;
}

/* Forward input cursor for MKPDU decoding: the byte-cursor helpers read from
 * buf at pos and advance it. Each decoder validates the parameter-set length
 * before reading, so the reads need no runtime bounds checks; cap is consulted
 * only by the debug-build assertions. */
typedef struct {
    const uint8_t* buf;
    /* used only by the debug-build bounds assertion */
    size_t cap;
    size_t pos;
} Reader;

/**
 * Copy n octets out of the reader at the cursor, advancing past them.
 *
 * Each decoder validates the parameter-set length before reading, so the
 * per-read path is unconditional; a debug build still asserts the bound.
 * @param[in,out] r    input cursor.
 * @param[out]    dst  destination buffer.
 * @param[in]     n    number of octets to copy.
 */
static MKA_INLINE void r_bytes(Reader* r, uint8_t* dst, size_t n)
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
static MKA_INLINE uint8_t rc_be8(Reader* r)
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
static MKA_INLINE uint32_t rc_be32(Reader* r)
{
    uint32_t v;
    WOLFMKA_ASSERT((r->pos + 4U) <= r->cap);
    v = rd_be32(&r->buf[r->pos]);
    r->pos += 4U;
    return v;
}

/**
 * Extract a parameter-set body length (a 12-bit field).
 * @param[in] hdr  The 4-octet parameter-set header.
 * @return The body length: low nibble of octet 2, then octet 3.
 */
#define param_body_len(hdr)                                                    \
    ((uint16_t)((((uint16_t)(hdr)[2] & 0x0FU) << 8U) | (uint16_t)(hdr)[3]))

/**
 * Round a length up to the next 4-octet boundary.
 * @param[in] n  The length to round.
 * @return n rounded up to a multiple of 4.
 */
#define align4(n) (((n) + 3U) & ~(size_t)3U)

/* ------------------------------------------------------------------------- */
/* Encode                                                                    */
/* ------------------------------------------------------------------------- */

/**
 * Encode the Basic Parameter Set (11.11.1) into the writer.
 * @param[in,out] w  output cursor.
 * @param[in]     b  the Basic Parameter Set to encode.
 */
static void mka_basic_encode(Writer* w, const MkaBasicParamSet* b)
{
    size_t body_len = MKA_SCI_LEN + MKA_MI_LEN + MKA_MN_LEN +
                      MKA_ALGO_AGILITY_LEN + b->ckn_len;
    uint8_t octet2;

    /* MKA Version || Key Server Priority || {Key Server, MACsec Desired, MACsec
     * Capability, body length} || SCI || Actor MI || Actor Message Number ||
     * Algorithm Agility || CAK Name; padded to 4 octets (11.11.1). */
    w_u8(w, b->version);
    w_u8(w, b->priority);

    /* Octet 2: KS | MD | cap(2) | body_len[11:8]. */
    octet2 = (uint8_t)(((b->key_server ? 0x80U : 0U)) |
                       ((b->macsec_desired ? 0x40U : 0U)) |
                       (((uint32_t)b->macsec_capability & 0x3U) << 4U) |
                       ((body_len >> 8U) & 0x0FU));
    w_u8(w, octet2);
    /* Octet 3: body_len[7:0] */
    w_u8(w, body_len & 0xFFU);

    w_bytes(w, b->sci, MKA_SCI_LEN);
    w_bytes(w, b->mi, MKA_MI_LEN);
    wc_be32(w, b->mn);
    wc_be32(w, b->algo_agility);
    w_bytes(w, b->ckn, b->ckn_len);
    w_pad4(w);
}

/**
 * Encode a Live or Potential Peer List (type 1 or 2), if present and non-empty.
 * @param[in,out] w     output cursor.
 * @param[in]     pl    the peer list to encode (skipped if absent or empty).
 * @param[in]     type  the parameter-set type octet (Live or Potential).
 */
static void mka_peer_list_encode(Writer* w, const MkaPeerList* pl, uint8_t type)
{
    if (pl->present && (pl->count != 0U)) {
        size_t body_len = pl->count * (MKA_MI_LEN + MKA_MN_LEN);
        size_t i;

        /* Parameter set type || {reserved, body length} || (Member Identifier
         * || Message Number) per peer; each entry is 16 octets, no pad
         * (11.11.2/11.11.3). */
        w_u8(w, type);
        /* reserved */
        w_u8(w, 0U);
        w_u8(w, (body_len >> 8U) & 0x0FU);
        w_u8(w, body_len & 0xFFU);
        for (i = 0U; i < pl->count; i++) {
            w_bytes(w, pl->peers[i].mi, MKA_MI_LEN);
            wc_be32(w, pl->peers[i].mn);
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
static void mka_sak_use_encode(Writer* w, const MkaSakUse* s)
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

        /* Body present (40 octets) unless this is a "no key" indication. */
        if ((s->key_flags & MKA_SAK_USE_KEY_MASK) != 0U) {
            body_len = 40U;
        }
        else {
            body_len = 0U;
        }

        octet1 = (uint8_t)((((uint32_t)s->latest_an & 0x3U) << 6U) |
                           (((uint32_t)s->old_an & 0x3U) << 2U) |
                           (s->key_flags & MKA_SAK_USE_KEY_MASK));
        octet2 = (uint8_t)((s->mode_flags & MKA_SAK_USE_MODE_MASK) |
                           ((body_len >> 8U) & 0x0FU));

        w_u8(w, (uint32_t)MKA_PS_SAK_USE);
        w_u8(w, octet1);
        w_u8(w, octet2);
        w_u8(w, body_len & 0xFFU);

        if (body_len != 0U) {
            w_bytes(w, s->latest_ks_mi, MKA_MI_LEN);
            wc_be32(w, s->latest_kn);
            wc_be32(w, s->latest_lpn);
            w_bytes(w, s->old_ks_mi, MKA_MI_LEN);
            wc_be32(w, s->old_kn);
            wc_be32(w, s->old_lpn);
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
static void mka_dist_sak_encode(Writer* w, const MkaDistSak* d)
{
    if (d->present) {
        bool explicit_cs;
        size_t body_len;
        uint8_t octet1;

        /* Parameter set type || {Distributed AN, Confidentiality Offset, body
         * length} || Key Number || [MACsec Cipher Suite] || AES Key Wrap of
         * SAK; the cipher suite is omitted for the default GCM-AES-128; padded
         * (11.11.5). */

        if (d->wrapped_len == 0U) {
            /* plain - no SAK distributed */
            body_len = 0U;
            explicit_cs = false;
        }
        else {
            /* Default GCM-AES-128 (16-octet SAK, 24-octet wrap) carries no
             * explicit cipher suite; anything else does (11.11.5). */
            explicit_cs = !((d->cipher_suite == 0U) && (d->wrapped_len == 24U));
            body_len = MKA_KN_LEN + (explicit_cs ? 8U : 0U) + d->wrapped_len;
        }

        octet1 =
            (uint8_t)((((uint32_t)d->distributed_an & 0x3U) << 6U) |
                      (((uint32_t)d->confidentiality_offset & 0x3U) << 4U));

        w_u8(w, (uint32_t)MKA_PS_DISTRIBUTED_SAK);
        w_u8(w, octet1);
        w_u8(w, (body_len >> 8U) & 0x0FU);
        w_u8(w, body_len & 0xFFU);

        if (body_len != 0U) {
            wc_be32(w, d->kn);
            if (explicit_cs) {
                uint8_t cs[8];
                size_t i;
                for (i = 0U; i < 8U; i++) {
                    cs[i] = (uint8_t)(d->cipher_suite >> (56U - (8U * i)));
                }
                w_bytes(w, cs, 8U);
            }
            w_bytes(w, d->wrapped_sak, d->wrapped_len);
        }
        w_pad4(w);
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
static void mka_dist_cak_encode(Writer* w, const MkaDistCak* d)
{
    if (d->present) {
        size_t body_len = d->body_len;

        w_u8(w, (uint32_t)MKA_PS_DISTRIBUTED_CAK);
        w_u8(w, 0U);
        w_u8(w, (body_len >> 8U) & 0x0FU);
        w_u8(w, body_len & 0xFFU);
        w_bytes(w, d->body, body_len);
        w_pad4(w);
    }
}
#endif /* WOLFMKA_DISTRIBUTED_CAK */

#ifdef WOLFMKA_KMD
/**
 * Encode the Key Management Domain parameter set (type 6), if present.
 * @param[in,out] w  output cursor.
 * @param[in]     k  the KMD parameter set to encode (skipped if absent).
 */
static void mka_kmd_encode(Writer* w, const MkaKmd* k)
{
    if (k->present) {
        size_t body_len = k->kmd_len;

        /* Parameter set type || {reserved, body length} || Key Management
         * Domain; padded (type 6). */
        w_u8(w, (uint32_t)MKA_PS_KMD);
        w_u8(w, 0U);
        w_u8(w, (body_len >> 8U) & 0x0FU);
        w_u8(w, body_len & 0xFFU);
        w_bytes(w, k->kmd, body_len);
        w_pad4(w);
    }
}
#endif /* WOLFMKA_KMD */

#ifndef WOLFMKA_NO_ANNOUNCEMENTS
/**
 * Encode the Announcement parameter set (11.12), if present and non-empty.
 * @param[in,out] w  output cursor.
 * @param[in]     a  the announcement to encode (skipped if absent or empty).
 */
static void mka_announce_encode(Writer* w, const MkaAnnounce* a)
{
    if (a->present && (a->count != 0U)) {
        size_t tlv_val_len = a->count * MKA_CS_TLV_ENTRY_LEN;
        /* one TLV: hdr + value */
        size_t body_len = 2U + tlv_val_len;

        /* Parameter set type || {reserved, body length} || Cipher Suites TLV
         * {type 112, length} || (Implementation Capability || MACsec Cipher
         * Suite) per suite; padded (11.12 / TLV 11.12.3, Figure 11-22). */
        size_t i;
        uint16_t tlv_hdr =
            (uint16_t)(((uint16_t)MKA_ANN_TLV_CIPHER_SUITES << 9U) |
                       (uint16_t)tlv_val_len);

        w_u8(w, (uint32_t)MKA_PS_ANNOUNCEMENT);
        /* reserved */
        w_u8(w, 0U);
        w_u8(w, (body_len >> 8U) & 0x0FU);
        w_u8(w, body_len & 0xFFU);

        /* MACsec Cipher Suites TLV: header, then one entry per suite. */
        wc_be16(w, tlv_hdr);
        for (i = 0U; i < a->count; i++) {
            uint8_t cs[8];
            size_t j;
            wc_be16(w, a->suites[i].capability);
            for (j = 0U; j < 8U; j++) {
                cs[j] =
                    (uint8_t)(a->suites[i].cipher_suite >> (56U - (8U * j)));
            }
            w_bytes(w, cs, 8U);
        }
        w_pad4(w);
    }
}
#endif /* WOLFMKA_NO_ANNOUNCEMENTS */

/**
 * Encode the MACsec XPN parameter set (11.11.6), if present.
 * @param[in,out] w  output cursor.
 * @param[in]     x  the XPN parameter set to encode (skipped if absent).
 */
static void mka_xpn_encode(Writer* w, const MkaXpn* x)
{
    if (x->present) {
        /* Parameter set type || {MKA Suspension Time, body length} || Latest
         * Lowest Acceptable PN (MSBs) || Old Lowest Acceptable PN (MSBs); the
         * fixed 12-octet set needs no padding (11.11.6). */
        w_u8(w, (uint32_t)MKA_PS_XPN);
        /* MKA suspension time (s) */
        w_u8(w, x->suspension_time);
        w_u8(w, ((uint32_t)MKA_XPN_BODY_LEN >> 8U) & 0x0FU);
        w_u8(w, MKA_XPN_BODY_LEN & 0xFFU);
        wc_be32(w, x->latest_lpn_msb);
        wc_be32(w, x->old_lpn_msb);
        /* Header (4) + fixed body (8) is always a 4-octet multiple: no pad. */
        WOLFMKA_ASSERT((w->len & 3U) == 0U);
    }
}

/** Encoded octet count of one parameter set: header + body, aligned. */
#define MKA_SET_SIZE(body) align4(MKA_PARAM_HDR_LEN + (body))

/* Each mka_*_size() returns the encoded octet count its parameter set
 * contributes (0 when absent), mirroring the matching mka_*_encode helper so
 * the size and the emit stay in lock-step. */

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
    if ((s->key_flags & MKA_SAK_USE_KEY_MASK) != 0U) {
        body = 40U;
    }
    return MKA_SET_SIZE(body);
}

/** Encoded size of the Distributed SAK set, or 0 if absent. */
static size_t mka_dist_sak_size(const MkaDistSak* d)
{
    size_t body = 0U;

    if (!d->present) {
        return 0U;
    }
    if (d->wrapped_len != 0U) {
        bool ecs = !((d->cipher_suite == 0U) && (d->wrapped_len == 24U));
        body = MKA_KN_LEN + (ecs ? 8U : 0U) + d->wrapped_len;
    }
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
        return MKA_SET_SIZE(2U + (a->count * MKA_CS_TLV_ENTRY_LEN));
    }
    return 0U;
}
#endif

/** Encoded size of the XPN set, or 0 if absent. */
static size_t mka_xpn_size(const MkaXpn* x)
{
    return x->present ? MKA_SET_SIZE(MKA_XPN_BODY_LEN) : 0U;
}

/* Mirrors the encode_* helpers exactly (EAPOL header + every present set, each
 * 4-octet aligned, + ICV Indicator + ICV) so a single up-front capacity check
 * can replace per-write bounds checks. */
size_t wm_Pdu_EncodedSize(const MkaPdu* pdu)
{
    size_t n;

    if (pdu == NULL) {
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
    Writer w;
    size_t total;
    size_t body_len;
    size_t icv_off;
    uint8_t icv[MKA_DEFAULT_ICV_LEN];
    MkaStatus rc;
#ifdef WOLFMKA_ICV_L2_ADDR
    uint8_t l2[MKA_ICV_L2_PREFIX_LEN];
#endif

    if ((pdu == NULL) || (ick == NULL) || (out == NULL) || (out_len == NULL)) {
        return MKA_ERR_BAD_ARG;
    }

    /* Size the whole frame once; the writes then need no bounds checks. */
    total = wm_Pdu_EncodedSize(pdu);
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
    w_u8(&w, EAPOL_VERSION_2010);
    w_u8(&w, EAPOL_TYPE_MKA);
    wc_be16(&w, (uint16_t)body_len);

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
    w_u8(&w, (uint32_t)MKA_PS_ICV_INDICATOR);
    w_u8(&w, 0U);
    w_u8(&w, 0U);
    w_u8(&w, MKA_DEFAULT_ICV_LEN);

    /* ICV = AES-CMAC(ICK, everything so far, i.e. through the ICV header). */
    icv_off = w.len;
#ifdef WOLFMKA_ICV_L2_ADDR
    mka_build_l2_prefix(l2, out);
    rc = wm_Crypto_IcvComputeL2(cmac, ick, ick_len, l2, sizeof l2, out,
                                icv_off, icv);
#else
    rc = wm_Crypto_IcvCompute(cmac, ick, ick_len, out, icv_off, icv);
#endif
    if (rc != MKA_OK) {
        return rc;
    }
    w_bytes(&w, icv, MKA_DEFAULT_ICV_LEN);

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
    Reader r;

    if (avail < MKA_PARAM_HDR_LEN) {
        return MKA_ERR_PARSE;
    }

    /* avail >= 4 is checked above, so the 4-octet header reads are in bounds;
     * the cap is tightened to the validated total before the body. */
    r.buf = p;
    r.cap = avail;
    r.pos = 0U;
    b->version = rc_be8(&r);
    b->priority = rc_be8(&r);
    octet2 = rc_be8(&r);
    octet3 = rc_be8(&r);
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

    total = align4(MKA_PARAM_HDR_LEN + body_len);
    if (total > avail) {
        return MKA_ERR_PARSE;
    }

    r.cap = total;
    r_bytes(&r, b->sci, MKA_SCI_LEN);
    r_bytes(&r, b->mi, MKA_MI_LEN);
    b->mn = rc_be32(&r);
    b->algo_agility = rc_be32(&r);
    /* Ignore an MKPDU whose Algorithm Agility names a KDF/cipher family we do
     * not implement (11.11.1); only the default 0x0080C201 is supported. */
    if (b->algo_agility != MKA_ALGO_AGILITY_DEFAULT) {
        return MKA_ERR_PARSE;
    }
    r_bytes(&r, b->ckn, ckn_len);
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
    Reader r;

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
    r.buf = p;
    r.cap = MKA_PARAM_HDR_LEN + body_len;
    r.pos = MKA_PARAM_HDR_LEN;
    for (i = 0U; i < n; i++) {
        r_bytes(&r, pl->peers[i].mi, MKA_MI_LEN);
        pl->peers[i].mn = rc_be32(&r);
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
    Reader r;

    /* Octets 1 and 2 carry the flag fields; skip the type octet (already
     * dispatched). */
    r.buf = p;
    r.cap = MKA_PARAM_HDR_LEN + body_len;
    r.pos = 1U;
    o1 = rc_be8(&r);
    o2 = rc_be8(&r);

    s->present = true;
    s->latest_an = (uint8_t)((o1 >> 6U) & 0x3U);
    s->old_an = (uint8_t)((o1 >> 2U) & 0x3U);
    s->key_flags = (uint8_t)(o1 & MKA_SAK_USE_KEY_MASK);
    s->mode_flags = (uint8_t)(o2 & MKA_SAK_USE_MODE_MASK);

    if (body_len == 0U) {
        return MKA_OK;
    }
    if (body_len != 40U) {
        return MKA_ERR_PARSE;
    }

    /* Advance past the body-length octet to the start of the body. */
    r.pos = MKA_PARAM_HDR_LEN;
    r_bytes(&r, s->latest_ks_mi, MKA_MI_LEN);
    s->latest_kn = rc_be32(&r);
    s->latest_lpn = rc_be32(&r);
    r_bytes(&r, s->old_ks_mi, MKA_MI_LEN);
    s->old_kn = rc_be32(&r);
    s->old_lpn = rc_be32(&r);
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
    Reader r;

    /* Octet 1 carries the flag fields; skip the type octet (already
     * dispatched). */
    r.buf = p;
    r.cap = MKA_PARAM_HDR_LEN + body_len;
    r.pos = 1U;
    o1 = rc_be8(&r);

    d->present = true;
    d->distributed_an = (uint8_t)((o1 >> 6U) & 0x3U);
    d->confidentiality_offset = (uint8_t)((o1 >> 4U) & 0x3U);

    /* plain - MACsec not in use */
    if (body_len == 0U) {
        d->wrapped_len = 0U;
        return MKA_OK;
    }
    if (body_len < (MKA_KN_LEN + 24U)) {
        return MKA_ERR_PARSE;
    }

    /* body_len 28 => default suite, no cipher-suite field. Otherwise the
     * 8-octet MACsec Cipher Suite precedes the wrapped SAK. */
    explicit_cs = (body_len != (MKA_KN_LEN + 24U));
    wrap_len = body_len - MKA_KN_LEN - (explicit_cs ? 8U : 0U);
    if ((wrap_len > MKA_MAX_WRAPPED_SAK) || ((wrap_len & 0x7U) != 0U)) {
        return MKA_ERR_PARSE;
    }

    /* Advance past the body-length octets to the start of the body. */
    r.pos = MKA_PARAM_HDR_LEN;
    d->kn = rc_be32(&r);
    d->cipher_suite = 0U;
    if (explicit_cs) {
        uint8_t cs[8];
        size_t i;
        r_bytes(&r, cs, 8U);
        for (i = 0U; i < 8U; i++) {
            d->cipher_suite = (d->cipher_suite << 8U) | (uint64_t)cs[i];
        }
    }
    r_bytes(&r, d->wrapped_sak, wrap_len);
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

    /* Walk the TLVs in the body. */
    while ((pos + 2U) <= end) {
        /* TLV header: 7-bit type, 9-bit value length. */
        uint16_t hdr = rd_be16(&p[pos]);
        uint8_t type = (uint8_t)((hdr >> 9U) & 0x7FU);
        uint16_t vlen16 = (uint16_t)(hdr & 0x1FFU);
        size_t vlen = vlen16;

        pos += 2U;
        /* Reject a value that runs past the body. */
        if ((pos + vlen) > end) {
            return MKA_ERR_PARSE;
        }
        if (type == (uint8_t)MKA_ANN_TLV_CIPHER_SUITES) {
            /* Read each (capability, cipher suite) entry, up to our limit. */
            size_t off = pos;
            a->present = true;
            a->count = 0U;
            while (((off + MKA_CS_TLV_ENTRY_LEN) <= (pos + vlen)) &&
                   (a->count < MKA_MAX_CIPHER_SUITES)) {
                uint64_t cs = 0U;
                size_t j;
                /* Only the two LSbits (MACsec Capability) are meaningful. */
                a->suites[a->count].capability =
                    (uint16_t)(rd_be16(&p[off]) & 0x3U);
                off += 2U;
                /* 8-octet cipher suite, network order. */
                for (j = 0U; j < 8U; j++) {
                    cs = (cs << 8U) | (uint64_t)p[off + j];
                }
                off += 8U;
                a->suites[a->count].cipher_suite = cs;
                a->count++;
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
    Reader r;

    if (body_len < MKA_XPN_BODY_LEN) {
        return MKA_ERR_PARSE;
    }
    x->present = true;
    r.buf = p;
    r.cap = MKA_PARAM_HDR_LEN + body_len;
    /* octet 1 is the MKA Suspension Time; skip the type octet. */
    r.pos = 1U;
    x->suspension_time = rc_be8(&r);
    /* Advance past the body-length octets to the start of the body. */
    r.pos = MKA_PARAM_HDR_LEN;
    x->latest_lpn_msb = rc_be32(&r);
    x->old_lpn_msb = rc_be32(&r);
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
    if (rc == MKA_OK) {
        rc = mka_decode_basic(body, body_len, basic, &consumed);
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
#ifdef WOLFMKA_ICV_L2_ADDR
    uint8_t l2[MKA_ICV_L2_PREFIX_LEN];
#endif

    rc = mka_parse_eapol(in, in_len, body, body_len);
    if (rc != MKA_OK) {
        return rc;
    }
    if ((EAPOL_HDR_LEN + *body_len) < MKA_DEFAULT_ICV_LEN) {
        return MKA_ERR_PARSE;
    }
    covered = (EAPOL_HDR_LEN + *body_len) - MKA_DEFAULT_ICV_LEN;
#ifdef WOLFMKA_ICV_L2_ADDR
    mka_build_l2_prefix(l2, in);
    return wm_Crypto_IcvVerifyL2(cmac, ick, ick_len, l2, sizeof l2, in,
                                 covered, &in[covered]);
#else
    return wm_Crypto_IcvVerify(cmac, ick, ick_len, in, covered, &in[covered]);
#endif
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

    while ((pos + MKA_PARAM_HDR_LEN) <= param_end) {
        const uint8_t* p = &body[pos];
        uint8_t type = p[0];
        uint16_t plen = param_body_len(p);
        size_t total = align4(MKA_PARAM_HDR_LEN + plen);
        MkaStatus rc;

        if (type == (uint8_t)MKA_PS_ICV_INDICATOR) {
            break;
        }
        if ((pos + total) > body_len) {
            return MKA_ERR_PARSE;
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

    if ((in == NULL) || (ick == NULL) || (pdu == NULL)) {
        return MKA_ERR_BAD_ARG;
    }
    (void)WOLFMKA_MEMSET(pdu, 0, sizeof(*pdu));

    /* Authenticate the frame, decode the mandatory Basic set, then walk the
     * remaining parameter sets. */
    rc = mka_verify_frame(cmac, in, in_len, ick, ick_len, &body, &body_len);
    if (rc != MKA_OK) {
        return rc;
    }
    rc = mka_decode_basic(body, body_len, &pdu->basic, &consumed);
    if (rc != MKA_OK) {
        return rc;
    }
    return mka_decode_param_sets(body, body_len, consumed, pdu);
}
