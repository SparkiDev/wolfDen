/* mka_crypto.c  -  wolfSSL-backed cryptography for MKA.
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

#include "wolfmka/mka_crypto.h"
#include "wolfmka/mka_mem.h"
#include "wolfmka/internal/mka_fault.h"
/* shared w_be16, rd_be48/w_be48 */
#include "wolfmka/mka_bytes.h"

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/cmac.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/memory.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

/* ------------------------------------------------------------------------- */
/* Small helpers                                                             */
/* ------------------------------------------------------------------------- */

/* wc_AesCmac success */
#define MKA_CMAC_OK 0

/** One pooled AES-CMAC context. Wraps the wolfSSL Cmac so the ~1 KB object
 * lives in wolfMKA-owned storage instead of a wolfSSL stack frame or
 * allocation; the pool is defined in wm_Crypto_CmacInit. */
struct MkaCmacCtx {
    /** the wolfSSL CMAC context this object exists to own */
    Cmac cmac;
    /** this pool slot is handed out */
    bool used;
};

/* The KDF assembles "counter || label || 0x00 || context || len" into one
 * buffer for a single AES-CMAC (streaming is not used: wolfSSL's Cmac context
 * is ~928 octets, far larger than this buffer, so it would be worse here).
 *
 * Sized for MKA's maxima: the longest label is 16 octets; the largest context
 * is the EAP CKN derivation's "Session-Id || 12-octet MACs" (the EAP Session-Id
 * reaches ~65 octets for EAP-TLS), or just the 16-octet KEK/ICK context without
 * EAP. Either way the buffer stays under 128 octets, so it always lives on the
 * stack - no global, no allocation, in every build. */
#define MKA_KDF_LABEL_MAX 24U
#ifdef WOLFMKA_NO_EAP
    #define MKA_KDF_CTX_MAX 16U
#else
    /* Session-Id (<= 84) || 12-octet MACs */
    #define MKA_KDF_CTX_MAX 96U
#endif
/* <= 124 */
#define MKA_KDF_BUF_LEN (1U + MKA_KDF_LABEL_MAX + 1U + MKA_KDF_CTX_MAX + 2U)

/* wm_Crypto_DeriveCknFromMsk places the 12 joined MAC octets into the scratch
 * buffer at mka_kdf_ctx_off(label_len, sid_len) *before* mka_kdf_run gets to
 * check the total length, so that placement must be in bounds on its own. It is
 * today - mka_sid_valid caps sid_len at MKA_KDF_CTX_MAX - 12, and the label is
 * 16 octets against MKA_KDF_LABEL_MAX 24 - but that rests on the relationship
 * between three constants that are declared apart from each other. Raising
 * MKA_KDF_CTX_MAX without MKA_KDF_LABEL_MAX, or lengthening a label, would turn
 * it into a stack overflow with an EAP-supplied length. Fail the build instead:
 * a negative array bound is the C99 way to say so. */
typedef char mka_kdf_bounds_check
    [((sizeof(MKA_LABEL_EAP_CKN) - 1U <= MKA_KDF_LABEL_MAX) &&
         (sizeof(MKA_LABEL_EAP_CAK) - 1U <= MKA_KDF_LABEL_MAX) &&
         (sizeof(MKA_LABEL_KEK) - 1U <= MKA_KDF_LABEL_MAX) &&
         (sizeof(MKA_LABEL_ICK) - 1U <= MKA_KDF_LABEL_MAX) &&
         ((1U + MKA_KDF_LABEL_MAX + 1U + MKA_KDF_CTX_MAX + 2U) ==
             MKA_KDF_BUF_LEN))
            ? 1
            : -1];

/* The magnitude of MKA_ERR_ICV, as a positive value.
 *
 * The two ICV verifiers select their return value branchlessly, by ANDing a
 * full-width mask with a code. Masking the negative code itself meant the
 * result was a large unsigned value - 0xFFFFFFFB - converted back to int32_t on
 * the way out, and converting an out-of-range unsigned to a signed type is
 * implementation-defined (C99 6.3.1.3p3). It yields the right answer on every
 * two's-complement target and C23 mandates two's complement, so nothing was
 * ever going to break - but it was an unrecorded reliance on that, in the one
 * piece of the library written to be branchless. Masking the magnitude and
 * negating afterwards keeps every intermediate in range, and costs the same
 * single negation. The static assertion below keeps the two in step. */
#define MKA_ICV_ERR_MAG 5U

typedef char
    mka_icv_err_mag_check[(MKA_ERR_ICV == -(int32_t)MKA_ICV_ERR_MAG) ? 1 : -1];

/**
 * Whether a key is usable: a non-NULL buffer of a valid MKA key length
 * (128-bit or 256-bit).
 * @param[in] key  the key buffer.
 * @param[in] len  its length in octets.
 * @return true if key is non-NULL and len is 16 or 32, else false.
 */
static bool mka_key_valid(const uint8_t* key, size_t len)
{
    return (key != NULL) && mka_aes_key_len_valid(len);
}

/**
 * Whether a size_t length survives the narrowing to wolfSSL's word32.
 *
 * Every length handed to wolfSSL crosses as a word32. On a host where size_t is
 * wider, an oversized length would truncate silently, and a truncated message
 * length is the worst kind of failure here: AES-CMAC succeeds over the wrong
 * span of octets and the caller gets a valid-looking ICV that authenticates
 * nothing. No length the library generates itself can get near the limit
 * (MKPDUs are bounded by MKA_MKPDU_MAX_LEN), so this guards the public
 * primitives against an integrator's own arithmetic. Where size_t is already
 * 32 bits or narrower the comparison is vacuous, so it is compiled out.
 * @param[in] len  the length in octets.
 * @return true if len is representable as a word32, else false.
 */
static bool mka_len_fits_word32(size_t len)
{
#if defined(SIZE_MAX) && (SIZE_MAX > 0xFFFFFFFFU)
    return len <= (size_t)0xFFFFFFFFU;
#else
    (void)len;
    return true;
#endif
}

#ifndef WOLFMKA_NO_EAP
/**
 * Concatenate two MAC addresses, numerically lower one first.
 *
 * Matches the ordering of IEEE Std 802.1X-2010, so the CAK/CKN derivation is
 * independent of which peer performs it. The compare and the selection are
 * branchless and examine every octet, so neither the timing nor the access
 * pattern reveals which MAC sorts first.
 * @param[in]  mac1  One PAE MAC address (6 octets).
 * @param[in]  mac2  The other PAE MAC address (6 octets).
 * @param[out] out   Destination, 12 octets.
 */
static void mka_join_two_macs(const uint8_t* mac1, const uint8_t* mac2,
    uint8_t* out)
{
    uint64_t a = rd_be48(mac1);
    uint64_t b = rd_be48(mac2);
    /* All-ones when mac1 < mac2: the borrow out of the 48-bit subtraction lands
     * in bit 63. Branchless, so the order is not leaked through timing. */
    uint64_t lt = (uint64_t)0U - ((a - b) >> 63U);

    w_be48(&out[0], (a & lt) | (b & ~lt));
    w_be48(&out[MKA_MAC_LEN], (b & lt) | (a & ~lt));
}
#endif /* WOLFMKA_NO_EAP */

/**
 * Compute one AES-CMAC over a single contiguous buffer.
 *
 * The wolfSSL Cmac context (~1 KB) is the caller-supplied workspace, so it
 * always lives in wolfMKA-owned storage - never a wolfSSL stack frame or
 * allocation. ctx is required (the public entry points reject a NULL one).
 * @param[in]  ctx      CMAC workspace (non-NULL).
 * @param[in]  key      CMAC key (16 or 32 octets selects AES-128/256).
 * @param[in]  key_len  Length of the CMAC key in octets.
 * @param[in]  msg      Message to authenticate.
 * @param[in]  msg_len  Length of the message in octets.
 * @param[out] mac      Output, MKA_DEFAULT_ICV_LEN octets.
 * @return 0 on success, or a wolfSSL error code.
 */
static int mka_aes_cmac(MkaCmacCtx* ctx, const uint8_t* key, size_t key_len,
    const uint8_t* msg, size_t msg_len, uint8_t mac[MKA_DEFAULT_ICV_LEN])
{
    word32 out_sz = (word32)MKA_DEFAULT_ICV_LEN;

    return MKA_FI(MKA_FI_CMAC,
        wc_AesCmacGenerate_ex(&ctx->cmac, mac, &out_sz, msg, (word32)msg_len,
            key, (word32)key_len, WOLFMKA_HEAP_HINT, INVALID_DEVID));
}

/* ------------------------------------------------------------------------- */
/* KDF (IEEE Std 802.1X-2010, 6.2.1)                                         */
/* ------------------------------------------------------------------------- */

/**
 * Run the CMAC iterations of the KDF into the output buffer.
 *
 * buf already holds the constant input; only the counter octet (buf[0])
 * changes for each successive 16-octet output block.
 * @param[in]     cmac     CMAC workspace (non-NULL).
 * @param[in]     key      Derivation key.
 * @param[in]     key_len  Length of the derivation key in octets.
 * @param[in,out] buf      Per-iteration CMAC input (counter at buf[0]).
 * @param[in]     in_len   Length of the CMAC input in octets.
 * @param[out]    out      Output keying material.
 * @param[in]     out_len  Number of octets to produce.
 * @return MKA_OK, or MKA_ERR_CRYPTO on CMAC failure.
 */
static MkaStatus mka_kdf_iterate(MkaCmacCtx* cmac, const uint8_t* key,
    size_t key_len, uint8_t* buf, size_t in_len, uint8_t* out, size_t out_len)
{
    MkaStatus rc = MKA_OK;
    uint8_t block[MKA_DEFAULT_ICV_LEN];
    size_t produced = 0U;
    uint32_t i;
    uint32_t n;

    /* Number of 16-octet CMAC blocks needed to cover out_len (rounded up). */
    n = (uint32_t)((out_len + (MKA_DEFAULT_ICV_LEN - 1U)) /
                   MKA_DEFAULT_ICV_LEN);
    for (i = 1U; i <= n; i++) {
        size_t take;

        /* One CMAC per block; the counter (buf[0]) is what differs per block.
         */
        buf[0] = (uint8_t)i;
        if (mka_aes_cmac(cmac, key, key_len, buf, in_len, block) !=
            MKA_CMAC_OK) {
            rc = MKA_ERR_CRYPTO;
            break;
        }

        /* Append the block, clamping the last one to the requested length. */
        take = out_len - produced;
        if (take > MKA_DEFAULT_ICV_LEN) {
            take = MKA_DEFAULT_ICV_LEN;
        }
        (void)WOLFMKA_MEMCPY(&out[produced], block, take);
        produced += take;
    }
    /* holds derived key material */
    wm_Crypto_ForceZero(block, sizeof block);
    if (rc != MKA_OK) {
        /* Blocks produced before the failure are already in the caller's
         * buffer: real derived key material, from a derivation that did not
         * complete. Wipe it for the same reason wm_Crypto_UnwrapSak wipes a
         * failed unwrap - a caller that ignores the return value must not be
         * able to go on using half a key. */
        wm_Crypto_ForceZero(out, out_len);
    }
    return rc;
}

/**
 * Offset in a KDF buffer at which a context segment begins: after the counter,
 * the label, the label terminator and any preceding context. Centralises the
 * "counter || label || 0x00 || ..." layout shared with mka_kdf_run so a caller
 * can write a context segment (e.g. the joined MACs) straight into the buffer
 * instead of into a separate buffer that is then copied in.
 * @param[in] label_len  length of the KDF label.
 * @param[in] pre_len    length of any context preceding this segment.
 * @return the octet offset within the buffer.
 */
static MKA_INLINE size_t mka_kdf_ctx_off(size_t label_len, size_t pre_len)
{
    /* counter(1) + label + 0x00(1) + pre */
    return label_len + pre_len + 2U;
}

/**
 * Assemble the KDF input in the caller's buffer and run the CMAC iterations.
 *
 * Builds "counter || label || 0x00 || c1 || placed || len" in `buf` and
 * produces out_len octets. `c1` is copied in; the `placed_len` octets that
 * follow it are assumed already written by the caller at
 * mka_kdf_ctx_off(label_len, c1_len) — e.g. the joined MACs — which avoids an
 * extra copy. `buf` is caller-owned scratch of MKA_KDF_BUF_LEN octets (under
 * 128, so it lives on the stack in every configuration).
 * @param[in]  cmac       CMAC workspace (non-NULL).
 * @param[in,out] buf        scratch of MKA_KDF_BUF_LEN octets; any placed
 *                           context is pre-written by the caller.
 * @param[in]  key        derivation key.
 * @param[in]  key_len    key length in octets.
 * @param[in]  label      label string.
 * @param[in]  label_len  length of the label.
 * @param[in]  c1         copied context segment (may be NULL when c1_len is 0).
 * @param[in]  c1_len     length of the copied context segment.
 * @param[in]  placed_len length of context already placed in buf after c1.
 * @param[out] out        output keying material.
 * @param[in]  out_len    number of octets to derive.
 * @return MKA_OK on success;
 *         MKA_ERR_BAD_ARG if the assembled input exceeds the buffer;
 *         MKA_ERR_CRYPTO if the underlying AES-CMAC fails.
 */
static MkaStatus mka_kdf_run(MkaCmacCtx* cmac, uint8_t* buf, const uint8_t* key,
    size_t key_len, const char* label, size_t label_len, const uint8_t* c1,
    size_t c1_len, size_t placed_len, uint8_t* out, size_t out_len)
{
    size_t in_len;
    size_t ctx_off;
    uint16_t out_bits;
    MkaStatus rc;

    /* Reject either caller-supplied length before summing them. The sum is
     * size_t arithmetic: an oversized label or context would wrap it to a small
     * value, sail past the total check below, and then be memcpy'd into a
     * scratch buffer of MKA_KDF_BUF_LEN octets on this stack frame.
     * wm_Crypto_Kdf is public and bounds neither its label nor its context
     * length, so that is reachable from outside the library. Once both are
     * bounded the sum cannot overflow - placed_len needs no check of its own,
     * being 0 or 2 * MKA_MAC_LEN from this file's own callers. */
    if ((label_len > MKA_KDF_BUF_LEN) || (c1_len > MKA_KDF_BUF_LEN)) {
        wm_Crypto_ForceZero(buf, MKA_KDF_BUF_LEN);
        return MKA_ERR_BAD_ARG;
    }
    /* The 255-block bound of IEEE Std 802.1X-2010 6.2.1, enforced here rather
     * than only in wm_Crypto_Kdf: two silent-truncation traps live below this
     * point, and the internal callers reach them without passing through the
     * public wrapper. mka_kdf_iterate's block counter is a single octet
     * (buf[0] = (uint8_t)i), so block 257 would repeat block 1; and out_bits
     * below is a uint16_t, so it truncates past 8191 octets. Both are bounded
     * by 255 * MKA_DEFAULT_ICV_LEN. Today every internal caller asks for 32
     * octets or fewer, so this is latent - but a future one asking for more
     * would get a silently wrong derivation and no diagnostic. */
    if ((out_len == 0U) || (out_len > (255U * MKA_DEFAULT_ICV_LEN))) {
        wm_Crypto_ForceZero(buf, MKA_KDF_BUF_LEN);
        return MKA_ERR_BAD_ARG;
    }
    in_len = 1U + label_len + 1U + c1_len + placed_len + 2U;
    ctx_off = mka_kdf_ctx_off(label_len, c1_len);

    if (in_len > MKA_KDF_BUF_LEN) {
        /* The caller may already have placed context into the buffer, so leave
         * by the same door as every other exit. */
        wm_Crypto_ForceZero(buf, MKA_KDF_BUF_LEN);
        return MKA_ERR_BAD_ARG;
    }

    out_bits = (uint16_t)(out_len * 8U);
    (void)WOLFMKA_MEMCPY(&buf[1], label, label_len);
    buf[1U + label_len] = 0x00U;
    if (c1_len > 0U) {
        (void)WOLFMKA_MEMCPY(&buf[mka_kdf_ctx_off(label_len, 0U)], c1, c1_len);
    }
    /* The placed_len octets of context (e.g. the joined MACs) are already at
     * buf[ctx_off]; skip over them to append the output length. */
    w_be16(&buf[ctx_off + placed_len], out_bits);

    rc = mka_kdf_iterate(cmac, key, key_len, buf, in_len, out, out_len);
    /* KDF input scratch */
    wm_Crypto_ForceZero(buf, MKA_KDF_BUF_LEN);
    return rc;
}

/* Validate the public arguments, then run the KDF with the caller's context as
 * the single context segment (the second segment is unused here). */
MkaStatus wm_Crypto_Kdf(MkaCmacCtx* cmac, const uint8_t* key, size_t key_len,
    const char* label, const uint8_t* context, size_t context_len, uint8_t* out,
    size_t out_len)
{
    uint8_t buf[MKA_KDF_BUF_LEN];

    if ((cmac == NULL) || (label == NULL) || (out == NULL)) {
        return MKA_ERR_BAD_ARG;
    }
    if (!mka_key_valid(key, key_len)) {
        return MKA_ERR_BAD_ARG;
    }
    if ((context_len > 0U) && (context == NULL)) {
        return MKA_ERR_BAD_ARG;
    }
    /* out_len is bounded inside mka_kdf_run, so the rule has one home and the
     * internal callers are covered by it too. */
    return mka_kdf_run(cmac, buf, key, key_len, label, WOLFMKA_STRLEN(label),
        context, context_len, 0U, out, out_len);
}

/* ------------------------------------------------------------------------- */
/* CAK / CKN derivation from an EAP MSK (9.3.2)                              */
/* ------------------------------------------------------------------------- */
#ifndef WOLFMKA_NO_EAP

/* The KDF key is the leftmost cak_len octets of the MSK; the context is the two
 * MACs ordered lowest-first (mka_join_two_macs) for peer-independent
 * derivation. */
MkaStatus wm_Crypto_DeriveCakFromMsk(MkaCmacCtx* cmac, const uint8_t* msk,
    size_t msk_len, const uint8_t mac1[MKA_MAC_LEN],
    const uint8_t mac2[MKA_MAC_LEN], uint8_t* cak, size_t cak_len)
{
    uint8_t buf[MKA_KDF_BUF_LEN];
    size_t label_len = WOLFMKA_STRLEN(MKA_LABEL_EAP_CAK);

    if ((cmac == NULL) || (msk == NULL) || (mac1 == NULL) || (mac2 == NULL)) {
        return MKA_ERR_BAD_ARG;
    }
    if (!mka_key_valid(cak, cak_len)) {
        return MKA_ERR_BAD_ARG;
    }
    /* The KDF key is the MSK, whole (9.3.2:
     * CAK = KDF(MSK, "IEEE8021 EAP CAK", mac1 | mac2, CAKlength)) - and the
     * AES-CMAC key length is what selects AES-128 or AES-256, so it is the MSK
     * length that decides which. This used to accept any msk_len >= cak_len and
     * key the CMAC with cak_len, i.e. with the leftmost cak_len octets: for a
     * 32-octet MSK and a 128-bit CAK the upper half of the MSK never entered
     * the derivation, and the result did not match what the formula above -
     * or hostapd's ieee802_1x_cak_aes_cmac, which passes 8 * msk_bytes - would
     * produce. hostapd's callers always pass equal lengths
     * (wpa_supplicant/wpas_kay.c clamps the MSK to DEFAULT_KEY_LEN and asks for
     * a CAK of the same size), so nothing interoperating was ever affected;
     * the divergence was reachable only through this API accepting a longer
     * MSK. Requiring the two to match removes that region without changing any
     * value this function has ever produced. */
    if (msk_len != cak_len) {
        return MKA_ERR_BAD_ARG;
    }

    /* Context = lower-MAC || higher-MAC (9.3.2), written straight into the KDF
     * buffer (no separate buffer or copy). */
    mka_join_two_macs(mac1, mac2, &buf[mka_kdf_ctx_off(label_len, 0U)]);

    return mka_kdf_run(cmac, buf, msk, msk_len, MKA_LABEL_EAP_CAK, label_len,
        NULL, 0U, 2U * MKA_MAC_LEN, cak, cak_len);
}

/* The Session-Id is streamed into the KDF as the first context segment and the
 * joined MACs as the second, so no separate context buffer is needed. */
/**
 * Whether the EAP Session-Id and its length are usable: consistent (no length
 * without a buffer) and fitting the KDF context with room for the two appended
 * MAC addresses.
 * @param[in] eap_session_id  the EAP Session-Id (may be NULL when sid_len is
 * 0).
 * @param[in] sid_len         its length in octets.
 * @return true if usable, else false.
 */
static bool mka_sid_valid(const uint8_t* eap_session_id, size_t sid_len)
{
    if ((eap_session_id == NULL) && (sid_len != 0U)) {
        return false;
    }
    /* Written as a subtraction from the bound rather than an addition to
     * sid_len: sid_len comes from the caller, and adding to it first would wrap
     * for a large value and report an oversized Session-Id as fitting. Both
     * operands are compile-time constants, with MKA_KDF_CTX_MAX (96 in an EAP
     * build) comfortably the larger, so the subtraction cannot underflow. The
     * comparison needs no cast: the constant widens to size_t on its own, and
     * casting the composite would be a MISRA 10.8 violation. */
    return sid_len <= (MKA_KDF_CTX_MAX - (2U * MKA_MAC_LEN));
}

/**
 * Whether a CKN (CAK Name) output is valid: a non-NULL buffer of
 * 1..MKA_MAX_CKN_LEN octets (9.3.1).
 * @param[in] ckn      the CKN buffer.
 * @param[in] ckn_len  its length in octets.
 * @return true if valid, else false.
 */
static bool mka_ckn_valid(const uint8_t* ckn, size_t ckn_len)
{
    return (ckn != NULL) && (ckn_len != 0U) && (ckn_len <= MKA_MAX_CKN_LEN);
}

MkaStatus wm_Crypto_DeriveCknFromMsk(MkaCmacCtx* cmac, const uint8_t* msk,
    size_t msk_len, const uint8_t* eap_session_id, size_t sid_len,
    const uint8_t mac1[MKA_MAC_LEN], const uint8_t mac2[MKA_MAC_LEN],
    uint8_t* ckn, size_t ckn_len)
{
    /* One KDF scratch buffer on the stack (under 128 octets); the joined MACs
     * are written straight into it, so no separate MAC buffer is needed. */
    uint8_t buf[MKA_KDF_BUF_LEN];
    size_t label_len = WOLFMKA_STRLEN(MKA_LABEL_EAP_CKN);

    if ((cmac == NULL) || (mac1 == NULL) || (mac2 == NULL)) {
        return MKA_ERR_BAD_ARG;
    }
    if (!mka_sid_valid(eap_session_id, sid_len)) {
        return MKA_ERR_BAD_ARG;
    }
    if (!mka_ckn_valid(ckn, ckn_len)) {
        return MKA_ERR_BAD_ARG;
    }
    /* the KDF key must be 16 or 32 octets */
    if (!mka_key_valid(msk, msk_len)) {
        return MKA_ERR_BAD_ARG;
    }

    /* Context = EAP Session-Id || lower-MAC || higher-MAC (9.3.2). The
     * Session-Id is copied in by mka_kdf_run; the joined MACs are written
     * straight into the buffer after it (no separate buffer or copy). */
    mka_join_two_macs(mac1, mac2, &buf[mka_kdf_ctx_off(label_len, sid_len)]);
    return mka_kdf_run(cmac, buf, msk, msk_len, MKA_LABEL_EAP_CKN, label_len,
        eap_session_id, sid_len, 2U * MKA_MAC_LEN, ckn, ckn_len);
}

#endif /* WOLFMKA_NO_EAP */

/* ------------------------------------------------------------------------- */
/* KEK / ICK derivation from a CAK (9.3.3)                                   */
/* ------------------------------------------------------------------------- */

/* KEK and ICK share the same context (the first 16 octets of the CKN, zero
 * padded) and key (the CAK); only the KDF label differs. */
MkaStatus wm_Crypto_DeriveKeys(MkaCmacCtx* cmac, const MkaCakPair* cak,
    MkaDerivedKeys* keys)
{
    uint8_t buf[MKA_KDF_BUF_LEN];
    uint8_t context[MKA_KEK_CONTEXT_LEN];
    size_t copy;
    MkaStatus rc;

    if ((cmac == NULL) || (cak == NULL) || (keys == NULL)) {
        return MKA_ERR_BAD_ARG;
    }
    if (!mka_key_valid(cak->cak, cak->cak_len)) {
        return MKA_ERR_BAD_ARG;
    }
    if ((cak->ckn_len == 0U) || (cak->ckn_len > MKA_MAX_CKN_LEN)) {
        return MKA_ERR_BAD_ARG;
    }

    /* Context is the leftmost 16 octets of the CKN, zero padded. */
    (void)WOLFMKA_MEMSET(context, 0, sizeof(context));
    copy = (cak->ckn_len < MKA_KEK_CONTEXT_LEN) ? cak->ckn_len
                                                : MKA_KEK_CONTEXT_LEN;
    (void)WOLFMKA_MEMCPY(context, cak->ckn, copy);

    keys->kek_len = cak->cak_len;
    keys->ick_len = cak->cak_len;

    rc = mka_kdf_run(cmac, buf, cak->cak, cak->cak_len, MKA_LABEL_KEK,
        WOLFMKA_STRLEN(MKA_LABEL_KEK), context, sizeof(context), 0U, keys->kek,
        keys->kek_len);
    if (rc == MKA_OK) {
        rc = mka_kdf_run(cmac, buf, cak->cak, cak->cak_len, MKA_LABEL_ICK,
            WOLFMKA_STRLEN(MKA_LABEL_ICK), context, sizeof(context), 0U,
            keys->ick, keys->ick_len);
    }
    /* The KDF context is a scratch copy of the CKN; wipe it. On any failure
     * (e.g. a CMAC fault after the KEK was already derived), wipe the output
     * too so the caller never receives stale or partially-derived key material.
     */
    wm_Crypto_ForceZero(context, sizeof(context));
    if (rc != MKA_OK) {
        wm_Crypto_ForceZero(keys, sizeof(*keys));
    }
    return rc;
}

/* ------------------------------------------------------------------------- */
/* SAK generation and AES Key Wrap distribution (9.8)                        */
/* ------------------------------------------------------------------------- */

/** A pool of RNG objects. wm_Crypto_RandomInit() seeds one and hands back a
 * reference so the costly wc_InitRng is paid once per long-lived holder, not
 * per call; the random-consuming functions take that reference. The backing
 * array is the pool's storage (no allocation); each object is used
 * single-threaded. */
struct MkaRandom {
    /** the wolfSSL RNG this object exists to own */
    WC_RNG rng;
    /** this pool slot is handed out */
    bool used;
};

/* Acquire and seed a free pool slot; return its reference, or NULL if the pool
 * is full or seeding fails. */
MkaRandom* wm_Crypto_RandomInit(void)
{
    /* The pool storage lives here: only this function hands out slots; callers
     * keep the returned reference (static storage, so it persists). */
    static struct MkaRandom pool[WOLFMKA_RANDOM_POOL_SIZE];
    size_t i;

    for (i = 0U; i < (size_t)WOLFMKA_RANDOM_POOL_SIZE; i++) {
        if (!pool[i].used) {
            /* wc_InitRng_ex, not wc_InitRng: the DRBG state is XMALLOCed from
             * rng->heap, and the plain form passes NULL - so an integrator who
             * set WOLFMKA_HEAP_HINT to route wolfSSL allocations into a static
             * pool would find this one coming from the default heap instead,
             * silently defeating the configuration. Every other wolfSSL call in
             * this file already threads the hint through. */
            if (MKA_FI(MKA_FI_RNG_INIT,
                    wc_InitRng_ex(&pool[i].rng, WOLFMKA_HEAP_HINT,
                        INVALID_DEVID)) != 0) {
                return NULL;
            }
            pool[i].used = true;
            return &pool[i];
        }
    }
    /* pool exhausted */
    return NULL;
}

/* Release a pool slot and free its RNG; a NULL reference is a no-op. */
void wm_Crypto_RandomFree(MkaRandom* rng)
{
    if (rng != NULL) {
        (void)wc_FreeRng(&rng->rng);
        rng->used = false;
    }
}

/* Acquire a free CMAC context from the pool; return its reference, or NULL if
 * the pool is exhausted. The per-call wc_AesCmacGenerate_ex re-initialises the
 * context, so the storage need only be reserved here, not seeded. */
MkaCmacCtx* wm_Crypto_CmacInit(void)
{
    /* The pool storage lives here: only this function hands out slots; callers
     * keep the returned reference (static storage, so it persists). */
    static struct MkaCmacCtx pool[WOLFMKA_CMAC_POOL_SIZE];
    size_t i;

    for (i = 0U; i < (size_t)WOLFMKA_CMAC_POOL_SIZE; i++) {
        if (!pool[i].used) {
            pool[i].used = true;
            return &pool[i];
        }
    }
    /* pool exhausted */
    return NULL;
}

/* Release a CMAC context back to the pool; a NULL reference is a no-op. */
void wm_Crypto_CmacFree(MkaCmacCtx* cmac)
{
    if (cmac != NULL) {
        cmac->used = false;
    }
}

/* Operational core of the RNG fill. The caller has already validated rng and
 * buf/len, so this is shared by both public entries without re-checking; the
 * block-generation result routes through MKA_FI for fault-path testing.
 *
 * There is deliberately no fall-back that seeds a throwaway RNG when rng is
 * NULL. Such a WC_RNG had to be declared in this stack frame, and under
 * WOLFSSL_NO_MALLOC a WC_RNG embeds its DRBG state inline - so the object was
 * several hundred octets of wolfMKA's stack in exactly the
 * WOLFMKA_SMALL_STACK / WOLFMKA_NO_MALLOC build the pool exists to serve, while
 * an ordinary wolfSSL build heap-allocated the DRBG on every call. Neither is
 * visible to make test-nomalloc, which greps wolfMKA's own objects and cannot
 * see an allocation made inside libwolfssl. */
static MkaStatus mka_random_fill(MkaRandom* rng, uint8_t* buf, size_t len)
{
    int ret = MKA_FI(MKA_FI_RNG_GEN,
        wc_RNG_GenerateBlock(&rng->rng, buf, (word32)len));

    return (ret == 0) ? MKA_OK : MKA_ERR_CRYPTO;
}

/* Public entry: validate the output buffer/length, then fill it. */
MkaStatus wm_Crypto_Random(MkaRandom* rng, uint8_t* buf, size_t len)
{
    if ((rng == NULL) || (buf == NULL) || (len == 0U) ||
        (!mka_len_fits_word32(len))) {
        return MKA_ERR_BAD_ARG;
    }
    return mka_random_fill(rng, buf, len);
}

/* Securely wipe sensitive material; wraps wc_ForceZero, which the optimiser may
 * not elide (unlike a plain memset). */
void wm_Crypto_ForceZero(void* mem, size_t len)
{
    /* Documented as ignoring NULL; wc_ForceZero would dereference it. */
    if (mem != NULL) {
        wc_ForceZero(mem, len);
    }
}

/* A SAK is just random octets of the (validated) length. mka_key_valid already
 * guarantees a non-NULL buffer and a 16/32 length, so this fills directly via
 * the shared core rather than re-validating through wm_Crypto_Random. */
MkaStatus wm_Crypto_GenerateSak(MkaRandom* rng, uint8_t* sak, size_t sak_len)
{
    if ((rng == NULL) || (!mka_key_valid(sak, sak_len))) {
        return MKA_ERR_BAD_ARG;
    }
    return mka_random_fill(rng, sak, sak_len);
}

/**
 * Whether a SAK to be wrapped is usable: a non-NULL buffer whose length is a
 * multiple of 8 octets and at least 16 (AES Key Wrap, RFC 3394 / 9.8.2).
 * @param[in] sak      the SAK buffer.
 * @param[in] sak_len  its length in octets.
 * @return true if usable, else false.
 */
static bool mka_sak_valid(const uint8_t* sak, size_t sak_len)
{
    return (sak != NULL) && ((sak_len & 0x7U) == 0U) && (sak_len >= 16U);
}

/**
 * Whether a wrapped key to be unwrapped is usable: a non-NULL buffer whose
 * length is a multiple of 8 octets and at least 24 (a 16-octet SAK plus the
 * 8-octet AES Key Wrap overhead).
 * @param[in] wrapped      the wrapped-key buffer.
 * @param[in] wrapped_len  its length in octets.
 * @return true if usable, else false.
 */
static bool mka_wrapped_valid(const uint8_t* wrapped, size_t wrapped_len)
{
    return (wrapped != NULL) && (wrapped_len >= 24U) &&
           ((wrapped_len & 0x7U) == 0U);
}

/**
 * Whether the wrapped-key output of AES Key Wrap is usable: a non-NULL buffer
 * and length pointer, with room for the result (sak_len + 8 octets).
 * @param[in] wrapped      the output buffer.
 * @param[in] wrapped_len  the in/out capacity pointer.
 * @param[in] sak_len      the SAK length being wrapped.
 * @return MKA_OK if usable; MKA_ERR_BAD_ARG on a NULL pointer; MKA_ERR_BUFFER
 *         if the buffer is too small.
 */
static MkaStatus mka_wrapped_out_valid(const uint8_t* wrapped,
    const size_t* wrapped_len, size_t sak_len)
{
    if ((wrapped == NULL) || (wrapped_len == NULL)) {
        return MKA_ERR_BAD_ARG;
    }
    if (*wrapped_len < (sak_len + 8U)) {
        return MKA_ERR_BUFFER;
    }
    /* Only a lower bound is checked above, so the capacity is otherwise
     * unbounded and crosses into wolfSSL as a word32 - the same narrowing the
     * ICV and random entry points already guard. */
    if (!mka_len_fits_word32(*wrapped_len)) {
        return MKA_ERR_BAD_ARG;
    }
    return MKA_OK;
}

/**
 * Whether the SAK output of AES Key Unwrap is usable: a non-NULL buffer and
 * length pointer, with room for the recovered SAK (wrapped_len - 8 octets).
 * @param[in] sak          the output buffer.
 * @param[in] sak_len      the in/out capacity pointer.
 * @param[in] wrapped_len  the wrapped-key length being unwrapped (>= 24).
 * @return MKA_OK if usable; MKA_ERR_BAD_ARG on a NULL pointer; MKA_ERR_BUFFER
 *         if the buffer is too small.
 */
static MkaStatus mka_sak_out_valid(const uint8_t* sak, const size_t* sak_len,
    size_t wrapped_len)
{
    if ((sak == NULL) || (sak_len == NULL)) {
        return MKA_ERR_BAD_ARG;
    }
    if (*sak_len < (wrapped_len - 8U)) {
        return MKA_ERR_BUFFER;
    }
    /* As mka_wrapped_out_valid: a lower bound only, so guard the narrowing to
     * word32 that the call into wolfSSL performs. */
    if (!mka_len_fits_word32(*sak_len)) {
        return MKA_ERR_BAD_ARG;
    }
    return MKA_OK;
}

/* wolfSSL's wc_AesKeyWrap returns the wrapped length (sak_len + 8) on success
 * or a negative error; *wrapped_len is updated to the bytes written. */
MkaStatus wm_Crypto_WrapSak(const uint8_t* kek, size_t kek_len,
    const uint8_t* sak, size_t sak_len, uint8_t* wrapped, size_t* wrapped_len)
{
    int ret;
    MkaStatus rc;

    /* Validate the KEK, the SAK input and the output buffer. */
    if (!mka_key_valid(kek, kek_len)) {
        return MKA_ERR_BAD_ARG;
    }
    if (!mka_sak_valid(sak, sak_len)) {
        return MKA_ERR_BAD_ARG;
    }
    rc = mka_wrapped_out_valid(wrapped, wrapped_len, sak_len);
    if (rc != MKA_OK) {
        return rc;
    }

    /* Wrap; on success return the wrapped length (sak_len + 8). */
    ret = MKA_FI(MKA_FI_KEYWRAP,
        wc_AesKeyWrap(kek, (word32)kek_len, sak, (word32)sak_len, wrapped,
            (word32)(*wrapped_len), NULL));
    if (ret < 0) {
        return MKA_ERR_CRYPTO;
    }

    *wrapped_len = (size_t)ret;
    return MKA_OK;
}

/* A negative wc_AesKeyUnWrap result also covers the RFC 3394 integrity-check
 * failure (e.g. a wrong KEK), reported here as MKA_ERR_CRYPTO. */
MkaStatus wm_Crypto_UnwrapSak(const uint8_t* kek, size_t kek_len,
    const uint8_t* wrapped, size_t wrapped_len, uint8_t* sak, size_t* sak_len)
{
    int ret;
    MkaStatus rc;

    /* Validate the KEK, the wrapped input and the output buffer. */
    if (!mka_key_valid(kek, kek_len)) {
        return MKA_ERR_BAD_ARG;
    }
    if (!mka_wrapped_valid(wrapped, wrapped_len)) {
        return MKA_ERR_BAD_ARG;
    }
    rc = mka_sak_out_valid(sak, sak_len, wrapped_len);
    if (rc != MKA_OK) {
        return rc;
    }

    /* Unwrap; a negative result includes the RFC 3394 integrity failure. */
    ret = MKA_FI(MKA_FI_KEYUNWRAP,
        wc_AesKeyUnWrap(kek, (word32)kek_len, wrapped, (word32)wrapped_len, sak,
            (word32)(*sak_len), NULL));
    if (ret < 0) {
        /* Defence in depth. wc_AesKeyUnWrap decrypts into `out` before it
         * compares the RFC 3394 integrity IV, so the caller's buffer can in
         * principle hold key-derived plaintext for a key being rejected -
         * though the wolfSSL this is built against zeroes the output itself on
         * that path, so today the wipe changes nothing observable. That is
         * wolfSSL's behaviour rather than its contract, and it costs one memset
         * on an error path to not depend on it.
         *
         * Wipe what could have been written - wrapped_len - 8, the unwrapped
         * size - rather than the caller's whole capacity. The capacity is
         * caller-supplied and only lower-bounded, so sizing the wipe by it
         * would write past the end of a buffer a caller merely *described* as
         * large. mka_sak_out_valid has already established the buffer holds at
         * least this much. */
        wm_Crypto_ForceZero(sak, wrapped_len - 8U);
        return MKA_ERR_CRYPTO;
    }

    *sak_len = (size_t)ret;
    return MKA_OK;
}

/* ------------------------------------------------------------------------- */
/* ICV (AES-CMAC with the ICK)                                               */
/* ------------------------------------------------------------------------- */

/* The ICV is a 16-octet AES-CMAC over the supplied data with the ICK. */
MkaStatus wm_Crypto_IcvCompute(MkaCmacCtx* cmac, const uint8_t* ick,
    size_t ick_len, const uint8_t* data, size_t data_len,
    uint8_t icv[MKA_DEFAULT_ICV_LEN])
{
    if ((cmac == NULL) || (data == NULL) || (icv == NULL)) {
        return MKA_ERR_BAD_ARG;
    }
    if (!mka_len_fits_word32(data_len)) {
        return MKA_ERR_BAD_ARG;
    }
    /* ICK is a 16/32-octet AES-CMAC key */
    if (!mka_key_valid(ick, ick_len)) {
        return MKA_ERR_BAD_ARG;
    }
    if (mka_aes_cmac(cmac, ick, ick_len, data, data_len, icv) != MKA_CMAC_OK) {
        return MKA_ERR_CRYPTO;
    }
    return MKA_OK;
}

/* Recompute the ICV and compare against the received one in constant time so
 * the comparison does not leak where a mismatch occurs. */
MkaStatus wm_Crypto_IcvVerify(MkaCmacCtx* cmac, const uint8_t* ick,
    size_t ick_len, const uint8_t* data, size_t data_len,
    const uint8_t icv[MKA_DEFAULT_ICV_LEN])
{
    uint8_t computed[MKA_DEFAULT_ICV_LEN];
    uint8_t diff = 0U;
    size_t i;
    uint32_t sel;
    MkaStatus rc;

    if (icv == NULL) {
        return MKA_ERR_BAD_ARG;
    }

    rc = wm_Crypto_IcvCompute(cmac, ick, ick_len, data, data_len, computed);
    if (rc != MKA_OK) {
        /* The compare path below wipes this buffer unconditionally; give it one
         * lifetime rule rather than two. wc_AesCmacGenerate_ex writes the tag
         * only in its final step, so nothing has been placed here on this path
         * today - but that is a property of the wolfSSL internals, not
         * something this function establishes, and the buffer holds an
         * ICK-derived value either way. */
        wm_Crypto_ForceZero(computed, sizeof(computed));
        return rc;
    }

    /* Constant-time comparison. */
    for (i = 0U; i < MKA_DEFAULT_ICV_LEN; i++) {
        diff |= (uint8_t)(computed[i] ^ icv[i]);
    }

    /* Branchless, table-free select: (0 - nz) is a full-width mask that is
     * all-ones exactly when any octet differed (nz == 1), else zero. ANDing it
     * with the error magnitude yields MKA_ICV_ERR_MAG on a mismatch and 0 on a
     * match, with no branch and no data-dependent memory access; the negation
     * on the return turns that into MKA_ERR_ICV or MKA_OK. Every intermediate
     * stays inside int32_t, so nothing here relies on the implementation's
     * choice for an out-of-range unsigned-to-signed conversion. */
    sel = (0U - (((uint32_t)diff + 0xFFU) >> 8U)) & MKA_ICV_ERR_MAG;
    /* The expected ICV is not secret, but it is derived from the ICK, and the
     * L2 variant wipes its copy - keep the two consistent so neither reads as
     * the deliberate exception. Unconditional, so it costs the same either way.
     */
    wm_Crypto_ForceZero(computed, sizeof computed);
    return (MkaStatus)(-(int32_t)sel);
}

/* AES-CMAC(ICK) over an L2 prefix (DA || SA || EAPOL EtherType) then the MKPDU,
 * via the streaming API so no scratch buffer is needed. Matches the ICV input
 * wpa_supplicant uses (IEEE Std 802.1X-2010, 11.11.3). */
static int mka_aes_cmac_l2(MkaCmacCtx* ctx, const uint8_t* key, size_t key_len,
    const uint8_t* l2, size_t l2_len, const uint8_t* data, size_t data_len,
    uint8_t mac[MKA_DEFAULT_ICV_LEN])
{
    word32 out_sz = (word32)MKA_DEFAULT_ICV_LEN;
    int ret;
    int opened = 0;

    /* Every stage goes through the fault-injection hook, not just the result.
     * The non-L2 helper is a single one-shot call, but this one is a four-step
     * streaming sequence, and its "did the previous step fail" guards are
     * otherwise unreachable in a test build - nothing can make an intermediate
     * wolfSSL call fail. MKA_FI is a no-op in production builds. */
    ret = MKA_FI(MKA_FI_CMAC,
        wc_InitCmac_ex(&ctx->cmac, key, (word32)key_len, WC_CMAC_AES, NULL,
            WOLFMKA_HEAP_HINT, INVALID_DEVID));
    if (ret == 0) {
        opened = 1;
        ret =
            MKA_FI(MKA_FI_CMAC, wc_CmacUpdate(&ctx->cmac, l2, (word32)l2_len));
    }
    if ((ret == 0) && (data_len > 0U)) {
        ret = MKA_FI(MKA_FI_CMAC,
            wc_CmacUpdate(&ctx->cmac, data, (word32)data_len));
    }
    if (ret == 0) {
        /* wc_CmacFinal releases the context itself, on success and on
         * failure alike. */
        ret = MKA_FI(MKA_FI_CMAC, wc_CmacFinal(&ctx->cmac, mac, &out_sz));
    }
    else if (opened != 0) {
        /* An intermediate step failed, so wc_CmacFinal never ran and the
         * context still holds the ICK-derived key schedule and subkeys in
         * wolfMKA's own static pool slot. Release it explicitly - wolfSSL's
         * one-shot wc_AesCmacGenerate_ex does the same for exactly this case,
         * and the non-L2 helper inherits that for free. */
        (void)wc_CmacFree(&ctx->cmac);
    }
    else {
        /* The context was never opened; there is nothing to release. */
    }
    return ret;
}

MkaStatus wm_Crypto_IcvComputeL2(MkaCmacCtx* cmac, const uint8_t* ick,
    size_t ick_len, const uint8_t* l2, size_t l2_len, const uint8_t* data,
    size_t data_len, uint8_t icv[MKA_DEFAULT_ICV_LEN])
{
    if ((cmac == NULL) || (l2 == NULL) || (data == NULL) || (icv == NULL)) {
        return MKA_ERR_BAD_ARG;
    }
    /* The L2 prefix is a fixed 14 octets (DA || SA || EtherType); reject any
     * other length so callers cannot silently ICV the wrong input. */
    if (l2_len != MKA_ICV_L2_PREFIX_LEN) {
        return MKA_ERR_BAD_ARG;
    }
    if (!mka_len_fits_word32(data_len)) {
        return MKA_ERR_BAD_ARG;
    }
    if (!mka_key_valid(ick, ick_len)) {
        return MKA_ERR_BAD_ARG;
    }
    if (mka_aes_cmac_l2(cmac, ick, ick_len, l2, l2_len, data, data_len, icv) !=
        MKA_CMAC_OK) {
        return MKA_ERR_CRYPTO;
    }
    return MKA_OK;
}

MkaStatus wm_Crypto_IcvVerifyL2(MkaCmacCtx* cmac, const uint8_t* ick,
    size_t ick_len, const uint8_t* l2, size_t l2_len, const uint8_t* data,
    size_t data_len, const uint8_t icv[MKA_DEFAULT_ICV_LEN])
{
    uint8_t computed[MKA_DEFAULT_ICV_LEN];
    uint8_t diff = 0U;
    size_t i;
    uint32_t sel;
    MkaStatus rc;

    if (icv == NULL) {
        return MKA_ERR_BAD_ARG;
    }
    rc = wm_Crypto_IcvComputeL2(cmac, ick, ick_len, l2, l2_len, data, data_len,
        computed);
    if (rc != MKA_OK) {
        /* Same lifetime rule as wm_Crypto_IcvVerify. */
        wm_Crypto_ForceZero(computed, sizeof(computed));
        return rc;
    }
    for (i = 0U; i < MKA_DEFAULT_ICV_LEN; i++) {
        diff |= (uint8_t)(computed[i] ^ icv[i]);
    }
    wm_Crypto_ForceZero(computed, sizeof computed);
    /* Branchless constant-time select, matching wm_Crypto_IcvVerify: the mask
     * selects the error magnitude, and the negation on the return turns it into
     * MKA_ERR_ICV when any octet differed, MKA_OK otherwise. */
    sel = (0U - (((uint32_t)diff + 0xFFU) >> 8U)) & MKA_ICV_ERR_MAG;
    return (MkaStatus)(-(int32_t)sel);
}
