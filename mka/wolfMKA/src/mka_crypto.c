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

/* One pooled AES-CMAC context. Wraps the wolfSSL Cmac so the ~1 KB object lives
 * in wolfMKA-owned storage instead of a wolfSSL stack frame or allocation; the
 * pool is defined in wm_Crypto_CmacInit. */
struct MkaCmacCtx {
    Cmac cmac;
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
    size_t in_len = 1U + label_len + 1U + c1_len + placed_len + 2U;
    size_t ctx_off = mka_kdf_ctx_off(label_len, c1_len);
    uint16_t out_bits;
    MkaStatus rc;

    if (in_len > MKA_KDF_BUF_LEN) {
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
    if ((out_len == 0U) || (out_len > (255U * MKA_DEFAULT_ICV_LEN))) {
        return MKA_ERR_BAD_ARG;
    }
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
    if (msk_len < cak_len) {
        return MKA_ERR_BAD_ARG;
    }

    /* Context = lower-MAC || higher-MAC (9.3.2), written straight into the KDF
     * buffer (no separate buffer or copy). The KDF key is the leftmost cak_len
     * octets of the MSK. */
    mka_join_two_macs(mac1, mac2, &buf[mka_kdf_ctx_off(label_len, 0U)]);

    return mka_kdf_run(cmac, buf, msk, cak_len, MKA_LABEL_EAP_CAK, label_len,
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
    return (sid_len + (2U * MKA_MAC_LEN)) <= MKA_KDF_CTX_MAX;
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

/* A pool of RNG objects. wm_Crypto_RandomInit() seeds one and hands back a
 * reference so the costly wc_InitRng is paid once per long-lived holder, not
 * per call; the random-consuming functions take that reference. The backing
 * array is the pool's storage (no allocation); each object is used
 * single-threaded. */
struct MkaRandom {
    WC_RNG rng;
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
            if (MKA_FI(MKA_FI_RNG_INIT, wc_InitRng(&pool[i].rng)) != 0) {
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

/* Operational core of the RNG fill: use the supplied pool RNG, else seed a
 * fresh one per call (rng NULL). The caller has already validated buf/len, so
 * this is shared by both public entries without re-checking. Both the init and
 * the block-generation results route through MKA_FI for fault-path testing. */
static MkaStatus mka_random_fill(MkaRandom* rng, uint8_t* buf, size_t len)
{
    WC_RNG local;
    WC_RNG* r;
    bool temp = false;
    int ret;

    /* Use the pooled RNG, or seed a throwaway one for this call. */
    if (rng != NULL) {
        r = &rng->rng;
    }
    else {
        if (MKA_FI(MKA_FI_RNG_INIT, wc_InitRng(&local)) != 0) {
            return MKA_ERR_CRYPTO;
        }
        r = &local;
        temp = true;
    }

    /* Fill the buffer. */
    ret = MKA_FI(MKA_FI_RNG_GEN, wc_RNG_GenerateBlock(r, buf, (word32)len));

    /* Free the throwaway RNG, if any. */
    if (temp) {
        (void)wc_FreeRng(&local);
    }

    return (ret == 0) ? MKA_OK : MKA_ERR_CRYPTO;
}

/* Public entry: validate the output buffer/length, then fill it. */
MkaStatus wm_Crypto_Random(MkaRandom* rng, uint8_t* buf, size_t len)
{
    if ((buf == NULL) || (len == 0U)) {
        return MKA_ERR_BAD_ARG;
    }
    return mka_random_fill(rng, buf, len);
}

/* Securely wipe sensitive material; wraps wc_ForceZero, which the optimiser may
 * not elide (unlike a plain memset). */
void wm_Crypto_ForceZero(void* mem, size_t len)
{
    wc_ForceZero(mem, len);
}

/* A SAK is just random octets of the (validated) length. mka_key_valid already
 * guarantees a non-NULL buffer and a 16/32 length, so this fills directly via
 * the shared core rather than re-validating through wm_Crypto_Random. */
MkaStatus wm_Crypto_GenerateSak(MkaRandom* rng, uint8_t* sak, size_t sak_len)
{
    if (!mka_key_valid(sak, sak_len)) {
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
        return rc;
    }

    /* Constant-time comparison. */
    for (i = 0U; i < MKA_DEFAULT_ICV_LEN; i++) {
        diff |= (uint8_t)(computed[i] ^ icv[i]);
    }

    /* Branchless, table-free select: (0 - nz) is a full-width mask that is
     * all-ones exactly when any octet differed (nz == 1), else zero. ANDing it
     * with the error code yields MKA_ERR_ICV on a mismatch and MKA_OK (0) on a
     * match, with no branch and no data-dependent memory access. */
    sel = (0U - (((uint32_t)diff + 0xFFU) >> 8U)) & (uint32_t)MKA_ERR_ICV;
    return (MkaStatus)(int32_t)sel;
}
