/* mka_crypto.h
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
 * Cryptographic primitives for MKA, implemented on top of wolfSSL.
 *
 *   - KDF: the AES-CMAC based key derivation function of IEEE Std 802.1X-2010,
 *     6.2.1 (NIST SP 800-108 counter mode with AES-CMAC as the PRF).
 *   - CAK/CKN derivation from an EAP MSK (9.3.2).
 *   - KEK and ICK derivation from a CAK (9.3.3).
 *   - SAK generation (9.8) and AES Key Wrap (RFC 3394) distribution.
 *   - ICV computation/verification over an MKPDU (AES-CMAC with the ICK).
 *
 * All routines return an MkaStatus.
 */

#ifndef WOLFMKA_CRYPTO_H
#define WOLFMKA_CRYPTO_H

#include "mka_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Number of RNG objects in the crypto layer's pool. Each
 * wm_Crypto_RandomInit hands out one; size it for the number of concurrent
 * RNG holders (e.g. one shared, or one per participant). Override at build
 * time. */
#ifndef WOLFMKA_RANDOM_POOL_SIZE
    #define WOLFMKA_RANDOM_POOL_SIZE 1U
#endif

/* Number of AES-CMAC contexts in the crypto layer's pool. Each
 * wm_Crypto_CmacInit hands out one; size it for the number of concurrent
 * CMAC users (one per participant covers the common single-threaded case, since
 * a participant's CMAC operations do not nest). Override at build time. */
#ifndef WOLFMKA_CMAC_POOL_SIZE
    #define WOLFMKA_CMAC_POOL_SIZE 1U
#endif

/* Label strings used by the various derivations (IEEE Std 802.1X-2010). */
#define MKA_LABEL_EAP_CAK "IEEE8021 EAP CAK"
#define MKA_LABEL_EAP_CKN "IEEE8021 EAP CKN"
#define MKA_LABEL_KEK     "IEEE8021 KEK"
#define MKA_LABEL_ICK     "IEEE8021 ICK"

/* Whether len is a valid MKA AES key length: 128-bit (16) or 256-bit (32).
 * Shared by the SAK/CAK key-length checks across the crypto and KaY layers. */
static MKA_INLINE bool mka_aes_key_len_valid(size_t len)
{
    return (len == 16U) || (len == 32U);
}

/**
 * The IEEE Std 802.1X-2010 KDF (6.2.1), AES-CMAC in counter mode.
 *
 *   for i in 1..n:
 *     K(i) = AES-CMAC(key, i || label || 0x00 || context || out_bits[BE16])
 *   output = leftmost out_len octets of K(1) || K(2) || ...
 *
 * This is the public KDF primitive with full argument validation. The library's
 * own CAK/CKN/KEK/ICK derivations use an internal fast path, so this is
 * provided for integrators that need the raw 802.1X KDF (e.g. to derive other
 * keys).
 *
 * @param[in]  cmac         CMAC workspace (wm_Crypto_CmacInit); required
 * (non-NULL).
 * @param[in]  key          Derivation key.
 * @param[in]  key_len      Key length in octets; must be 16 or 32.
 * @param[in]  label        NUL-terminated label string.
 * @param[in]  context      Optional context octets; may be NULL when
 *                          context_len 0.
 * @param[in]  context_len  Length of the context in octets.
 * @param[out] out          Buffer receiving the derived keying material.
 * @param[in]  out_len      Number of octets to derive (1 .. 255*16).
 * @return MKA_OK on success;
 *         MKA_ERR_BAD_ARG if cmac, key, label or out is NULL, key_len is not
 * 16/32, context is NULL with a non-zero context_len, out_len is 0 or over
 *         255*16, or the assembled input exceeds the internal buffer;
 *         MKA_ERR_CRYPTO if the underlying AES-CMAC fails.
 */
MkaStatus wm_Crypto_Kdf(MkaCmacCtx* cmac, const uint8_t* key, size_t key_len,
    const char* label, const uint8_t* context, size_t context_len, uint8_t* out,
    size_t out_len);

/* EAP-MSK key derivation is optional; compile it out with WOLFMKA_NO_EAP for a
 * pre-shared-key-only build. */
#ifndef WOLFMKA_NO_EAP

/**
 * Derive a CAK from an EAP MSK (IEEE Std 802.1X-2010, 9.3.2).
 *
 *   CAK = KDF(MSK, "IEEE8021 EAP CAK", lowerMAC || higherMAC, cak_len_bits)
 * mac1/mac2 are the two PAE MAC addresses in any order; they are concatenated
 * lower-address-first internally, per IEEE Std 802.1X-2010 9.3.2, so both peers
 * derive the same CAK.
 *
 * @param[in]  cmac     CMAC workspace (wm_Crypto_CmacInit); required
 * (non-NULL).
 * @param[in]  msk      The EAP Master Session Key.
 * @param[in]  msk_len  Length of the MSK in octets; must be >= cak_len.
 * @param[in]  mac1     One PAE MAC address (6 octets).
 * @param[in]  mac2     The other PAE MAC address (6 octets).
 * @param[out] cak      Buffer receiving the derived CAK.
 * @param[in]  cak_len  Desired CAK length; must be 16 or 32.
 * @return MKA_OK on success;
 *         MKA_ERR_BAD_ARG if cmac, msk, mac1, mac2 or cak is NULL, cak_len is
 * not 16 or 32, or msk_len < cak_len; MKA_ERR_CRYPTO if the underlying AES-CMAC
 * fails.
 */
MkaStatus wm_Crypto_DeriveCakFromMsk(MkaCmacCtx* cmac, const uint8_t* msk,
    size_t msk_len, const uint8_t mac1[MKA_MAC_LEN],
    const uint8_t mac2[MKA_MAC_LEN], uint8_t* cak, size_t cak_len);

/**
 * Derive a CKN from an EAP MSK (IEEE Std 802.1X-2010, 9.3.2).
 *
 *   CKN = KDF(MSK, "IEEE8021 EAP CKN",
 *             eap_session_id || lowerMAC || higherMAC, ckn_len_bits)
 * A 128-bit (16-octet) CKN is the common interoperable choice; pass
 * ckn_len = 16 unless the peer expects otherwise.
 *
 * @param[in]  cmac            CMAC workspace (wm_Crypto_CmacInit); required
 * (non-NULL).
 * @param[in]  msk             The EAP Master Session Key.
 * @param[in]  msk_len         Length of the MSK in octets; must be 16 or 32.
 * @param[in]  eap_session_id  EAP Session-Id; may be NULL only when sid_len is
 *                             0.
 * @param[in]  sid_len         Length of the EAP Session-Id in octets.
 * @param[in]  mac1            One PAE MAC address (6 octets).
 * @param[in]  mac2            The other PAE MAC address (6 octets).
 * @param[out] ckn             Buffer receiving the derived CKN.
 * @param[in]  ckn_len         Desired CKN length; 1 .. MKA_MAX_CKN_LEN.
 * @return MKA_OK on success;
 *         MKA_ERR_BAD_ARG if cmac, msk, mac1, mac2 or ckn is NULL,
 * eap_session_id is NULL with a non-zero sid_len, ckn_len is 0 or >
 * MKA_MAX_CKN_LEN, the context exceeds the KDF buffer, or msk_len is not 16 or
 * 32; MKA_ERR_CRYPTO if the underlying AES-CMAC fails.
 */
MkaStatus wm_Crypto_DeriveCknFromMsk(MkaCmacCtx* cmac, const uint8_t* msk,
    size_t msk_len, const uint8_t* eap_session_id, size_t sid_len,
    const uint8_t mac1[MKA_MAC_LEN], const uint8_t mac2[MKA_MAC_LEN],
    uint8_t* ckn, size_t ckn_len);

#endif /* WOLFMKA_NO_EAP */

/**
 * Derive KEK and ICK from a CAK/CKN pair (IEEE 802.1X-2010, 9.3.3).
 *
 *   KEK = KDF(CAK, "IEEE8021 KEK", CKN[0..15 padded], cak_len_bits)
 *   ICK = KDF(CAK, "IEEE8021 ICK", CKN[0..15 padded], cak_len_bits)
 * The context is the first 16 octets of the CKN, zero-padded if shorter.
 *
 * @param[in]  cmac CMAC workspace (wm_Crypto_CmacInit); required (non-NULL).
 * @param[in]  cak  The CAK and its CKN.
 * @param[out] keys Receives the derived KEK and ICK (and their lengths).
 * @return MKA_OK on success;
 *         MKA_ERR_BAD_ARG if cmac, cak or keys is NULL, cak->cak_len is not 16
 * or 32, or cak->ckn_len is 0 or > MKA_MAX_CKN_LEN; MKA_ERR_CRYPTO if the
 * underlying AES-CMAC fails.
 */
MkaStatus wm_Crypto_DeriveKeys(MkaCmacCtx* cmac, const MkaCakPair* cak,
    MkaDerivedKeys* keys);

/**
 * Generate a fresh SAK using the supplied RNG (9.8).
 *
 * IEEE Std 802.1X-2010, 9.8 allows a random SAK generated by the Key Server.
 *
 * @param[in]  rng      RNG from wm_Crypto_RandomInit; NULL seeds one for
 *                      this call.
 * @param[out] sak      Buffer receiving the SAK.
 * @param[in]  sak_len  Desired SAK length; must be 16 or 32.
 * @return MKA_OK on success;
 *         MKA_ERR_BAD_ARG if sak_len is not 16 or 32, or sak is NULL;
 *         MKA_ERR_CRYPTO if the wolfSSL RNG fails.
 */
MkaStatus wm_Crypto_GenerateSak(MkaRandom* rng, uint8_t* sak, size_t sak_len);

/**
 * Wrap a SAK with the KEK using AES Key Wrap, RFC 3394 (9.8.2).
 *
 * @param[in]     kek          The Key Encrypting Key.
 * @param[in]     kek_len      KEK length; must be 16 or 32.
 * @param[in]     sak          The SAK to wrap.
 * @param[in]     sak_len      SAK length; a multiple of 8 and >= 16.
 * @param[out]    wrapped      Buffer receiving the wrapped key.
 * @param[in,out] wrapped_len  In: capacity of wrapped; out: octets written
 *                             (sak_len+8).
 * @return MKA_OK on success;
 *         MKA_ERR_BAD_ARG if kek, sak, wrapped or wrapped_len is NULL, kek_len
 *         is not 16 or 32, or sak_len is not a multiple of 8 or is below 16;
 *         MKA_ERR_BUFFER if *wrapped_len is smaller than sak_len + 8;
 *         MKA_ERR_CRYPTO if the AES Key Wrap operation fails.
 */
MkaStatus wm_Crypto_WrapSak(const uint8_t* kek, size_t kek_len,
    const uint8_t* sak, size_t sak_len, uint8_t* wrapped, size_t* wrapped_len);

/**
 * Unwrap a SAK with the KEK (AES Key Unwrap, RFC 3394).
 *
 * @param[in]     kek          The Key Encrypting Key.
 * @param[in]     kek_len      KEK length; must be 16 or 32.
 * @param[in]     wrapped      The wrapped key.
 * @param[in]     wrapped_len  Wrapped length; a multiple of 8 and >= 24.
 * @param[out]    sak          Buffer receiving the recovered SAK.
 * @param[in,out] sak_len      In: capacity of sak; out: octets written
 *                             (wrapped_len-8).
 * @return MKA_OK on success;
 *         MKA_ERR_BAD_ARG if kek, wrapped, sak or sak_len is NULL, kek_len is
 *         not 16 or 32, or wrapped_len is below 24 or not a multiple of 8;
 *         MKA_ERR_BUFFER if *sak_len is smaller than wrapped_len - 8;
 *         MKA_ERR_CRYPTO if unwrap fails (e.g. the integrity check fails).
 */
MkaStatus wm_Crypto_UnwrapSak(const uint8_t* kek, size_t kek_len,
    const uint8_t* wrapped, size_t wrapped_len, uint8_t* sak, size_t* sak_len);

/**
 * Compute the MKPDU ICV: AES-CMAC(ICK, data) (9.4.1 / 11.11).
 *
 * `data` is the entire MKPDU up to and including the ICV Indicator header, but
 * excluding the ICV value itself.
 *
 * @param[in]  cmac      CMAC workspace (wm_Crypto_CmacInit); required
 * (non-NULL).
 * @param[in]  ick       The Integrity Check Key.
 * @param[in]  ick_len   ICK length; must be 16 or 32.
 * @param[in]  data      The data to authenticate.
 * @param[in]  data_len  Length of data in octets.
 * @param[out] icv       Output, MKA_DEFAULT_ICV_LEN octets.
 * @return MKA_OK on success;
 *         MKA_ERR_BAD_ARG if cmac, ick, data or icv is NULL, or ick_len is not
 * 16/32; MKA_ERR_CRYPTO if the underlying AES-CMAC fails.
 */
MkaStatus wm_Crypto_IcvCompute(MkaCmacCtx* cmac, const uint8_t* ick,
    size_t ick_len, const uint8_t* data, size_t data_len,
    uint8_t icv[MKA_DEFAULT_ICV_LEN]);

/**
 * Verify an MKPDU ICV in constant time.
 *
 * @param[in] cmac      CMAC workspace (wm_Crypto_CmacInit); required
 * (non-NULL).
 * @param[in] ick       The Integrity Check Key.
 * @param[in] ick_len   ICK length; must be 16 or 32.
 * @param[in] data      The authenticated data.
 * @param[in] data_len  Length of data in octets.
 * @param[in] icv       The received ICV to check, MKA_DEFAULT_ICV_LEN octets.
 * @return MKA_OK if the ICV matches;
 *         MKA_ERR_BAD_ARG if icv, ick or data is NULL, or ick_len is not 16/32;
 *         MKA_ERR_CRYPTO if the underlying AES-CMAC fails;
 *         MKA_ERR_ICV if the computed and received ICVs differ.
 */
MkaStatus wm_Crypto_IcvVerify(MkaCmacCtx* cmac, const uint8_t* ick,
    size_t ick_len, const uint8_t* data, size_t data_len,
    const uint8_t icv[MKA_DEFAULT_ICV_LEN]);

#ifdef WOLFMKA_ICV_L2_ADDR
    /* The L2 prefix is a fixed 14 octets: DA(6) || SA(6) || EAPOL EtherType(2).
     */
    #define MKA_ICV_L2_PREFIX_LEN 14U
/**
 * Compute/verify the MKPDU ICV over an L2 prefix (@p l2 = DA || SA || EAPOL
 * EtherType, MKA_ICV_L2_PREFIX_LEN octets) then @p data. @p l2_len must equal
 * MKA_ICV_L2_PREFIX_LEN. Matches wpa_supplicant's ICV input (IEEE Std
 * 802.1X-2010, 11.11.3). Same return codes as wm_Crypto_IcvCompute/Verify.
 */
MkaStatus wm_Crypto_IcvComputeL2(MkaCmacCtx* cmac, const uint8_t* ick,
    size_t ick_len, const uint8_t* l2, size_t l2_len, const uint8_t* data,
    size_t data_len, uint8_t icv[MKA_DEFAULT_ICV_LEN]);

MkaStatus wm_Crypto_IcvVerifyL2(MkaCmacCtx* cmac, const uint8_t* ick,
    size_t ick_len, const uint8_t* l2, size_t l2_len, const uint8_t* data,
    size_t data_len, const uint8_t icv[MKA_DEFAULT_ICV_LEN]);
#endif /* WOLFMKA_ICV_L2_ADDR */

/**
 * Acquire and seed one RNG object from the pool so that later random/SAK
 * generation reuses it instead of seeding a fresh RNG on every call (seeding is
 * the costly step).
 *
 * Returns a reference the caller passes to the random-consuming functions and
 * releases with wm_Crypto_RandomFree. The pool holds
 * WOLFMKA_RANDOM_POOL_SIZE objects; if none is free, or seeding fails, NULL is
 * returned. Single-threaded use per object.
 * @return a reference to a seeded RNG, or NULL on pool exhaustion or RNG
 *         initialisation failure.
 */
MkaRandom* wm_Crypto_RandomInit(void);

/**
 * Release an RNG object back to the pool (freeing the wolfSSL RNG). A no-op
 * when rng is NULL.
 * @param[in] rng  the object from wm_Crypto_RandomInit.
 */
void wm_Crypto_RandomFree(MkaRandom* rng);

/**
 * Acquire one AES-CMAC context from the pool.
 *
 * The returned workspace holds the wolfSSL Cmac object in wolfMKA-owned
 * storage, so passing it to the CMAC-consuming functions keeps that ~1 KB
 * object off the stack and out of any allocation - the property a
 * WOLFMKA_SMALL_STACK / WOLFMKA_NO_MALLOC build needs. The pool holds
 * WOLFMKA_CMAC_POOL_SIZE contexts; if none is free, NULL is returned.
 * Single-threaded use per object.
 * @return a reference to a CMAC context, or NULL on pool exhaustion.
 */
MkaCmacCtx* wm_Crypto_CmacInit(void);

/**
 * Release an AES-CMAC context back to the pool. A no-op when cmac is NULL.
 * @param[in] cmac  the object from wm_Crypto_CmacInit.
 */
void wm_Crypto_CmacFree(MkaCmacCtx* cmac);

/**
 * Fill a buffer with cryptographically strong random bytes.
 *
 * Used for Member Identifiers and Key Numbers. Uses the supplied pool RNG, or
 * seeds one for this call when rng is NULL.
 *
 * @param[in]  rng  RNG from wm_Crypto_RandomInit; NULL seeds one for this
 *                  call.
 * @param[out] buf  Destination buffer.
 * @param[in]  len  Number of random octets to generate; must be non-zero.
 * @return MKA_OK on success;
 *         MKA_ERR_BAD_ARG if buf is NULL or len is 0;
 *         MKA_ERR_CRYPTO if the wolfSSL RNG fails to initialise or generate.
 */
MkaStatus wm_Crypto_Random(MkaRandom* rng, uint8_t* buf, size_t len);

/**
 * Securely zeroize a buffer that held sensitive material.
 *
 * Wraps wolfSSL's wc_ForceZero, which the optimiser may not elide. Used to wipe
 * keys, SAKs and key-derivation scratch once they are no longer needed.
 * @param[out] mem  Buffer to clear (ignored if NULL).
 * @param[in]  len  Number of octets to clear.
 */
void wm_Crypto_ForceZero(void* mem, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* WOLFMKA_CRYPTO_H */
