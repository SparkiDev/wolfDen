/* test_crypto.c - validate the MKA crypto layer against published vectors.
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
 */

#include "test_util.h"
#include "wolfmka/mka_crypto.h"

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/cmac.h>

/* RFC 4493 - AES-CMAC test vectors (key 2b7e..., the AES-128 example key). */
static void test_rfc4493_cmac(void)
{
    const char* key_hex = "2b7e151628aed2a6abf7158809cf4f3c";
    const char* msg_hex = "6bc1bee22e409f96e93d7e117393172a"
                          "ae2d8a571e03ac9c9eb76fac45af8e51"
                          "30c81c46a35ce411e5fbc1191a0a52ef"
                          "f69f2445df4f9b17ad2b417be66c3710";
    struct {
        size_t mlen;
        const char* mac;
    } v[] = {
        {0, "bb1d6929e95937287fa37d129b756746"},
        {16, "070a16b46b4d4144f79bdd9dd04a287c"},
        {40, "dfa66747de9ae63030ca32611497c827"},
        {64, "51f0bebf7e3b9d92fc49741779363cfe"},
    };
    uint8_t key[16], msg[64], exp[16], mac[16];
    word32 macSz;
    size_t i;

    hexparse(key_hex, key, sizeof(key));
    hexparse(msg_hex, msg, sizeof(msg));

    printf("RFC 4493 AES-CMAC:\n");
    for (i = 0; i < sizeof(v) / sizeof(v[0]); i++) {
        hexparse(v[i].mac, exp, sizeof(exp));
        macSz = sizeof(mac);
        CHECK(wc_AesCmacGenerate(mac, &macSz, msg, (word32)v[i].mlen, key,
                  sizeof(key)) == 0,
            "cmac gen");
        CHECK_EQ_MEM(mac, exp, 16, "RFC4493 mac");

        /* Drive the same vector through the wolfMKA CMAC wrapper (the primitive
         * the KDF and ICV use) so the library's own path - not just wolfSSL -
         * is pinned to the RFC 4493 answer. The empty-message case is covered
         * above; IcvCompute is exercised over the non-empty messages. */
        if (v[i].mlen != 0) {
            uint8_t wmac[MKA_DEFAULT_ICV_LEN];
            CHECK(wm_Crypto_IcvCompute(g_cmac, key, sizeof(key), msg, v[i].mlen,
                      wmac) == MKA_OK,
                "wolfMKA CMAC ok");
            CHECK_EQ_MEM(wmac, exp, 16, "wolfMKA CMAC == RFC4493");
        }
    }
}

/* RFC 3394 - AES Key Wrap, 4.1: wrap 128 bits of data with a 128-bit KEK. */
static void test_rfc3394_keywrap(void)
{
    uint8_t kek[16], kdata[16], expw[24], wrapped[24], unwrapped[16];
    size_t wlen = sizeof(wrapped), ulen = sizeof(unwrapped);

    hexparse("000102030405060708090a0b0c0d0e0f", kek, sizeof(kek));
    hexparse("00112233445566778899aabbccddeeff", kdata, sizeof(kdata));
    hexparse("1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5", expw,
        sizeof(expw));

    printf("RFC 3394 AES Key Wrap:\n");
    CHECK(wm_Crypto_WrapSak(kek, sizeof(kek), kdata, sizeof(kdata), wrapped,
              &wlen) == MKA_OK,
        "wrap ok");
    CHECK(wlen == 24, "wrapped len 24");
    CHECK_EQ_MEM(wrapped, expw, 24, "RFC3394 wrapped");

    CHECK(wm_Crypto_UnwrapSak(kek, sizeof(kek), wrapped, wlen, unwrapped,
              &ulen) == MKA_OK,
        "unwrap ok");
    CHECK(ulen == 16, "unwrapped len 16");
    CHECK_EQ_MEM(unwrapped, kdata, 16, "RFC3394 roundtrip");
}

/* KDF structural / self-consistency checks (IEEE Std 802.1X-2010, 6.2.1) plus
 * KEK/ICK derivation from the CAK (9.3.3). */
static void test_kdf_and_keys(void)
{
    /* A 128-bit CAK and a CKN. */
    MkaCakPair cak;
    MkaDerivedKeys k1, k2;
    uint8_t out32a[32], out32b[32];

    printf("KDF / KEK / ICK derivation:\n");

    memset(&cak, 0, sizeof(cak));
    hexparse("0123456789abcdef0123456789abcdef", cak.cak, sizeof(cak.cak));
    cak.cak_len = 16;
    hexparse("746573745f636b6e", cak.ckn, sizeof(cak.ckn)); /* "test_ckn" */
    cak.ckn_len = 8;

    CHECK(wm_Crypto_DeriveKeys(g_cmac, &cak, &k1) == MKA_OK, "derive keys");
    CHECK(k1.kek_len == 16 && k1.ick_len == 16, "key lengths");
    /* KEK and ICK must differ (different labels). */
    CHECK(memcmp(k1.kek, k1.ick, 16) != 0, "KEK != ICK");

    /* Determinism: same inputs -> same outputs. */
    CHECK(wm_Crypto_DeriveKeys(g_cmac, &cak, &k2) == MKA_OK, "derive keys 2");
    CHECK_EQ_MEM(k1.kek, k2.kek, 16, "KEK deterministic");
    CHECK_EQ_MEM(k1.ick, k2.ick, 16, "ICK deterministic");

    /* A multi-block KDF output (>16 octets) must be deterministic, and its two
     * 16-octet halves must differ: each block folds in a distinct counter, so
     * block 1 != block 2. Verify both properties for a 32-octet request. */
    CHECK(wm_Crypto_Kdf(g_cmac, cak.cak, 16, MKA_LABEL_KEK, cak.ckn, 16, out32a,
              32) == MKA_OK,
        "kdf 32");
    CHECK(wm_Crypto_Kdf(g_cmac, cak.cak, 16, MKA_LABEL_KEK, cak.ckn, 16, out32b,
              32) == MKA_OK,
        "kdf 32 again");
    CHECK_EQ_MEM(out32a, out32b, 32, "kdf 32 deterministic");
    CHECK(memcmp(out32a, out32a + 16, 16) != 0, "kdf blocks differ");

    /* Empty-context KDF (context_len 0): the optional context segment is
     * absent, exercising the c1_len==0 path in mka_kdf_run. A valid SP 800-108
     * invocation in its own right, and the only driver of that path in a
     * PSK-only (WOLFMKA_NO_EAP) build. */
    CHECK(wm_Crypto_Kdf(g_cmac, cak.cak, 16, MKA_LABEL_KEK, NULL, 0, out32a,
              16) == MKA_OK,
        "kdf empty context");
    /* Same key and label, but the context segment differs (empty vs. the CKN
     * used for k1.kek): a collapsed / ignored context would make the two equal,
     * so the empty-context output must differ from the with-context KEK. */
    CHECK(memcmp(out32a, k1.kek, 16) != 0,
        "empty-context KDF differs from with-context KEK");

    /* Bad arguments. */
    CHECK(wm_Crypto_Kdf(g_cmac, cak.cak, 17, MKA_LABEL_KEK, cak.ckn, 16, out32a,
              16) == MKA_ERR_BAD_ARG,
        "kdf bad key len");
    CHECK(wm_Crypto_Kdf(g_cmac, cak.cak, 16, MKA_LABEL_KEK, cak.ckn, 16, out32a,
              0) == MKA_ERR_BAD_ARG,
        "kdf zero out");
}

/* SAK generation + wrap/unwrap roundtrip with a derived KEK (IEEE Std
 * 802.1X-2010, 9.8). */
static void test_sak_distribution(void)
{
    MkaCakPair cak;
    MkaDerivedKeys keys;
    uint8_t sak[16], wrapped[24], recovered[16];
    size_t wlen = sizeof(wrapped), rlen = sizeof(recovered);

    printf("SAK generation + distribution:\n");

    memset(&cak, 0, sizeof(cak));
    memset(cak.cak, 0xA5, 16);
    cak.cak_len = 16;
    memset(cak.ckn, 0x5A, 4);
    cak.ckn_len = 4;
    CHECK(wm_Crypto_DeriveKeys(g_cmac, &cak, &keys) == MKA_OK, "derive keys");

    CHECK(wm_Crypto_GenerateSak(NULL, sak, sizeof(sak)) == MKA_OK, "gen sak");
    CHECK(wm_Crypto_WrapSak(keys.kek, keys.kek_len, sak, sizeof(sak), wrapped,
              &wlen) == MKA_OK,
        "wrap sak");
    CHECK(wlen == 24, "wrapped sak len");
    CHECK(wm_Crypto_UnwrapSak(keys.kek, keys.kek_len, wrapped, wlen, recovered,
              &rlen) == MKA_OK,
        "unwrap sak");
    CHECK(rlen == 16, "recovered len");
    CHECK_EQ_MEM(sak, recovered, 16, "sak roundtrip");

    /* Wrong KEK must not recover the SAK (unwrap should fail integrity). */
    keys.kek[0] ^= 0xFF;
    rlen = sizeof(recovered);
    CHECK(wm_Crypto_UnwrapSak(keys.kek, keys.kek_len, wrapped, wlen, recovered,
              &rlen) == MKA_ERR_CRYPTO,
        "unwrap wrong kek fails the integrity check");
}

/* ICV compute / verify. */
static void test_icv(void)
{
    uint8_t ick[16], data[64], icv[16];

    printf("ICV compute / verify:\n");
    memset(ick, 0x11, sizeof(ick));
    memset(data, 0x22, sizeof(data));

    CHECK(wm_Crypto_IcvCompute(g_cmac, ick, sizeof(ick), data, sizeof(data),
              icv) == MKA_OK,
        "icv compute");
    CHECK(wm_Crypto_IcvVerify(g_cmac, ick, sizeof(ick), data, sizeof(data),
              icv) == MKA_OK,
        "icv verify ok");
    /* Tamper a byte. */
    data[0] ^= 0x01;
    CHECK(wm_Crypto_IcvVerify(g_cmac, ick, sizeof(ick), data, sizeof(data),
              icv) == MKA_ERR_ICV,
        "icv verify tamper");
}

/* EAP-MSK derivation, pinned to hostapd/wpa_supplicant-verified output (these
 * exact bytes are reproduced by hostapd's ieee802_1x_*_aes_cmac). CAK and CKN
 * are derived from the EAP MSK per IEEE Std 802.1X-2010, 9.3.2; also checks
 * MAC-order independence. */
#ifndef WOLFMKA_NO_EAP
static void test_eap_derivation(void)
{
    uint8_t msk[32];
    uint8_t mac1[6] = {0x02, 0, 0, 0, 0, 0x01},
            mac2[6] = {0x02, 0, 0, 0, 0, 0x02};
    uint8_t sid[4] = {0x11, 0x22, 0x33, 0x44};
    uint8_t cak16[16], cak32[32], ckn[16], swapped[16];
    uint8_t e_cak16[16], e_cak32[32], e_ckn[16];
    size_t i;

    printf("EAP-MSK CAK/CKN derivation (hostapd-pinned vectors):\n");
    for (i = 0; i < 32; i++)
        msk[i] = (uint8_t)i;

    hexparse("f7c54b9b518839f4453a7415c65d4be3", e_cak16, 16);
    hexparse("00a576209229b866b3d59d1e54ad8b9b5ace0c503dc214c391fc2c9b46d365"
             "7c",
        e_cak32, 32);
    hexparse("9c97b8ea80a9a9110cca65f4560bff96", e_ckn, 16);

    CHECK(wm_Crypto_DeriveCakFromMsk(g_cmac, msk, 16, mac1, mac2, cak16, 16) ==
              MKA_OK,
        "cak128");
    CHECK_EQ_MEM(cak16, e_cak16, 16, "CAK-128 vector");
    CHECK(wm_Crypto_DeriveCakFromMsk(g_cmac, msk, 32, mac1, mac2, cak32, 32) ==
              MKA_OK,
        "cak256");
    CHECK_EQ_MEM(cak32, e_cak32, 32, "CAK-256 vector");
    CHECK(wm_Crypto_DeriveCknFromMsk(g_cmac, msk, 16, sid, 4, mac1, mac2, ckn,
              16) == MKA_OK,
        "ckn");
    CHECK_EQ_MEM(ckn, e_ckn, 16, "CKN vector");

    /* Swapping the two MACs must not change the derived CAK
     * (mka_join_two_macs). */
    CHECK(wm_Crypto_DeriveCakFromMsk(g_cmac, msk, 16, mac2, mac1, swapped,
              16) == MKA_OK,
        "cak swap");
    CHECK_EQ_MEM(swapped, cak16, 16, "CAK MAC-order independent");

    /* CKN derivation with an empty EAP Session-Id: the first KDF context
     * segment has zero length, exercising the c1_len == 0 path. */
    CHECK(wm_Crypto_DeriveCknFromMsk(g_cmac, msk, 16, NULL, 0, mac1, mac2, ckn,
              16) == MKA_OK,
        "ckn with empty session-id");
}
#endif /* WOLFMKA_NO_EAP */

#define BAD MKA_ERR_BAD_ARG

/* wm_Crypto_Kdf: exercise every argument-validation branch. */
static void test_kdf_errors(void)
{
    uint8_t k16[16] = {0}, ctx[16] = {0}, out[16];
    char big[160];
    size_t i;

    printf("crypto error paths (kdf):\n");
    for (i = 0; i < sizeof big - 1U; i++) {
        big[i] = 'A';
    }
    big[sizeof big - 1U] = '\0';

    /* NULL key/label/out positions are covered once, in
     * test_crypto_invalid_params; here only the value/length error paths are
     * exercised. */
    CHECK(wm_Crypto_Kdf(g_cmac, k16, 24, "L", NULL, 0, out, 16) == BAD,
        "kdf key len 24");
    CHECK(wm_Crypto_Kdf(g_cmac, k16, 16, "L", NULL, 5, out, 16) == BAD,
        "kdf ctx null+len");
    CHECK(wm_Crypto_Kdf(g_cmac, k16, 16, "L", ctx, 16, out, 0) == BAD,
        "kdf out len 0");
    CHECK(wm_Crypto_Kdf(g_cmac, k16, 16, "L", ctx, 16, out, 16 * 256) == BAD,
        "kdf out big");
    CHECK(wm_Crypto_Kdf(g_cmac, k16, 16, big, NULL, 0, out, 16) == BAD,
        "kdf label too big");
}

/* mka_derive_*: every branch of the CAK/CKN/KEK/ICK derivations. */
static void test_derive_errors(void)
{
    MkaCakPair cak;
    MkaDerivedKeys dk;

    printf("crypto error paths (derive):\n");
#ifndef WOLFMKA_NO_EAP
    uint8_t msk[32] = {0}, m1[6] = {0}, m2[6] = {0}, out[32], sid[160] = {0};
    /* derive_cak_from_msk (NULL positions covered in
     * test_crypto_invalid_params) */
    CHECK(wm_Crypto_DeriveCakFromMsk(g_cmac, msk, 16, m1, m2, out, 20) == BAD,
        "cak len");
    CHECK(wm_Crypto_DeriveCakFromMsk(g_cmac, msk, 8, m1, m2, out, 16) == BAD,
        "cak<msk");
    /* derive_ckn_from_msk (msk-NULL covered in test_crypto_invalid_params) */
    CHECK(wm_Crypto_DeriveCknFromMsk(g_cmac, msk, 16, NULL, 4, m1, m2, out,
              16) == BAD,
        "ckn sid null+len");
    CHECK(wm_Crypto_DeriveCknFromMsk(g_cmac, msk, 16, sid, 4, m1, m2, out, 0) ==
              BAD,
        "ckn len 0");
    CHECK(wm_Crypto_DeriveCknFromMsk(g_cmac, msk, 16, sid, 4, m1, m2, out,
              33) == BAD,
        "ckn len 33");
    CHECK(wm_Crypto_DeriveCknFromMsk(g_cmac, msk, 16, sid, 120, m1, m2, out,
              16) == BAD,
        "ckn sid too long");
    CHECK(wm_Crypto_DeriveCknFromMsk(g_cmac, msk, 24, sid, 4, m1, m2, out,
              16) == BAD,
        "ckn msk len 24");
#endif /* WOLFMKA_NO_EAP */
    /* derive_keys */
    memset(&cak, 0, sizeof cak);
    cak.cak_len = 16;
    cak.ckn_len = 4;
    CHECK(wm_Crypto_DeriveKeys(g_cmac, NULL, &dk) == BAD, "keys null cak");
    CHECK(wm_Crypto_DeriveKeys(g_cmac, &cak, NULL) == BAD, "keys null out");
    cak.cak_len = 20;
    CHECK(wm_Crypto_DeriveKeys(g_cmac, &cak, &dk) == BAD, "keys cak len");
    cak.cak_len = 16;
    cak.ckn_len = 0;
    CHECK(wm_Crypto_DeriveKeys(g_cmac, &cak, &dk) == BAD, "keys ckn 0");
    cak.ckn_len = 33;
    CHECK(wm_Crypto_DeriveKeys(g_cmac, &cak, &dk) == BAD, "keys ckn 33");
}

/* SAK gen, wrap/unwrap, random and ICV argument validation. */
static void test_sak_icv_errors(void)
{
    uint8_t buf[64] = {0}, k16[16] = {0}, k32[32] = {0};
    size_t n;

    /* NULL positions for these functions are covered once in
     * test_crypto_invalid_params; this exercises only the length/buffer paths.
     */
    printf("crypto error paths (sak/icv):\n");
    CHECK(wm_Crypto_GenerateSak(NULL, buf, 20) == BAD, "sak len 20");
    CHECK(wm_Crypto_Random(NULL, buf, 0) == BAD, "random len 0");

    n = sizeof buf;
    CHECK(wm_Crypto_WrapSak(k16, 20, buf, 16, buf, &n) == BAD, "wrap kek len");
    CHECK(wm_Crypto_WrapSak(k16, 16, buf, 12, buf, &n) == BAD, "wrap sak<16");
    CHECK(wm_Crypto_WrapSak(k16, 16, buf, 17, buf, &n) == BAD, "wrap sak%8");
    n = 4;
    CHECK(wm_Crypto_WrapSak(k16, 16, buf, 16, buf, &n) == MKA_ERR_BUFFER,
        "wrap buf");

    n = sizeof buf;
    CHECK(wm_Crypto_UnwrapSak(k32, 20, buf, 24, buf, &n) == BAD,
        "unwrap kek len");
    CHECK(wm_Crypto_UnwrapSak(k32, 32, buf, 20, buf, &n) == BAD,
        "unwrap short");
    CHECK(wm_Crypto_UnwrapSak(k32, 32, buf, 25, buf, &n) == BAD, "unwrap %8");
    n = 4;
    CHECK(wm_Crypto_UnwrapSak(k32, 32, buf, 24, buf, &n) == MKA_ERR_BUFFER,
        "unw buf");

    CHECK(wm_Crypto_IcvCompute(g_cmac, k16, 24, buf, 8, buf) == BAD,
        "icv bad ick len");
    CHECK(wm_Crypto_IcvVerify(g_cmac, k16, 24, buf, 8, buf) == BAD,
        "icv verify bad len");
}

/* Exhaustive invalid-parameter testing: every pointer argument of every public
 * crypto function rejected as NULL at *each* position (not just the first), so
 * each operand of the compound NULL guards is exercised both ways; plus both
 * valid key/SAK lengths (16 and 32) so each length-check operand is too. */
static void test_crypto_invalid_params(void)
{
    uint8_t k16[16] = {0}, k32[32] = {0};
    uint8_t in32[32] = {0}, out[32], icv[16], wrapped[40];
    size_t n, wl;
    MkaCakPair cak;
    MkaDerivedKeys dk;

    printf("invalid parameters: every public crypto function:\n");

    /* wm_Crypto_Kdf */
    CHECK(wm_Crypto_Kdf(g_cmac, NULL, 16, "L", NULL, 0, out, 16) == BAD,
        "kdf key NULL");
    CHECK(wm_Crypto_Kdf(g_cmac, k16, 16, NULL, NULL, 0, out, 16) == BAD,
        "kdf label NULL");
    CHECK(wm_Crypto_Kdf(g_cmac, k16, 16, "L", NULL, 0, NULL, 16) == BAD,
        "kdf out NULL");

#ifndef WOLFMKA_NO_EAP
    uint8_t m1[6] = {0}, m2[6] = {0}, sid[8] = {0};
    /* wm_Crypto_DeriveCakFromMsk: each pointer position */
    CHECK(wm_Crypto_DeriveCakFromMsk(g_cmac, NULL, 16, m1, m2, out, 16) == BAD,
        "cak msk NULL");
    CHECK(wm_Crypto_DeriveCakFromMsk(g_cmac, k16, 16, NULL, m2, out, 16) == BAD,
        "cak mac1 NULL");
    CHECK(wm_Crypto_DeriveCakFromMsk(g_cmac, k16, 16, m1, NULL, out, 16) == BAD,
        "cak mac2 NULL");
    CHECK(wm_Crypto_DeriveCakFromMsk(g_cmac, k16, 16, m1, m2, NULL, 16) == BAD,
        "cak out NULL");

    /* wm_Crypto_DeriveCknFromMsk: each pointer position + valid msk len 32
     */
    CHECK(wm_Crypto_DeriveCknFromMsk(g_cmac, NULL, 16, sid, 4, m1, m2, out,
              16) == BAD,
        "ckn msk NULL");
    CHECK(wm_Crypto_DeriveCknFromMsk(g_cmac, k16, 16, sid, 4, NULL, m2, out,
              16) == BAD,
        "ckn mac1 NULL");
    CHECK(wm_Crypto_DeriveCknFromMsk(g_cmac, k16, 16, sid, 4, m1, NULL, out,
              16) == BAD,
        "ckn mac2 NULL");
    CHECK(wm_Crypto_DeriveCknFromMsk(g_cmac, k16, 16, sid, 4, m1, m2, NULL,
              16) == BAD,
        "ckn out NULL");
    CHECK(wm_Crypto_DeriveCknFromMsk(g_cmac, k32, 32, sid, 4, m1, m2, out,
              16) == MKA_OK,
        "ckn msk len 32 ok");
    /* CKN length at exactly MKA_MAX_CKN_LEN must be accepted - pins the
     * inclusive upper bound (`ckn_len <= MAX`, not `< MAX`); the len-0 and
     * len-33 rejections above only pin the other side. */
    CHECK(wm_Crypto_DeriveCknFromMsk(g_cmac, k32, 32, sid, 4, m1, m2, out,
              MKA_MAX_CKN_LEN) == MKA_OK,
        "ckn len == MKA_MAX_CKN_LEN accepted");
#endif /* WOLFMKA_NO_EAP */

    /* wm_Crypto_DeriveKeys: valid cak len 32 (complements the len-16
     * positive).
     */
    memset(&cak, 0, sizeof cak);
    cak.cak_len = 32;
    cak.ckn_len = 4;
    CHECK(wm_Crypto_DeriveKeys(g_cmac, &cak, &dk) == MKA_OK,
        "keys cak len 32 ok");

    /* wm_Crypto_GenerateSak / wm_Crypto_Random (NULL rng => per-call). */
    CHECK(wm_Crypto_GenerateSak(NULL, NULL, 16) == BAD, "gen sak NULL buf");
    CHECK(wm_Crypto_GenerateSak(NULL, out, 32) == MKA_OK, "gen sak len 32 ok");
    CHECK(wm_Crypto_Random(NULL, NULL, 4) == BAD, "random NULL");

    /* wm_Crypto_RandomInit / RandomFree: a pool of RNG objects. Acquire
     * until exhausted, use one, release all (plus a NULL no-op free). Works for
     * any WOLFMKA_RANDOM_POOL_SIZE. */
    {
        MkaRandom* rs[WOLFMKA_RANDOM_POOL_SIZE] = {0};
        MkaRandom* r;
        size_t got = 0U;
        size_t j;
        while ((r = wm_Crypto_RandomInit()) != NULL) {
            rs[got] = r;
            got++;
        }
        CHECK(got == WOLFMKA_RANDOM_POOL_SIZE, "pool fully acquired");
        CHECK(wm_Crypto_RandomInit() == NULL, "pool exhausted -> NULL");
        CHECK(wm_Crypto_Random(rs[0], out, 16) == MKA_OK, "random via pool");
        CHECK(wm_Crypto_GenerateSak(rs[0], out, 16) == MKA_OK,
            "gen sak via pool");
        for (j = 0U; j < got; j++) {
            wm_Crypto_RandomFree(rs[j]);
        }
        wm_Crypto_RandomFree(NULL);
    }

    /* wm_Crypto_CmacInit / CmacFree: the CMAC pool. main() holds the shared
     * workspace (g_cmac); with the default single-slot pool that leaves it
     * exhausted, so a further acquire returns NULL. A NULL free is a no-op.
     * (The success path and the workspace itself are exercised throughout the
     * suite via g_cmac.) */
    CHECK(wm_Crypto_CmacInit() == NULL, "cmac pool exhausted -> NULL");
    wm_Crypto_CmacFree(NULL);

    /* Each CMAC-consuming entry point rejects a NULL workspace. */
    CHECK(wm_Crypto_Kdf(NULL, k16, 16, "L", NULL, 0, out, 16) == BAD,
        "kdf NULL cmac");
#ifndef WOLFMKA_NO_EAP
    CHECK(wm_Crypto_DeriveCakFromMsk(NULL, k16, 16, m1, m2, out, 16) == BAD,
        "derive cak NULL cmac");
    CHECK(wm_Crypto_DeriveCknFromMsk(NULL, k16, 16, sid, 4, m1, m2, out, 16) ==
              BAD,
        "derive ckn NULL cmac");
#endif /* WOLFMKA_NO_EAP */
    CHECK(wm_Crypto_DeriveKeys(NULL, &cak, &dk) == BAD, "derive NULL cmac");
    CHECK(wm_Crypto_IcvCompute(NULL, k16, 16, in32, sizeof in32, out) == BAD,
        "icv compute NULL cmac");

    /* wm_Crypto_WrapSak: each pointer position + small-but-aligned SAK +
     * len 32.
     */
    wl = sizeof wrapped;
    CHECK(wm_Crypto_WrapSak(NULL, 16, in32, 16, wrapped, &wl) == BAD,
        "wrap kek NULL");
    CHECK(wm_Crypto_WrapSak(k16, 16, NULL, 16, wrapped, &wl) == BAD,
        "wrap sak NULL");
    CHECK(wm_Crypto_WrapSak(k16, 16, in32, 16, NULL, &wl) == BAD,
        "wrap out NULL");
    CHECK(wm_Crypto_WrapSak(k16, 16, in32, 16, wrapped, NULL) == BAD,
        "wrap wrapped_len NULL");
    CHECK(wm_Crypto_WrapSak(k16, 16, in32, 8, wrapped, &wl) == BAD,
        "wrap aligned SAK below 16");
    wl = sizeof wrapped;
    CHECK(wm_Crypto_WrapSak(k32, 32, in32, 32, wrapped, &wl) == MKA_OK,
        "wrap kek/sak len 32 ok");

    /* wm_Crypto_UnwrapSak: each pointer position + a valid round-trip. */
    n = sizeof out;
    CHECK(wm_Crypto_UnwrapSak(NULL, 32, wrapped, wl, out, &n) == BAD,
        "unwrap kek NULL");
    CHECK(wm_Crypto_UnwrapSak(k32, 32, NULL, wl, out, &n) == BAD,
        "unwrap wrapped NULL");
    CHECK(wm_Crypto_UnwrapSak(k32, 32, wrapped, wl, NULL, &n) == BAD,
        "unwrap sak NULL");
    CHECK(wm_Crypto_UnwrapSak(k32, 32, wrapped, wl, out, NULL) == BAD,
        "unwrap sak_len NULL");
    n = sizeof out;
    CHECK(wm_Crypto_UnwrapSak(k32, 32, wrapped, wl, out, &n) == MKA_OK,
        "unwrap round-trip ok");

    /* wm_Crypto_IcvCompute / wm_Crypto_IcvVerify: each pointer position +
     * ick len 32. */
    CHECK(wm_Crypto_IcvCompute(g_cmac, NULL, 16, in32, 8, icv) == BAD,
        "icv ick NULL");
    CHECK(wm_Crypto_IcvCompute(g_cmac, k16, 16, NULL, 8, icv) == BAD,
        "icv data NULL");
    CHECK(wm_Crypto_IcvCompute(g_cmac, k16, 16, in32, 8, NULL) == BAD,
        "icv out NULL");
    CHECK(wm_Crypto_IcvCompute(g_cmac, k32, 32, in32, 8, icv) == MKA_OK,
        "icv ick 32 ok");
    CHECK(wm_Crypto_IcvVerify(g_cmac, NULL, 16, in32, 8, icv) == BAD,
        "verify ick NULL");
    CHECK(wm_Crypto_IcvVerify(g_cmac, k16, 16, NULL, 8, icv) == BAD,
        "verify data NULL");
    CHECK(wm_Crypto_IcvVerify(g_cmac, k16, 16, in32, 8, NULL) == BAD,
        "verify icv NULL");
}

/* wm_Crypto_ForceZero wipes transient key material (generated/unwrapped
 * SAKs, KDF scratch), so it must clear exactly `len` octets - under-wiping
 * leaks a secret, over-wiping corrupts adjacent state - and tolerate a zero
 * length. */
static void test_force_zero(void)
{
    uint8_t b[32];
    uint8_t zero[16] = {0};
    uint8_t a5[16];

    printf("crypto ForceZero (secret wipe):\n");
    memset(b, 0xA5, sizeof b);
    memset(a5, 0xA5, sizeof a5);
    wm_Crypto_ForceZero(b, 16);
    CHECK_EQ_MEM(b, zero, 16, "first 16 octets wiped to zero");
    CHECK_EQ_MEM(b + 16, a5, 16, "octets past len left untouched");
    /* A zero length must be a no-op, not a crash or an over-write. */
    wm_Crypto_ForceZero(b + 16, 0);
    CHECK_EQ_MEM(b + 16, a5, 16, "len 0 wipes nothing");
}

void run_crypto_tests(void)
{
    printf("== crypto ==\n");
    test_rfc4493_cmac();
    test_rfc3394_keywrap();
    test_kdf_and_keys();
    test_sak_distribution();
    test_icv();
#ifndef WOLFMKA_NO_EAP
    test_eap_derivation();
#endif
    test_kdf_errors();
    test_derive_errors();
    test_sak_icv_errors();
    test_crypto_invalid_params();
    test_force_zero();
}
