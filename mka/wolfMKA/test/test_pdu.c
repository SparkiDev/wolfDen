/* test_pdu.c - MKPDU encode/decode roundtrip and ICV behaviour.
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
#include "wolfmka/mka_pdu.h"
#include "wolfmka/mka_crypto.h"

#define BAD MKA_ERR_BAD_ARG

/* Populate a Basic Parameter Set with well-formed, fixed test values shared by
 * the encode/decode cases below. The SCI, MI and CKN bytes are arbitrary but
 * fixed so a failing CHECK_EQ_MEM prints a stable, recognisable pattern. */
static void fill_basic(MkaBasicParamSet* b)
{
    static const uint8_t sci[8] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x00,
        0x01};
    static const uint8_t mi[12] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    memset(b, 0, sizeof(*b));
    b->version = 1;
    b->priority = 16;
    b->key_server = 1;
    b->macsec_desired = 1;
    b->macsec_capability = MKA_CAP_INTEGRITY_CONF_OFFSET;
    memcpy(b->sci, sci, 8);
    memcpy(b->mi, mi, 12);
    b->mn = 42;
    b->algo_agility = MKA_ALGO_AGILITY_DEFAULT;
    memcpy(b->ckn, "my-ckn", 6);
    b->ckn_len = 6;
}

/* Encode/decode round-trip of an MKPDU carrying only the Basic Parameter Set
 * (IEEE Std 802.1X-2010, 11.11.1). */
static void test_roundtrip_basic_only(void)
{
    uint8_t ick[16];
    uint8_t buf[256];
    size_t out_len = sizeof(buf);
    MkaPdu in, out;
    MkaStatus rc;

    printf("MKPDU encode/decode (basic only):\n");
    memset(ick, 0x33, sizeof(ick));
    memset(&in, 0, sizeof(in));
    fill_basic(&in.basic);

    rc = wm_Pdu_Encode(g_cmac, &in, ick, sizeof(ick), buf, sizeof(buf),
        &out_len);
    CHECK(rc == MKA_OK, "encode ok");
    /* EAPOL header sanity. */
    CHECK(buf[0] == EAPOL_VERSION_2010, "eapol version");
    CHECK(buf[1] == EAPOL_TYPE_MKA, "eapol type");

    rc = wm_Pdu_Decode(g_cmac, buf, out_len, ick, sizeof(ick), &out);
    CHECK(rc == MKA_OK, "decode ok");
    CHECK(out.basic.version == 1, "version");
    CHECK(out.basic.priority == 16, "priority");
    CHECK(out.basic.key_server == 1, "key_server");
    CHECK(out.basic.macsec_desired == 1, "macsec_desired");
    CHECK(out.basic.macsec_capability == MKA_CAP_INTEGRITY_CONF_OFFSET, "cap");
    CHECK_EQ_MEM(out.basic.sci, in.basic.sci, 8, "sci");
    CHECK_EQ_MEM(out.basic.mi, in.basic.mi, 12, "mi");
    CHECK(out.basic.mn == 42, "mn");
    CHECK(out.basic.algo_agility == MKA_ALGO_AGILITY_DEFAULT, "algo");
    CHECK(out.basic.ckn_len == 6, "ckn_len");
    CHECK_EQ_MEM(out.basic.ckn, in.basic.ckn, 6, "ckn");
}

/* Encode/decode round-trip of a full MKPDU: the Basic set plus Live/Potential
 * Peer Lists, MACsec SAK Use (IEEE Std 802.1X-2010, 11.11.4) and Distributed
 * SAK (11.11.5). */
static void test_roundtrip_full(void)
{
    uint8_t ick[32];
    uint8_t buf[512];
    size_t out_len = sizeof(buf);
    MkaPdu in, out;
    MkaStatus rc;

    printf("MKPDU encode/decode (full):\n");
    memset(ick, 0x77, sizeof(ick));
    memset(&in, 0, sizeof(in));
    fill_basic(&in.basic);

    /* Live + potential peers. */
    in.live_peers.present = 1;
    in.live_peers.count = 2;
    memset(in.live_peers.peers[0].mi, 0xA1, 12);
    in.live_peers.peers[0].mn = 7;
    memset(in.live_peers.peers[1].mi, 0xB2, 12);
    in.live_peers.peers[1].mn = 9;

    in.potential_peers.present = 1;
    in.potential_peers.count = 1;
    memset(in.potential_peers.peers[0].mi, 0xC3, 12);
    in.potential_peers.peers[0].mn = 3;

    /* SAK use. */
    in.sak_use.present = 1;
    in.sak_use.latest_an = 1;
    in.sak_use.key_flags = MKA_SAK_USE_LATEST_TX | MKA_SAK_USE_LATEST_RX;
    memset(in.sak_use.latest_ks_mi, 0xD4, 12);
    in.sak_use.latest_kn = 5;
    in.sak_use.latest_lpn = 1000;

    /* Distributed SAK: default cipher suite, 24-octet wrap. */
    in.dist_sak.present = 1;
    in.dist_sak.distributed_an = 1;
    in.dist_sak.confidentiality_offset = MKA_CONF_OFFSET_30;
    in.dist_sak.kn = 5;
    in.dist_sak.cipher_suite = 0;
    memset(in.dist_sak.wrapped_sak, 0xEE, 24);
    in.dist_sak.wrapped_len = 24;

    rc = wm_Pdu_Encode(g_cmac, &in, ick, sizeof(ick), buf, sizeof(buf),
        &out_len);
    CHECK(rc == MKA_OK, "encode ok");

    rc = wm_Pdu_Decode(g_cmac, buf, out_len, ick, sizeof(ick), &out);
    CHECK(rc == MKA_OK, "decode ok");

    CHECK(out.live_peers.present, "live peers present");
    CHECK(out.live_peers.count == 2, "live peers count == 2");
    CHECK_EQ_MEM(out.live_peers.peers[0].mi, in.live_peers.peers[0].mi, 12,
        "live mi0");
    CHECK(out.live_peers.peers[0].mn == 7, "live mn0");
    CHECK(out.live_peers.peers[1].mn == 9, "live mn1");

    CHECK(out.potential_peers.present, "potential peers present");
    CHECK(out.potential_peers.count == 1, "potential peers count == 1");
    CHECK(out.potential_peers.peers[0].mn == 3, "pot mn0");

    CHECK(out.sak_use.present, "sak_use present");
    CHECK(out.sak_use.latest_an == 1, "latest_an");
    CHECK(MKA_SAK_USE_IS_LATEST_TX(&out.sak_use), "latest tx flag set");
    CHECK(MKA_SAK_USE_IS_LATEST_RX(&out.sak_use), "latest rx flag set");
    CHECK(out.sak_use.latest_kn == 5, "latest_kn");
    CHECK(out.sak_use.latest_lpn == 1000, "latest_lpn");
    CHECK_EQ_MEM(out.sak_use.latest_ks_mi, in.sak_use.latest_ks_mi, 12,
        "ks_mi");

    CHECK(out.dist_sak.present, "dist_sak present");
    CHECK(out.dist_sak.distributed_an == 1, "dist an");
    CHECK(out.dist_sak.confidentiality_offset == MKA_CONF_OFFSET_30,
        "dist conf offset");
    CHECK(out.dist_sak.kn == 5, "dist kn");
    CHECK(out.dist_sak.wrapped_len == 24, "wrap len");
    CHECK_EQ_MEM(out.dist_sak.wrapped_sak, in.dist_sak.wrapped_sak, 24,
        "wrap data");
}

/* Distributed SAK carrying an explicit cipher suite and a 256-bit wrapped key
 * (IEEE Std 802.1X-2010, 11.11.5). */
static void test_dist_sak_explicit_cs(void)
{
    uint8_t ick[16], buf[512];
    size_t out_len = sizeof(buf);
    MkaPdu in, out;

    printf("MKPDU dist SAK (explicit cipher suite, 256-bit):\n");
    memset(ick, 0x12, sizeof(ick));
    memset(&in, 0, sizeof(in));
    fill_basic(&in.basic);
    in.dist_sak.present = 1;
    in.dist_sak.kn = 11;
    in.dist_sak.cipher_suite = MKA_CIPHER_GCM_AES_XPN_256; /* 256-bit SAK */
    memset(in.dist_sak.wrapped_sak, 0x5C, 40);
    in.dist_sak.wrapped_len = 40;

    CHECK(wm_Pdu_Encode(g_cmac, &in, ick, sizeof(ick), buf, sizeof(buf),
              &out_len) == MKA_OK,
        "encode ok");
    CHECK(wm_Pdu_Decode(g_cmac, buf, out_len, ick, sizeof(ick), &out) == MKA_OK,
        "decode ok");
    CHECK(out.dist_sak.cipher_suite == in.dist_sak.cipher_suite,
        "cipher suite");
    CHECK(out.dist_sak.kn == 11, "dist kn (4-octet big-endian)");
    CHECK(out.dist_sak.wrapped_len == 40, "wrap len 40");
    CHECK_EQ_MEM(out.dist_sak.wrapped_sak, in.dist_sak.wrapped_sak, 40,
        "wrap data");
}

static void test_icv_tamper(void)
{
    uint8_t ick[16], buf[256];
    size_t out_len = sizeof(buf);
    MkaPdu in, out;

    printf("MKPDU ICV tamper / wrong key:\n");
    memset(ick, 0x44, sizeof(ick));
    memset(&in, 0, sizeof(in));
    fill_basic(&in.basic);
    CHECK(wm_Pdu_Encode(g_cmac, &in, ick, sizeof(ick), buf, sizeof(buf),
              &out_len) == MKA_OK,
        "encode ok");

    /* Positive control: the pristine frame decodes cleanly, so the two failures
     * below are caused by the tamper / wrong key, not a malformed encode that
     * would fail the ICV unconditionally. */
    CHECK(wm_Pdu_Decode(g_cmac, buf, out_len, ick, sizeof(ick), &out) == MKA_OK,
        "pristine frame decodes");

    /* Flip a byte in the body -> ICV must fail. */
    buf[8] ^= 0x01;
    CHECK(wm_Pdu_Decode(g_cmac, buf, out_len, ick, sizeof(ick), &out) ==
              MKA_ERR_ICV,
        "tamper detected");
    buf[8] ^= 0x01;

    /* Wrong ICK -> ICV must fail. */
    ick[0] ^= 0xFF;
    CHECK(wm_Pdu_Decode(g_cmac, buf, out_len, ick, sizeof(ick), &out) ==
              MKA_ERR_ICV,
        "wrong ick detected");
}

/* Golden frame: encode a fixed PDU (Basic set + Distributed SAK) and compare
 * the on-the-wire bytes - up to the ICV - against a hand-derived expected
 * layout. A roundtrip (encode->decode) test cannot catch a *shared*
 * encode/decode layout bug (e.g. both sides swapping fields or mis-ordering a
 * multi-octet value); this pins the positive wire format independently of the
 * decoder. The 16-octet ICV trailer is an AES-CMAC (covered by the ICV KATs)
 * and is not asserted here. */
static void test_pdu_golden_frame(void)
{
    MkaPdu in;
    uint8_t buf[160];
    size_t n = sizeof buf;
    uint8_t ick[16];
    static const uint8_t sci[8] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0x77};
    static const uint8_t mi[12] = {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6,
        0xA7, 0xA8, 0xA9, 0xAA, 0xAB};
    static const uint8_t ckn[4] = {0xCC, 0xDD, 0xEE, 0xFF};
    static const uint8_t wrapped[24] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21,
        0x22, 0x23, 0x24, 0x25, 0x26, 0x27};
    /* EAPOL(4) + Basic(4 hdr + 32 body) + Dist SAK(4 hdr + 28 body) +
     * ICV-Indicator(4) = 76 octets before the 16-octet ICV. */
    static const uint8_t want[76] = {0x03, 0x05, 0x00,
        0x58, /* EAPOL: ver 3, type 5, body=88   */
        0x01, /* MKA version                     */
        0x10, /* Key Server priority = 16        */
        0xC0, /* KS=1 MD=1 cap=0 bodylen[11:8]=0 */
        0x20, /* Basic body length[7:0] = 32     */
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, /* SCI      */
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB,
        0x01, 0x02, 0x03, 0x04, /* Message Number (big-endian)     */
        0x00, 0x80, 0xC2, 0x01, /* Algorithm Agility (default)     */
        0xCC, 0xDD, 0xEE, 0xFF, /* CAK Name                        */
        0x04,                   /* Distributed SAK type            */
        0x40,                   /* dist AN=1, conf offset=0        */
        0x00, 0x1C,             /* Dist SAK body length = 28       */
        0x00, 0x00, 0x00, 0x07, /* Key Number (big-endian)         */
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        0x17, /* AES-wrapped SAK ... */
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23,
        0x24, 0x25, 0x26, 0x27, 0xFF, 0x00, 0x00,
        0x10}; /* ICV Indicator: type 255, len 16 */

    printf("golden frame: encoded bytes match the expected wire layout:\n");
    memset(ick, 0x5A, sizeof ick);
    memset(&in, 0, sizeof in);
    in.basic.version = 1;
    in.basic.priority = 16;
    in.basic.key_server = 1;
    in.basic.macsec_desired = 1;
    in.basic.macsec_capability = 0;
    memcpy(in.basic.sci, sci, 8);
    memcpy(in.basic.mi, mi, 12);
    in.basic.mn = 0x01020304U;
    in.basic.algo_agility = MKA_ALGO_AGILITY_DEFAULT;
    memcpy(in.basic.ckn, ckn, 4);
    in.basic.ckn_len = 4;
    in.dist_sak.present = 1;
    in.dist_sak.distributed_an = 1;
    in.dist_sak.confidentiality_offset = 0;
    in.dist_sak.kn = 0x00000007U;
    in.dist_sak.cipher_suite = 0U; /* default GCM-AES-128, no explicit suite */
    memcpy(in.dist_sak.wrapped_sak, wrapped, sizeof wrapped);
    in.dist_sak.wrapped_len = sizeof wrapped;

    CHECK(wm_Pdu_Encode(g_cmac, &in, ick, sizeof ick, buf, sizeof buf, &n) ==
              MKA_OK,
        "encode golden frame");
    CHECK(n == sizeof(want) + MKA_DEFAULT_ICV_LEN, "golden frame length");
    CHECK_EQ_MEM(buf, want, sizeof want, "golden frame wire bytes");
}

static void test_peek(void)
{
    uint8_t ick[16], buf[256];
    size_t out_len = sizeof(buf);
    MkaPdu in;
    MkaBasicParamSet basic;

    printf("MKPDU peek basic (no ICV check):\n");
    memset(ick, 0x44, sizeof(ick));
    memset(&in, 0, sizeof(in));
    fill_basic(&in.basic);
    CHECK(wm_Pdu_Encode(g_cmac, &in, ick, sizeof(ick), buf, sizeof(buf),
              &out_len) == MKA_OK,
        "peek encode ok");

    CHECK(wm_Pdu_PeekBasic(buf, out_len, &basic) == MKA_OK, "peek ok");
    CHECK(basic.ckn_len == 6, "peek ckn_len");
    CHECK_EQ_MEM(basic.ckn, "my-ckn", 6, "peek ckn");
    CHECK_EQ_MEM(basic.mi, in.basic.mi, 12, "peek mi");
}

/* Recompute the trailing ICV after surgically corrupting a frame, so the
 * decoder passes ICV verification and reaches the parameter-set parser. */
static void reseal(uint8_t* f, size_t len, const uint8_t* ick);

/* An MKPDU whose Algorithm Agility is not the supported default (0x0080C201)
 * must be ignored, even when its ICV is otherwise valid. The field is part of
 * the Basic Parameter Set (IEEE Std 802.1X-2010, 11.11.1) and sits at frame
 * offset 32 (EAPOL 4 + basic hdr 4 + SCI 8 + MI 12 + MN 4). */
static void test_pdu_algo_agility(void)
{
    uint8_t ick[16], buf[256];
    size_t out_len = sizeof(buf);
    MkaPdu in, out;
    MkaBasicParamSet basic;

    printf("MKPDU unsupported Algorithm Agility rejected:\n");
    memset(ick, 0x66, sizeof(ick));
    memset(&in, 0, sizeof(in));
    fill_basic(&in.basic);
    CHECK(wm_Pdu_Encode(g_cmac, &in, ick, sizeof(ick), buf, sizeof(buf),
              &out_len) == MKA_OK,
        "encode ok");
    /* Sanity: it decodes before corruption. */
    CHECK(wm_Pdu_Decode(g_cmac, buf, out_len, ick, sizeof(ick), &out) == MKA_OK,
        "default algo decodes");

    /* Flip the top octet of algo_agility, then reseal so the ICV still passes;
     * decode and peek must both reject on the algorithm-agility check alone. */
    buf[32] ^= 0xFFU;
    reseal(buf, out_len, ick);
    CHECK(wm_Pdu_Decode(g_cmac, buf, out_len, ick, sizeof(ick), &out) ==
              MKA_ERR_PARSE,
        "non-default algo agility rejected on decode");
    CHECK(wm_Pdu_PeekBasic(buf, out_len, &basic) == MKA_ERR_PARSE,
        "non-default algo agility rejected on peek");
}

/* Two decode edge cases:
 *   1. A Distributed SAK set that is present but carries no key (MACsec not yet
 *      in use) round-trips with wrapped_len == 0.
 *   2. An unknown parameter set (type 9, absent from the decoder's switch)
 *      wedged between the Basic set and the ICV Indicator is silently skipped
 *      (mka_decode_one's default arm) - the decode still succeeds, the Basic
 *      set past it still parses, and because the ICV covers the whole frame the
 *      unknown set is still integrity-protected. */
static void test_pdu_edge_cases(void)
{
    uint8_t ick[16], buf[256], frm[256], icv[16];
    size_t out_len = sizeof(buf);
    size_t basic_end, pos, body;
    MkaPdu in, out;

    printf("MKPDU edge cases (plain dist-SAK, unknown set skip):\n");
    memset(ick, 0x55, sizeof(ick));
    memset(&in, 0, sizeof(in));
    fill_basic(&in.basic);

    /* Distributed SAK present but carrying no key (MACsec not yet in use). */
    in.dist_sak.present = 1;
    in.dist_sak.wrapped_len = 0;
    CHECK(wm_Pdu_Encode(g_cmac, &in, ick, sizeof(ick), buf, sizeof(buf),
              &out_len) == MKA_OK,
        "encode plain dist-sak");
    CHECK(wm_Pdu_Decode(g_cmac, buf, out_len, ick, sizeof(ick), &out) == MKA_OK,
        "decode");
    CHECK(out.dist_sak.present, "plain dist-sak present");
    CHECK(out.dist_sak.wrapped_len == 0, "plain dist-sak carries no key");

    /* Hand-build a frame with an unknown set spliced in. Start from a freshly
     * encoded basic-only frame - layout [EAPOL:4][Basic][ICV-Ind:4][ICV:16] -
     * so the EAPOL header and Basic set are well-formed, then copy the Basic
     * set, append the unknown set and a fresh ICV Indicator, and re-sign the
     * result exactly as wm_Pdu_Encode does. */
    memset(&in, 0, sizeof(in));
    fill_basic(&in.basic);
    out_len = sizeof(buf);
    CHECK(wm_Pdu_Encode(g_cmac, &in, ick, sizeof(ick), buf, sizeof(buf),
              &out_len) == MKA_OK,
        "encode basic for splice");

    basic_end = out_len - (MKA_PARAM_HDR_LEN + MKA_DEFAULT_ICV_LEN);
    memcpy(frm, buf, basic_end);
    pos = basic_end;

    /* Unknown parameter set: type 9, 4-octet zero body (already 4-aligned). */
    frm[pos++] = 9U;
    frm[pos++] = 0U;
    frm[pos++] = 0U;
    frm[pos++] = 4U; /* body length */
    memset(&frm[pos], 0, 4);
    pos += 4U;

    /* ICV Indicator parameter set: type 255, body length = ICV length. */
    frm[pos++] = (uint8_t)MKA_PS_ICV_INDICATOR;
    frm[pos++] = 0U;
    frm[pos++] = 0U;
    frm[pos++] = (uint8_t)MKA_DEFAULT_ICV_LEN;

    /* Rewrite the EAPOL body-length field, then sign the spliced frame. */
    body = (pos + MKA_DEFAULT_ICV_LEN) - EAPOL_HDR_LEN;
    frm[2] = (uint8_t)(body >> 8);
    frm[3] = (uint8_t)(body & 0xFFU);
    test_seal_icv(g_cmac, ick, sizeof(ick), frm, pos);
    memcpy(icv, &frm[pos], MKA_DEFAULT_ICV_LEN);
    out_len = pos + MKA_DEFAULT_ICV_LEN;

    /* The unknown set is skipped: decode succeeds and the Basic set still
     * parses, proving the walk advanced past it by its declared length. */
    memset(&out, 0, sizeof(out));
    CHECK(wm_Pdu_Decode(g_cmac, frm, out_len, ick, sizeof(ick), &out) == MKA_OK,
        "unknown set skipped on decode");
    CHECK(out.basic.mn == 42 && out.basic.ckn_len == 6,
        "basic set still decoded past unknown set");

    /* The ICV covers the unknown set: mutating one body octet without
     * re-signing must be caught as an integrity failure. */
    frm[basic_end + MKA_PARAM_HDR_LEN] ^= 0x01;
    CHECK(wm_Pdu_Decode(g_cmac, frm, out_len, ick, sizeof(ick), &out) ==
              MKA_ERR_ICV,
        "tampered unknown set fails ICV");
}

/* Recompute the trailing ICV after surgically corrupting a frame, so the
 * decoder passes ICV verification and reaches the parameter-set parser. */
/* Recompute a frame's ICV in place after the test has altered its body, so the
 * decoder rejects on the field under test rather than on the seal. It must seal
 * the same input the library verifies: with WOLFMKA_ICV_L2_ADDR that includes
 * the L2 prefix the PDU layer derives from the frame (DA || SA || EtherType,
 * the SA taken from the SCI in the Basic Parameter Set). */
static void reseal(uint8_t* f, size_t len, const uint8_t* ick)
{
    test_seal_icv(g_cmac, ick, 16, f, len - 16U);
}

/* Targeted malformed data exercising each parse-error branch of
 * wm_Pdu_Decode and the decode_* helpers. The basic set is 40 octets (CKN
 * "my-ckn"), so the next parameter set begins at frame offset 44 and its length
 * byte at 47. */
static void test_pdu_decode_negative(void)
{
    uint8_t ick[16], buf[256];
    size_t out_len;
    MkaPdu in, out;

    printf("MKPDU decode negative (targeted parse failures):\n");
    memset(ick, 0x5A, sizeof ick);

    /* Basic Parameter Set: body length below the fixed minimum (28). */
    memset(&in, 0, sizeof in);
    fill_basic(&in.basic);
    out_len = sizeof buf;
    wm_Pdu_Encode(g_cmac, &in, ick, 16, buf, sizeof buf, &out_len);
    buf[7] = 10;
    reseal(buf, out_len, ick);
    CHECK(wm_Pdu_Decode(g_cmac, buf, out_len, ick, 16, &out) == MKA_ERR_PARSE,
        "basic body too small");

    /* Basic Parameter Set: total length overruns the frame (total > avail). */
    out_len = sizeof buf;
    wm_Pdu_Encode(g_cmac, &in, ick, 16, buf, sizeof buf, &out_len);
    buf[6] = (uint8_t)(buf[6] & 0xF0);
    buf[7] = 60;
    reseal(buf, out_len, ick);
    CHECK(wm_Pdu_Decode(g_cmac, buf, out_len, ick, 16, &out) == MKA_ERR_PARSE,
        "basic length over frame");

    /* Basic Parameter Set: implied CKN length exceeds the 32-octet maximum. */
    out_len = sizeof buf;
    wm_Pdu_Encode(g_cmac, &in, ick, 16, buf, sizeof buf, &out_len);
    buf[6] = (uint8_t)((buf[6] & 0xF0) | 0x0F);
    buf[7] = 0xFF;
    reseal(buf, out_len, ick);
    CHECK(wm_Pdu_Decode(g_cmac, buf, out_len, ick, 16, &out) == MKA_ERR_PARSE,
        "basic ckn too long");

    /* Live Peer List: body length not a multiple of 16. */
    memset(&in, 0, sizeof in);
    fill_basic(&in.basic);
    in.live_peers.present = 1;
    in.live_peers.count = 1;
    memset(in.live_peers.peers[0].mi, 0xA1, 12);
    out_len = sizeof buf;
    wm_Pdu_Encode(g_cmac, &in, ick, 16, buf, sizeof buf, &out_len);
    buf[47] = 8;
    reseal(buf, out_len, ick);
    CHECK(wm_Pdu_Decode(g_cmac, buf, out_len, ick, 16, &out) == MKA_ERR_PARSE,
        "peer list bad length");

    /* MACsec SAK Use: body length neither 0 nor 40. */
    memset(&in, 0, sizeof in);
    fill_basic(&in.basic);
    in.sak_use.present = 1;
    in.sak_use.key_flags = MKA_SAK_USE_LATEST_TX;
    out_len = sizeof buf;
    wm_Pdu_Encode(g_cmac, &in, ick, 16, buf, sizeof buf, &out_len);
    buf[47] = 20;
    reseal(buf, out_len, ick);
    CHECK(wm_Pdu_Decode(g_cmac, buf, out_len, ick, 16, &out) == MKA_ERR_PARSE,
        "sak use bad length");

    /* Distributed SAK: body shorter than KN + minimum wrap (28). */
    memset(&in, 0, sizeof in);
    fill_basic(&in.basic);
    in.dist_sak.present = 1;
    in.dist_sak.kn = 1;
    memset(in.dist_sak.wrapped_sak, 0xEE, 24);
    in.dist_sak.wrapped_len = 24;
    out_len = sizeof buf;
    wm_Pdu_Encode(g_cmac, &in, ick, 16, buf, sizeof buf, &out_len);
    buf[47] = 20;
    reseal(buf, out_len, ick);
    CHECK(wm_Pdu_Decode(g_cmac, buf, out_len, ick, 16, &out) == MKA_ERR_PARSE,
        "dist sak too short");

    /* Distributed SAK: wrap length not a multiple of 8. */
    out_len = sizeof buf;
    wm_Pdu_Encode(g_cmac, &in, ick, 16, buf, sizeof buf, &out_len);
    buf[47] = 29;
    reseal(buf, out_len, ick);
    CHECK(wm_Pdu_Decode(g_cmac, buf, out_len, ick, 16, &out) == MKA_ERR_PARSE,
        "dist sak bad wrap");

    /* A parameter set that overruns the body (main-loop bound check). */
    out_len = sizeof buf;
    wm_Pdu_Encode(g_cmac, &in, ick, 16, buf, sizeof buf, &out_len);
    buf[46] = (uint8_t)((buf[46] & 0xF0) | 0x0F);
    buf[47] = 0xF0;
    reseal(buf, out_len, ick);
    CHECK(wm_Pdu_Decode(g_cmac, buf, out_len, ick, 16, &out) == MKA_ERR_PARSE,
        "param set overruns body");

    /* An unknown parameter set type is skipped (decoder default branch). */
    memset(&in, 0, sizeof in);
    fill_basic(&in.basic);
    in.sak_use.present = 1;
    in.sak_use.key_flags = MKA_SAK_USE_LATEST_TX;
    out_len = sizeof buf;
    wm_Pdu_Encode(g_cmac, &in, ick, 16, buf, sizeof buf, &out_len);
    buf[44] = 99;
    reseal(buf, out_len, ick);
    CHECK(wm_Pdu_Decode(g_cmac, buf, out_len, ick, 16, &out) == MKA_OK,
        "unknown set skipped");

    /* XPN parameter set: body length below the fixed 8 octets. The set follows
     * the 40-octet basic set, so its body-length low byte is at offset 47. */
    memset(&in, 0, sizeof in);
    fill_basic(&in.basic);
    in.xpn.present = 1;
    in.xpn.latest_lpn_msb = 1;
    in.xpn.old_lpn_msb = 2;
    out_len = sizeof buf;
    wm_Pdu_Encode(g_cmac, &in, ick, 16, buf, sizeof buf, &out_len);
    buf[46] = (uint8_t)(buf[46] & 0xF0);
    buf[47] = 4; /* body_len = 4 < 8 */
    reseal(buf, out_len, ick);
    CHECK(wm_Pdu_Decode(g_cmac, buf, out_len, ick, 16, &out) == MKA_ERR_PARSE,
        "xpn body too short");

#ifndef WOLFMKA_NO_ANNOUNCEMENTS
    /* Announcement: the cipher-suites TLV declares a length past the body end.
     * The TLV header (7-bit type, 9-bit length) sits at offset 48. */
    memset(&in, 0, sizeof in);
    fill_basic(&in.basic);
    in.announce.present = 1;
    in.announce.count = 1;
    in.announce.suites[0].cipher_suite = MKA_CIPHER_GCM_AES_128;
    out_len = sizeof buf;
    wm_Pdu_Encode(g_cmac, &in, ick, 16, buf, sizeof buf, &out_len);
    buf[48] = 0xE1;
    buf[49] = 0xFF; /* type 112, length 511 (over) */
    reseal(buf, out_len, ick);
    CHECK(wm_Pdu_Decode(g_cmac, buf, out_len, ick, 16, &out) == MKA_ERR_PARSE,
        "announcement TLV overruns body");

    /* Announcement: a non-cipher-suites TLV type is skipped (present 0). */
    out_len = sizeof buf;
    wm_Pdu_Encode(g_cmac, &in, ick, 16, buf, sizeof buf, &out_len);
    buf[48] = 0x64;
    buf[49] = 0x0A; /* type 50, length 10 -> not 112 */
    reseal(buf, out_len, ick);
    CHECK(wm_Pdu_Decode(g_cmac, buf, out_len, ick, 16, &out) == MKA_OK,
        "decode frame with non-cipher-suites TLV");
    CHECK(!out.announce.present, "non-cipher-suites announcement TLV skipped");

    /* Announcement: a cipher-suites TLV too short to hold even one entry
     * carries no constraint, so it must not be reported as present. Marking it
     * present would make the KaY clear whatever the peer previously announced
     * and treat the empty set as "accepts any cipher suite". */
    out_len = sizeof buf;
    wm_Pdu_Encode(g_cmac, &in, ick, 16, buf, sizeof buf, &out_len);
    buf[48] = 0xE0;
    buf[49] = 0x04; /* type 112, length 4 - short of the 10-octet entry */
    memset(&buf[50], 0, 10U);
    reseal(buf, out_len, ick);
    CHECK(wm_Pdu_Decode(g_cmac, buf, out_len, ick, 16, &out) == MKA_OK,
        "decode frame with a short cipher-suites TLV");
    CHECK(!out.announce.present,
        "a TLV too short for one entry announces nothing");
#endif /* WOLFMKA_NO_ANNOUNCEMENTS */
}

/* Malformed / truncated frames and bad args must be rejected, not crash. */
static void test_pdu_malformed(void)
{
    uint8_t ick[16], buf[256];
    size_t out_len = sizeof(buf);
    MkaPdu in, out;
    MkaBasicParamSet basic;
    uint8_t t, h, l;

    printf("MKPDU malformed input rejection:\n");
    memset(ick, 0x66, sizeof(ick));
    memset(&in, 0, sizeof(in));
    fill_basic(&in.basic);
    wm_Pdu_Encode(g_cmac, &in, ick, sizeof(ick), buf, sizeof(buf), &out_len);

    /* Too short to hold an EAPOL header. */
    CHECK(wm_Pdu_Decode(g_cmac, buf, 2, ick, 16, &out) == MKA_ERR_PARSE,
        "runt frame");
    /* Older EAPOL version. */
    t = buf[0];
    buf[0] = 1;
    CHECK(wm_Pdu_Decode(g_cmac, buf, out_len, ick, 16, &out) == MKA_ERR_VERSION,
        "old version");
    buf[0] = t;
    /* Wrong EAPOL packet type. */
    t = buf[1];
    buf[1] = 0x00;
    CHECK(wm_Pdu_Decode(g_cmac, buf, out_len, ick, 16, &out) == MKA_ERR_PARSE,
        "bad type");
    buf[1] = t;
    /* EAPOL body length larger than the buffer. */
    h = buf[2];
    l = buf[3];
    buf[2] = 0xFF;
    buf[3] = 0xFF;
    CHECK(wm_Pdu_Decode(g_cmac, buf, out_len, ick, 16, &out) == MKA_ERR_PARSE,
        "len overflow");
    buf[2] = h;
    buf[3] = l;
    /* Truncated below the ICV. */
    CHECK(wm_Pdu_Decode(g_cmac, buf, EAPOL_HDR_LEN + 4, ick, 16, &out) ==
              MKA_ERR_PARSE,
        "truncated pre-icv");
    /* NULL args. */
    CHECK(wm_Pdu_Decode(g_cmac, NULL, out_len, ick, 16, &out) ==
              MKA_ERR_BAD_ARG,
        "decode null in");
    CHECK(wm_Pdu_Decode(g_cmac, buf, out_len, NULL, 16, &out) ==
              MKA_ERR_BAD_ARG,
        "decode null ick");
    CHECK(wm_Pdu_Decode(g_cmac, buf, out_len, ick, 16, NULL) == MKA_ERR_BAD_ARG,
        "decode null pdu");
    CHECK(wm_Pdu_Decode(NULL, buf, out_len, ick, 16, &out) == MKA_ERR_BAD_ARG,
        "decode null cmac");
    CHECK(wm_Pdu_PeekBasic(NULL, out_len, &basic) == MKA_ERR_BAD_ARG,
        "peek null in");
    CHECK(wm_Pdu_PeekBasic(buf, out_len, NULL) == MKA_ERR_BAD_ARG,
        "peek null out");
    CHECK(wm_Pdu_PeekBasic(buf, 3, &basic) == MKA_ERR_PARSE, "peek runt");
    /* Undersized buffer. Encode's NULL-argument positions are covered once, in
     * test_pdu_invalid_params. */
    out_len = 8;
    CHECK(wm_Pdu_Encode(g_cmac, &in, ick, 16, buf, 8, &out_len) ==
              MKA_ERR_BUFFER,
        "encode small buf");
}

/* Further edge branches: a "no key" SAK Use (zero-length body), an output
 * buffer too small for the trailing ICV, a body too short to contain an ICV,
 * and a Live Peer List claiming more peers than MKA_MAX_PEERS (clamped). */
static void test_pdu_more_negative(void)
{
    uint8_t ick[16], buf[700];
    size_t out_len, full;
    MkaPdu in, out;
    MkaBasicParamSet basic;
    size_t ins, i;

    printf("MKPDU more edge branches:\n");
    memset(ick, 0x77, sizeof ick);

    /* SAK Use present but with no key in use -> zero-length body on encode,
     * accepted as a "no key" indication on decode. */
    memset(&in, 0, sizeof in);
    fill_basic(&in.basic);
    in.sak_use.present = 1; /* all latest/old tx/rx flags false */
    out_len = sizeof buf;
    CHECK(wm_Pdu_Encode(g_cmac, &in, ick, 16, buf, sizeof buf, &out_len) ==
              MKA_OK,
        "encode no-key SAK Use");
    CHECK(wm_Pdu_Decode(g_cmac, buf, out_len, ick, 16, &out) == MKA_OK,
        "decode no-key SAK Use");
    CHECK(out.sak_use.present, "no-key SAK Use present");
    CHECK(!MKA_SAK_USE_IS_LATEST_TX(&out.sak_use),
        "no-key SAK Use clears latest tx");

    /* The converse shape, which no wolfMKA encoder produces: a SAK Use set
     * whose key-in-use flags are set but whose body is absent. The Key Server
     * MI, Key Number and Lowest Acceptable PN that would identify the key were
     * never on the wire, so the flags cannot be honoured - decode has to agree
     * with encode that "no body" means "no key in use". Built by encoding a
     * 40-octet body and then cutting it out, so the frame is well formed and
     * authenticated: this is a semantic case, not a bounds case. */
    memset(&in, 0, sizeof in);
    fill_basic(&in.basic);
    in.sak_use.present = 1;
    in.sak_use.key_flags = MKA_SAK_USE_LATEST_TX;
    in.sak_use.latest_kn = 7U;
    out_len = sizeof buf;
    CHECK(wm_Pdu_Encode(g_cmac, &in, ick, 16, buf, sizeof buf, &out_len) ==
              MKA_OK,
        "encode SAK Use with a key in use");
    /* The Basic Parameter Set is 40 octets, so the SAK Use header follows the
     * 4-octet EAPOL header at offset 44 and its body at 48. */
    CHECK(buf[44] == (uint8_t)MKA_PS_SAK_USE, "SAK Use set located");
    CHECK(((size_t)(buf[46] & 0x0FU) << 8U) + buf[47] == 40U,
        "and carries the 40-octet body");
    CHECK((buf[45] & MKA_SAK_USE_KEY_MASK) == MKA_SAK_USE_LATEST_TX,
        "with Latest Tx asserted");
    buf[46] = (uint8_t)(buf[46] & 0xF0U); /* body length 40 -> 0 */
    buf[47] = 0U;
    memmove(&buf[48], &buf[88], out_len - 88U); /* drop the body */
    out_len -= 40U;
    {
        size_t body = out_len - EAPOL_HDR_LEN;
        buf[2] = (uint8_t)(body >> 8U);
        buf[3] = (uint8_t)(body & 0xFFU);
    }
    reseal(buf, out_len, ick);
    CHECK(wm_Pdu_Decode(g_cmac, buf, out_len, ick, 16, &out) == MKA_OK,
        "a body-less SAK Use with flags set still decodes");
    CHECK(out.sak_use.present, "the set is present");
    CHECK(out.sak_use.key_flags == 0U,
        "but no key is reported in use, matching the absent body");
    CHECK(!MKA_SAK_USE_IS_LATEST_TX(&out.sak_use), "so Latest Tx is not set");
    CHECK((out.sak_use.latest_an == 0U) && (out.sak_use.old_an == 0U),
        "and neither is an Association Number the set never named");

    /* At most one parameter set of each type per MKPDU (11.11). Every decoder
     * here assigns rather than merges, so a second set of a type would
     * overwrite the first - letting an authenticated member hide a Live Peer
     * List proving our liveness behind a later, unrelated one. Splice a copy of
     * the Live Peer List in and reseal, so the frame is well formed and passes
     * the ICV: this has to be rejected on the duplicate alone. */
    memset(&in, 0, sizeof in);
    fill_basic(&in.basic);
    in.live_peers.present = 1;
    in.live_peers.count = 1;
    memset(in.live_peers.peers[0].mi, 0x51, 12);
    in.live_peers.peers[0].mn = 3U;
    out_len = sizeof buf;
    CHECK(wm_Pdu_Encode(g_cmac, &in, ick, 16, buf, sizeof buf, &out_len) ==
              MKA_OK,
        "encode a one-peer Live Peer List");
    CHECK(wm_Pdu_Decode(g_cmac, buf, out_len, ick, 16, &out) == MKA_OK,
        "which decodes on its own");
    /* The Basic Parameter Set is 40 octets, so the peer list sits at offset 44
     * and spans a 4-octet header plus one 16-octet entry. */
    CHECK(buf[44] == (uint8_t)MKA_PS_LIVE_PEER_LIST, "peer list located");
    ins = 44U + 20U;
    memmove(&buf[ins + 20U], &buf[ins], out_len - ins);
    memmove(&buf[ins], &buf[44], 20U); /* the duplicate */
    out_len += 20U;
    {
        size_t body = out_len - EAPOL_HDR_LEN;
        buf[2] = (uint8_t)(body >> 8U);
        buf[3] = (uint8_t)(body & 0xFFU);
    }
    reseal(buf, out_len, ick);
    CHECK(wm_Pdu_Decode(g_cmac, buf, out_len, ick, 16, &out) == MKA_ERR_PARSE,
        "a duplicated parameter set is rejected");

    /* A parameter set this decoder does not know is skipped without touching
     * the MkaPdu, so repeating one clobbers nothing and stays acceptable - the
     * forward-compatibility rule the duplicate check must not break. */
    memset(&in, 0, sizeof in);
    fill_basic(&in.basic);
    out_len = sizeof buf;
    CHECK(wm_Pdu_Encode(g_cmac, &in, ick, 16, buf, sizeof buf, &out_len) ==
              MKA_OK,
        "encode a bare frame");
    ins = 44U; /* immediately before the ICV Indicator */
    memmove(&buf[ins + 8U], &buf[ins], out_len - ins);
    memset(&buf[ins], 0, 8U);
    buf[ins] = 20U;      /* an unknown parameter-set type, body length 0 */
    buf[ins + 4U] = 20U; /* and a second copy of it */
    out_len += 8U;
    {
        size_t body = out_len - EAPOL_HDR_LEN;
        buf[2] = (uint8_t)(body >> 8U);
        buf[3] = (uint8_t)(body & 0xFFU);
    }
    reseal(buf, out_len, ick);
    CHECK(wm_Pdu_Decode(g_cmac, buf, out_len, ick, 16, &out) == MKA_OK,
        "two unknown parameter sets of the same type are skipped, not "
        "rejected");

    /* Output buffer one short word smaller than needed: everything fits up to
     * the ICV, whose append then overflows -> MKA_ERR_BUFFER. */
    memset(&in, 0, sizeof in);
    fill_basic(&in.basic);
    full = sizeof buf;
    wm_Pdu_Encode(g_cmac, &in, ick, 16, buf, sizeof buf, &full);
    out_len = full - 8U;
    CHECK(wm_Pdu_Encode(g_cmac, &in, ick, 16, buf, full - 8U, &out_len) ==
              MKA_ERR_BUFFER,
        "buffer too small for ICV");

    /* A frame whose EAPOL body is shorter than an ICV is rejected. */
    out_len = sizeof buf;
    wm_Pdu_Encode(g_cmac, &in, ick, 16, buf, sizeof buf, &out_len);
    buf[2] = 0;
    buf[3] = 10; /* body length 10 < 16 */
    CHECK(wm_Pdu_Decode(g_cmac, buf, EAPOL_HDR_LEN + 10U, ick, 16, &out) ==
              MKA_ERR_PARSE,
        "body too short for ICV");

    /* Peek with a body too short to hold even a parameter-set header. */
    out_len = sizeof buf;
    wm_Pdu_Encode(g_cmac, &in, ick, 16, buf, sizeof buf, &out_len);
    buf[2] = 0;
    buf[3] = 2; /* body length 2 < 4-octet param header */
    CHECK(wm_Pdu_PeekBasic(buf, EAPOL_HDR_LEN + 2U, &basic) == MKA_ERR_PARSE,
        "peek body below param header");

    /* Live Peer List claiming 33 peers: decode clamps to MKA_MAX_PEERS rather
     * than overrun. Build a 32-peer frame, then splice in a 33rd entry. */
    memset(&in, 0, sizeof in);
    fill_basic(&in.basic);
    in.live_peers.present = 1;
    in.live_peers.count = MKA_MAX_PEERS;
    for (i = 0; i < MKA_MAX_PEERS; i++) {
        memset(in.live_peers.peers[i].mi, (int)(0x40 + i), 12);
        in.live_peers.peers[i].mn = (uint32_t)i + 1U;
    }
    out_len = sizeof buf;
    CHECK(wm_Pdu_Encode(g_cmac, &in, ick, 16, buf, sizeof buf, &out_len) ==
              MKA_OK,
        "encode 32-peer frame");
    /* The ICV indicator + ICV occupy the last 20 octets; insert one 16-octet
     * peer entry just before them and grow the length fields by 16. */
    ins = out_len - 20U;
    memmove(&buf[ins + 16U], &buf[ins], 20U);
    memset(&buf[ins], 0xAB, 16U);
    buf[47] = (uint8_t)(buf[47] + 16U); /* peer-list body 512 -> 528 */
    {
        size_t body = (out_len + 16U) - EAPOL_HDR_LEN;
        buf[2] = (uint8_t)(body >> 8U);
        buf[3] = (uint8_t)(body & 0xFFU);
    }
    out_len += 16U;
    reseal(buf, out_len, ick);
    CHECK(wm_Pdu_Decode(g_cmac, buf, out_len, ick, 16, &out) == MKA_OK,
        "over-long peer list decodes");
    CHECK(out.live_peers.count == MKA_MAX_PEERS,
        "peer list clamped to MKA_MAX_PEERS");

    /* SAK Use carrying the plain-text transmit/receive flags (the
     * MKA_SAK_USE_PLAIN_* bits in octet 2 of the encoder). */
    memset(&in, 0, sizeof in);
    fill_basic(&in.basic);
    in.sak_use.present = 1;
    in.sak_use.key_flags = MKA_SAK_USE_LATEST_TX; /* 40-octet body */
    in.sak_use.mode_flags = MKA_SAK_USE_PLAIN_TX | MKA_SAK_USE_PLAIN_RX;
    out_len = sizeof buf;
    CHECK(wm_Pdu_Encode(g_cmac, &in, ick, 16, buf, sizeof buf, &out_len) ==
              MKA_OK,
        "encode SAK Use with plain tx/rx");
    CHECK(wm_Pdu_Decode(g_cmac, buf, out_len, ick, 16, &out) == MKA_OK,
        "decode SAK Use with plain tx/rx");
    CHECK(MKA_SAK_USE_IS_PLAIN_TX(&out.sak_use), "plain tx flag round-trips");
    CHECK(MKA_SAK_USE_IS_PLAIN_RX(&out.sak_use), "plain rx flag round-trips");

    /* XPN parameter set (type 8): the 32 MSBs of the Latest and Old LPNs. */
    memset(&in, 0, sizeof in);
    fill_basic(&in.basic);
    in.sak_use.present = 1;
    in.sak_use.key_flags = MKA_SAK_USE_LATEST_TX;
    in.sak_use.latest_lpn = 0xDEADBEEFu;
    in.sak_use.old_lpn = 0x0000CAFEu;
    in.xpn.present = 1;
    in.xpn.suspension_time = 0x2A; /* header octet 2 */
    in.xpn.latest_lpn_msb = 0x00000123u;
    in.xpn.old_lpn_msb = 0x04050607u;
    out_len = sizeof buf;
    CHECK(wm_Pdu_Encode(g_cmac, &in, ick, 16, buf, sizeof buf, &out_len) ==
              MKA_OK,
        "encode XPN parameter set");
    CHECK(wm_Pdu_Decode(g_cmac, buf, out_len, ick, 16, &out) == MKA_OK,
        "decode XPN parameter set");
    CHECK(out.xpn.present, "XPN parameter set present");
    CHECK((out.xpn.latest_lpn_msb == 0x00000123u) &&
              (out.xpn.old_lpn_msb == 0x04050607u),
        "XPN latest/old LPN MSBs round-trip");
    CHECK(out.xpn.suspension_time == 0x2A, "XPN suspension time round-trips");
    CHECK(out.sak_use.latest_lpn == 0xDEADBEEFu,
        "XPN low bits stay in SAK Use");

#ifndef WOLFMKA_NO_ANNOUNCEMENTS
    /* Announcement parameter set (type 7): MACsec Cipher Suites TLV (112). */
    memset(&in, 0, sizeof in);
    fill_basic(&in.basic);
    in.announce.present = 1;
    in.announce.count = 2;
    in.announce.suites[0].capability = MKA_CAP_INTEGRITY_CONF_OFFSET;
    in.announce.suites[0].cipher_suite = MKA_CIPHER_GCM_AES_128;
    in.announce.suites[1].capability = MKA_CAP_INTEGRITY_CONF;
    in.announce.suites[1].cipher_suite = MKA_CIPHER_GCM_AES_XPN_256;
    out_len = sizeof buf;
    CHECK(wm_Pdu_Encode(g_cmac, &in, ick, 16, buf, sizeof buf, &out_len) ==
              MKA_OK,
        "encode Announcement set");
    CHECK(wm_Pdu_Decode(g_cmac, buf, out_len, ick, 16, &out) == MKA_OK,
        "decode Announcement set");
    CHECK(out.announce.present, "announcement present");
    CHECK(out.announce.count == 2, "announcement suite count == 2");
    CHECK((out.announce.suites[0].cipher_suite == MKA_CIPHER_GCM_AES_128) &&
              (out.announce.suites[0].capability ==
                  MKA_CAP_INTEGRITY_CONF_OFFSET),
        "announcement suite[0] round-trips");
    CHECK((out.announce.suites[1].cipher_suite == MKA_CIPHER_GCM_AES_XPN_256) &&
              (out.announce.suites[1].capability == MKA_CAP_INTEGRITY_CONF),
        "announcement suite[1] round-trips");

    /* Announcement marked present but carrying no suites: not emitted. */
    memset(&in, 0, sizeof in);
    fill_basic(&in.basic);
    in.announce.present = 1;
    in.announce.count = 0;
    out_len = sizeof buf;
    CHECK(wm_Pdu_Encode(g_cmac, &in, ick, 16, buf, sizeof buf, &out_len) ==
              MKA_OK,
        "encode empty announcement");
    CHECK(wm_Pdu_Decode(g_cmac, buf, out_len, ick, 16, &out) == MKA_OK,
        "decode frame with empty announcement");
    CHECK(!out.announce.present, "empty announcement omitted");
#endif /* WOLFMKA_NO_ANNOUNCEMENTS */
}

/* Each pointer argument of every public PDU function rejected as NULL at each
 * position (decode/peek NULLs are covered in test_pdu_malformed; this completes
 * wm_Pdu_Encode's multi-operand guard). */
static void test_pdu_invalid_params(void)
{
    uint8_t ick[16] = {0}, buf[256];
    size_t n = sizeof buf;
    MkaPdu in;

    printf("invalid parameters: public PDU functions:\n");
    memset(&in, 0, sizeof in);
    fill_basic(&in.basic);

    CHECK(wm_Pdu_Encode(g_cmac, NULL, ick, 16, buf, sizeof buf, &n) ==
              MKA_ERR_BAD_ARG,
        "encode pdu NULL");
    /* Rejected before anything is written, rather than after the whole frame
     * has been laid into the caller's buffer. */
    memset(buf, 0xE7, sizeof buf);
    CHECK(wm_Pdu_Encode(NULL, &in, ick, 16, buf, sizeof buf, &n) ==
              MKA_ERR_BAD_ARG,
        "encode cmac NULL");
    CHECK(buf[0] == 0xE7U, "and the output buffer is untouched");
    CHECK(wm_Pdu_Encode(g_cmac, &in, NULL, 16, buf, sizeof buf, &n) ==
              MKA_ERR_BAD_ARG,
        "encode ick NULL");

    /* Encode sizes the frame once and then writes without per-field bounds
     * checks, so a length larger than the array behind it would be reported in
     * the size - passing the capacity check - and then over-read the caller's
     * MkaPdu. Every length field is checked up front instead. */
    {
        MkaPdu bad;
        size_t m;

#define CHECK_LEN_REJECTED(field, value, msg)                                  \
    do {                                                                       \
        memset(&bad, 0, sizeof bad);                                           \
        fill_basic(&bad.basic);                                                \
        (field) = (value);                                                     \
        CHECK(wm_Pdu_EncodedSize(&bad) == 0U, msg " sized as zero");           \
        m = sizeof buf;                                                        \
        CHECK(wm_Pdu_Encode(g_cmac, &bad, ick, 16, buf, sizeof buf, &m) ==     \
                  MKA_ERR_BAD_ARG,                                             \
            msg);                                                              \
    } while (0)

        /* The in-range baseline, so the checks below are the only difference.
         */
        memset(&bad, 0, sizeof bad);
        fill_basic(&bad.basic);
        CHECK(wm_Pdu_EncodedSize(&bad) != 0U, "an in-range PDU still sizes");

        CHECK_LEN_REJECTED(bad.basic.ckn_len, sizeof bad.basic.ckn + 1U,
            "an over-long CKN is rejected");
        CHECK_LEN_REJECTED(bad.live_peers.count, (size_t)MKA_MAX_PEERS + 1U,
            "an over-long Live Peer List is rejected");
        CHECK_LEN_REJECTED(bad.potential_peers.count,
            (size_t)MKA_MAX_PEERS + 1U,
            "an over-long Potential Peer List is rejected");
        CHECK_LEN_REJECTED(bad.dist_sak.wrapped_len,
            sizeof bad.dist_sak.wrapped_sak + 1U,
            "an over-long wrapped SAK is rejected");
#ifdef WOLFMKA_DISTRIBUTED_CAK
        CHECK_LEN_REJECTED(bad.dist_cak.body_len, sizeof bad.dist_cak.body + 1U,
            "an over-long Distributed CAK body is rejected");
#endif
#ifdef WOLFMKA_KMD
        CHECK_LEN_REJECTED(bad.kmd.kmd_len, sizeof bad.kmd.kmd + 1U,
            "an over-long KMD is rejected");
#endif
#ifndef WOLFMKA_NO_ANNOUNCEMENTS
        CHECK_LEN_REJECTED(bad.announce.count,
            (size_t)MKA_MAX_CIPHER_SUITES + 1U,
            "an over-long announcement is rejected");
#endif
#undef CHECK_LEN_REJECTED
    }
    CHECK(wm_Pdu_Encode(g_cmac, &in, ick, 16, NULL, sizeof buf, &n) ==
              MKA_ERR_BAD_ARG,
        "encode out NULL");
    CHECK(wm_Pdu_Encode(g_cmac, &in, ick, 16, buf, sizeof buf, NULL) == BAD,
        "encode out_len NULL");
}

/* Distributed SAK whose implied wrapped-key length exceeds the maximum: hits
 * the (wrap_len > MKA_MAX_WRAPPED_SAK) arm of the length check. Encode a valid
 * dist-SAK with an explicit cipher suite and a 40-octet wrap (body 52), then
 * enlarge the declared body to 56 so the decoder computes wrap_len = 44 (> 40).
 * The 4 extra octets come from the trailing ICV-indicator set, which is now
 * absorbed into the (rejected) dist-SAK body; the real ICV still re-seals. */
static void test_pdu_dist_sak_overlong(void)
{
    uint8_t ick[16], buf[256];
    size_t out_len = sizeof buf;
    MkaPdu in, out;

    printf("MKPDU dist-SAK wrapped key over the maximum:\n");
    memset(ick, 0x3D, sizeof ick);
    memset(&in, 0, sizeof in);
    fill_basic(&in.basic);
    in.dist_sak.present = 1;
    in.dist_sak.kn = 1;
    in.dist_sak.cipher_suite = MKA_CIPHER_GCM_AES_256; /* explicit suite */
    memset(in.dist_sak.wrapped_sak, 0xEE, 40);
    in.dist_sak.wrapped_len = 40;
    wm_Pdu_Encode(g_cmac, &in, ick, 16, buf, sizeof buf, &out_len);

    /* The dist-SAK set begins at offset 44; its body-length low byte is at 47.
     * 52 -> 56 makes wrap_len = 56 - KN(4) - cipher-suite(8) = 44. */
    buf[47] = 56;
    reseal(buf, out_len, ick);
    CHECK(wm_Pdu_Decode(g_cmac, buf, out_len, ick, 16, &out) == MKA_ERR_PARSE,
        "dist-SAK wrap length over maximum rejected");
}

/* A frame whose parameter region ends without an ICV-indicator parameter set:
 * the decode loop terminates via its while condition (the trailing 16 octets
 * are still taken as the ICV) rather than the ICV-indicator break. */
static void test_pdu_no_icv_indicator(void)
{
    uint8_t ick[16], buf[256];
    size_t out_len = sizeof buf;
    MkaPdu in, out;
    size_t icv_off, body;

    printf("MKPDU with no ICV-indicator set (natural loop exit):\n");
    memset(ick, 0x7E, sizeof ick);
    memset(&in, 0, sizeof in);
    fill_basic(&in.basic);
    wm_Pdu_Encode(g_cmac, &in, ick, 16, buf, sizeof buf, &out_len);

    /* The encoder appends a 4-octet ICV-indicator set then the 16-octet ICV.
     * Drop the indicator by shifting the ICV left over it, shrink the EAPOL
     * body length to match, and re-seal so the (now adjacent) ICV verifies. */
    icv_off = out_len - 16U;
    memmove(&buf[icv_off - 4U], &buf[icv_off], 16U);
    out_len -= 4U;
    body = out_len - EAPOL_HDR_LEN;
    buf[2] = (uint8_t)(body >> 8U);
    buf[3] = (uint8_t)(body & 0xFFU);
    reseal(buf, out_len, ick);

    CHECK(wm_Pdu_Decode(g_cmac, buf, out_len, ick, 16, &out) == MKA_OK,
        "decode frame without ICV indicator");
    CHECK(out.basic.ckn_len == 6, "basic set still decoded");
}

/* Encode @in into every buffer capacity from 0 up to size+1, asserting that
 * wm_Pdu_EncodedSize is the exact boundary: too-small buffers are
 * rejected with MKA_ERR_BUFFER and any capacity >= the computed size succeeds
 * writing exactly that many octets. */
static void sweep_buf_sizes(const MkaPdu* in, const uint8_t* ick,
    const char* tag)
{
    uint8_t buf[600];
    size_t size = wm_Pdu_EncodedSize(in);
    size_t cap;
    int ok = (size + 1U) <= sizeof buf; /* test buffer big enough */

    for (cap = 0U; (cap <= (size + 1U)) && (ok != 0); cap++) {
        size_t out_len = 0U;
        MkaStatus rc = wm_Pdu_Encode(g_cmac, in, ick, 16, buf, cap, &out_len);
        if (cap < size) {
            if (rc != MKA_ERR_BUFFER) {
                ok = 0;
            }
        }
        else {
            if ((rc != MKA_OK) || (out_len != size)) {
                ok = 0;
            }
        }
    }
    CHECK(ok != 0, tag);
}

/* wm_Pdu_EncodedSize matches wm_Pdu_Encode's output at the exact
 * byte, for a range of message shapes, swept across buffer capacities
 * 0..size+1. */
static void test_pdu_size_boundary(void)
{
    uint8_t ick[16];
    MkaPdu in;
    size_t i;

    printf("encoded-size boundary sweep (cap 0..size+1):\n");
    memset(ick, 0x2C, sizeof ick);

    /* Basic only. */
    memset(&in, 0, sizeof in);
    fill_basic(&in.basic);
    CHECK(wm_Pdu_EncodedSize(&in) > 0, "size of basic-only > 0");
    sweep_buf_sizes(&in, ick, "basic-only");

    /* Basic + Live Peer List. */
    memset(&in, 0, sizeof in);
    fill_basic(&in.basic);
    in.live_peers.present = 1;
    in.live_peers.count = 3;
    for (i = 0; i < 3; i++) {
        memset(in.live_peers.peers[i].mi, (int)(0x30 + i), 12);
        in.live_peers.peers[i].mn = (uint32_t)i + 1U;
    }
    sweep_buf_sizes(&in, ick, "basic + live peers");

    /* Basic + SAK Use + Distributed SAK (explicit cipher suite). */
    memset(&in, 0, sizeof in);
    fill_basic(&in.basic);
    in.sak_use.present = 1;
    in.sak_use.key_flags = MKA_SAK_USE_LATEST_TX;
    in.dist_sak.present = 1;
    in.dist_sak.kn = 7;
    in.dist_sak.cipher_suite = MKA_CIPHER_GCM_AES_256;
    memset(in.dist_sak.wrapped_sak, 0x5A, 40);
    in.dist_sak.wrapped_len = 40;
    sweep_buf_sizes(&in, ick, "basic + SAK Use + dist-SAK");

    /* Basic + plain (keyless) Distributed SAK. */
    memset(&in, 0, sizeof in);
    fill_basic(&in.basic);
    in.dist_sak.present = 1;
    in.dist_sak.wrapped_len = 0;
    sweep_buf_sizes(&in, ick, "basic + plain dist-SAK");

    /* NULL pdu reports size 0. */
    CHECK(wm_Pdu_EncodedSize(NULL) == 0, "size of NULL is 0");
}

/* Encode @in and require success (exercises the encode_* and size paths). */
static void enc_ok(const MkaPdu* in, const uint8_t* ick, const char* tag)
{
    uint8_t buf[600];
    size_t n = sizeof buf;
    CHECK(wm_Pdu_Encode(g_cmac, in, ick, 16, buf, sizeof buf, &n) == MKA_OK,
        tag);
}

/* Exercise the remaining condition operands in the encoders and the size
 * calculation: present-but-empty peer lists, each SAK Use flag in isolation,
 * and every Distributed-SAK cipher-suite/length combination. */
static void test_pdu_branch_combos(void)
{
    uint8_t ick[16];
    MkaPdu in;

    printf("encoder condition-operand combinations:\n");
    memset(ick, 0x4B, sizeof ick);

    /* Live and Potential Peer Lists: present but empty (count == 0). */
    memset(&in, 0, sizeof in);
    fill_basic(&in.basic);
    in.live_peers.present = 1;
    in.live_peers.count = 0;
    enc_ok(&in, ick, "live peers present, count 0");
    memset(&in, 0, sizeof in);
    fill_basic(&in.basic);
    in.potential_peers.present = 1;
    in.potential_peers.count = 0;
    enc_ok(&in, ick, "potential peers present, count 0");

    /* A Potential Peer List with entries (the encode/size potential path). */
    memset(&in, 0, sizeof in);
    fill_basic(&in.basic);
    in.potential_peers.present = 1;
    in.potential_peers.count = 2;
    memset(in.potential_peers.peers[0].mi, 0x71, 12);
    memset(in.potential_peers.peers[1].mi, 0x72, 12);
    enc_ok(&in, ick, "potential peers with entries");

    /* SAK Use: each tx/rx flag in isolation, plus the all-clear (no-key) case,
     * so every operand of the 4-way OR is evaluated both ways. */
    {
        unsigned k;
        for (k = 0U; k < 5U; k++) {
            memset(&in, 0, sizeof in);
            fill_basic(&in.basic);
            in.sak_use.present = 1;
            switch (k) {
                case 0U: in.sak_use.key_flags = MKA_SAK_USE_LATEST_TX; break;
                case 1U: in.sak_use.key_flags = MKA_SAK_USE_LATEST_RX; break;
                case 2U: in.sak_use.key_flags = MKA_SAK_USE_OLD_TX; break;
                case 3U: in.sak_use.key_flags = MKA_SAK_USE_OLD_RX; break;
                default: break; /* all clear: no-key SAK Use */
            }
            enc_ok(&in, ick, "SAK Use single-flag");
        }
    }

    /* Distributed SAK: default suite (cs 0, 24-octet wrap) -> no explicit
     * cipher suite; cs 0 with a longer wrap, and an explicit suite -> both
     * other branches. */
    memset(&in, 0, sizeof in);
    fill_basic(&in.basic);
    in.dist_sak.present = 1;
    in.dist_sak.kn = 1;
    in.dist_sak.cipher_suite = 0;
    in.dist_sak.wrapped_len = 24;
    enc_ok(&in, ick, "dist-SAK default suite (cs 0, wrap 24)");
    in.dist_sak.wrapped_len = 32; /* cs 0 but non-default length */
    enc_ok(&in, ick, "dist-SAK cs 0, wrap 32");
    in.dist_sak.cipher_suite = MKA_CIPHER_GCM_AES_256;
    in.dist_sak.wrapped_len = 40;
    enc_ok(&in, ick, "dist-SAK explicit suite");

#ifndef WOLFMKA_NO_ANNOUNCEMENTS
    /* Announcement: every decision of `a->present && (a->count != 0U)`
     * (mka_encode_announce / encoded_size). present && count==0 -> count
     * operand false (skip); present && count!=0 -> both true (emit); present==0
     * -> present operand false (skip), covered by every other encode above. */
    {
        uint8_t buf[600];
        size_t n;
        MkaPdu out;

        memset(&in, 0, sizeof in);
        fill_basic(&in.basic);
        in.announce.present = 1;
        in.announce.count = 0;
        n = sizeof buf;
        CHECK(wm_Pdu_Encode(g_cmac, &in, ick, 16, buf, sizeof buf, &n) ==
                  MKA_OK,
            "announce present, count 0: encodes");
        CHECK(wm_Pdu_Decode(g_cmac, buf, n, ick, 16, &out) == MKA_OK,
            "announce present, count 0: decodes");
        CHECK(!out.announce.present, "announce present, count 0: not emitted");

        in.announce.count = 1;
        in.announce.suites[0].cipher_suite = MKA_CIPHER_GCM_AES_128;
        in.announce.suites[0].capability = MKA_CAP_INTEGRITY_CONF;
        n = sizeof buf;
        CHECK(wm_Pdu_Encode(g_cmac, &in, ick, 16, buf, sizeof buf, &n) ==
                  MKA_OK,
            "announce present, one suite: encodes");
        CHECK(wm_Pdu_Decode(g_cmac, buf, n, ick, 16, &out) == MKA_OK,
            "announce present, one suite: decodes");
        CHECK(out.announce.present && (out.announce.count == 1),
            "announce present, one suite: emitted");
    }
#endif /* WOLFMKA_NO_ANNOUNCEMENTS */
}

/* Decode robustness: a MACsec Cipher Suites TLV carrying more entries than
 * MKA_MAX_CIPHER_SUITES. The struct caps at the maximum, so the frame is built
 * by hand - encode a 4-suite announcement, splice in a fifth 10-octet entry,
 * and re-seal. The decoder keeps the first four and ignores the rest (the
 * `a->count < MKA_MAX_CIPHER_SUITES` guard in mka_decode_announce). */
#ifndef WOLFMKA_NO_ANNOUNCEMENTS
static void test_announce_suite_cap(void)
{
    uint8_t ick[16], buf[256];
    size_t out_len = sizeof buf;
    MkaPdu in, out;
    uint16_t ebody;
    size_t i;

    printf("announcement cipher-suite cap (> MAX entries):\n");
    memset(ick, 0x37, sizeof ick);

    /* Encode the maximum the struct allows: 4 suites (TLV value 40 octets). */
    memset(&in, 0, sizeof in);
    fill_basic(&in.basic);
    in.announce.present = 1;
    in.announce.count = MKA_MAX_CIPHER_SUITES;
    for (i = 0U; i < (size_t)MKA_MAX_CIPHER_SUITES; i++) {
        in.announce.suites[i].cipher_suite = MKA_CIPHER_GCM_AES_128;
        in.announce.suites[i].capability = MKA_CAP_INTEGRITY_CONF;
    }
    CHECK(wm_Pdu_Encode(g_cmac, &in, ick, 16, buf, sizeof buf, &out_len) ==
              MKA_OK,
        "encode 4-suite announcement");
    CHECK(out_len == 112U, "4-suite frame layout as expected");

    /* Layout: EAPOL hdr 0..3, basic 4..43, announcement 44..91 (ICV indicator
     * at 92, ICV at 96). Splice a fifth entry: move the 20-octet tail (ICV
     * indicator + ICV) down 8 octets, widen the TLV value to 50 octets and the
     * set body to 52, grow the EAPOL body by 8, then re-seal. */
    memmove(&buf[100], &buf[92], 20U);
    for (i = 0U; i < MKA_CS_TLV_ENTRY_LEN; i++) {
        buf[90U + i] = (uint8_t)(0xA0U + i); /* fifth entry: ignored */
    }
    buf[48] = 0xE0;
    buf[49] = 0x32; /* TLV type 112, length 50 */
    buf[46] = 0x00;
    buf[47] = 52; /* set body length 52 */
    ebody = (uint16_t)(((uint16_t)buf[2] << 8) | buf[3]);
    ebody = (uint16_t)(ebody + 8U);
    buf[2] = (uint8_t)(ebody >> 8);
    buf[3] = (uint8_t)ebody;
    out_len += 8U;
    reseal(buf, out_len, ick);

    CHECK(wm_Pdu_Decode(g_cmac, buf, out_len, ick, 16, &out) == MKA_OK,
        "decode oversized announcement");
    CHECK(out.announce.present, "clamped announcement present");
    CHECK(out.announce.count == (size_t)MKA_MAX_CIPHER_SUITES,
        "cipher-suite list clamped to MKA_MAX_CIPHER_SUITES");
}

/* The other end of the same field: a cipher-suites TLV too short to hold even
 * one entry, and two of them in one announcement. Both parse cleanly and are
 * about what the result *means*, so the bounds tests do not reach them and
 * neither does structural coverage. */
static void test_announce_semantic_negative(void)
{
    uint8_t ick[16], buf[256];
    size_t out_len;
    MkaPdu in, out;
    uint16_t ebody;
    size_t i;

    printf("announcement semantic edge cases:\n");
    memset(ick, 0x38, sizeof ick);

    /* A one-suite announcement to cut down. Layout: EAPOL hdr 0..3, basic
     * 4..43, announcement set 44..59 (4 header + 2 TLV header + 10 entry, then
     * padding), ICV indicator at 60, ICV at 64. */
    memset(&in, 0, sizeof in);
    fill_basic(&in.basic);
    in.announce.present = 1;
    in.announce.count = 1;
    in.announce.suites[0].cipher_suite = MKA_CIPHER_GCM_AES_256;
    in.announce.suites[0].capability = MKA_CAP_INTEGRITY_CONF;
    out_len = sizeof buf;
    CHECK(wm_Pdu_Encode(g_cmac, &in, ick, 16, buf, sizeof buf, &out_len) ==
              MKA_OK,
        "encode a one-suite announcement");
    CHECK(out_len == 80U, "one-suite frame layout as expected");
    CHECK(buf[44] == (uint8_t)MKA_PS_ANNOUNCEMENT, "announcement located");
    CHECK(wm_Pdu_Decode(g_cmac, buf, out_len, ick, 16, &out) == MKA_OK,
        "which decodes on its own");
    CHECK(out.announce.present && (out.announce.count == 1U),
        "carrying its one suite");

    /* Case 1: the TLV declares a zero-length value. A cipher-suites TLV with no
     * entries states no constraint, and marking the announcement present would
     * be read by the KaY as "this peer accepts anything" - erasing whatever the
     * peer last announced. It must decode to absent, not to an empty set. */
    {
        uint8_t f[256];
        size_t n;

        memcpy(f, buf, out_len);
        n = out_len;
        f[48] = 0xE0;
        f[49] = 0x00; /* TLV type 112, value length 0 */
        f[46] = 0x00;
        f[47] = MKA_ANN_TLV_HDR_LEN;      /* set body: the TLV header alone */
        memmove(&f[52], &f[60], n - 60U); /* drop the entry, keep 4-alignment */
        f[50] = 0x00;
        f[51] = 0x00;
        n -= 8U;
        ebody = (uint16_t)(n - EAPOL_HDR_LEN);
        f[2] = (uint8_t)(ebody >> 8);
        f[3] = (uint8_t)ebody;
        reseal(f, n, ick);
        CHECK(wm_Pdu_Decode(g_cmac, f, n, ick, 16, &out) == MKA_OK,
            "an empty cipher-suites TLV still parses");
        CHECK(!out.announce.present,
            "but announces nothing, rather than an empty (unconstrained) set");
        CHECK(out.announce.count == 0U, "and carries no suites");
    }

    /* Case 2: two cipher-suites TLVs in one announcement. The walk assigns
     * rather than merges, so the second would replace the first - a constraint
     * stated and then buried under a permissive copy, one nesting level below
     * the duplicate parameter set. Rejected on the same grounds. */
    {
        uint8_t f[256];
        size_t n;

        memcpy(f, buf, out_len);
        n = out_len;
        memmove(&f[72], &f[60], n - 60U); /* room for a second 12-octet TLV */
        memcpy(&f[60], &f[48], 12U);      /* the duplicate */
        for (i = 0U; i < 8U; i++) {
            f[62U + 2U + i] = 0x00U; /* a different, permissive suite */
        }
        f[46] = 0x00;
        f[47] = (uint8_t)(2U * (MKA_ANN_TLV_HDR_LEN + MKA_CS_TLV_ENTRY_LEN));
        n += 12U;
        ebody = (uint16_t)(n - EAPOL_HDR_LEN);
        f[2] = (uint8_t)(ebody >> 8);
        f[3] = (uint8_t)ebody;
        reseal(f, n, ick);
        CHECK(wm_Pdu_Decode(g_cmac, f, n, ick, 16, &out) == MKA_ERR_PARSE,
            "a second cipher-suites TLV is rejected");
    }
}
#endif /* WOLFMKA_NO_ANNOUNCEMENTS */

/* Two more shapes that parse but mean something the bounds tests do not check:
 * an XPN set longer than this revision defines, and a peer list that is present
 * but empty. Both are about the decoded meaning, not about staying in bounds.
 */
static void test_decode_forward_compatible_shapes(void)
{
    uint8_t ick[16], buf[256];
    size_t out_len;
    MkaPdu in, out;
    uint16_t ebody;

    printf("forward-compatible decoder shapes:\n");
    memset(ick, 0x39, sizeof ick);

#ifndef WOLFMKA_NO_XPN
    /* A future revision may extend the XPN parameter set. Trailing octets past
     * the fields this one knows must be ignored rather than rejected, or a
     * newer peer becomes undecodable; the fields that are defined must still
     * decode. Neither direction was pinned. */
    memset(&in, 0, sizeof in);
    fill_basic(&in.basic);
    in.xpn.present = 1;
    in.xpn.latest_lpn_msb = 0xAABBCCDDU;
    in.xpn.old_lpn_msb = 0x11223344U;
    out_len = sizeof buf;
    CHECK(wm_Pdu_Encode(g_cmac, &in, ick, 16, buf, sizeof buf, &out_len) ==
              MKA_OK,
        "encode an XPN set");
    /* Layout: EAPOL hdr 0..3, basic 4..43, XPN set 44..55 (4 header + 8 body),
     * ICV indicator at 56. Widen the body to 12 with four trailing octets. */
    CHECK(buf[44] == (uint8_t)MKA_PS_XPN, "XPN set located");
    CHECK(buf[47] == (uint8_t)MKA_XPN_BODY_LEN, "with the defined body length");
    memmove(&buf[60], &buf[56], out_len - 56U);
    buf[56] = 0xDE;
    buf[57] = 0xAD;
    buf[58] = 0xBE;
    buf[59] = 0xEF;
    buf[47] = (uint8_t)(MKA_XPN_BODY_LEN + 4U);
    out_len += 4U;
    ebody = (uint16_t)(out_len - EAPOL_HDR_LEN);
    buf[2] = (uint8_t)(ebody >> 8);
    buf[3] = (uint8_t)ebody;
    reseal(buf, out_len, ick);
    CHECK(wm_Pdu_Decode(g_cmac, buf, out_len, ick, 16, &out) == MKA_OK,
        "an over-long XPN set is accepted, not rejected");
    CHECK(out.xpn.present, "and marked present");
    CHECK(out.xpn.latest_lpn_msb == 0xAABBCCDDU, "the Latest MSBs decode");
    CHECK(out.xpn.old_lpn_msb == 0x11223344U, "and so do the Old ones");
#endif /* WOLFMKA_NO_XPN */

    /* A Live Peer List that is present but names nobody. This is a real
     * statement - "I currently see no live peer" - not a malformed set, so it
     * has to decode as present with a count of zero rather than be rejected or
     * silently read as absent. */
    memset(&in, 0, sizeof in);
    fill_basic(&in.basic);
    in.live_peers.present = 1;
    in.live_peers.count = 1;
    memset(in.live_peers.peers[0].mi, 0x77, MKA_MI_LEN);
    out_len = sizeof buf;
    CHECK(wm_Pdu_Encode(g_cmac, &in, ick, 16, buf, sizeof buf, &out_len) ==
              MKA_OK,
        "encode a one-peer Live Peer List");
    /* Peer list at 44: 4-octet header plus one 16-octet entry. Cut the entry
     * out, leaving a header declaring a zero-length body. */
    CHECK(buf[44] == (uint8_t)MKA_PS_LIVE_PEER_LIST, "peer list located");
    buf[46] = 0x00;
    buf[47] = 0x00;
    memmove(&buf[48], &buf[64], out_len - 64U);
    out_len -= 16U;
    ebody = (uint16_t)(out_len - EAPOL_HDR_LEN);
    buf[2] = (uint8_t)(ebody >> 8);
    buf[3] = (uint8_t)ebody;
    reseal(buf, out_len, ick);
    CHECK(wm_Pdu_Decode(g_cmac, buf, out_len, ick, 16, &out) == MKA_OK,
        "an empty Live Peer List parses");
    CHECK(out.live_peers.present, "and is present - the peer said something");
    CHECK(out.live_peers.count == 0U, "namely that it sees no live peer");
}

#ifdef WOLFMKA_DISTRIBUTED_CAK
/* Distributed CAK (parameter set type 5): the opaque body (wrapped CAK || CKN)
 * round-trips through encode/decode, and a body larger than the receive buffer
 * is rejected as a parse error rather than overflowing it. */
static void test_dist_cak(void)
{
    uint8_t ick[16], buf[256], frm[256];
    size_t out_len = sizeof(buf);
    size_t basic_end, pos, body, i;
    MkaPdu in, out;
    uint8_t payload[30];

    printf("MKPDU Distributed CAK (type 5) round-trip + oversized:\n");
    memset(ick, 0x77, sizeof(ick));
    for (i = 0; i < sizeof(payload); i++) {
        payload[i] = (uint8_t)(0xC0U + i);
    }

    /* Round-trip an opaque body. */
    memset(&in, 0, sizeof(in));
    fill_basic(&in.basic);
    in.dist_cak.present = 1;
    memcpy(in.dist_cak.body, payload, sizeof(payload));
    in.dist_cak.body_len = sizeof(payload);
    CHECK(wm_Pdu_Encode(g_cmac, &in, ick, sizeof(ick), buf, sizeof(buf),
              &out_len) == MKA_OK,
        "encode dist-cak");
    CHECK(wm_Pdu_Decode(g_cmac, buf, out_len, ick, sizeof(ick), &out) == MKA_OK,
        "decode dist-cak");
    CHECK(out.dist_cak.present && (out.dist_cak.body_len == sizeof(payload)),
        "dist-cak present + body len");
    CHECK_EQ_MEM(out.dist_cak.body, payload, sizeof(payload), "dist-cak body");

    /* Hand-build a type-5 set whose declared body (80 octets) exceeds the
     * receive buffer, spliced between the Basic set and the ICV, and confirm
     * decode rejects it instead of overflowing. */
    memset(&in, 0, sizeof(in));
    fill_basic(&in.basic);
    out_len = sizeof(buf);
    (void)wm_Pdu_Encode(g_cmac, &in, ick, sizeof(ick), buf, sizeof(buf),
        &out_len);
    basic_end = out_len - (MKA_PARAM_HDR_LEN + MKA_DEFAULT_ICV_LEN);
    memcpy(frm, buf, basic_end);
    pos = basic_end;
    frm[pos++] = (uint8_t)MKA_PS_DISTRIBUTED_CAK;
    frm[pos++] = 0U;
    frm[pos++] = 0U;
    frm[pos++] = 80U; /* body length 80 > sizeof(dist_cak.body) (72) */
    memset(&frm[pos], 0xAB, 80U);
    pos += 80U;
    frm[pos++] = (uint8_t)MKA_PS_ICV_INDICATOR;
    frm[pos++] = 0U;
    frm[pos++] = 0U;
    frm[pos++] = (uint8_t)MKA_DEFAULT_ICV_LEN;
    body = (pos + MKA_DEFAULT_ICV_LEN) - EAPOL_HDR_LEN;
    frm[2] = (uint8_t)(body >> 8);
    frm[3] = (uint8_t)(body & 0xFFU);
    test_seal_icv(g_cmac, ick, sizeof(ick), frm, pos);
    out_len = pos + MKA_DEFAULT_ICV_LEN;
    CHECK(wm_Pdu_Decode(g_cmac, frm, out_len, ick, sizeof(ick), &out) ==
              MKA_ERR_PARSE,
        "oversized dist-cak body rejected");
}
#endif /* WOLFMKA_DISTRIBUTED_CAK */

#ifdef WOLFMKA_KMD
/* Key Management Domain (parameter set type 6): the octet-string body round-
 * trips through encode/decode, and a body larger than the receive buffer is
 * rejected rather than overflowing it. */
static void test_kmd(void)
{
    uint8_t ick[16], buf[256], frm[256];
    size_t out_len = sizeof(buf);
    size_t basic_end, pos, body;
    MkaPdu in, out;
    static const uint8_t name[12] = {'k', 'm', 'd', '.', 'e', 'x', 'a', 'm',
        'p', 'l', 'e', '1'};

    printf("MKPDU Key Management Domain (type 6) round-trip + oversized:\n");
    memset(ick, 0x88, sizeof(ick));

    memset(&in, 0, sizeof(in));
    fill_basic(&in.basic);
    in.kmd.present = 1;
    memcpy(in.kmd.kmd, name, sizeof(name));
    in.kmd.kmd_len = sizeof(name);
    CHECK(wm_Pdu_Encode(g_cmac, &in, ick, sizeof(ick), buf, sizeof(buf),
              &out_len) == MKA_OK,
        "encode kmd");
    CHECK(wm_Pdu_Decode(g_cmac, buf, out_len, ick, sizeof(ick), &out) == MKA_OK,
        "decode kmd");
    CHECK(out.kmd.present && (out.kmd.kmd_len == sizeof(name)),
        "kmd present + len");
    CHECK_EQ_MEM(out.kmd.kmd, name, sizeof(name), "kmd body");

    /* Splice a type-6 set whose declared body (80) exceeds MKA_MAX_KMD_LEN
     * (64), and confirm decode rejects it instead of overflowing the buffer. */
    memset(&in, 0, sizeof(in));
    fill_basic(&in.basic);
    out_len = sizeof(buf);
    (void)wm_Pdu_Encode(g_cmac, &in, ick, sizeof(ick), buf, sizeof(buf),
        &out_len);
    basic_end = out_len - (MKA_PARAM_HDR_LEN + MKA_DEFAULT_ICV_LEN);
    memcpy(frm, buf, basic_end);
    pos = basic_end;
    frm[pos++] = (uint8_t)MKA_PS_KMD;
    frm[pos++] = 0U;
    frm[pos++] = 0U;
    frm[pos++] = 80U; /* body length 80 > MKA_MAX_KMD_LEN (64) */
    memset(&frm[pos], 0xCD, 80U);
    pos += 80U;
    frm[pos++] = (uint8_t)MKA_PS_ICV_INDICATOR;
    frm[pos++] = 0U;
    frm[pos++] = 0U;
    frm[pos++] = (uint8_t)MKA_DEFAULT_ICV_LEN;
    body = (pos + MKA_DEFAULT_ICV_LEN) - EAPOL_HDR_LEN;
    frm[2] = (uint8_t)(body >> 8);
    frm[3] = (uint8_t)(body & 0xFFU);
    test_seal_icv(g_cmac, ick, sizeof(ick), frm, pos);
    out_len = pos + MKA_DEFAULT_ICV_LEN;
    CHECK(wm_Pdu_Decode(g_cmac, frm, out_len, ick, sizeof(ick), &out) ==
              MKA_ERR_PARSE,
        "oversized kmd body rejected");
}
#endif /* WOLFMKA_KMD */

/* The ICV is the last 16 octets of the MKPDU *body*. Measuring the frame
 * instead admits declared body lengths of 12..15, for which the authenticated
 * region shrinks to nothing and the "received ICV" starts inside the EAPOL
 * header (skoll M: ICV-length guard off by EAPOL_HDR_LEN). */
static void test_pdu_short_body_rejected(void)
{
    uint8_t ick[16];
    uint8_t frm[32];
    MkaPdu out;
    MkaBasicParamSet basic;
    size_t body;

    printf("body too short to hold an ICV is rejected:\n");
    memset(ick, 0x66, sizeof ick);

    for (body = 12U; body < MKA_DEFAULT_ICV_LEN; body++) {
        memset(frm, 0xA5, sizeof frm);
        frm[0] = (uint8_t)EAPOL_VERSION_2010;
        frm[1] = (uint8_t)EAPOL_TYPE_MKA;
        frm[2] = 0U;
        frm[3] = (uint8_t)body;
        CHECK(wm_Pdu_Decode(g_cmac, frm, EAPOL_HDR_LEN + body, ick, sizeof ick,
                  &out) == MKA_ERR_PARSE,
            "short body rejected on decode");
        CHECK(wm_Pdu_PeekBasic(frm, EAPOL_HDR_LEN + body, &basic) ==
                  MKA_ERR_PARSE,
            "short body rejected on peek");
    }

    /* Bodies long enough to hold the ICV but leaving less than a parameter-set
     * header for the mandatory Basic set. The peek reaches this without
     * verifying an ICV, so the case holds however the ICV is computed. */
    for (body = MKA_DEFAULT_ICV_LEN;
        body < (MKA_DEFAULT_ICV_LEN + MKA_PARAM_HDR_LEN); body++) {
        memset(frm, 0xA5, sizeof frm);
        frm[0] = (uint8_t)EAPOL_VERSION_2010;
        frm[1] = (uint8_t)EAPOL_TYPE_MKA;
        frm[2] = 0U;
        frm[3] = (uint8_t)body;
        CHECK(wm_Pdu_PeekBasic(frm, EAPOL_HDR_LEN + body, &basic) ==
                  MKA_ERR_PARSE,
            "no room for a Basic set is rejected on peek");
    }
}

/* A parameter set must not be allowed to reach into the trailing ICV: those
 * octets are not payload, and a set declared long enough to swallow them would
 * be handed to a parameter-set decoder as if they were (skoll M: walk bounded
 * against the whole body). */
static void test_pdu_set_cannot_eat_icv(void)
{
    uint8_t ick[16], buf[256];
    size_t out_len = sizeof(buf);
    MkaPdu in, out;

    printf("a parameter set cannot consume the ICV:\n");
    memset(ick, 0x66, sizeof ick);
    memset(&in, 0, sizeof in);
    fill_basic(&in.basic);
    CHECK(wm_Pdu_Encode(g_cmac, &in, ick, sizeof(ick), buf, sizeof(buf),
              &out_len) == MKA_OK,
        "encode a Basic-only frame");
    /* EAPOL(4) + Basic(40) + ICV Indicator(4) + ICV(16); the body is 60, so the
     * ICV starts at body offset 44. */
    CHECK(out_len == 64U, "frame is the expected length");
    CHECK(wm_Pdu_Decode(g_cmac, buf, out_len, ick, sizeof ick, &out) == MKA_OK,
        "it decodes before tampering");

    /* Replace the ICV Indicator with a set declaring a 16-octet body: that is
     * exactly the ICV region. */
    buf[44] = 6U; /* an unknown/optional type */
    buf[45] = 0U;
    buf[46] = 0U;
    buf[47] = (uint8_t)MKA_DEFAULT_ICV_LEN;
    reseal(buf, out_len, ick);
    CHECK(wm_Pdu_Decode(g_cmac, buf, out_len, ick, sizeof ick, &out) ==
              MKA_ERR_PARSE,
        "a set overlapping the ICV is rejected");

    /* A body that is nothing but the ICV leaves no room for the mandatory
     * Basic set at all.
     *
     * Not meaningful with WOLFMKA_ICV_L2_ADDR: there the ICV also covers an L2
     * prefix taken from the sender SCI at frame offset 8, which for a body this
     * short lies inside the ICV itself - sealing the frame rewrites the very
     * octets the prefix is derived from, so the check would fail on the seal
     * rather than on the missing Basic set. */
#ifndef WOLFMKA_ICV_L2_ADDR
    {
        uint8_t tiny[EAPOL_HDR_LEN + MKA_DEFAULT_ICV_LEN];
        memset(tiny, 0, sizeof tiny);
        tiny[0] = (uint8_t)EAPOL_VERSION_2010;
        tiny[1] = (uint8_t)EAPOL_TYPE_MKA;
        tiny[2] = 0U;
        tiny[3] = (uint8_t)MKA_DEFAULT_ICV_LEN;
        test_seal_icv(g_cmac, ick, sizeof ick, tiny, EAPOL_HDR_LEN);
        CHECK(wm_Pdu_Decode(g_cmac, tiny, sizeof tiny, ick, sizeof ick, &out) ==
                  MKA_ERR_PARSE,
            "a body holding only the ICV has no Basic set");
    }
#endif

    /* The ICV Indicator ends the walk, so a bogus one would hide every set
     * after it. It must sit immediately before the ICV and declare the ICV's
     * length. */
    out_len = sizeof(buf);
    memset(&in, 0, sizeof in);
    fill_basic(&in.basic);
    in.sak_use.present = 1;
    MKA_SAK_USE_SET_LATEST_RX(&in.sak_use);
    in.sak_use.latest_kn = 1U;
    CHECK(wm_Pdu_Encode(g_cmac, &in, ick, sizeof(ick), buf, sizeof(buf),
              &out_len) == MKA_OK,
        "encode with an optional set present");
    CHECK(wm_Pdu_Decode(g_cmac, buf, out_len, ick, sizeof ick, &out) == MKA_OK,
        "it decodes before tampering");
    /* Turn the SAK Use set at body offset 40 into an ICV Indicator: it is now
     * an indicator in the wrong place. */
    buf[EAPOL_HDR_LEN + 40U] = (uint8_t)MKA_PS_ICV_INDICATOR;
    reseal(buf, out_len, ick);
    CHECK(wm_Pdu_Decode(g_cmac, buf, out_len, ick, sizeof ick, &out) ==
              MKA_ERR_PARSE,
        "an ICV Indicator before the ICV region is rejected");

    /* And a well-formed one - type 255, declared length 16 - spliced in ahead
     * of the real one, so only its position gives it away. Everything the
     * splice pushes past it, the real indicator included, would go unread. */
    out_len = sizeof(buf);
    memset(&in, 0, sizeof in);
    fill_basic(&in.basic);
    CHECK(wm_Pdu_Encode(g_cmac, &in, ick, sizeof(ick), buf, sizeof(buf),
              &out_len) == MKA_OK,
        "re-encode");
    {
        const size_t tail = MKA_PARAM_HDR_LEN + MKA_DEFAULT_ICV_LEN;
        size_t new_len = out_len + tail;

        CHECK(new_len <= sizeof buf, "room to splice");
        memmove(&buf[out_len], &buf[out_len - tail], tail);
        buf[out_len - tail] = (uint8_t)MKA_PS_ICV_INDICATOR;
        buf[out_len - tail + 1U] = 0U;
        buf[out_len - tail + 2U] = 0U;
        buf[out_len - tail + 3U] = (uint8_t)MKA_DEFAULT_ICV_LEN;
        memset(&buf[out_len - tail + MKA_PARAM_HDR_LEN], 0xA5,
            MKA_DEFAULT_ICV_LEN);
        buf[2] = (uint8_t)((new_len - EAPOL_HDR_LEN) >> 8);
        buf[3] = (uint8_t)(new_len - EAPOL_HDR_LEN);
        reseal(buf, new_len, ick);
        CHECK(wm_Pdu_Decode(g_cmac, buf, new_len, ick, sizeof ick, &out) ==
                  MKA_ERR_PARSE,
            "an early ICV Indicator is rejected on position alone");
    }

    /* And one in the right place but declaring the wrong length. */
    memset(&in, 0, sizeof in);
    fill_basic(&in.basic);
    in.sak_use.present = 1;
    MKA_SAK_USE_SET_LATEST_RX(&in.sak_use);
    in.sak_use.latest_kn = 1U;
    out_len = sizeof(buf);
    CHECK(wm_Pdu_Encode(g_cmac, &in, ick, sizeof(ick), buf, sizeof(buf),
              &out_len) == MKA_OK,
        "re-encode");
    buf[out_len - MKA_DEFAULT_ICV_LEN - 1U] = 8U; /* declared body 8, not 16 */
    reseal(buf, out_len, ick);
    CHECK(wm_Pdu_Decode(g_cmac, buf, out_len, ick, sizeof ick, &out) ==
              MKA_ERR_PARSE,
        "an ICV Indicator with the wrong length is rejected");

    /* The mandatory Basic set is bounded the same way: a declared length that
     * reaches into the ICV would otherwise be read as CKN octets. Back to a
     * basic-only frame, so the widened set really does reach the ICV. */
    memset(&in, 0, sizeof in);
    fill_basic(&in.basic);
    out_len = sizeof(buf);
    CHECK(wm_Pdu_Encode(g_cmac, &in, ick, sizeof(ick), buf, sizeof(buf),
              &out_len) == MKA_OK,
        "re-encode");
    /* Basic set header is body[0..3]; widen its declared body from 34 to 50,
     * which pushes the set to 56 octets against a 44-octet pre-ICV region. */
    buf[EAPOL_HDR_LEN + 2U] &= 0xF0U;
    buf[EAPOL_HDR_LEN + 3U] = 50U;
    reseal(buf, out_len, ick);
    CHECK(wm_Pdu_Decode(g_cmac, buf, out_len, ick, sizeof ick, &out) ==
              MKA_ERR_PARSE,
        "a Basic set overlapping the ICV is rejected");
}

void run_pdu_tests(void)
{
    printf("\n== pdu ==\n");
    test_roundtrip_basic_only();
    test_roundtrip_full();
    test_dist_sak_explicit_cs();
    test_icv_tamper();
    test_pdu_golden_frame();
    test_peek();
    test_pdu_algo_agility();
    test_pdu_edge_cases();
    test_pdu_decode_negative();
    test_pdu_malformed();
    test_pdu_more_negative();
    test_pdu_invalid_params();
    test_pdu_no_icv_indicator();
    test_pdu_dist_sak_overlong();
    test_pdu_size_boundary();
    test_pdu_branch_combos();
#ifndef WOLFMKA_NO_ANNOUNCEMENTS
    test_announce_suite_cap();
    test_announce_semantic_negative();
#endif
    test_decode_forward_compatible_shapes();
#ifdef WOLFMKA_DISTRIBUTED_CAK
    test_dist_cak();
#endif
#ifdef WOLFMKA_KMD
    test_kmd();
#endif
    test_pdu_short_body_rejected();
    test_pdu_set_cannot_eat_icv();
}
