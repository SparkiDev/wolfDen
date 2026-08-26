/* eap_derive.c
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
 * Derive a CAK/CKN pair from an EAP MSK and print them as hex - the wolfMKA
 * half of the Tier 3 interop check. The harness runs a real EAP exchange
 * between hostapd and wpa_supplicant, recovers the MSK and the CAK/CKN
 * wpa_supplicant derived from it, then runs this over the same inputs and
 * compares. Nothing here is MKA: it is purely IEEE Std 802.1X-2010 9.3.2.
 *
 *   eap_derive <msk-hex> <mac1> <mac2> <session-id-hex> <cak-octets>
 *
 * MACs are 12 hex digits. The MSK must be as long as the CAK (the MSK is the
 * KDF key in full, and its length selects AES-128 or AES-256 CMAC), which is
 * also what wpa_supplicant does - it clamps the MSK to the CAK length before
 * deriving.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wolfmka/mka_crypto.h"

static int unhex(const char* s, unsigned char* out, size_t cap, size_t* len)
{
    size_t n = strlen(s);
    size_t i;

    if (((n % 2u) != 0u) || ((n / 2u) > cap)) {
        return -1;
    }
    for (i = 0; i < n; i += 2) {
        unsigned v;
        if (sscanf(&s[i], "%2x", &v) != 1) {
            return -1;
        }
        out[i / 2] = (unsigned char)v;
    }
    *len = n / 2u;
    return 0;
}

static void put(const char* tag, const unsigned char* p, size_t n)
{
    size_t i;
    printf("%s=", tag);
    for (i = 0; i < n; i++) {
        printf("%02x", p[i]);
    }
    printf("\n");
}

int main(int argc, char** argv)
{
    unsigned char msk[MKA_MAX_CAK_LEN], m1[6], m2[6], sid[64];
    unsigned char cak[MKA_MAX_CAK_LEN], ckn[MKA_MAX_CKN_LEN];
    size_t msk_len, l1, l2, sid_len, cak_len;
    MkaCmacCtx* cmac;
    int rc = 1;

    if (argc != 6) {
        fprintf(stderr,
            "usage: %s <msk-hex> <mac1> <mac2> <session-id-hex> <cak-octets>\n",
            argv[0]);
        return 2;
    }
    cak_len = (size_t)strtoul(argv[5], NULL, 10);
    if ((unhex(argv[1], msk, sizeof msk, &msk_len) != 0) ||
        (unhex(argv[2], m1, sizeof m1, &l1) != 0) || (l1 != 6) ||
        (unhex(argv[3], m2, sizeof m2, &l2) != 0) || (l2 != 6) ||
        (unhex(argv[4], sid, sizeof sid, &sid_len) != 0)) {
        fprintf(stderr, "bad hex argument\n");
        return 2;
    }

    cmac = wm_Crypto_CmacInit();
    if (cmac == NULL) {
        fprintf(stderr, "cmac workspace unavailable\n");
        return 1;
    }
    if (wm_Crypto_DeriveCakFromMsk(cmac, msk, msk_len, m1, m2, cak, cak_len) !=
        MKA_OK) {
        fprintf(stderr, "CAK derivation failed (msk_len must equal cak_len)\n");
        goto out;
    }
    if (wm_Crypto_DeriveCknFromMsk(cmac, msk, msk_len, sid, sid_len, m1, m2,
            ckn, 16) != MKA_OK) {
        fprintf(stderr, "CKN derivation failed\n");
        goto out;
    }
    put("CAK", cak, cak_len);
    put("CKN", ckn, 16);
    rc = 0;
out:
    wm_Crypto_CmacFree(cmac);
    return rc;
}
