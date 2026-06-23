/* fuzz_pdu.c
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
 * libFuzzer harness for the MKPDU decoder (wm_Pdu_Decode). The decoder
 * authenticates the trailing ICV before parsing, so each input is exercised
 * two ways:
 *
 *   - "raw": the fuzz bytes are decoded as-is. Most reject at the EAPOL header,
 *     the declared-length check or the ICV, exercising the malformed/truncated
 *     surface (FMEA FM-03) that guards against out-of-bounds reads.
 *   - "authentic": the fuzz bytes are wrapped as the parameter-set body of a
 *     well-formed frame and a VALID ICV is computed over them, so decoding
 *     passes authentication and drives the full parameter-set parser (the Basic
 *     set plus every optional set) on attacker-controlled content.
 *
 * Build/run with `make fuzz-pdu` (clang -fsanitize=fuzzer,address,undefined).
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "wolfmka/mka_kay.h"
#include "wolfmka/mka_pdu.h"
#include "wolfmka/mka_crypto.h"
#include "wolfmka/mka_types.h"

/* A fixed ICK: its only job is to be identical for the compute and the verify,
 * so the "authentic" frames pass and reach the parser. */
static const uint8_t g_ick[16] = {0x49, 0x43, 0x4B, 0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C};
static MkaCmacCtx* g_cmac;

int LLVMFuzzerInitialize(int* argc, char*** argv)
{
    (void)argc;
    (void)argv;
    g_cmac = wm_Crypto_CmacInit();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    uint8_t frame[MKA_MKPDU_MAX_LEN];
    uint8_t icv[MKA_DEFAULT_ICV_LEN];
    MkaPdu pdu;
    size_t params;
    size_t body_len;
    size_t covered;

    if (g_cmac == NULL) {
        return 0;
    }

    /* Raw path: arbitrary bytes straight into the decoder. */
    (void)wm_Pdu_Decode(g_cmac, data, size, g_ick, sizeof g_ick, &pdu);

    /* Authentic path: wrap the input as the body and forge a valid ICV. */
    params = size;
    if (params > sizeof(frame) - EAPOL_HDR_LEN - MKA_DEFAULT_ICV_LEN) {
        params = sizeof(frame) - EAPOL_HDR_LEN - MKA_DEFAULT_ICV_LEN;
    }
    body_len = params + MKA_DEFAULT_ICV_LEN;

    frame[0] = (uint8_t)EAPOL_VERSION_2010;
    frame[1] = (uint8_t)EAPOL_TYPE_MKA;
    frame[2] = (uint8_t)(body_len >> 8);
    frame[3] = (uint8_t)(body_len & 0xFFU);
    if (params != 0U) {
        memcpy(&frame[EAPOL_HDR_LEN], data, params);
    }

    covered = EAPOL_HDR_LEN + params;
    if (wm_Crypto_IcvCompute(g_cmac, g_ick, sizeof g_ick, frame, covered,
            icv) != MKA_OK) {
        return 0;
    }
    memcpy(&frame[covered], icv, MKA_DEFAULT_ICV_LEN);

    (void)wm_Pdu_Decode(g_cmac, frame, covered + MKA_DEFAULT_ICV_LEN, g_ick,
        sizeof g_ick, &pdu);
    return 0;
}
