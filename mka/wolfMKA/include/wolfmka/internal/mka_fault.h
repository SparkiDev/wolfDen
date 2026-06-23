/* mka_fault.h
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
 * Fault-injection hook for otherwise-unreachable error branches.
 *
 * Several error paths in the crypto-binding layer only execute when an
 * underlying wolfSSL primitive fails (e.g. AES-CMAC, the RNG, AES Key Wrap).
 * With valid inputs those primitives never fail, so the corresponding
 * "return MKA_ERR_CRYPTO" branches cannot be reached by ordinary tests.
 *
 * To make them testable, each such call site routes its return value through
 * MKA_FI(site, expr). In a normal build MKA_FI expands to the bare expression
 * with zero overhead and no change in behaviour - the `site` argument is
 * discarded by the preprocessor and never reaches the compiler. Only when
 * WOLFMKA_FAULT_INJECT is defined (test builds) does MKA_FI route through a
 * programmable hook that a test can arm to force a chosen return value.
 *
 * This header therefore adds no code, types, or symbols to a production build.
 */

#ifndef WOLFMKA_FAULT_H
#define WOLFMKA_FAULT_H

#ifdef WOLFMKA_FAULT_INJECT

    #ifdef __cplusplus
extern "C" {
    #endif

/* Injectable call sites. */
typedef enum {
    MKA_FI_NONE = 0,
    /* wc_AesCmacGenerate */
    MKA_FI_CMAC,
    /* wc_InitRng */
    MKA_FI_RNG_INIT,
    /* wc_RNG_GenerateBlock */
    MKA_FI_RNG_GEN,
    /* wc_AesKeyWrap */
    MKA_FI_KEYWRAP,
    /* wc_AesKeyUnWrap */
    MKA_FI_KEYUNWRAP,
    /* MKPDU body-length overflow check (encode) */
    MKA_FI_BODY_LEN,
    MKA_FI_SITE_COUNT
} MkaFaultSite;

/**
 * Evaluate an injectable call site.
 * @param[in] site        the call-site identifier.
 * @param[in] real_value  the value the real call produced.
 * @return real_value, unless a test has armed an override for site, in which
 *         case the armed code is returned and the override auto-disarms.
 */
int wm_Fault_Eval(int site, int real_value);

/** Arm: the next evaluation at site returns code, then auto-disarms. */
void wm_Fault_Arm(int site, int code);

/** Disarm every site. */
void wm_Fault_Reset(void);

    #ifdef __cplusplus
}
    #endif

    #define MKA_FI(site, expr) wm_Fault_Eval((int)(site), (int)(expr))

#else /* !WOLFMKA_FAULT_INJECT - production: zero overhead, no symbols */

    #define MKA_FI(site, expr) (expr)

#endif /* WOLFMKA_FAULT_INJECT */

#endif /* WOLFMKA_FAULT_H */
