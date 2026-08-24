/**
 * @file fault_impl.h
 * The fault-injection hook the library calls through MKA_FI.
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
 * Shared by every suite that needs to drive a wolfSSL failure: the library
 * declares wm_Fault_Eval/Arm/Reset under WOLFMKA_FAULT_INJECT but does not
 * define them, so exactly one translation unit per test binary provides them.
 * Kept in a header rather than a .c so a suite picks it up by including it,
 * without changing what the delivered library links against.
 *
 * The state is file-static, so including this in more than one translation unit
 * of the same binary would give each its own copy - include it once.
 */

#ifndef MKA_TEST_FAULT_IMPL_H
#define MKA_TEST_FAULT_IMPL_H

#include "wolfmka/internal/mka_fault.h"

/* ---- the injection hook the library calls through MKA_FI ---------------- */
static int g_armed_site = MKA_FI_NONE;
static int g_armed_code;

/* A windowed arm: fail a contiguous run of calls at one site - skip the first
 * `skip`, fail the next `count`, then pass. Lets a test fail specific calls
 * (e.g. the 2nd and 3rd of four). */
static int g_win_site = MKA_FI_NONE;
static unsigned g_win_skip;
static unsigned g_win_count;
static unsigned g_win_seen;
static int g_win_code;

int wm_Fault_Eval(int site, int real_value)
{
    if ((site != MKA_FI_NONE) && (site == g_win_site)) {
        unsigned idx = g_win_seen;
        g_win_seen++;
        if ((idx >= g_win_skip) && (idx < (g_win_skip + g_win_count))) {
            return g_win_code;
        }
        return real_value;
    }
    if ((site != MKA_FI_NONE) && (site == g_armed_site)) {
        g_armed_site = MKA_FI_NONE; /* one-shot */
        return g_armed_code;
    }
    return real_value;
}
void wm_Fault_Arm(int site, int code)
{
    g_armed_site = site;
    g_armed_code = code;
}
void wm_Fault_Reset(void)
{
    g_armed_site = MKA_FI_NONE;
    g_win_site = MKA_FI_NONE;
    g_win_seen = 0U;
}

#endif /* MKA_TEST_FAULT_IMPL_H */
