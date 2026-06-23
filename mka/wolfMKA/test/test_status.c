/* test_status.c - exhaustive coverage of wm_Status_String (all codes +
 * default).
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
 */

#include "test_util.h"
#include "wolfmka/mka_types.h"

#include <string.h>

/* Every MkaStatus value maps to its own name, and any out-of-range value maps
 * to "MKA_ERR_UNKNOWN" - exercising every switch case and the default. */
static void test_status_strings(void)
{
    struct {
        MkaStatus code;
        const char* name;
    } v[] = {
        {MKA_OK, "MKA_OK"},
        {MKA_ERR_BAD_ARG, "MKA_ERR_BAD_ARG"},
        {MKA_ERR_CRYPTO, "MKA_ERR_CRYPTO"},
        {MKA_ERR_BUFFER, "MKA_ERR_BUFFER"},
        {MKA_ERR_PARSE, "MKA_ERR_PARSE"},
        {MKA_ERR_ICV, "MKA_ERR_ICV"},
        {MKA_ERR_VERSION, "MKA_ERR_VERSION"},
        {MKA_ERR_NO_PEER, "MKA_ERR_NO_PEER"},
        {MKA_ERR_STATE, "MKA_ERR_STATE"},
        {MKA_ERR_FULL, "MKA_ERR_FULL"},
        {MKA_ERR_NOT_KS, "MKA_ERR_NOT_KS"},
        {MKA_ERR_INTERNAL, "MKA_ERR_INTERNAL"},
        {MKA_ERR_REPLAY, "MKA_ERR_REPLAY"},
    };
    size_t i;

    printf("wm_Status_String (all codes + unknown):\n");
    for (i = 0; i < sizeof(v) / sizeof(v[0]); i++) {
        CHECK(strcmp(wm_Status_String(v[i].code), v[i].name) == 0, v[i].name);
    }
    /* A value outside the enumeration hits the default clause. */
    CHECK(strcmp(wm_Status_String((MkaStatus)1), "MKA_ERR_UNKNOWN") == 0,
        "unknown positive code");
    CHECK(strcmp(wm_Status_String((MkaStatus)-99), "MKA_ERR_UNKNOWN") == 0,
        "unknown negative code");
}

void run_status_tests(void)
{
    printf("\n== status ==\n");
    test_status_strings();
}
