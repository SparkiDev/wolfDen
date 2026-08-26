/* mka_status.c  -  human-readable names for MkaStatus return codes.
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

#include "wolfmka/mka_types.h"

/* A switch with an explicit case per code keeps the mapping exhaustive; the
 * default covers any out-of-range value. */
const char* wm_Status_String(MkaStatus status)
{
    const char* s;

    switch (status) {
        case MKA_OK: s = "MKA_OK"; break;
        case MKA_ERR_BAD_ARG: s = "MKA_ERR_BAD_ARG"; break;
        case MKA_ERR_CRYPTO: s = "MKA_ERR_CRYPTO"; break;
        case MKA_ERR_BUFFER: s = "MKA_ERR_BUFFER"; break;
        case MKA_ERR_PARSE: s = "MKA_ERR_PARSE"; break;
        case MKA_ERR_ICV: s = "MKA_ERR_ICV"; break;
        case MKA_ERR_VERSION: s = "MKA_ERR_VERSION"; break;
        case MKA_ERR_NO_PEER: s = "MKA_ERR_NO_PEER"; break;
        case MKA_ERR_STATE: s = "MKA_ERR_STATE"; break;
        case MKA_ERR_FULL: s = "MKA_ERR_FULL"; break;
        case MKA_ERR_NOT_KS: s = "MKA_ERR_NOT_KS"; break;
        case MKA_ERR_INTERNAL: s = "MKA_ERR_INTERNAL"; break;
        case MKA_ERR_REPLAY: s = "MKA_ERR_REPLAY"; break;
        case MKA_ERR_REKEY_BUSY: s = "MKA_ERR_REKEY_BUSY"; break;
        default: s = "MKA_ERR_UNKNOWN"; break;
    }
    return s;
}
