/* mka_bytes.h
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
 * Internal big-endian (network order) octet serialization helpers shared by the
 * MKPDU codec (mka_pdu.c) and the crypto layer (mka_crypto.c). These operate on
 * raw buffers; the MKPDU writer wraps them with cursor bookkeeping
 * (mka_w_be16 / mka_w_be32 in mka_pdu.c). Not part of the public wolfMKA API.
 *
 * Part of wolfMKA - an MKA implementation using wolfSSL for cryptography.
 */

#ifndef WOLFMKA_BYTES_H
#define WOLFMKA_BYTES_H

/* MKA_INLINE, uintN_t, MKA_MAC_LEN, endianness, MEMCPY */
#include "mka_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * On a big-endian host the value's native representation already matches the
 * wire, so it is copied whole (one load/store; documented MISRA Rule 21.15
 * deviation, see MISRA.md); otherwise the octets are written/read
 * most-significant first. Reads of 16/32-bit values use the byte-shift form on
 * every host (no deviation), recognised as a single load at -O2.
 */

/**
 * Write a 16-bit value to 2 octets in big-endian order.
 * @param[out] p  Destination, at least 2 octets.
 * @param[in]  v  Value to store.
 */
static MKA_INLINE void w_be16(uint8_t* p, uint16_t v)
{
#ifdef WOLFMKA_BIG_ENDIAN
    (void)WOLFMKA_MEMCPY(p, &v, sizeof(v));
#else
    p[0] = (uint8_t)(v >> 8U);
    p[1] = (uint8_t)v;
#endif
}

/**
 * Write a 32-bit value to 4 octets in big-endian order.
 * @param[out] p  Destination, at least 4 octets.
 * @param[in]  v  Value to store.
 */
static MKA_INLINE void w_be32(uint8_t* p, uint32_t v)
{
#ifdef WOLFMKA_BIG_ENDIAN
    (void)WOLFMKA_MEMCPY(p, &v, sizeof(v));
#else
    p[0] = (uint8_t)(v >> 24U);
    p[1] = (uint8_t)(v >> 16U);
    p[2] = (uint8_t)(v >> 8U);
    p[3] = (uint8_t)v;
#endif
}

/**
 * Write the low 48 bits of a value to 6 octets in big-endian order.
 * @param[out] p  Destination, at least 6 octets.
 * @param[in]  v  Value whose low 48 bits are stored.
 */
static MKA_INLINE void w_be48(uint8_t* p, uint64_t v)
{
#ifdef WOLFMKA_BIG_ENDIAN
    /* left-align the 48-bit value into the top 6 */
    uint64_t tmp = v << 16U;
    (void)WOLFMKA_MEMCPY(p, &tmp, MKA_MAC_LEN);
#else
    p[0] = (uint8_t)(v >> 40U);
    p[1] = (uint8_t)(v >> 32U);
    p[2] = (uint8_t)(v >> 24U);
    p[3] = (uint8_t)(v >> 16U);
    p[4] = (uint8_t)(v >> 8U);
    p[5] = (uint8_t)v;
#endif
}

/**
 * Write a 64-bit value to 8 octets in big-endian order.
 * @param[out] p  Destination, at least 8 octets.
 * @param[in]  v  Value to store.
 */
static MKA_INLINE void w_be64(uint8_t* p, uint64_t v)
{
#ifdef WOLFMKA_BIG_ENDIAN
    (void)WOLFMKA_MEMCPY(p, &v, sizeof(v));
#else
    p[0] = (uint8_t)(v >> 56U);
    p[1] = (uint8_t)(v >> 48U);
    p[2] = (uint8_t)(v >> 40U);
    p[3] = (uint8_t)(v >> 32U);
    p[4] = (uint8_t)(v >> 24U);
    p[5] = (uint8_t)(v >> 16U);
    p[6] = (uint8_t)(v >> 8U);
    p[7] = (uint8_t)v;
#endif
}

/**
 * Read a big-endian 16-bit value.
 * @param[in] p  Source, at least 2 octets.
 * @return The decoded value.
 */
static MKA_INLINE uint16_t rd_be16(const uint8_t* p)
{
    return (uint16_t)(((uint16_t)p[0] << 8U) | (uint16_t)p[1]);
}

/**
 * Read a big-endian 32-bit value.
 * @param[in] p  Source, at least 4 octets.
 * @return The decoded value.
 */
static MKA_INLINE uint32_t rd_be32(const uint8_t* p)
{
    return ((uint32_t)p[0] << 24U) | ((uint32_t)p[1] << 16U) |
           ((uint32_t)p[2] << 8U) | (uint32_t)p[3];
}

/**
 * Read a 48-bit big-endian value (a MAC address) from 6 octets.
 * @param[in] p  Source, at least 6 octets.
 * @return The value in the low 48 bits.
 */
static MKA_INLINE uint64_t rd_be48(const uint8_t* p)
{
#ifdef WOLFMKA_BIG_ENDIAN
    /* load into the top 6 octets, then shift down */
    uint64_t v = 0U;
    (void)WOLFMKA_MEMCPY(&v, p, MKA_MAC_LEN);
    return v >> 16U;
#else
    return ((uint64_t)p[0] << 40U) | ((uint64_t)p[1] << 32U) |
           ((uint64_t)p[2] << 24U) | ((uint64_t)p[3] << 16U) |
           ((uint64_t)p[4] << 8U) | (uint64_t)p[5];
#endif
}

/**
 * Read a big-endian 64-bit value from 8 octets.
 * @param[in] p  Source, at least 8 octets.
 * @return The decoded value.
 */
static MKA_INLINE uint64_t rd_be64(const uint8_t* p)
{
#ifdef WOLFMKA_BIG_ENDIAN
    uint64_t v = 0U;
    (void)WOLFMKA_MEMCPY(&v, p, sizeof(v));
    return v;
#else
    return ((uint64_t)p[0] << 56U) | ((uint64_t)p[1] << 48U) |
           ((uint64_t)p[2] << 40U) | ((uint64_t)p[3] << 32U) |
           ((uint64_t)p[4] << 24U) | ((uint64_t)p[5] << 16U) |
           ((uint64_t)p[6] << 8U) | (uint64_t)p[7];
#endif
}

#ifdef __cplusplus
}
#endif

#endif /* WOLFMKA_BYTES_H */
