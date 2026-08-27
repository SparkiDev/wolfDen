/* wolfMKA ABI check against the linked wolfSSL.
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * wolfMKA embeds wolfSSL's WC_RNG and Cmac *by value* in its crypto pools
 * (src/mka_crypto.c), so that a WOLFMKA_SMALL_STACK / WOLFMKA_NO_MALLOC build
 * allocates nothing. That makes the size of those structures part of the ABI
 * between this project and libwolfssl - and both of them are conditional on
 * the C standard the compiler is in:
 *
 *     wolfssl/wolfcrypt/types.h defines HAVE_ANONYMOUS_INLINE_AGGREGATES only
 *     when __STDC_VERSION__ >= 201101L, because anonymous union/struct members
 *     are a C11 feature. Under that macro random.h wraps the DRBG members in
 *     an anonymous struct, whose size rounds up to its own 8-byte alignment
 *     and shifts every field after it.
 *
 * On x86-64 that is sizeof(WC_RNG) == 48 under -std=c99 or -std=gnu99 and 56
 * from -std=c11 upwards. wolfMKA compiles at -std=c99; a wolfSSL built at the
 * autotools default (gnu17) therefore writes eight octets past the end of the
 * WC_RNG this build reserved - straight into the neighbouring `used` flag of
 * the pool slot. The damage is normally invisible, because the very next
 * statement assigns that flag; it surfaces only on a path that returns early,
 * which is why `make test-fault` was the one target that failed.
 *
 * This program reproduces the pool layout and puts a guard immediately after
 * each embedded structure, exactly where the real `used` flag sits. It is
 * compiled with the project's own CFLAGS and linked against the configured
 * WOLFSSL_DIR, so it fails whenever those two disagree.
 *
 * The fix is never to pad or reorder anything here: build wolfSSL with the
 * same -std wolfMKA uses.
 */

#include <stdio.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/cmac.h>
#include <wolfssl/wolfcrypt/random.h>

#define GUARD_LEN  32
#define GUARD_BYTE 0xA5

/* Mirrors struct MkaRandom / struct MkaCmacCtx: the wolfSSL object followed
 * immediately by wolfMKA's own bookkeeping. */
typedef struct {
    WC_RNG rng;
    unsigned char guard[GUARD_LEN];
} RngSlot;

typedef struct {
    Cmac cmac;
    unsigned char guard[GUARD_LEN];
} CmacSlot;

/* Returns how far past the end of the structure the library wrote: the index
 * of the last clobbered guard octet, plus one. Counting from the last one
 * rather than the first matters because an overrun octet can coincidentally
 * equal the guard byte, and because the reach of the overrun - not where it
 * happens to start - is what identifies the size disagreement. */
static int guard_overrun(const unsigned char* g)
{
    int i;
    int last = -1;

    for (i = 0; i < GUARD_LEN; i++) {
        if (g[i] != (unsigned char)GUARD_BYTE) {
            last = i;
        }
    }
    return (last < 0) ? -1 : (last + 1);
}

static void report(const char* what, size_t sz, int over)
{
    if (over < 0) {
        printf("  %-8s sizeof=%-4zu OK\n", what, sz);
    }
    else {
        printf("  %-8s sizeof=%-4zu OVERRUN: libwolfssl wrote at least %d "
               "octet(s) past the end (this build reserved %zu)\n",
            what, sz, over, sz);
    }
}

int main(void)
{
    static RngSlot r;
    static CmacSlot c;
    unsigned char key[16];
    int rng_bad;
    int cmac_bad;
    int rc;

    printf("wolfMKA <-> wolfSSL ABI check "
           "(__STDC_VERSION__=%ld)\n",
#ifdef __STDC_VERSION__
        (long)__STDC_VERSION__
#else
        -1L
#endif
    );

    memset(&r, 0, sizeof r);
    memset(r.guard, GUARD_BYTE, sizeof r.guard);
    rc = wc_InitRng_ex(&r.rng, NULL, INVALID_DEVID);
    if (rc != 0) {
        printf("  wc_InitRng_ex failed (%d) - cannot check\n", rc);
        return 2;
    }
    rng_bad = guard_overrun(r.guard);
    report("WC_RNG", sizeof(WC_RNG), rng_bad);
    (void)wc_FreeRng(&r.rng);

    memset(&c, 0, sizeof c);
    memset(c.guard, GUARD_BYTE, sizeof c.guard);
    memset(key, 0x0B, sizeof key);
    rc = wc_InitCmac_ex(&c.cmac, key, (word32)sizeof key, WC_CMAC_AES, NULL,
        NULL, INVALID_DEVID);
    if (rc != 0) {
        printf("  wc_InitCmac_ex failed (%d) - cannot check\n", rc);
        return 2;
    }
    cmac_bad = guard_overrun(c.guard);
    report("Cmac", sizeof(Cmac), cmac_bad);

    if ((rng_bad >= 0) || (cmac_bad >= 0)) {
        printf(
            "\n"
            "ABI MISMATCH: libwolfssl and wolfMKA disagree on the size of a\n"
            "structure wolfMKA embeds by value, so every pool slot is\n"
            "corrupted as it is initialised.\n"
            "\n"
            "wolfSSL must be built with the same -std as wolfMKA. wolfMKA\n"
            "uses -std=c99 by default, so configure wolfSSL with:\n"
            "\n"
            "    ./configure --prefix=<WOLFSSL_DIR> --enable-cmac \\\n"
            "        --enable-aeskeywrap --enable-aesgcm \\\n"
            "        CFLAGS=\"-std=c99 -O2\"\n"
            "\n"
            "If wolfMKA's CFLAGS name a different standard, match that one\n"
            "instead - a separate wolfSSL build per standard is expected.\n");
        return 1;
    }
    printf("  wolfSSL and wolfMKA agree on both layouts\n");
    return 0;
}
