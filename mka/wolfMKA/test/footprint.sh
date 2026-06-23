#!/bin/sh
# footprint.sh - measure wolfMKA code size, large-object size and worst-case
# stack across representative build configurations.
#
# Copyright (C) 2006-2026 wolfSSL Inc.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Code size is the sum of each translation unit's .text/.data/.bss at -Os
# (pre-link, so an upper bound; the linker's --gc-sections drops the unused
# parts of whatever the application actually calls). Large objects are the
# caller-allocated control structures an integrator must budget for. Worst-case
# stack is the deepest single frame reported by -fstack-usage.
set -eu

CC=${CC:-gcc}
WS=${WOLFSSL_DIR:-../wolfssl/install-mka}
INC="-Iinclude -I$WS/include"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

FEATURE_OFF="-DWOLFMKA_NO_EAP -DWOLFMKA_NO_XPN -DWOLFMKA_NO_DELAY_PROTECT \
-DWOLFMKA_NO_RETRY -DWOLFMKA_NO_ANNOUNCEMENTS -DWOLFMKA_NO_AUTO_REKEY"
FEATURE_ON="-DWOLFMKA_DISTRIBUTED_CAK -DWOLFMKA_KMD -DWOLFMKA_SUSPENSION \
-DWOLFMKA_CIPHER_NEGOTIATION"

measure() {
    label=$1
    flags=$2
    text=0
    data=0
    bss=0
    maxstk=0
    for f in src/*.c; do
        $CC -Os -std=c99 $flags $INC -c "$f" -o "$TMP/o.o" 2>/dev/null || {
            printf '%-10s (does not build in this configuration)\n' "$label"
            return
        }
        set -- $(size "$TMP/o.o" | awk 'NR==2{print $1, $2, $3}')
        text=$((text + $1))
        data=$((data + $2))
        bss=$((bss + $3))
        $CC -Os -std=c99 $flags $INC -fstack-usage -c "$f" -o "$TMP/s.o" \
            2>/dev/null || continue
        if [ -f "$TMP/s.su" ]; then
            m=$(awk -F'\t' '{print $2+0}' "$TMP/s.su" | sort -n | tail -1)
            [ "${m:-0}" -gt "$maxstk" ] && maxstk=$m
            rm -f "$TMP/s.su"
        fi
    done

    cat >"$TMP/sz.c" <<'EOF'
#include <stdio.h>
#include "wolfmka/mka_kay.h"
int main(void)
{
    printf("%lu %lu %lu\n", (unsigned long)sizeof(MkaParticipant),
        (unsigned long)sizeof(MkaKay), (unsigned long)sizeof(MkaPdu));
    return 0;
}
EOF
    if $CC -std=c99 $flags $INC "$TMP/sz.c" -o "$TMP/sz" 2>/dev/null; then
        set -- $("$TMP/sz")
        part=$1
        kay=$2
        pdu=$3
    else
        part="?"
        kay="?"
        pdu="?"
    fi

    printf '%-10s %7s %6s %6s   %8s %8s %7s   %7s\n' \
        "$label" "$text" "$data" "$bss" "$part" "$kay" "$pdu" "$maxstk"
}

echo "wolfMKA footprint  (gcc -Os, bytes; code size is pre-link sum of all TUs)"
echo
printf '%-10s %7s %6s %6s   %8s %8s %7s   %7s\n' \
    "config" ".text" ".data" ".bss" "Particip" "Kay" "Pdu" "maxstk"
printf '%-10s %7s %6s %6s   %8s %8s %7s   %7s\n' \
    "----------" "-------" "------" "------" "--------" "--------" "-------" \
    "-------"
measure "default" ""
measure "minimal" "$FEATURE_OFF"
measure "embedded" "-DWOLFMKA_SMALL_STACK -DWOLFMKA_NO_MALLOC $FEATURE_OFF"
measure "full" "$FEATURE_ON"
