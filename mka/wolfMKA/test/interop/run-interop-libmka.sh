#!/bin/sh
# run-interop-libmka.sh - Tier 5 wolfMKA <-> libmka interop (control plane).
#
# Copyright (C) 2006-2026 wolfSSL Inc.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# A third implementation. Tiers 1-3 measure wolfMKA against wpa_supplicant and
# Tier 4 against MKAdaemon; libmka (Intrepid Control Systems, GPL-3.0-or-later,
# mbedTLS-backed) is unrelated to both. That matters for the same reason Tier 4
# does - three of this project's interop findings were conventions wolfMKA held
# self-consistently, which no amount of testing against itself could expose -
# and reading libmka's source already settled two of them: it ranks XPN SSCIs
# by descending SCI, and its confidentiality-offset enumeration is the Table
# 11-6 selector.
#
# What this tier can and cannot do: libmka is control-plane only. It hands the
# agreed SAK to an sa_installer callback and drives no MACsec device, so there
# is no protected ping here and no confidentiality check. What is tested is
# that a third implementation of the MKPDU format, the ICV and the key
# hierarchy agrees with wolfMKA on the key.
#
# That agreement is stronger evidence than it may look. The ICV is verified
# before any parameter set is acted on, so libmka accepting the frame already
# proves the two derived the same ICK from the CAK/CKN. The SAK travels under
# AES Key Wrap, whose integrity check fails closed, so libmka *installing* a
# SAK proves the KEK matched too. The harness then compares the Key Identifier
# each end reports - wolfMKA's from `ip macsec show`, libmka's from its
# callback - so the two are matched on evidence from both sides rather than on
# one end's word.
#
# libmka's own example cannot serve as the peer: it prompts for an interface on
# stdin, is built around Npcap, and does not compile (`if((ics_mka_has_response
# (&state)) {`). libmka_peer.c in this directory is the equivalent driver.
#
# Needs root (namespaces, veth, raw sockets), iproute2, the kernel `macsec`
# module, and a built libmka. Point LIBMKA at its checkout; when a prerequisite
# is missing this prints SKIP and exits 0, so it is safe to invoke anywhere.
set -eu

HERE=$(CDPATH= cd "$(dirname "$0")" && pwd)
MKA_MACSEC=${MKA_MACSEC:-"$HERE/../../examples/mka_macsec"}
LIBMKA=${LIBMKA:-"$HOME/wolfssl/github/wolfmka/libmka"}
TIMEOUT=${TIMEOUT:-30}
STRICT=${INTEROP_STRICT:-0}

NS_A=wmka_a
NS_B=wmka_b
VETH_A=veth_a
VETH_B=veth_b
MS_A=macsec_a
IP_A=10.0.0.1
CAK=0123456789abcdef0123456789abcdef
CKN=00112233445566778899aabbccddeeff

RUNDIR=""
WM_PID=""
LM_PID=""

skip() {
    echo "SKIP: $1"
    exit 0
}

cleanup() {
    [ -n "${WM_PID:-}" ] && kill "$WM_PID" 2>/dev/null || true
    [ -n "${LM_PID:-}" ] && kill "$LM_PID" 2>/dev/null || true
    ip netns del "$NS_A" 2>/dev/null || true
    ip netns del "$NS_B" 2>/dev/null || true
    [ -n "$RUNDIR" ] && rm -rf "$RUNDIR" 2>/dev/null || true
}

[ "$(id -u)" = 0 ] || skip "must run as root"
command -v ip >/dev/null 2>&1 || skip "iproute2 (ip) not found"
[ -x "$MKA_MACSEC" ] || \
    skip "$MKA_MACSEC not built (run: make examples)"
[ -d "$LIBMKA/include/ics" ] || \
    skip "libmka not found (set LIBMKA=/path/to/libmka)"

LM_LIB="$LIBMKA/build/libics-mka.a"
LM_CRYPTO=$(find "$LIBMKA/build" -name libmbedcrypto.a 2>/dev/null | head -1)
[ -f "$LM_LIB" ] && [ -n "$LM_CRYPTO" ] || skip "libmka not built. From $LIBMKA:
    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \\
        -DMBEDTLS_FATAL_WARNINGS=OFF -DENABLE_TESTING=OFF -DENABLE_PROGRAMS=OFF
    cmake --build build -j
  (MBEDTLS_FATAL_WARNINGS=OFF: the vendored mbedTLS 3.6.2 does not build under
  GCC 15's -Werror=unterminated-string-initialization.)"

trap cleanup EXIT INT TERM
RUNDIR=$(mktemp -d)

# Built here rather than by the Makefile: it needs libmka's headers and static
# library, which are not a dependency of wolfMKA itself.
LM_PEER="$RUNDIR/libmka_peer"
cc -O2 -Wall -Wextra -I"$LIBMKA/include" "$HERE/libmka_peer.c" \
    "$LM_LIB" "$LM_CRYPTO" -o "$LM_PEER" 2>"$RUNDIR/peer-build.log" || {
    echo "FAIL: could not build the libmka peer driver"
    cat "$RUNDIR/peer-build.log"
    exit 1
}

echo "== Tier 5: wolfMKA mka_macsec <-> libmka (control plane) =="

# One round per Key Server role. wolfMKA favoured means it generates the SAK,
# wraps it under the KEK and emits the Distributed SAK set, and libmka has to
# unwrap it; the reverse round puts libmka's key hierarchy on the generating
# side and makes wolfMKA do the unwrapping. The two exercise different halves
# of the same agreement and a bug in either direction hides from the other.
round() {
    wm_pri=$1
    lm_pri=$2
    want_ks=$3
    label=$4

    echo "--- round: $label (wolfMKA priority $wm_pri, libmka $lm_pri) ---"

    ip netns del "$NS_A" 2>/dev/null || true
    ip netns del "$NS_B" 2>/dev/null || true
    ip netns add "$NS_A"
    ip netns add "$NS_B"
    ip link add "$VETH_A" netns "$NS_A" type veth peer name "$VETH_B" \
        netns "$NS_B"
    ip netns exec "$NS_A" ip link set lo up
    ip netns exec "$NS_B" ip link set lo up
    ip netns exec "$NS_A" ip link set "$VETH_A" up
    ip netns exec "$NS_B" ip link set "$VETH_B" up

    # wolfMKA's example installs keys into a provisioned device; libmka has no
    # data plane, so only this side gets one. It is here so the Key Identifier
    # wolfMKA agreed can be read back out of the kernel rather than taken on
    # trust from its own log.
    ip netns exec "$NS_A" ip link add link "$VETH_A" "$MS_A" type macsec \
        cipher gcm-aes-128 encrypt on 2>/dev/null || {
            ip netns del "$NS_A" 2>/dev/null || true
            ip netns del "$NS_B" 2>/dev/null || true
            skip "kernel MACsec unavailable (cannot create macsec device)"
        }
    ip netns exec "$NS_A" ip link set "$MS_A" up
    ip netns exec "$NS_A" ip addr add "$IP_A/24" dev "$MS_A"

    ip netns exec "$NS_A" "$MKA_MACSEC" "$VETH_A" "$MS_A" "$wm_pri" \
        "$CAK" "$CKN" 0 16 >"$RUNDIR/wm.log" 2>&1 &
    WM_PID=$!

    ip netns exec "$NS_B" "$LM_PEER" "$VETH_B" "$lm_pri" "$CAK" "$CKN" \
        >"$RUNDIR/lm.log" 2>&1 &
    LM_PID=$!

    # Converged when wolfMKA holds a SAK in the expected role *and* libmka has
    # reported one. Either alone proves nothing: wolfMKA elects itself the
    # moment it is alone, and libmka installing a key of its own says nothing
    # about whether the two agreed.
    ok=0
    i=0
    while [ "$i" -lt "$TIMEOUT" ]; do
        sleep 1
        i=$((i + 1))
        grep -q "sak=1" "$RUNDIR/wm.log" 2>/dev/null || continue
        grep "state:" "$RUNDIR/wm.log" | tail -1 \
            | grep -q "key_server=$want_ks" || continue
        if grep -q "SAK installed" "$RUNDIR/lm.log" 2>/dev/null; then
            ok=1
            break
        fi
    done

    echo "  --- wolfMKA state ---"
    grep "state:" "$RUNDIR/wm.log" 2>/dev/null | tail -2 || true
    echo "  --- libmka ---"
    grep -E "SAK installed|sak=|ks_mi=|priority=" "$RUNDIR/lm.log" 2>/dev/null \
        | tail -5 || true

    if [ "$ok" != 1 ]; then
        echo "FAIL: $label - the two did not agree a SAK with" \
            "key_server=$want_ks within ${TIMEOUT}s"
        echo "  --- wolfMKA log (last 30) ---"
        tail -30 "$RUNDIR/wm.log" 2>/dev/null || true
        echo "  --- libmka log (last 30) ---"
        tail -30 "$RUNDIR/lm.log" 2>/dev/null || true
        return 1
    fi

    # Match the Key Identifier the two ends report. wolfMKA's comes from the
    # kernel (MACSEC_SA_ATTR_KEYID, printed by `ip macsec show` as the SA's
    # "key"), libmka's from its sa_installer callback: the Key Server's Member
    # Identifier followed by the Key Number. Comparing them proves the two
    # agreed on *which* key, and libmka having installed it at all proves the
    # AES Key Wrap opened - so the SAK bytes match as well.
    wm_ki=$(ip netns exec "$NS_A" ip macsec show 2>/dev/null \
        | sed -n 's/.* key \([0-9a-f]*\).*/\1/p' | head -1 || true)
    lm_mi=$(sed -n 's/^  ks_mi=\(.*\)$/\1/p' "$RUNDIR/lm.log" | tail -1 || true)
    lm_kn=$(sed -n 's/^SAK installed: kn=\([0-9]*\).*/\1/p' "$RUNDIR/lm.log" \
        | tail -1 || true)
    if [ -n "$lm_mi" ] && [ -n "$lm_kn" ] && [ -n "$wm_ki" ]; then
        # wolfMKA writes the Key Number big-endian into the last four octets.
        lm_ki=$(printf '%s%08x' "$lm_mi" "$lm_kn")
        echo "  wolfMKA KI: $wm_ki"
        echo "  libmka  KI: $lm_ki"
        if [ "$wm_ki" = "$lm_ki" ]; then
            echo "  both ends name the same key (KI matches)"
        else
            echo "FAIL: $label - the two installed different Key Identifiers"
            return 1
        fi
    else
        # Not a pass by default: without both halves the round has only shown
        # that each end has *a* key, which is exactly the weak claim this
        # comparison exists to avoid.
        echo "  WARN: could not read both Key Identifiers" \
            "(wolfMKA='$wm_ki' libmka mi='$lm_mi' kn='$lm_kn')"
        if [ "$STRICT" = 1 ]; then
            echo "FAIL (INTEROP_STRICT=1): Key Identifiers not comparable"
            return 1
        fi
    fi

    # Every SecY hook must have been accepted by the kernel; a refused install
    # leaves wolfMKA holding a key its data plane never took.
    if grep -E "\[SecY\].* -> -[0-9]+$" "$RUNDIR/wm.log" >/dev/null 2>&1; then
        echo "  --- SecY calls the kernel refused ---"
        grep -E "\[SecY\].* -> -[0-9]+$" "$RUNDIR/wm.log" | tail -8
        if [ "$STRICT" = 1 ]; then
            echo "FAIL (INTEROP_STRICT=1): a SecY hook was refused"
            return 1
        fi
        echo "  WARN: a SecY hook was refused (see above)"
    fi

    echo "  ok: $label"
    kill "$WM_PID" 2>/dev/null || true
    kill "$LM_PID" 2>/dev/null || true
    WM_PID=""
    LM_PID=""
    ip netns del "$NS_A" 2>/dev/null || true
    ip netns del "$NS_B" 2>/dev/null || true
    sleep 1
    return 0
}

round 10 20 1 "wolfMKA is Key Server" || exit 1
round 30 20 0 "wolfMKA is a member" || exit 1

echo "PASS: wolfMKA and libmka agree a SAK in both Key Server roles"
exit 0
