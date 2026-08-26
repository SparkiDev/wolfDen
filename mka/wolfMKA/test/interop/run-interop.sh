#!/bin/sh
# run-interop.sh - Tier 1 wolfMKA <-> wpa_supplicant control-plane interop.
#
# Copyright (C) 2006-2026 wolfSSL Inc.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Stands two MKA implementations back-to-back over a veth pair in separate
# network namespaces - wolfMKA's `mka_link` on one side, wpa_supplicant's MKA on
# the other - sharing one pre-shared CAK/CKN, and verifies they discover each
# other, elect a Key Server and agree a SAK. This is control-plane only: the
# wolfMKA side uses its logging SecY (no kernel MACsec); see
# run-interop-dataplane.sh (Tier 2) for the data path.
#
# Needs root (network namespaces, veth, raw sockets), iproute2 and a
# wpa_supplicant built with CONFIG_MACSEC + CONFIG_DRIVER_MACSEC_LINUX. When a
# prerequisite is missing it prints SKIP and exits 0, so it is safe to invoke
# anywhere; it only does real work (and can FAIL) where it can run.
set -eu

HERE=$(CDPATH= cd "$(dirname "$0")" && pwd)
MKA_LINK=${MKA_LINK:-"$HERE/../../examples/mka_link"}
WPA=${WPA_SUPPLICANT:-wpa_supplicant}
TIMEOUT=${TIMEOUT:-25}

NS_A=wmka_a
NS_B=wmka_b
VETH_A=veth_a
VETH_B=veth_b
CAK=0123456789abcdef0123456789abcdef
CKN=00112233445566778899aabbccddeeff
RUNDIR=

# A harness that skips when it cannot run is convenient, but a skip reads
# exactly like a pass in a CI log. Set INTEROP_STRICT=1 where the prerequisites
# are supposed to be present and a skip should fail the job instead.
STRICT=${INTEROP_STRICT:-0}

skip() {
    if [ "$STRICT" = 1 ]; then
        echo "FAIL (INTEROP_STRICT=1): $1"
        exit 1
    fi
    echo "SKIP: $1"
    exit 0
}

cleanup() {
    [ -n "${WM_PID:-}" ] && kill "$WM_PID" 2>/dev/null || true
    [ -n "${WPA_PID:-}" ] && kill "$WPA_PID" 2>/dev/null || true
    ip netns del "$NS_A" 2>/dev/null || true
    ip netns del "$NS_B" 2>/dev/null || true
    [ -n "$RUNDIR" ] && rm -rf "$RUNDIR" 2>/dev/null || true
}

[ "$(id -u)" = 0 ] || skip "must run as root"
command -v ip >/dev/null 2>&1 || skip "iproute2 (ip) not found"
command -v "$WPA" >/dev/null 2>&1 || skip "wpa_supplicant not found"
[ -x "$MKA_LINK" ] || skip "mka_link not built ($MKA_LINK) - run 'make examples'"

trap cleanup EXIT INT TERM
RUNDIR=$(mktemp -d)

echo "== Tier 1: wolfMKA mka_link <-> wpa_supplicant (control plane) =="

# Run the exchange once per Key Server role. With wolfMKA favoured it drives
# distribution: it generates the SAK, wraps it under the KEK and emits the
# Distributed SAK set. With wpa_supplicant favoured wolfMKA is a plain member,
# which exercises the opposite half - unwrapping a peer's SAK, installing it and
# reporting it back in MACsec SAK Use - against a real implementation rather
# than against wolfMKA's own encoder. Only the first half was ever covered.
round() {
    wm_pri=$1
    wpa_pri=$2
    want_ks=$3
    sak_len=$4
    label=$5

    # macsec_csindex selects wpa_supplicant's cipher suite: 0 = GCM-AES-128,
    # 1 = GCM-AES-256. wolfMKA picks the same one from the SAK length.
    if [ "$sak_len" = 32 ]; then csindex=1; else csindex=0; fi

    echo "--- round: $label (wolfMKA priority $wm_pri, wpa $wpa_pri," \
        "SAK ${sak_len}o) ---"

    ip netns add "$NS_A"
    ip netns add "$NS_B"
    ip link add "$VETH_A" netns "$NS_A" type veth peer name "$VETH_B" \
        netns "$NS_B"
    ip netns exec "$NS_A" ip link set lo up
    ip netns exec "$NS_B" ip link set lo up
    ip netns exec "$NS_A" ip link set "$VETH_A" up
    ip netns exec "$NS_B" ip link set "$VETH_B" up

    ip netns exec "$NS_A" "$MKA_LINK" "$VETH_A" "$wm_pri" "$CAK" "$CKN" \
        "$sak_len" >"$RUNDIR/wm.log" 2>&1 &
    WM_PID=$!

    sed -e "s|@CTRL@|$RUNDIR/wpa|g" -e "s|@CAK@|$CAK|g" -e "s|@CKN@|$CKN|g" \
        -e "s|@PRIORITY@|$wpa_pri|g" -e "s|@CSINDEX@|$csindex|g" \
        "$HERE/peer.conf.in" >"$RUNDIR/peer.conf"
    ip netns exec "$NS_B" "$WPA" -i "$VETH_B" -D macsec_linux \
        -c "$RUNDIR/peer.conf" >"$RUNDIR/wpa.log" 2>&1 &
    WPA_PID=$!

    # Converged when wolfMKA reports a SAK and wpa has a receive SC - proof it
    # learned the peer SCI and keyed.
    ok=0
    i=0
    while [ "$i" -lt "$TIMEOUT" ]; do
        sleep 1
        i=$((i + 1))
        grep -q "sak=1" "$RUNDIR/wm.log" 2>/dev/null || continue
        # The role is part of the condition, not an assertion afterwards. With
        # no peer yet a capable participant elects itself, so in the member
        # round wolfMKA briefly is Key Server with a SAK of its own before it
        # yields - polling on sak alone could catch that instant and "prove"
        # the wrong half.
        grep "state:" "$RUNDIR/wm.log" | tail -1 \
            | grep -q "key_server=$want_ks" || continue
        if ip netns exec "$NS_B" ip macsec show 2>/dev/null | grep -q "RXSC"
        then
            ok=1
            break
        fi
    done

    echo "  --- wolfMKA (mka_link) state ---"
    grep "state:" "$RUNDIR/wm.log" 2>/dev/null | tail -3 || true
    echo "  --- wpa_supplicant macsec ---"
    ip netns exec "$NS_B" ip macsec show 2>/dev/null | sed -n '1,6p' || true

    if [ "$ok" != 1 ]; then
        echo "FAIL: $label - no SAK convergence as key_server=$want_ks" \
            "within ${TIMEOUT}s"
        # Enough context to tell the failure modes apart without another run:
        # never became live (nothing on the wire is accepted), became live but
        # no SAK was distributed or installed, or keyed and then churned.
        echo "  --- wolfMKA log (last 40) ---"
        tail -40 "$RUNDIR/wm.log" 2>/dev/null || true
        echo "  --- wolfMKA SecY calls, counted ---"
        grep -c "install TX SA" "$RUNDIR/wm.log" 2>/dev/null \
            | sed 's/^/    install TX SA: /' || true
        grep -c "install RX SA" "$RUNDIR/wm.log" 2>/dev/null \
            | sed 's/^/    install RX SA: /' || true
        echo "  --- wpa_supplicant MKA lines (last 40) ---"
        grep -E "KaY|MKA|SAK|ICV|Key Server|participant" "$RUNDIR/wpa.log" \
            2>/dev/null | tail -40 || true
        return 1
    fi

    if [ "$want_ks" = 0 ]; then
        # As a member wolfMKA must have installed a key it did not generate:
        # the Distributed SAK arrived, unwrapped under the KEK and reached the
        # SecY. Without this the round could pass on wolfMKA merely holding a
        # key of its own.
        grep -q "install TX SA" "$RUNDIR/wm.log" || {
            echo "FAIL: $label - wolfMKA never installed the peer's SAK"
            return 1
        }
    fi

    echo "  ok: $label"
    kill "$WM_PID" 2>/dev/null || true
    kill "$WPA_PID" 2>/dev/null || true
    WM_PID=""
    WPA_PID=""
    ip netns del "$NS_A" 2>/dev/null || true
    ip netns del "$NS_B" 2>/dev/null || true
    sleep 1
    return 0
}

round 10 20 1 16 "wolfMKA is Key Server" || exit 1
round 30 20 0 16 "wolfMKA is a member" || exit 1
# GCM-AES-256 is not the default suite, so the Distributed SAK parameter set
# names it explicitly on the wire and the SAK is 32 octets - a different encode
# path and a different key wrap from the two rounds above.
round 10 20 1 32 "GCM-AES-256, wolfMKA is Key Server" || exit 1

echo "PASS: wolfMKA and wpa_supplicant agreed a SAK over MKA - both roles," \
    "GCM-AES-128 and GCM-AES-256"
exit 0
