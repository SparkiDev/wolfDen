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

skip() { echo "SKIP: $1"; exit 0; }

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

# Two namespaces joined by a veth pair: each implementation gets its own MAC,
# SCI and EAPOL endpoint, isolated from the host stack.
ip netns add "$NS_A"
ip netns add "$NS_B"
ip link add "$VETH_A" netns "$NS_A" type veth peer name "$VETH_B" netns "$NS_B"
ip netns exec "$NS_A" ip link set lo up
ip netns exec "$NS_B" ip link set lo up
ip netns exec "$NS_A" ip link set "$VETH_A" up
ip netns exec "$NS_B" ip link set "$VETH_B" up

# wolfMKA side (priority 10 -> favoured as Key Server).
ip netns exec "$NS_A" "$MKA_LINK" "$VETH_A" 10 "$CAK" "$CKN" \
    >"$RUNDIR/wm.log" 2>&1 &
WM_PID=$!

# wpa_supplicant side (priority 20).
sed -e "s|@CTRL@|$RUNDIR/wpa|g" -e "s|@CAK@|$CAK|g" -e "s|@CKN@|$CKN|g" \
    -e "s|@PRIORITY@|20|g" "$HERE/peer.conf.in" >"$RUNDIR/peer.conf"
ip netns exec "$NS_B" "$WPA" -i "$VETH_B" -D macsec_linux \
    -c "$RUNDIR/peer.conf" >"$RUNDIR/wpa.log" 2>&1 &
WPA_PID=$!

# Poll for convergence: wolfMKA reports a SAK, and wpa created a MACsec child
# device with a receive SC (proof it learned the peer SCI and keyed).
ok=0
i=0
while [ "$i" -lt "$TIMEOUT" ]; do
    sleep 1
    i=$((i + 1))
    grep -q "sak=1" "$RUNDIR/wm.log" 2>/dev/null || continue
    if ip netns exec "$NS_B" ip macsec show 2>/dev/null | grep -q "RXSC"; then
        ok=1
        break
    fi
done

echo "--- wolfMKA (mka_link) state ---"
grep "state:" "$RUNDIR/wm.log" 2>/dev/null | tail -3 || true
echo "--- wpa_supplicant macsec ---"
ip netns exec "$NS_B" ip macsec show 2>/dev/null | sed -n '1,6p' || true

if [ "$ok" = 1 ]; then
    echo "PASS: wolfMKA and wpa_supplicant agreed a SAK over MKA"
    exit 0
fi
echo "FAIL: no SAK convergence within ${TIMEOUT}s"
echo "  wolfMKA log tail:"; tail -5 "$RUNDIR/wm.log" 2>/dev/null || true
echo "  wpa log tail:";     tail -5 "$RUNDIR/wpa.log" 2>/dev/null || true
exit 1
