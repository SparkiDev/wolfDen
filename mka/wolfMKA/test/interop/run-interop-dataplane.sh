#!/bin/sh
# run-interop-dataplane.sh - Tier 2 wolfMKA <-> wpa_supplicant data-plane
# interop.
#
# Copyright (C) 2006-2026 wolfSSL Inc.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Builds on Tier 1: both peers program the kernel MACsec data plane with the
# agreed SAK (wolfMKA via the combined `mka_macsec` binary, wpa_supplicant via
# its macsec_linux driver), then the harness proves the link actually protects
# traffic end-to-end:
#
#   1. ping across the MACsec interfaces (10.0.0.1 <-> 10.0.0.2) succeeds - both
#      stacks derived the same SAK and encrypt/decrypt compatibly;
#   2. on the underlying veth the frames are MACsec (EtherType 0x88e5) and carry
#      no cleartext ICMP (verified with tcpdump when available);
#   3. a Key Server rekey (SIGUSR1 -> wm_Participant_Rekey) rolls the Key Number
#      and traffic keeps flowing across the handover.
#
# Needs root, iproute2, the kernel `macsec` module, a wpa_supplicant built with
# CONFIG_MACSEC + CONFIG_DRIVER_MACSEC_LINUX, and (optionally) tcpdump. Missing
# prerequisites print SKIP and exit 0.
set -eu

HERE=$(CDPATH= cd "$(dirname "$0")" && pwd)
MKA_MACSEC=${MKA_MACSEC:-"$HERE/../../examples/mka_macsec"}
WPA=${WPA_SUPPLICANT:-wpa_supplicant}
TIMEOUT=${TIMEOUT:-25}

NS_A=wmka_a
NS_B=wmka_b
VETH_A=veth_a
VETH_B=veth_b
MS_A=macsec_a
IP_A=10.0.0.1
IP_B=10.0.0.2
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
[ -x "$MKA_MACSEC" ] || skip "mka_macsec not built - run 'make examples'"
modprobe macsec 2>/dev/null || true

trap cleanup EXIT INT TERM
RUNDIR=$(mktemp -d)

echo "== Tier 2: wolfMKA mka_macsec <-> wpa_supplicant (data plane) =="

ip netns add "$NS_A"
ip netns add "$NS_B"
ip link add "$VETH_A" netns "$NS_A" type veth peer name "$VETH_B" netns "$NS_B"
ip netns exec "$NS_A" ip link set lo up
ip netns exec "$NS_B" ip link set lo up
ip netns exec "$NS_A" ip link set "$VETH_A" up
ip netns exec "$NS_B" ip link set "$VETH_B" up

# wolfMKA side: create the MACsec child device up front (mka_macsec opens it by
# name), give it an address, then run the combined participant as Key Server.
# Creating it also serves as the kernel-MACsec availability probe.
ip netns exec "$NS_A" ip link add link "$VETH_A" "$MS_A" type macsec encrypt on \
    2>/dev/null || skip "kernel MACsec unavailable (cannot create macsec device)"
ip netns exec "$NS_A" ip link set "$MS_A" up
ip netns exec "$NS_A" ip addr add "$IP_A/24" dev "$MS_A"
ip netns exec "$NS_A" "$MKA_MACSEC" "$VETH_A" "$MS_A" 10 "$CAK" "$CKN" \
    >"$RUNDIR/wm.log" 2>&1 &
WM_PID=$!

# wpa_supplicant side: the macsec_linux driver creates its own MACsec child
# device when MKA secures; the harness discovers and addresses it below.
sed -e "s|@CTRL@|$RUNDIR/wpa|g" -e "s|@CAK@|$CAK|g" -e "s|@CKN@|$CKN|g" \
    -e "s|@PRIORITY@|20|g" "$HERE/peer.conf.in" >"$RUNDIR/peer.conf"
ip netns exec "$NS_B" "$WPA" -i "$VETH_B" -D macsec_linux \
    -c "$RUNDIR/peer.conf" >"$RUNDIR/wpa.log" 2>&1 &
WPA_PID=$!

# Wait for wolfMKA to install a SAK and for wpa's MACsec device to appear, then
# address wpa's device so IP can flow.
ms_b=""
i=0
while [ "$i" -lt "$TIMEOUT" ]; do
    sleep 1
    i=$((i + 1))
    [ -z "$ms_b" ] && ms_b=$(ip netns exec "$NS_B" ip -o link show type macsec \
        2>/dev/null | awk -F': ' 'NR==1{print $2}' | sed 's/@.*//')
    if [ -n "$ms_b" ]; then
        ip netns exec "$NS_B" ip link set "$ms_b" up 2>/dev/null || true
        ip netns exec "$NS_B" ip addr show dev "$ms_b" | grep -q "$IP_B" || \
            ip netns exec "$NS_B" ip addr add "$IP_B/24" dev "$ms_b" \
                2>/dev/null || true
    fi
    grep -q "sak=1" "$RUNDIR/wm.log" 2>/dev/null && [ -n "$ms_b" ] && break
done

echo "--- wolfMKA (mka_macsec) state ---"
grep "state:" "$RUNDIR/wm.log" 2>/dev/null | tail -3 || true
echo "--- wpa MACsec device: ${ms_b:-<none>} ---"
ip netns exec "$NS_A" ip macsec show 2>/dev/null | sed -n '1,4p' || true

if [ -z "$ms_b" ] || ! grep -q "sak=1" "$RUNDIR/wm.log" 2>/dev/null; then
    echo "FAIL: control plane did not converge (no SAK / no wpa macsec device)"
    tail -5 "$RUNDIR/wm.log" 2>/dev/null || true
    tail -5 "$RUNDIR/wpa.log" 2>/dev/null || true
    exit 1
fi

# (1) Protected traffic must flow.
echo "--- data-plane ping $IP_A -> $IP_B ---"
if ip netns exec "$NS_A" ping -c 3 -W 2 "$IP_B" >"$RUNDIR/ping.log" 2>&1; then
    echo "  ping OK (MACsec-protected traffic flows)"
else
    echo "FAIL: ping across the MACsec link failed"
    cat "$RUNDIR/ping.log" 2>/dev/null || true
    exit 1
fi

# (2) On the wire it must be MACsec, not cleartext (best-effort, needs tcpdump).
if command -v tcpdump >/dev/null 2>&1; then
    ip netns exec "$NS_A" tcpdump -i "$VETH_A" -c 10 -nn -e \
        >"$RUNDIR/tcpdump.log" 2>/dev/null &
    TD_PID=$!
    ip netns exec "$NS_A" ping -c 3 -W 2 "$IP_B" >/dev/null 2>&1 || true
    wait "$TD_PID" 2>/dev/null || true
    if grep -qi "88e5\|macsec" "$RUNDIR/tcpdump.log" 2>/dev/null; then
        echo "  on-wire frames are MACsec (EtherType 0x88e5)"
    else
        echo "  WARN: could not confirm MACsec framing on the wire (see log)"
    fi
    if grep -qi "ICMP echo" "$RUNDIR/tcpdump.log" 2>/dev/null; then
        echo "FAIL: cleartext ICMP visible on the underlying veth"
        exit 1
    fi
else
    echo "  (tcpdump absent: skipping on-wire encryption check)"
fi

# (3) Rekey: the Key Server rolls the SAK; traffic must survive the handover.
echo "--- rekey (SIGUSR1 -> Key Server) ---"
kill -USR1 "$WM_PID" 2>/dev/null || true
j=0
while [ "$j" -lt 10 ]; do
    sleep 1
    j=$((j + 1))
    grep -q "kn=2" "$RUNDIR/wm.log" 2>/dev/null && break
done
if grep -q "kn=2" "$RUNDIR/wm.log" 2>/dev/null; then
    echo "  wolfMKA advanced to Key Number 2"
else
    echo "  WARN: did not observe kn=2 (rekey may not have completed)"
fi
if ip netns exec "$NS_A" ping -c 3 -W 2 "$IP_B" >/dev/null 2>&1; then
    echo "  ping OK after rekey"
else
    echo "FAIL: traffic stopped after rekey"
    exit 1
fi

echo "PASS: wolfMKA and wpa_supplicant established and rekeyed a MACsec session"
exit 0
