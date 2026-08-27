#!/bin/sh
# run-interop-eap.sh - Tier 3 wolfMKA <-> wpa_supplicant EAP-MSK key derivation.
#
# Copyright (C) 2006-2026 wolfSSL Inc.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Tiers 1 and 2 key from a pre-shared CAK, so IEEE Std 802.1X-2010 9.3.2 - the
# CAK and CKN derived from an EAP Master Session Key - never runs. This tier
# covers it.
#
# wolfMKA has no EAP of its own: it consumes an MSK the integrator supplies. So
# the exchange is run by the two implementations that do have one - hostapd as
# the 802.1X authenticator with its built-in EAP server, wpa_supplicant as the
# supplicant - over a veth pair. EAP-GPSK is used because it needs no
# certificates and still yields an MSK. wpa_supplicant then derives its CAK/CKN
# from that MSK, and logs both along with the MSK itself under -dd -K. The test
# recovers all three, runs wolfMKA's derivation over the same MSK, MAC pair and
# EAP Session-Id, and requires the bytes to be identical.
#
# What this proves that a known-answer vector does not: the inputs come from a
# live EAP exchange rather than from a fixture - in particular the Session-Id,
# whose construction is method-specific, and the MAC ordering, which both ends
# must agree on independently.
#
# Needs root, iproute2, wpa_supplicant and hostapd. Prints SKIP and exits 0 when
# a prerequisite is missing, unless INTEROP_STRICT=1.
set -eu

HERE=$(CDPATH= cd "$(dirname "$0")" && pwd)
DERIVE=${EAP_DERIVE:-"$HERE/eap_derive"}
WPA=${WPA_SUPPLICANT:-wpa_supplicant}
HOSTAPD=${HOSTAPD:-hostapd}
TIMEOUT=${TIMEOUT:-25}

NS_A=wmka_ea
NS_B=wmka_eb
VETH_A=veth_ea
VETH_B=veth_eb
RUNDIR=

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
    [ -n "${HAP_PID:-}" ] && kill "$HAP_PID" 2>/dev/null || true
    [ -n "${WPA_PID:-}" ] && kill "$WPA_PID" 2>/dev/null || true
    ip netns del "$NS_A" 2>/dev/null || true
    ip netns del "$NS_B" 2>/dev/null || true
    [ -n "$RUNDIR" ] && rm -rf "$RUNDIR" 2>/dev/null || true
}

[ "$(id -u)" = 0 ] || skip "must run as root"
command -v ip >/dev/null 2>&1 || skip "iproute2 (ip) not found"
command -v "$WPA" >/dev/null 2>&1 || skip "wpa_supplicant not found"
command -v "$HOSTAPD" >/dev/null 2>&1 || skip "hostapd not found"
[ -x "$DERIVE" ] || skip "eap_derive not built - run 'make test/interop/eap_derive'"

trap cleanup EXIT INT TERM
RUNDIR=$(mktemp -d)

echo "== Tier 3: wolfMKA <-> wpa_supplicant EAP-MSK CAK/CKN derivation =="

ip netns add "$NS_A"
ip netns add "$NS_B"
ip link add "$VETH_A" netns "$NS_A" type veth peer name "$VETH_B" netns "$NS_B"
ip netns exec "$NS_A" ip link set lo up
ip netns exec "$NS_B" ip link set lo up
ip netns exec "$NS_A" ip link set "$VETH_A" up
ip netns exec "$NS_B" ip link set "$VETH_B" up

MAC_A=$(ip netns exec "$NS_A" cat "/sys/class/net/$VETH_A/address" | tr -d ':')
MAC_B=$(ip netns exec "$NS_B" cat "/sys/class/net/$VETH_B/address" | tr -d ':')
echo "  authenticator MAC $MAC_A / supplicant MAC $MAC_B"

# hostapd: 802.1X authenticator on a wired interface with the built-in EAP
# server. No MACsec here - hostapd is only the EAP peer.
cat >"$RUNDIR/hostapd.conf" <<CFG
interface=$VETH_A
driver=wired
ieee8021x=1
eap_server=1
eap_user_file=$RUNDIR/eap_user
eapol_version=2
CFG
# Phase-1 entry: identity, permitted method, then the EAP-GPSK shared secret.
# No [2] flag - that marks an entry as phase-2 only, so the phase-1 lookup for
# this identity would find nothing and hostapd would answer EAP-Failure the
# moment the Identity response arrived.
printf '"wolfmka"\tGPSK\t"0123456789abcdef0123456789abcdef"\n' \
    >"$RUNDIR/eap_user"

cat >"$RUNDIR/sup.conf" <<CFG
ctrl_interface=$RUNDIR/wpa
eapol_version=2
ap_scan=0
network={
	key_mgmt=IEEE8021X
	eap=GPSK
	identity="wolfmka"
	password="0123456789abcdef0123456789abcdef"
	eapol_flags=0
	macsec_policy=1
}
CFG

ip netns exec "$NS_A" "$HOSTAPD" "$RUNDIR/hostapd.conf" \
    >"$RUNDIR/hap.log" 2>&1 &
HAP_PID=$!
sleep 1
# macsec_linux, not wired: ieee802_1x_notify_create_actor returns early unless
# wpa_s->kay already exists, and the KaY is only allocated for a MACsec-capable
# driver - so under -D wired the CAK/CKN are never derived at all, however well
# the EAP exchange goes.
ip netns exec "$NS_B" "$WPA" -i "$VETH_B" -D macsec_linux \
    -c "$RUNDIR/sup.conf" -dd -K >"$RUNDIR/wpa.log" 2>&1 &
WPA_PID=$!

# Wait for the supplicant to finish EAP and derive its CAK/CKN.
i=0
while [ "$i" -lt "$TIMEOUT" ]; do
    sleep 1
    i=$((i + 1))
    grep -q "Derived CKN" "$RUNDIR/wpa.log" 2>/dev/null && break
done

hexline() {
    # wpa_hexdump_key prints "<tag> - hexdump(len=N): xx xx ..".
    sed -n "s/.*$1 - hexdump(len=[0-9]*): //p" "$RUNDIR/wpa.log" \
        | tail -1 | tr -d ' '
}

MSK=$(hexline "EAP-GPSK: MSK")
[ -n "$MSK" ] && MSK=$(hexline "EAP-GPSK: MSK") || MSK=$(hexline "master key")
CAK_W=$(hexline "Derived CAK")
CKN_W=$(hexline "Derived CKN")
# Every EAP method that produces one logs it as "EAP-<METHOD>: Derived
# Session-Id"; matching the trailing part keeps this method-agnostic.
SID=$(hexline "Derived Session-Id")

if [ -z "$CAK_W" ] || [ -z "$CKN_W" ]; then
    if grep -q "CTRL-EVENT-EAP-FAILURE" "$RUNDIR/wpa.log" 2>/dev/null; then
        echo "FAIL: the EAP exchange itself failed (check eap_user / GPSK psk)"
    elif grep -q "CTRL-EVENT-EAP-SUCCESS" "$RUNDIR/wpa.log" 2>/dev/null; then
        echo "FAIL: EAP succeeded but no CAK/CKN was derived (no KaY? check" \
            "macsec_policy and that the driver is MACsec-capable)"
    else
        echo "FAIL: wpa_supplicant did not derive a CAK/CKN from an EAP MSK"
    fi
    echo "  --- hostapd log (last 25) ---"; tail -25 "$RUNDIR/hap.log" || true
    echo "  --- supplicant EAP lines (last 30) ---"
    grep -E "EAP|MSK|CAK|CKN|Session-Id" "$RUNDIR/wpa.log" | tail -30 || true
    exit 1
fi

# An input the harness failed to extract must not be passed on as empty. The
# CAK's KDF context is only the MAC pair, so a missing Session-Id still produces
# a matching CAK and the run looks like a genuine CKN disagreement between the
# two implementations - when in fact the two sides were given different inputs.
# Fail here instead, and say where to look.
if [ -z "$MSK" ] || [ -z "$SID" ]; then
    echo "FAIL: could not recover the EAP inputs from the supplicant log" \
        "(MSK='${MSK:-}' Session-Id='${SID:-}')"
    echo "  this is a harness extraction problem, not a derivation mismatch"
    echo "  --- candidate lines ---"
    grep -E "MSK|Session-Id|master key" "$RUNDIR/wpa.log" | tail -20 || true
    exit 1
fi

# wpa_supplicant clamps the MSK to the CAK length before deriving, so the CAK
# length is how much MSK entered the KDF.
CAK_LEN=$((${#CAK_W} / 2))
MSK_USED=$(echo "$MSK" | cut -c1-$((CAK_LEN * 2)))

echo "  EAP Session-Id : ${SID:-<none>}"
echo "  MSK (first $CAK_LEN octets): $MSK_USED"
echo "  wpa_supplicant : CAK=$CAK_W"
echo "                   CKN=$CKN_W"

OUT=$("$DERIVE" "$MSK_USED" "$MAC_B" "$MAC_A" "$SID" "$CAK_LEN") || {
    echo "FAIL: wolfMKA derivation returned an error"; exit 1; }
CAK_M=$(echo "$OUT" | sed -n 's/^CAK=//p')
CKN_M=$(echo "$OUT" | sed -n 's/^CKN=//p')
echo "  wolfMKA        : CAK=$CAK_M"
echo "                   CKN=$CKN_M"

rc=0
[ "$CAK_M" = "$CAK_W" ] || { echo "FAIL: CAK differs"; rc=1; }
[ "$CKN_M" = "$CKN_W" ] || { echo "FAIL: CKN differs"; rc=1; }
[ "$rc" = 0 ] || exit 1

echo "PASS: wolfMKA and wpa_supplicant derived an identical CAK/CKN from a live EAP MSK"
exit 0
