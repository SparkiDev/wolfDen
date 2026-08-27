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
# SAK length, which selects the cipher suite on both sides: 16 -> GCM-AES-128,
# 32 -> GCM-AES-256 (macsec_csindex=1 for wpa_supplicant). The make target runs
# the whole tier once per suite; each invocation builds and tears down its own
# namespaces, so they cannot interfere.
SAK_LEN=${SAK_LEN:-16}
if [ "$SAK_LEN" = 32 ]; then
    CSINDEX=1; SUITE=GCM-AES-256; CIPHER=gcm-aes-256
else
    CSINDEX=0; SUITE=GCM-AES-128; CIPHER=gcm-aes-128
fi

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

# See run-interop.sh: a skip reads like a pass in a CI log, so INTEROP_STRICT=1
# turns a missing prerequisite into a failure.
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
[ -x "$MKA_MACSEC" ] || skip "mka_macsec not built - run 'make examples'"
modprobe macsec 2>/dev/null || true

trap cleanup EXIT INT TERM
RUNDIR=$(mktemp -d)

echo "== Tier 2: wolfMKA mka_macsec <-> wpa_supplicant (data plane," \
    "$SUITE) =="

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
# The cipher suite is a property of the MACsec device, fixed when it is created.
# The example does implement set_cipher_suite, but only to record the SSCI that
# the XPN suites need - it cannot re-cipher a live device, so a device left at
# the default GCM-AES-128 stays there however long a 32-octet SAK is.
# wpa_supplicant creates its own child device from macsec_csindex, so without
# this the two ends run different suites and no frame decrypts.
#
# wpa_supplicant 2.11 implements only GCM-AES-128 and GCM-AES-256, so no XPN
# round is possible here; Tier 4 covers XPN against MKAdaemon.
ip netns exec "$NS_A" ip link add link "$VETH_A" "$MS_A" type macsec \
    cipher "$CIPHER" encrypt on \
    2>/dev/null || skip "kernel MACsec unavailable (cannot create macsec device)"
ip netns exec "$NS_A" ip link set "$MS_A" up
ip netns exec "$NS_A" ip addr add "$IP_A/24" dev "$MS_A"
# Arg 6 is the auto-rekey period (0 = off; the rekey below is driven by
# SIGUSR1), arg 7 the SAK length.
ip netns exec "$NS_A" "$MKA_MACSEC" "$VETH_A" "$MS_A" 10 "$CAK" "$CKN" \
    0 "$SAK_LEN" >"$RUNDIR/wm.log" 2>&1 &
WM_PID=$!

# wpa_supplicant side: the macsec_linux driver creates its own MACsec child
# device when MKA secures; the harness discovers and addresses it below.
sed -e "s|@CTRL@|$RUNDIR/wpa|g" -e "s|@CAK@|$CAK|g" -e "s|@CKN@|$CKN|g" \
    -e "s|@PRIORITY@|20|g" -e "s|@CSINDEX@|$CSINDEX|g" \
    "$HERE/peer.conf.in" >"$RUNDIR/peer.conf"
# -dd: the KaY logs its reason for ignoring a Distributed SAK only at debug
# level, and that reason is the whole diagnosis when a rekey does not take.
ip netns exec "$NS_B" "$WPA" -i "$VETH_B" -D macsec_linux \
    -c "$RUNDIR/peer.conf" -dd >"$RUNDIR/wpa.log" 2>&1 &
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
# Both ends, each from its own namespace. The kernel does not echo SAK bytes
# back, so the "key" column here is not the agreed key - what matters is that
# each side has a TXSC and an RXSC in state on.
echo "--- wolfMKA MACsec device (ns $NS_A) ---"
ip netns exec "$NS_A" ip macsec show 2>/dev/null | sed -n '1,6p' || true
echo "--- wpa_supplicant MACsec device: ${ms_b:-<none>} (ns $NS_B) ---"
ip netns exec "$NS_B" ip macsec show 2>/dev/null | sed -n '1,6p' || true

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
#
# Run more than once. The first rekey is the interesting one for the handover
# itself, but several bugs only show up from the *second* SAK onwards - the KaY
# re-creating a receive Secure Channel that already exists is one (Linux
# answers -EEXIST), and an Old SA that is never torn down is another, since a
# single rekey leaves a plausible-looking two SAs either way. So the round is a
# function of the Key Number it expects.

# Number of SecY teardown calls so far. A delete from an earlier round is
# already in the log, so "did a delete happen" is vacuous after round one;
# what matters is that this round produced a new one.
secy_deletes() {
    # grep -c exits 1 when the count is zero and 2 when the file is missing,
    # so the status is discarded and the (possibly empty) output defaulted -
    # `|| echo 0` would append a second line to a count that is already "0".
    n=$(grep -c "\[SecY\] delete" "$RUNDIR/wm.log" 2>/dev/null || true)
    echo "${n:-0}"
}

# Every SA the kernel currently holds, across both Secure Channels. Make-
# before-break tops out at Old + Latest per SC, so 4 is the ceiling while a
# handover is in flight and 2 is the resting state. A count that climbs with
# the round number means the old SAs are never reclaimed, which ends with the
# Association Numbers wrapping onto a key that is still installed.
secy_sa_count() {
    n=$(ip netns exec "$NS_A" ip macsec show 2>/dev/null \
        | grep -cE "^[[:space:]]+[0-9]+: PN " || true)
    echo "${n:-0}"
}

rekey_round() {
    want_kn=$1
    label=$2

    echo "--- rekey $label (SIGUSR1 -> Key Server, expecting kn=$want_kn) ---"
    deletes_before=$(secy_deletes)
    kill -USR1 "$WM_PID" 2>/dev/null || true
    j=0
    while [ "$j" -lt 10 ]; do
        sleep 1
        j=$((j + 1))
        grep -q "kn=$want_kn" "$RUNDIR/wm.log" 2>/dev/null && break
    done
    if grep -q "kn=$want_kn" "$RUNDIR/wm.log" 2>/dev/null; then
        echo "  wolfMKA advanced to Key Number $want_kn"
    else
        echo "  WARN: did not observe kn=$want_kn" \
            "(rekey may not have completed)"
    fi
    # The Key Number appearing means wolfMKA has *adopted* the new key, not
    # that the handover is over: make-before-break keeps transmitting on the
    # Old key until every live peer reports receiving on the Latest one, and
    # the peer first has to receive the Distributed SAK and program it.
    # Pinging the instant it appears races that, so poll until traffic is
    # flowing again and fail only if it never resumes.
    # How long it took is printed either way - a handover that takes many
    # seconds is worth noticing even when it eventually completes.
    # Wall clock, not an attempt count: a ping that fails with "host
    # unreachable" returns immediately, so counting iterations measures how
    # fast ping gives up, not how long traffic was down.
    t0=$(date +%s)
    resumed=0
    while [ $(($(date +%s) - t0)) -lt 20 ]; do
        if ip netns exec "$NS_A" ping -c 1 -W 1 "$IP_B" >/dev/null 2>&1; then
            resumed=1
            break
        fi
        sleep 1
    done
    k=$(($(date +%s) - t0))
    if [ "$resumed" = 1 ]; then
        echo "  ping OK after rekey (traffic down for ~${k}s)"
        # Make-before-break is supposed to be seamless: the Old key keeps
        # carrying traffic until every live peer reports receiving on the
        # Latest one, so a multi-second gap means something waited for a timer
        # rather than for the handshake. Not a failure - the peer's own MKA
        # cadence is outside our control - but a regression here is worth
        # seeing, so it is called out.
        echo "  --- wolfMKA SecY timeline across the rekey ---"
        grep -E "\[SecY\]|rekey requested|peer:|state:" "$RUNDIR/wm.log" \
            | tail -24 || true
        if [ "$k" -gt 3 ]; then
            echo "  NOTE: the handover cost ${k}s of traffic;" \
                "a make-before-break rekey should be close to seamless"
        fi
        # (4) Every SecY hook must have been accepted by the kernel. The traffic
        # check above cannot see this: a rejected call leaves the device in a
        # state that still happens to forward, so a bookkeeping bug survives a
        # green ping. The trace prints the return code of every hook, so a
        # single grep for a negative one covers all of them. This caught the
        # KaY re-creating an existing receive SC, answered with -EEXIST.
        if grep -E "\[SecY\].* -> -[0-9]+$" "$RUNDIR/wm.log" \
                >/dev/null 2>&1; then
            echo "  --- SecY calls the kernel refused ---"
            grep -E "\[SecY\].* -> -[0-9]+$" "$RUNDIR/wm.log" | tail -12
            if [ "$STRICT" = 1 ]; then
                echo "FAIL (INTEROP_STRICT=1): a SecY hook was refused"
                exit 1
            fi
            echo "  WARN: a SecY hook was refused (see above)"
        else
            echo "  every SecY hook was accepted by the kernel"
        fi
        # (5) Old-key retirement. Make-before-break installs the new SAK
        # alongside the old one, so the interesting part is not that the new key
        # appeared but that the old one is eventually torn down - otherwise the
        # device accumulates a live SA per rekey and the Association Numbers
        # wrap into a key that is still installed.
        r=0
        while [ "$r" -lt 15 ]; do
            [ "$(secy_deletes)" -gt "$deletes_before" ] && break
            sleep 1
            r=$((r + 1))
        done
        if [ "$(secy_deletes)" -gt "$deletes_before" ]; then
            echo "  old key retired after ~${r}s:"
            grep "\[SecY\] delete" "$RUNDIR/wm.log" | tail -4
        else
            echo "  --- wolfMKA SAs still installed ---"
            ip netns exec "$NS_A" ip macsec show 2>/dev/null \
                | sed -n '1,12p' || true
            if [ "$STRICT" = 1 ]; then
                echo "FAIL (INTEROP_STRICT=1): the old SAK was never deleted"
                exit 1
            fi
            echo "  WARN: the old SAK was never deleted within 15s of the rekey"
        fi
    else
        echo "FAIL: traffic never resumed within 20s of the rekey"
        echo "  --- wolfMKA state (last 6) ---"
        grep "state:" "$RUNDIR/wm.log" | tail -6 || true
        echo "  --- wolfMKA SecY calls (last 12) ---"
        grep -E "install|transmit|delete" "$RUNDIR/wm.log" | tail -12 || true
        echo "  --- wolfMKA MACsec device ---"
        ip netns exec "$NS_A" ip macsec show 2>/dev/null | sed -n '1,8p' || true
        echo "  --- wpa_supplicant MACsec device ---"
        ip netns exec "$NS_B" ip macsec show 2>/dev/null | sed -n '1,8p' || true
        # Every reason ieee802_1x_mka_decode_dist_sak_body has for ignoring a
        # Distributed SAK, so the one that fired is named rather than inferred.
        echo "  --- wpa_supplicant: why the Distributed SAK was ignored ---"
        grep -E "not principal|I'm a key server|MACsec-desired|not in my live" \
            "$RUNDIR/wpa.log" 2>/dev/null | tail -5 || true
        grep -E "key server is not elected|already been installed|Cipher Suite" \
            "$RUNDIR/wpa.log" 2>/dev/null | tail -5 || true
        grep -E "AES unwrap failed|Distributed SAK|distributed SAK" \
            "$RUNDIR/wpa.log" 2>/dev/null | tail -10 || true
        echo "  --- wpa_supplicant KaY lines (last 25) ---"
        grep -E "KaY" "$RUNDIR/wpa.log" 2>/dev/null | tail -25 || true
        exit 1
    fi

    sa_now=$(secy_sa_count)
    echo "  kernel holds $sa_now SA(s) after rekey $label"
    # The device's own view, not the trace's. These have disagreed: hooks that
    # reported -EEXIST/-EBUSY still left the SA installed and traffic flowing,
    # which means a refused-looking return code is not proof the command
    # failed. Print the table so the two can be reconciled from one run.
    echo "  --- wolfMKA SAs after rekey $label ---"
    ip netns exec "$NS_A" ip macsec show 2>/dev/null | sed -n '1,20p' || true
    if [ "$sa_now" -gt 4 ]; then
        echo "  --- wolfMKA MACsec device ---"
        ip netns exec "$NS_A" ip macsec show 2>/dev/null \
            | sed -n '1,20p' || true
        echo "FAIL: $sa_now SAs installed; make-before-break tops out at 4" \
            "(Old + Latest per Secure Channel), so they are accumulating"
        exit 1
    fi
}

rekey_round 2 "1/2"
rekey_round 3 "2/2"

echo "PASS: wolfMKA and wpa_supplicant established and rekeyed a MACsec" \
    "session ($SUITE)"
exit 0
