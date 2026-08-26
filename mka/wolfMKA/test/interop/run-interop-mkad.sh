#!/bin/sh
# run-interop-mkad.sh - Tier 4 wolfMKA <-> MKAdaemon interop.
#
# Copyright (C) 2006-2026 wolfSSL Inc.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Tiers 1-3 all measure wolfMKA against wpa_supplicant. One peer is one
# reading of IEEE Std 802.1X-2010: where the standard is ambiguous, or where
# both implementations share an assumption, agreeing with it proves
# compatibility with wpa_supplicant rather than conformance. MKAdaemon
# (Technica Engineering, GPL-2.0-or-later) is an unrelated implementation with
# an automotive lineage, so it is a genuinely independent check.
#
# It also reaches cases wpa_supplicant cannot. The wpa_supplicant tested
# against has no XPN support at all, while MKAdaemon negotiates
# GCM_AES_XPN_128/256 - see the note on XPN at the bottom of this file for why
# that is still not exercised here.
#
# Structure follows Tier 2: two namespaces over a veth pair, both ends program
# the kernel MACsec data plane, and the round is repeated per Key Server role
# and per cipher suite. wolfMKA's side is the combined `mka_macsec` example;
# MKAdaemon creates its own protected device from `intf_mode: STATIC`.
#
# The wolfMKA binary needs one non-default build flag, so `make interop-mkad`
# builds examples/mka_macsec_mkad rather than reusing another tier's:
# WOLFMKA_MKA_VERSION=3U. MKAdaemon discards any MKPDU not announcing version
# 3; wolfMKA defaults to 1, the 802.1X-2010 value.
#
# Needs root (namespaces, veth, raw sockets), iproute2, the kernel `macsec`
# module and an `mkad` binary. Point MKAD at it; when a prerequisite is missing
# this prints SKIP and exits 0, so it is safe to invoke anywhere.
set -eu

HERE=$(CDPATH= cd "$(dirname "$0")" && pwd)
MKA_MACSEC=${MKA_MACSEC:-"$HERE/../../examples/mka_macsec"}
MKAD=${MKAD:-mkad}
TIMEOUT=${TIMEOUT:-30}

NS_A=wmka_a
NS_B=wmka_b
VETH_A=veth_a
VETH_B=veth_b
MS_A=macsec_a
MS_B=macsec_b
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
    [ -n "${MKAD_PID:-}" ] && kill "$MKAD_PID" 2>/dev/null || true
    ip netns del "$NS_A" 2>/dev/null || true
    ip netns del "$NS_B" 2>/dev/null || true
    [ -n "$RUNDIR" ] && rm -rf "$RUNDIR" 2>/dev/null || true
}

[ "$(id -u)" = 0 ] || skip "must run as root"
command -v ip >/dev/null 2>&1 || skip "iproute2 (ip) not found"
command -v "$MKAD" >/dev/null 2>&1 || [ -x "$MKAD" ] || \
    skip "MKAdaemon not found (set MKAD=/path/to/mkad)"
[ -x "$MKA_MACSEC" ] || \
    skip "mka_macsec not built ($MKA_MACSEC) - run 'make examples'"

trap cleanup EXIT INT TERM
RUNDIR=$(mktemp -d)

echo "== Tier 4: wolfMKA mka_macsec <-> MKAdaemon (data plane) =="

# The CAK/CKN are one hex string for wolfMKA and space-separated octets for
# MKAdaemon. Deriving the second from the first keeps a single source of truth:
# two hand-written constants that must match is exactly the kind of mismatch
# that reads as a library bug (a CAK that agrees but a CKN that does not looks
# identical to a failed key derivation).
spaced_hex() {
    echo "$1" | sed 's/../& /g' | sed 's/ $//'
}

round() {
    wm_pri=$1
    mkad_pri=$2
    want_ks=$3
    sak_len=$4
    label=$5
    xpn=${6:-0}
    rekey=${7:-0}
    restart=${8:-0}
    bad_cak=${9:-0}

    if [ "$xpn" = 1 ]; then
        if [ "$sak_len" = 32 ]; then
            cipher=GCM_AES_XPN_256
            kcipher=gcm-aes-xpn-256
        else
            cipher=GCM_AES_XPN_128
            kcipher=gcm-aes-xpn-128
        fi
    elif [ "$sak_len" = 32 ]; then
        cipher=GCM_AES_256
        kcipher=gcm-aes-256
    else
        cipher=GCM_AES_128
        kcipher=gcm-aes-128
    fi

    # Same CKN, different CAK: both ends select the CA by CKN and then fail to
    # verify each other's ICV. That is the interesting half - a CKN mismatch is
    # rejected by a string compare, an ICV mismatch is rejected by the crypto.
    peer_cak=$CAK
    wait_for=$TIMEOUT
    if [ "$bad_cak" = 1 ]; then
        peer_cak=0123456789abcdef0123456789abcdee
        # Nothing should ever converge, so this window only has to be long
        # enough to be convincing.
        wait_for=10
    fi

    echo "--- round: $label (wolfMKA priority $wm_pri, mkad $mkad_pri," \
        "$cipher) ---"

    ip netns add "$NS_A"
    ip netns add "$NS_B"
    ip link add "$VETH_A" netns "$NS_A" type veth peer name "$VETH_B" \
        netns "$NS_B"
    ip netns exec "$NS_A" ip link set lo up
    ip netns exec "$NS_B" ip link set lo up
    ip netns exec "$NS_A" ip link set "$VETH_A" up
    ip netns exec "$NS_B" ip link set "$VETH_B" up

    # wolfMKA's example installs keys into an already-provisioned device and
    # implements no set_cipher_suite hook, so the device must be created with
    # the suite under test - a 32-octet SAK agreed against a device left at
    # GCM-AES-128 decrypts nothing. Creating it doubles as the kernel-MACsec
    # availability probe.
    ip netns exec "$NS_A" ip link add link "$VETH_A" "$MS_A" type macsec \
        cipher "$kcipher" encrypt on 2>/dev/null || {
            ip netns del "$NS_A" 2>/dev/null || true
            ip netns del "$NS_B" 2>/dev/null || true
            if [ "$xpn" = 1 ]; then
                # Only the XPN suites are missing - the earlier rounds already
                # created a device, so this is not "no MACsec". Skip this round
                # rather than the tier, and say which one went unrun.
                echo "  SKIP: $label - kernel or iproute2 has no $kcipher"
                return 0
            fi
            skip "kernel MACsec unavailable (cannot create macsec device)"
        }
    ip netns exec "$NS_A" ip link set "$MS_A" up
    ip netns exec "$NS_A" ip addr add "$IP_A/24" dev "$MS_A"

    # Arg 6 is the auto-rekey period (0 = off), arg 7 the SAK length.
    ip netns exec "$NS_A" "$MKA_MACSEC" "$VETH_A" "$MS_A" "$wm_pri" \
        "$CAK" "$CKN" 0 "$sak_len" "$xpn" >"$RUNDIR/wm.log" 2>&1 &
    WM_PID=$!

    sed -e "s|@DEVICE@|$VETH_B|g" -e "s|@PROTECTED@|$MS_B|g" \
        -e "s|@PRIORITY@|$mkad_pri|g" -e "s|@CIPHER@|$cipher|g" \
        -e "s|@CAK@|$(spaced_hex "$peer_cak")|g" \
        -e "s|@CKN@|$(spaced_hex "$CKN")|g" \
        "$HERE/mkad.conf.in" >"$RUNDIR/mkad.conf"
    # An unsubstituted placeholder goes into the config verbatim and MKAdaemon
    # refuses to start, which shows up as a convergence timeout rather than as
    # a config error. Adding a placeholder to the template means adding it
    # above; this catches the case where that was forgotten.
    if grep -q "@[A-Z_]*@" "$RUNDIR/mkad.conf"; then
        echo "FAIL: unsubstituted placeholder in mkad.conf:"
        grep -o "@[A-Z_]*@" "$RUNDIR/mkad.conf" | sort -u | sed 's/^/    /'
        return 1
    fi

    # -f keeps it in the foreground so the harness owns the PID; without it
    # mkad daemonizes and the kill in cleanup() misses.
    ip netns exec "$NS_B" "$MKAD" -c "$RUNDIR/mkad.conf" -f -v 3 \
        >"$RUNDIR/mkad.log" 2>&1 &
    MKAD_PID=$!

    # Converged when wolfMKA holds a SAK in the expected role and MKAdaemon has
    # a receive SC - proof it learned the peer SCI and keyed, not merely that
    # it is running. The role is part of the condition rather than an assertion
    # afterwards: with no peer yet a capable participant elects itself, so
    # polling on the SAK alone can catch that instant and "prove" the wrong
    # half of the test.
    ok=0
    i=0
    while [ "$i" -lt "$wait_for" ]; do
        sleep 1
        i=$((i + 1))
        ip netns exec "$NS_B" ip link set "$MS_B" up 2>/dev/null || true
        ip netns exec "$NS_B" ip addr show dev "$MS_B" 2>/dev/null \
            | grep -q "$IP_B" || \
            ip netns exec "$NS_B" ip addr add "$IP_B/24" dev "$MS_B" \
                2>/dev/null || true
        grep -q "sak=1" "$RUNDIR/wm.log" 2>/dev/null || continue
        grep "state:" "$RUNDIR/wm.log" | tail -1 \
            | grep -q "key_server=$want_ks" || continue
        if ip netns exec "$NS_B" ip macsec show 2>/dev/null | grep -q "RXSC"
        then
            ok=1
            break
        fi
    done

    echo "  --- wolfMKA (mka_macsec) state ---"
    grep "state:" "$RUNDIR/wm.log" 2>/dev/null | tail -3 || true
    echo "  --- MKAdaemon macsec device ---"
    ip netns exec "$NS_B" ip macsec show 2>/dev/null | sed -n '1,6p' || true

    if [ "$bad_cak" = 1 ]; then
        if [ "$ok" = 1 ]; then
            echo "FAIL: $label - associated with a peer holding a different CAK"
            return 1
        fi
        # Silence is the expected outcome, so check it is the *right* silence:
        # wolfMKA must hold no key at all, and MKAdaemon must say why it is
        # discarding rather than simply having heard nothing.
        if grep -q "sak=1" "$RUNDIR/wm.log" 2>/dev/null; then
            echo "FAIL: $label - wolfMKA installed a SAK despite the CAK" \
                "mismatch"
            tail -20 "$RUNDIR/wm.log" 2>/dev/null || true
            return 1
        fi
        if ip netns exec "$NS_B" ip macsec show 2>/dev/null | grep -q "RXSC"
        then
            echo "FAIL: $label - MKAdaemon keyed a receive SC despite the CAK" \
                "mismatch"
            return 1
        fi
        if grep -qiE "icv|integrity" "$RUNDIR/mkad.log" 2>/dev/null; then
            echo "  MKAdaemon rejected the MKPDUs on their ICV"
        else
            # Not a failure - MKAdaemon may log it differently - but worth
            # saying, because "no association" would also be the result if the
            # two never exchanged a frame at all.
            echo "  NOTE: no ICV rejection in MKAdaemon's log; frames may not"
            echo "        have reached it. Confirm the link before trusting"
            echo "        this as an ICV test."
        fi
        echo "  ok: $label"
        kill "$WM_PID" 2>/dev/null || true
        kill "$MKAD_PID" 2>/dev/null || true
        WM_PID=""
        MKAD_PID=""
        ip netns del "$NS_A" 2>/dev/null || true
        ip netns del "$NS_B" 2>/dev/null || true
        sleep 1
        return 0
    fi

    if [ "$ok" != 1 ]; then
        echo "FAIL: $label - no SAK convergence as key_server=$want_ks" \
            "within ${wait_for}s"
        echo "  --- wolfMKA log (last 40) ---"
        tail -40 "$RUNDIR/wm.log" 2>/dev/null || true
        # MKAdaemon names its reason for discarding an MKPDU, so the one that
        # fired is read off rather than inferred.
        echo "  --- MKAdaemon: rejected MKPDUs / ICV / CKN ---"
        grep -iE "icv|ckn|discard|reject|invalid|cannot|fail" \
            "$RUNDIR/mkad.log" 2>/dev/null | tail -20 || true
        # The two one-way incompatibilities that make MKAdaemon discard every
        # frame while looking healthy, called out by name because both present
        # as a plain convergence timeout.
        if grep -q "unsupported version" "$RUNDIR/mkad.log" 2>/dev/null; then
            echo "  NOTE: MKAdaemon discards MKPDUs that do not announce MKA"
            echo "        version 3. Build the wolfMKA side with"
            echo "        -DWOLFMKA_MKA_VERSION=3U (examples/mka_macsec_mkad)."
        fi
        if grep -qi "invalid ICV" "$RUNDIR/mkad.log" 2>/dev/null; then
            echo "  NOTE: ICV mismatch. The ICV covers DA || SA || EtherType"
            echo "        ahead of the MKPDU (802.1X-2020 9.4.1); a peer that"
            echo "        signs the MKPDU alone cannot match it."
        fi
        echo "  --- MKAdaemon log (last 40) ---"
        tail -40 "$RUNDIR/mkad.log" 2>/dev/null || true
        return 1
    fi

    if [ "$want_ks" = 0 ]; then
        # As a member wolfMKA must have installed a key it did not generate:
        # the Distributed SAK arrived, unwrapped under the KEK and reached the
        # SecY. Without this the round could pass on wolfMKA merely holding a
        # key of its own.
        grep -q "install TX SA" "$RUNDIR/wm.log" || {
            echo "FAIL: $label - wolfMKA never installed MKAdaemon's SAK"
            return 1
        }
    fi

    # The whole point of the data-plane tier: both stacks derived the same SAK
    # and encrypt/decrypt compatibly.
    if ip netns exec "$NS_A" ping -c 3 -W 2 "$IP_B" >"$RUNDIR/ping.log" 2>&1
    then
        echo "  ping OK (MACsec-protected traffic flows)"
    else
        echo "FAIL: $label - ping across the MACsec link failed"
        cat "$RUNDIR/ping.log" 2>/dev/null || true
        echo "  --- wolfMKA MACsec device ---"
        ip netns exec "$NS_A" ip macsec show 2>/dev/null | sed -n '1,12p' \
            || true
        echo "  --- MKAdaemon MACsec device ---"
        ip netns exec "$NS_B" ip macsec show 2>/dev/null | sed -n '1,12p' \
            || true
        return 1
    fi

    # Both ends must actually be encrypting. The Confidentiality Offset is a
    # two-bit Table 11-6 selector in the Distributed SAK, and 0 means "no
    # confidentiality" - so an off-by-one encoding leaves the peer protecting
    # without encrypting while everything else looks healthy. The ping above
    # cannot see it: the SecTAG carries the E bit per frame, so one end
    # encrypting and the other not still passes traffic.
    # MKAdaemon creates its own device (drv_macsec_mode: software) from the
    # offset it was given, so $NS_B is the real assertion; this script creates
    # $NS_A's device with "encrypt on" itself, so that end is a sanity check
    # that will start carrying weight once the example implements
    # set_cipher_suite.
    for ns_dev in "$NS_A:wolfMKA" "$NS_B:MKAdaemon"; do
        ns=${ns_dev%%:*}
        who=${ns_dev#*:}
        if ! ip netns exec "$ns" ip macsec show 2>/dev/null \
            | grep -q "encrypt on"; then
            echo "FAIL: $label - $who is protecting without encrypting"
            echo "        (confidentiality offset negotiated as \"none\")"
            ip netns exec "$ns" ip macsec show 2>/dev/null | sed -n '1,4p' \
                || true
            return 1
        fi
    done
    echo "  both ends encrypt (confidentiality offset in force)"

    # Every SecY hook must have been accepted by the kernel. A refused call can
    # leave a device that still happens to forward, so this does not follow
    # from the ping above.
    if grep -E "\[SecY\].* -> -[0-9]+$" "$RUNDIR/wm.log" >/dev/null 2>&1; then
        echo "  --- SecY calls the kernel refused ---"
        grep -E "\[SecY\].* -> -[0-9]+$" "$RUNDIR/wm.log" | tail -12
        if [ "$STRICT" = 1 ]; then
            echo "FAIL (INTEROP_STRICT=1): a SecY hook was refused"
            return 1
        fi
        echo "  WARN: a SecY hook was refused (see above)"
    fi

    # A rekey is where the XPN derivations get their only moving input: the
    # Salt is folded from the Key Number, so KN 1 and KN 2 are different salts
    # that both ends must recompute independently and in step. An end that
    # derived the salt once and cached it passes every round above and fails
    # here.
    if [ "$rekey" = 1 ]; then
        echo "  --- rekey (SIGUSR1 -> wolfMKA as Key Server, expecting kn=2) ---"
        kill -USR1 "$WM_PID" 2>/dev/null || true
        i=0
        while [ "$i" -lt 15 ]; do
            sleep 1
            i=$((i + 1))
            grep -q "kn=2" "$RUNDIR/wm.log" 2>/dev/null && break
        done
        if ! grep -q "kn=2" "$RUNDIR/wm.log" 2>/dev/null; then
            echo "FAIL: $label - no rekey to kn=2 within 15s"
            tail -20 "$RUNDIR/wm.log" 2>/dev/null || true
            return 1
        fi
        echo "  wolfMKA advanced to Key Number 2"
        if ip netns exec "$NS_A" ping -c 3 -W 2 "$IP_B" \
            >"$RUNDIR/ping2.log" 2>&1; then
            echo "  ping OK after rekey (new Key Number, new salt)"
        else
            echo "FAIL: $label - ping failed after the rekey"
            cat "$RUNDIR/ping2.log" 2>/dev/null || true
            echo "  --- wolfMKA MACsec device ---"
            ip netns exec "$NS_A" ip macsec show 2>/dev/null | sed -n '1,12p' \
                || true
            echo "  --- MKAdaemon MACsec device ---"
            ip netns exec "$NS_B" ip macsec show 2>/dev/null | sed -n '1,12p' \
                || true
            return 1
        fi
    fi

    # Peer loss and rejoin. MKAdaemon is stopped, wolfMKA must expire it after
    # the MKA Life Time and tear the SAs down, then MKAdaemon comes back with a
    # fresh Member Identifier - a different participant as far as MKA is
    # concerned, so a new SAK has to be agreed. That makes the Key Identifier
    # change, and with it the XPN Salt, on a path where neither end was
    # restarted deliberately. Nothing else in this tier covers expiry at all.
    # The mirror: this end goes away and comes back. MKAdaemon has to expire
    # us, and we have to rejoin a CA that is already running - a different path
    # from forming one, and the only round where wolfMKA is the returning
    # participant rather than the one doing the expiring.
    if [ "$restart" = 2 ]; then
        echo "  --- self restart (stop wolfMKA, expire, bring it back) ---"
        kill "$WM_PID" 2>/dev/null || true
        WM_PID=""
        # Long enough for MKAdaemon to pass the MKA Life Time and drop us.
        i=0
        while [ "$i" -lt 12 ]; do
            sleep 1
            i=$((i + 1))
            ip netns exec "$NS_B" ip macsec show 2>/dev/null \
                | grep -q "RXSC" || break
        done

        ip netns exec "$NS_A" "$MKA_MACSEC" "$VETH_A" "$MS_A" "$wm_pri" \
            "$CAK" "$CKN" 0 "$sak_len" "$xpn" >>"$RUNDIR/wm.log" 2>&1 &
        WM_PID=$!

        i=0
        ok=0
        while [ "$i" -lt "$wait_for" ]; do
            sleep 1
            i=$((i + 1))
            ip netns exec "$NS_B" ip link set "$MS_B" up 2>/dev/null || true
            ip netns exec "$NS_B" ip addr show dev "$MS_B" 2>/dev/null \
                | grep -q "$IP_B" || \
                ip netns exec "$NS_B" ip addr add "$IP_B/24" dev "$MS_B" \
                    2>/dev/null || true
            if grep "state:" "$RUNDIR/wm.log" 2>/dev/null | tail -1 \
                | grep -q "sak=1"; then
                if grep "state:" "$RUNDIR/wm.log" 2>/dev/null | tail -1 \
                    | grep -q "live=[1-9]"; then
                    ok=1
                    break
                fi
            fi
        done
        if [ "$ok" != 1 ]; then
            echo "FAIL: $label - wolfMKA did not rejoin after restarting"
            echo "  --- wolfMKA log (last 25) ---"
            tail -25 "$RUNDIR/wm.log" 2>/dev/null || true
            echo "  --- MKAdaemon log (last 25) ---"
            tail -25 "$RUNDIR/mkad.log" 2>/dev/null || true
            return 1
        fi
        echo "  wolfMKA rejoined the running CA"

        if ip netns exec "$NS_A" ping -c 3 -W 2 "$IP_B" \
            >"$RUNDIR/ping4.log" 2>&1; then
            echo "  ping OK after wolfMKA restarted"
        else
            echo "FAIL: $label - ping failed after wolfMKA restarted"
            cat "$RUNDIR/ping4.log" 2>/dev/null || true
            echo "  --- wolfMKA SecY timeline (last 25) ---"
            grep -E "\[SecY\]|state:|peer:" "$RUNDIR/wm.log" 2>/dev/null \
                | tail -25 || true
            ip netns exec "$NS_A" ip macsec show 2>/dev/null | sed -n '1,12p' \
                || true
            ip netns exec "$NS_B" ip macsec show 2>/dev/null | sed -n '1,12p' \
                || true
            return 1
        fi
    fi

    if [ "$restart" = 1 ]; then
        echo "  --- peer restart (stop MKAdaemon, expire, bring it back) ---"
        before_kn=$(grep "state:" "$RUNDIR/wm.log" 2>/dev/null | tail -1 \
            | sed 's/.*kn=//' || true)
        before_kn=${before_kn:-0}
        # Every round opens with "state: live=0 ..." before the peer is heard
        # from, so the expiry has to be looked for strictly after this point in
        # the log - searching the whole file matches that opening line and
        # "detects" an expiry that has not happened.
        before_lines=$(wc -l <"$RUNDIR/wm.log" 2>/dev/null || echo 0)
        kill "$MKAD_PID" 2>/dev/null || true
        MKAD_PID=""

        i=0
        expired=0
        while [ "$i" -lt 20 ]; do
            sleep 1
            i=$((i + 1))
            if tail -n +$((before_lines + 1)) "$RUNDIR/wm.log" 2>/dev/null \
                | grep -q "live=0"; then
                expired=1
                break
            fi
        done
        if [ "$expired" != 1 ]; then
            echo "FAIL: $label - wolfMKA never expired the stopped peer"
            tail -20 "$RUNDIR/wm.log" 2>/dev/null || true
            return 1
        fi
        echo "  wolfMKA expired the peer (MKA Life Time)"

        ip netns exec "$NS_B" "$MKAD" -c "$RUNDIR/mkad.conf" -f -v 3 \
            >>"$RUNDIR/mkad.log" 2>&1 &
        MKAD_PID=$!

        # Re-converged only when a *newer* Key Number is in force: the returning
        # peer has a fresh MI, so reusing the old SAK would be a bug, and
        # polling on "sak=1" alone would match the key from before the restart.
        #
        # MKAdaemon deletes and recreates its macsec device when it restarts -
        # the new one has a different ifindex and, more to the point, none of
        # the IP configuration the harness put on the old one. Reapply it here
        # as the first convergence loop does, or the round fails on a ping to
        # an address that no longer exists while MACsec itself is working
        # perfectly.
        i=0
        ok=0
        while [ "$i" -lt "$TIMEOUT" ]; do
            sleep 1
            i=$((i + 1))
            ip netns exec "$NS_B" ip link set "$MS_B" up 2>/dev/null || true
            ip netns exec "$NS_B" ip addr show dev "$MS_B" 2>/dev/null \
                | grep -q "$IP_B" || \
                ip netns exec "$NS_B" ip addr add "$IP_B/24" dev "$MS_B" \
                    2>/dev/null || true
            now_kn=$(grep "state:" "$RUNDIR/wm.log" 2>/dev/null | tail -1 \
                | sed 's/.*kn=//' || true)
            now_kn=${now_kn:-0}
            # Both halves matter. A higher Key Number on its own proves
            # nothing about the peer: losing it forces a rekey on the Key
            # Server, so that alone is satisfied while the peer is still gone,
            # and the round would then ping into the void. The last state line
            # must also show a live peer again.
            if [ "$now_kn" -gt "$before_kn" ] 2>/dev/null && \
                grep "state:" "$RUNDIR/wm.log" 2>/dev/null | tail -1 \
                    | grep -q "live=[1-9]"; then
                ok=1
                break
            fi
        done
        if [ "$ok" != 1 ]; then
            echo "FAIL: $label - the peer did not return with a fresh" \
                "SAK (Key Number $before_kn -> $now_kn, last state above)"
            tail -20 "$RUNDIR/wm.log" 2>/dev/null || true
            tail -20 "$RUNDIR/mkad.log" 2>/dev/null || true
            return 1
        fi
        echo "  peer rejoined and a fresh SAK was agreed (kn $before_kn -> $now_kn)"

        if ip netns exec "$NS_A" ping -c 3 -W 2 "$IP_B" \
            >"$RUNDIR/ping3.log" 2>&1; then
            echo "  ping OK after the peer rejoined"
        else
            echo "FAIL: $label - ping failed after the peer rejoined"
            cat "$RUNDIR/ping3.log" 2>/dev/null || true
            echo "  --- wolfMKA SecY timeline (last 25) ---"
            grep -E "\[SecY\]|state:|peer:" "$RUNDIR/wm.log" 2>/dev/null \
                | tail -25 || true
            if ! ip netns exec "$NS_B" ip addr show dev "$MS_B" 2>/dev/null \
                | grep -q "$IP_B"; then
                echo "  NOTE: the restarted peer's device has no $IP_B - the"
                echo "        daemon recreates it, so this is the harness"
                echo "        failing to re-address it, not a MACsec failure."
            fi
            ip netns exec "$NS_A" ip macsec show 2>/dev/null | sed -n '1,12p' \
                || true
            ip netns exec "$NS_B" ip macsec show 2>/dev/null | sed -n '1,12p' \
                || true
            return 1
        fi
    fi

    echo "  ok: $label"
    kill "$WM_PID" 2>/dev/null || true
    kill "$MKAD_PID" 2>/dev/null || true
    WM_PID=""
    MKAD_PID=""
    ip netns del "$NS_A" 2>/dev/null || true
    ip netns del "$NS_B" 2>/dev/null || true
    sleep 1
    return 0
}

# Both Key Server roles. wolfMKA favoured drives distribution - it generates
# the SAK, wraps it under the KEK and emits the Distributed SAK set. MKAdaemon
# favoured exercises the opposite half: unwrapping a third party's SAK,
# installing it and reporting it back in MACsec SAK Use.
round 10 20 1 16 "wolfMKA is Key Server" 0 0 1 || exit 1
round 30 20 0 16 "wolfMKA is a member" || exit 1
# GCM-AES-256 names the cipher suite explicitly in the Distributed SAK set and
# wraps 32 octets rather than 16 - a different encode and unwrap path.
round 10 20 1 32 "wolfMKA is Key Server, GCM-AES-256" || exit 1

# Extended Packet Numbering. Worth its own rounds because almost everything
# about the data plane changes: the packet number widens to 64 bits, the SA
# carries a Short SCI, and the initialisation vector takes a 12-octet salt that
# MKA never distributes - each end derives it from the Key Identifier instead.
# A salt or SSCI that disagrees by one octet still converges the CA and still
# installs SAs; only the traffic fails, so the ping below is the real check.
# Both roles are run: as Key Server wolfMKA assigns the SSCIs, as a member it
# has to adopt MKAdaemon's.
round 10 20 1 16 "wolfMKA is Key Server, GCM-AES-XPN-128" 1 1 1 || exit 1
round 30 20 0 16 "wolfMKA is a member, GCM-AES-XPN-128" 1 || exit 1
round 10 20 1 32 "wolfMKA is Key Server, GCM-AES-XPN-256" 1 1 || exit 1

# wolfMKA is the one that goes away and comes back: it must rejoin a CA that is
# already running, under a fresh Member Identifier, rather than form one.
round 10 20 1 16 "wolfMKA restarts and rejoins" 0 0 2 || exit 1

# Negative: same CKN, different CAK. Nothing may associate - and the check is
# that nothing does, not merely that the ping fails.
round 10 20 1 16 "a peer with the wrong CAK is not admitted" 0 0 0 1 || exit 1

echo "PASS: wolfMKA and MKAdaemon interoperate (both Key Server roles," \
    "GCM-AES-128/256 and GCM-AES-XPN-128/256)"
exit 0
