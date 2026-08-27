# wolfMKA interoperability harness

These scripts validate wolfMKA against independent MKA implementations
(hostapd/wpa_supplicant, and MKAdaemon in Tier 4) over a real wire,
complementing the byte-pinned crypto
vectors in the unit suite (`test_eap_derivation`, `test_icv`). Where those prove
the *cryptographic constructions* match hostapd, these prove two separate stacks
complete the protocol on the wire: discovery, Key Server election, SAK
distribution and — in Tier 2 — kernel MACsec bring-up and protected traffic.

Every tier runs the two implementations in separate Linux **network
namespaces** joined by a **veth** pair, sharing one pre-shared CAK/CKN (PSK-CAK
mode; Tier 3 is the exception - it derives the CAK from a real EAP exchange).

## The ICV covers the Ethernet framing

IEEE Std 802.1X-2020, 9.4.1 defines the MKPDU ICV as

```
ICV = AES-CMAC(ICK, M, 128)
M   = DA + SA + (MSDU - ICV)
```

with M "the concatenation of the destination and source MAC addresses, each
represented by a sequence of 6 octets in canonical format order, with the MSDU
of the MKPDU including the allocated Ethertype, and up to but not including,
the generated ICV". There is no variant: Algorithm Agility is the only
mechanism by which the ICV computation may differ, and the standard withholds
any conformance claim from an alternate.

Every peer tested here computes it that way - wpa_supplicant
(`ieee802_1x_kay_encode_mkpdu` assembles DA, SA and EtherType into the buffer it
hashes), MKAdaemon (`mka_receive_from_l2` hands `mka_mkpdu_verify` the whole
frame buffer, Ethernet header still on the front), and libmka
(`ics_mka_gen_icv` feeds the CMAC destination address, source address and
EtherType before the MKPDU). Three unrelated implementations, one reading.

wolfMKA used to sign the MKPDU alone unless built with `WOLFMKA_ICV_L2_ADDR`,
which made the default build non-conformant and unable to interoperate with any
of them; the flag is gone and the framing is unconditional. Historical note,
because it shaped this harness: every tier used to build its own binaries with
that flag set.

| Script | Tier | Proves |
| --- | --- | --- |
| `run-interop.sh` | 1 — control plane | wolfMKA `mka_link` and wpa_supplicant discover each other, elect a Key Server and agree a SAK — three rounds: each side favoured in turn, then GCM-AES-256 |
| `run-interop-dataplane.sh` | 2 — data plane | both program the kernel MACsec SA; `ping` flows protected; on-wire frames are MACsec (0x88e5), not cleartext; two successive Key Server rekeys roll the key, traffic survives each, every SecY call is accepted and the SAs do not accumulate — run once per cipher suite |
| `run-interop-eap.sh` | 3 — EAP key derivation | hostapd and wpa_supplicant run a real EAP-GPSK exchange; wolfMKA derives a CAK/CKN from the resulting MSK and must match wpa_supplicant's byte for byte |
| `run-interop-mkad.sh` | 4 — second implementation | the Tier 2 data-plane exercise against **MKAdaemon** instead of wpa_supplicant — both Key Server roles, GCM-AES-128 and GCM-AES-256 |

## Both Key Server roles

Tier 1 runs the exchange twice. With wolfMKA favoured (priority 10 against 20)
it drives distribution: generates the SAK, wraps it under the KEK and emits the
Distributed SAK parameter set. With wpa_supplicant favoured (wolfMKA at 30) it
is a plain member, which exercises the opposite half — unwrapping a peer's SAK,
installing it into the SecY and reporting it back in MACsec SAK Use — against a
real implementation rather than against wolfMKA's own encoder. Only the first
half used to be covered.

Tier 2 is likewise run once per suite (`SAK_LEN=32` selects GCM-AES-256), which
additionally drives the *kernel* MACsec device at 256-bit — something Tier 1
cannot reach, since it uses the logging SecY. The cipher suite is fixed when a
MACsec device is created, and `mka_macsec` implements no `set_cipher_suite`
hook, so the harness creates the device with the matching `cipher` — a 32-octet
SAK agreed against a device left at GCM-AES-128 decrypts nothing.

The rekey step reports how long traffic took to resume. Make-before-break
should be close to seamless, so a multi-second gap is called out: it means
something waited for a timer rather than for the handshake.

The rekey runs **twice**. The first round is the interesting one for the
handover itself, but a single rekey is a weak test of everything around it:
several bugs only appear from the second SAK onwards - the KaY re-creating a
receive Secure Channel that already exists is one (Linux answers `-EEXIST`),
and an SA that is never reclaimed is another, since after one rekey a device
holding Old + Latest looks identical either way. After each round the harness
counts the SAs the kernel actually holds and fails if there are more than four,
which is the make-before-break ceiling: Old + Latest on each of the two Secure
Channels.

Two things are then checked that a green `ping` cannot see. First, **every
SecY hook must have been accepted by the kernel**: `mka_macsec` traces the
return code of each one, so a single grep for a negative code covers them all.
A refused call can leave a device that still happens to forward, so without
this a bookkeeping bug passes the traffic test - which is how the KaY
re-creating an already-existing receive SC (Linux answers `-EEXIST`) went
unnoticed.

> This check earned its place on the first run that used it. It warned on
> every rekey, with codes that could not belong to the commands they were
> printed against — `install_rx_sa` reporting `-EEXIST` when the kernel answers
> a duplicate receive SA with `-EBUSY`, and `install_tx_sa` reporting `-EBUSY`
> on a demonstrably fresh Association Number. Two separate bugs: the KaY was
> deleting the Old key's receive SAs without disabling them first, which Linux
> refuses with `-EBUSY` so they were never deleted at all; and
> `nl_send_ack` was not matching replies to requests, so that refusal appeared
> against a later, innocent command. Both are fixed. Traffic had survived every
> rekey throughout, which is why the ping check never noticed — the leak only
> becomes an outage once the Association Numbers wrap onto an SA that is still
> installed.

Second, **the old key must be retired**: make-before-break installs
the new SAK alongside the old one, and if the old SA is never torn down the
device accumulates one per rekey until the Association Numbers wrap onto a key
that is still installed. Both are warnings by default and failures under
`INTEROP_STRICT=1`.

`peer.conf.in` is shared by tiers 1 and 2 and carries `@CAK@`, `@CKN@`,
`@CTRL@`, `@PRIORITY@` and `@CSINDEX@`. Every consumer must substitute every
placeholder: an unsubstituted one goes into wpa_supplicant's config verbatim and
it refuses to start, which surfaces as a convergence timeout rather than as a
config error. Adding a placeholder means updating both scripts.

A third round repeats the Key Server case with **GCM-AES-256**
(`macsec_csindex=1` on the wpa side, a 32-octet SAK on wolfMKA's). That is not
the default suite, so the Distributed SAK parameter set names it explicitly on
the wire and the key wrap is over 32 octets rather than 16 — a different encode
path and a different unwrap from the first two rounds, neither of which any
other tier reaches.

The expected role is part of the convergence condition, not an assertion made
afterwards: with no peer yet a capable participant elects *itself*, so in the
member round wolfMKA is briefly Key Server with a SAK of its own before it
yields. Polling on "has a SAK" alone could catch that instant and report the
wrong half as proven.

## Tier 3: the EAP-derived CAK

Tiers 1 and 2 key from a **pre-shared** CAK/CKN (`key_mgmt=NONE`), so IEEE Std
802.1X-2010 9.3.2 — the CAK and CKN derived from an EAP Master Session Key —
never runs there. `run-interop-eap.sh` covers it.

wolfMKA has no EAP of its own: it consumes an MSK the integrator supplies. So
the exchange is run by the two implementations that do have one — **hostapd** as
the 802.1X authenticator with its built-in EAP server (`driver=wired`,
`eap_server=1`), and **wpa_supplicant** as the supplicant — over a veth pair,
using **EAP-GPSK** because it needs no certificates and still yields an MSK.
wpa_supplicant derives its own CAK/CKN from that MSK and, under `-dd -K`, logs
the MSK, the EAP Session-Id and both derived keys. The harness recovers all
three, runs wolfMKA's derivation over the same inputs via `eap_derive`, and
requires the bytes to be identical.

Two configuration points are not obvious and both produce silent failures:

- The supplicant must run with **`-D macsec_linux`**, not `-D wired`.
  `ieee802_1x_notify_create_actor` returns early unless `wpa_s->kay` already
  exists, and the KaY is only allocated for a MACsec-capable driver — so under
  `-D wired` the CAK/CKN are never derived at all, however well EAP goes.
- The `eap_user` entry must **not** carry the `[2]` flag, which marks an entry
  phase-2 only. hostapd's phase-1 lookup then finds nothing and answers
  EAP-Failure the moment the Identity response arrives.

What this proves that a known-answer vector does not: the inputs come from a
live exchange rather than a fixture — in particular the **Session-Id**, whose
construction is method-specific, the **MAC ordering**, which both ends must
independently concatenate lowest-first, and the **MSK truncation**, since
wpa_supplicant clamps the MSK to the CAK length before deriving (the harness
reads that length from wpa's own output). That last point is the
`msk_len == cak_len` rule checked against the real implementation rather than
against a reading of its source.

`kdf_oracle.py` remains as the offline complement: an independent transcription
of hostapd's `aes_kdf` (`src/pae/ieee802_1x_key.c`), written from that source
rather than from wolfMKA, which reproduces every EAP vector pinned in
`test_eap_derivation` and can regenerate or extend them:

    python3 test/interop/kdf_oracle.py

## Tier 4: a second, unrelated implementation

Tiers 1-3 all measure wolfMKA against hostapd/wpa_supplicant. That is one
reading of IEEE Std 802.1X-2010: where the standard is ambiguous, or where both
implementations happen to share an assumption, agreeing with it demonstrates
compatibility with wpa_supplicant rather than conformance to the standard.

[MKAdaemon](https://github.com/Technica-Engineering/MKAdaemon) (Technica
Engineering, GPL-2.0-or-later) is an unrelated implementation with an automotive
lineage, so it is a genuinely independent check. Tier 4 repeats the Tier 2
data-plane exercise against it: both Key Server roles, GCM-AES-128 and
GCM-AES-256, protected `ping` across the link, and the same "every SecY call was
accepted" check, plus one Tier 2 has no reason to make - that **both ends are
actually encrypting**.

It earned its place on its first green run. The Confidentiality Offset in the
Distributed SAK is a two-bit Table 11-6 selector where 0 means *no
confidentiality*, and wolfMKA numbered the enumeration one low, so it sent 0 to
mean "encrypt from octet 0". MKAdaemon read it as sent: every round in which
wolfMKA was Key Server brought MKAdaemon's data plane up `encrypt off`, and the
round in which MKAdaemon held the role came up `encrypt on`.

Nothing else in the harness could have caught it. The CA converges, the SAKs
match, and the `ping` passes either way, because the SecTAG carries the E bit
per frame - so one end encrypting and the other not is a working link that
silently protects without confidentiality. Tier 2 is blind to it for a
different reason: wpa_supplicant does not act on the received field, so it
encrypted whatever wolfMKA sent. Two implementations sharing an assumption is
the failure mode this tier exists for; here they did not share one, and only
the second peer showed it.

### MKAdaemon needs a non-default flag

Tier 4 builds its own `examples/mka_macsec_mkad` rather than reusing Tier 2's
binary, because it needs `WOLFMKA_MKA_VERSION=3U`.

`WOLFMKA_MKA_VERSION` is the MKA version announced in the Basic Parameter Set
(11.11.1): **1** for IEEE Std 802.1X-2010, **2** for 802.1Xbx-2014, **3** for
802.1X-2020. wolfMKA defaults to 1 — the base its wire format is implemented to
— and wpa_supplicant both sends and accepts 1. MKAdaemon comes from the OPEN
Alliance side, where version 3 is mandated: it announces 3 and **discards any
MKPDU that does not announce exactly 3**, with an `MKA_ALLOW_OTHER_VERSIONS`
build switch that is off by default.

wolfMKA never rejects on a peer's announced version — it records it and moves
on — so the incompatibility is one-way and presents as MKAdaemon looking
perfectly healthy while never going live, with `Received MKPDU with unsupported
version 1. Discarding.` buried in its debug log. The harness names this case
explicitly when a round times out. Announcing 3 costs nothing: the field is
advisory and the wire format is unchanged.

It is not part of CI. MKAdaemon is not packaged, so a CI job would have to build
it from source, and a step that silently skips when that build fails is exactly
the failure mode the `INTEROP_STRICT` flag exists to prevent. It also needs five
`-dev` packages that a runner image will not have by default (`libyaml-dev`,
`libbsd-dev`, `libnl-3-dev`, `libnl-genl-3-dev`, `libnl-route-3-dev`); note that
without `libbsd-dev` the `configure` probe for XPN kernel support reports `no`
rather than failing, because it links rather than merely compiles. Run it
locally:

```sh
git clone --depth 1 https://github.com/Technica-Engineering/MKAdaemon.git
cd MKAdaemon
# DISABLE_DBUS drops the gdbus-codegen/glib/libxml2 requirements, which the
# harness does not use. Recent GCC turns an upstream warning in
# src/utils/mka_logging.c into an error under its -Werror, hence -Wno-error.
DISABLE_DBUS=1 CFLAGS="-Wno-unterminated-string-initialization -Wno-error" \
    ./configure
python3 waf build
```

Then, from `mka/wolfMKA`:

```sh
sudo make interop-mkad MKAD=/path/to/MKAdaemon/build/mkad
```

Check the configure output for `Checking linux kernel support for XPN : yes`.
That probe compiles *and links* a fragment, so an unrelated missing library
makes it report `no` and silently drop the XPN cipher suites rather than failing
the build.

`mkad.conf.in` carries `@DEVICE@`, `@PROTECTED@`, `@PRIORITY@`, `@CIPHER@`,
`@CAK@` and `@CKN@`. As in `peer.conf.in`, every placeholder must be
substituted — MKAdaemon rejects the file outright on an unknown token, which
surfaces as a convergence timeout rather than a config error, so the harness
checks for survivors before starting the daemon. The CAK and CKN are derived
from the same hex constants the wolfMKA side uses rather than written out twice
in MKAdaemon's space-separated format: two hand-maintained copies that must
agree is precisely the mismatch that reads as a library bug, since a CAK that
agrees with a CKN that does not looks identical to a failed key derivation.

MKAdaemon also requires `transmit_empty_dist_sak`, `transmit_empty_sak_use`,
`transmit_null_xpn` and `secy_polling_ms` to be present in the global section —
it refuses to start naming them rather than defaulting them.

### XPN, and why only this tier can test it

MKAdaemon negotiates `GCM_AES_XPN_128` and `GCM_AES_XPN_256`. The
wpa_supplicant tested against (2.11) implements GCM-AES-128 and GCM-AES-256 and
nothing else, so Tier 4 is not merely the most convenient place to exercise
Extended Packet Numbering — it is the only one. Three XPN rounds run here, both
Key Server roles and both SAK lengths, two of them rekeying.

XPN changes almost everything below the KaY. The packet number widens to 64
bits, so `MACSEC_SA_ATTR_PN` becomes a `u64` — an XPN device rejects the 32-bit
form. Each SA gains a Short SCI, `MACSEC_SA_ATTR_SSCI`, in network order, and
it is *per Secure Channel*: ours on the transmit SA, the peer's on each receive
SA, so one shared value decrypts nothing. And the initialisation vector takes a
12-octet Salt that MKA never puts on the wire.

The Salt is the part worth stating precisely, because getting it wrong is
undetectable from the control plane. It is **not** derived from the SAK. It is
the Key Identifier's Member Identifier with the Key Number folded into the
first four octets, with the Key Number's two 16-bit halves swapped:

```
salt[0] = mi[0] ^ (kn >>  8)      salt[2] = mi[2] ^ (kn >> 24)
salt[1] = mi[1] ^  kn             salt[3] = mi[3] ^ (kn >> 16)
salt[4..11] = mi[4..11]
```

Both ends already hold the MI and the Key Number from the Distributed SAK, so
neither has to transmit it. A salt or SSCI that disagrees by a single octet
still elects a Key Server, still installs SAs, and still reports a healthy CA
on both sides — only the traffic fails. That is why the XPN rounds lean on the
protected `ping` rather than on convergence.

The two Key Server XPN rounds also rekey. That is the only moving input these
derivations get: the Salt is folded from the Key Number, so KN 1 and KN 2 are
different salts that both ends must recompute independently and stay in step
on. An implementation that derived the salt once and cached it passes every
non-rekeying round and fails there.

**A rekeying run still does not exercise the interesting half of the fold.**
Key Numbers start at 1 and a round reaches 2, and for any KN below 256 three of
the four XOR terms above are zero - only `salt[1]` varies. The swapped-halves
ordering, which is the surprising part and the easiest to get wrong, needs
KN >= 256 to touch `salt[0]` and KN >= 65536 for `salt[3]`. Nothing here can
drive a Key Number that high, so that ordering rests on reading MKAdaemon's
source rather than on a passing round.

The derivation as a whole is matched against MKAdaemon, which is the only XPN
peer available here; it has not been cross-checked against a third
implementation or against the standard's text. The same caveat applies to the
SSCI ranking direction (highest SCI = 1, IEEE Std 802.1AE-2018 10.7.13): it is
what MKAdaemon implements, and wolfMKA ranked the other way until these rounds
were run.

### What the rounds cover

Eight rounds: both Key Server roles, GCM-AES-128/256 and GCM-AES-XPN-128/256,
Key-Server-driven rekeys on the XPN rounds, a peer restart, a wolfMKA restart,
and one negative round.

The two restart rounds are not the same test twice. When MKAdaemon restarts,
wolfMKA is the one that has to expire a peer, tear its SAs down and key a
returning stranger. When wolfMKA restarts, it is the one that has to rejoin a
CA that is already running - forming a CA and joining one are different paths,
and only this round exercises the second from our side.

The negative round gives MKAdaemon a **different CAK under the same CKN**. Both
ends select the CA by CKN and then fail to verify each other's ICV, so this
exercises the crypto rejection rather than the string compare a CKN mismatch
would hit. It asserts that nothing associates - no SAK on our side, no receive
SC on theirs - rather than merely that traffic does not flow, and it looks for
MKAdaemon's own ICV complaint in its log. If that complaint is absent the round
still passes but says so, because "nothing associated" is equally what you get
when the two never exchanged a frame at all, and a negative test that cannot
tell those apart is not evidence of anything.

### A restarted participant meets its own leftovers

wolfMKA's example is handed a MACsec device rather than owning one, so the SAs
it installs are still there when it exits. On restart the Association Numbers
begin again at 0 and the kernel answers `-EBUSY`; the example evicts the stale
SA and retries.

Worth knowing because of how it presents: the restarted end holds a *fresh* SAK
that never reached its data plane, so it keeps transmitting under the old key
while its peer has moved on. Both ends report a healthy CA. The signature in
the SecY trace is `install TX SA ... -> -16` followed by `state: ... sak=1` -
the participant declaring a key the kernel refused.

Note that wolfMKA itself does not currently act on a SecY hook returning an
error; `mka_secy_track` counts only the asynchronous-pending case. A data plane
that rejects a key is therefore invisible to the KaY, which goes on to
advertise that key as in use in its MACsec SAK Use parameter set.

### MKAdaemon recreates its device on restart

The peer-restart round stops MKAdaemon and brings it back. MKAdaemon owns its
macsec device (`drv_macsec_mode: software`) and deletes and recreates it across
that restart - the returning device has a new ifindex and none of the harness's
IP configuration, though the same MAC and therefore the same SCI. The round
reapplies the address while waiting to re-converge.

Getting this wrong looks alarming and means nothing: the CA re-forms, both ends
agree a fresh SAK, and `ip macsec show` shows packet numbers advancing in step
on both sides - and the ping still fails, because the address it is aimed at no
longer exists. Matching, advancing PNs on both TXSC/RXSC pairs are the signal
that MACsec is fine and the problem is above it.

## Tier 5: libmka, a third implementation

libmka (Intrepid Control Systems, GPL-3.0-or-later, mbedTLS-backed) is
unrelated to both wpa_supplicant and MKAdaemon.
`make interop-libmka LIBMKA=/path/to/libmka` runs two rounds, one per Key
Server role.

**It is control-plane only.** libmka hands the agreed SAK to an `sa_installer`
callback and drives no MACsec device, so there is no protected ping here and no
confidentiality check. What is tested is that a third implementation of the
MKPDU format, the ICV and the key hierarchy agrees with wolfMKA on the key.

That is stronger evidence than it looks. The ICV is verified before any
parameter set is acted on, so libmka accepting a frame already proves both
derived the same ICK from the CAK/CKN. The SAK travels under AES Key Wrap,
whose integrity check fails closed, so libmka *installing* a SAK proves the KEK
matched too. The round then compares the Key Identifier each end reports -
wolfMKA's read back from the kernel via `ip macsec show`, libmka's from its
callback - so the two are matched on evidence from both sides rather than on
either one's word. Under `INTEROP_STRICT=1` a round that cannot read both Key
Identifiers fails rather than passing on the weaker claim.

### Two traps in libmka's API, both hit on the first run

Worth recording, because neither produces an error - the two ends simply never
hear each other:

- **`ics_mka_has_response` is a boolean wearing a result code.** It is declared
  `mka_result_t` but returns the value of a `||` expression: **1** when there
  *is* something to send, which is `MKA_ERROR` in that enumeration, and **0** -
  `MKA_SUCCESS` - when there is not. Test it for truth, never against
  `MKA_SUCCESS`; doing the latter transmits exactly when there is nothing to
  say. (libmka's own example writes `if((ics_mka_has_response(&state))`, which
  reads it correctly and does not compile.)
- **`ics_mka_next_pdu`'s last parameter is the next packet number, not a
  timestamp.** Passing a millisecond clock there advertises that value as the
  Lowest Acceptable PN.
- **`mka_new_sa_t.key_server` names a peer, so it is NULL when libmka is
  itself the Key Server** - the Member Identifier to use is then the local
  `state->id`. libmka makes the same substitution internally when deriving the
  Salt (`key_server ? &key_server->id : &state->id`). Without it, the round
  where libmka holds the role has no Key Identifier to compare and degrades to
  the weaker "each end has a key" claim.

libmka's own example cannot serve as the peer: it prompts for an interface on
stdin, is built around Npcap, and does not compile (`if((ics_mka_has_response
(&state)) {` has unbalanced parentheses). `libmka_peer.c` in this directory is
the equivalent driver, taking its parameters on the command line and running on
an `AF_PACKET` socket. It prints the SAK, which no production tool should do;
comparing the key both stacks derived is the point of the tier.

### Three-or-more-member CAs are not covered by any tier

Every tier here is two participants on a veth pair, and several things only
diverge beyond two. The XPN SSCI mapping is the clearest: with two members each
end can rank the two SCIs itself and get the same answer, which is why the
802.1X-2020 9.10 machinery - the ordered Live Peer List and the Key Server's
own SSCI - makes no observable difference here. wolfMKA implements both halves
of it and the unit suite pins them, but no round exercises them against another
implementation, and MKAdaemon's own SSCI code is explicitly two-member
(`in our case, N=2`).

### What libmka's source settled before a single round ran

Reading it closed three questions this project had been carrying on weaker
evidence:

- **XPN SSCI ranking.** `calculate_ssci` starts at 1 and increments per peer
  with a *greater* SCI - descending, highest SCI first. Third implementation to
  agree, after MKAdaemon and IEEE Std 802.1AE-2018.
- **Confidentiality Offset.** `MKA_NO_CONFIDENTIALITY = 0`,
  `MKA_CONFIDENTIALITY_NO_OFFSET = 1`, `_OFFSET_30 = 2`, `_OFFSET_50 = 3` -
  the Table 11-6 selector.
- **MKA Version 3.** It sorts the Live Peer List (`// MKA version 3 or above
  requires sorted peers`) and encodes `key_server_ssci`, the same two
  obligations 802.1X-2020 11.11 states as a *shall*.

It also confirmed the ICV framing: `ics_mka_gen_icv` feeds the CMAC
destination address, source address and EtherType before the MKPDU. Being the
third independent implementation to do so is what prompted re-reading 9.4.1,
which turned out to mandate it - see "The ICV covers the Ethernet framing"
above. wolfMKA's default is now the same, and the opt-in flag is gone.

## Prerequisites

- **root** (network namespaces, veth, raw sockets, MACsec netlink)
- **iproute2** (`ip`)
- the kernel **`macsec`** module (`modprobe macsec`) — Tiers 2 and 4
- **wpa_supplicant** built with `CONFIG_MACSEC=y` and
  `CONFIG_DRIVER_MACSEC_LINUX=y` — Tiers 1-3
- **hostapd** with an EAP server and the wired driver — Tier 3 only
- **MKAdaemon** (`MKAD=/path/to/mkad`) — Tier 4 only; see above for the build
- **tcpdump** (optional — Tier 2 uses it for the on-wire encryption check)

**XPN suites (GCM-AES-XPN-128/256) are covered by Tier 4 only**, in three
rounds — both Key Server roles, both SAK lengths. No other tier can: the
wpa_supplicant used here has no XPN support, so MKAdaemon is the only peer that
will negotiate those suites. See "XPN, and why only this tier can test it"
above, particularly for the Salt derivation, which the control plane cannot
check.

Both scripts print `SKIP` and exit 0 when a prerequisite is missing, so they are
safe to invoke anywhere. That is convenient and also a trap: in a CI log a skip
is indistinguishable from a pass, and this harness carried a build-configuration
defect for exactly that reason — it had never actually run. Set
**`INTEROP_STRICT=1`** where the prerequisites are supposed to be present and a
skip should fail the job instead.

CI runs tiers 1 and 3 with `INTEROP_STRICT=1`, so a runner that cannot provide
wpa_supplicant, hostapd or network namespaces fails the job rather than quietly
passing. Tier 2 is left non-strict there because it additionally needs a
loadable kernel `macsec` module, which not every runner image has. Tier 4 is
not in CI at all — see above.

Each script checks its prerequisites and prints `SKIP` (exit 0) when any is
missing, so it is safe to invoke in a constrained environment; it only does real
work — and can `FAIL` — where it can actually run.

## Running

From the repository root (the Makefile builds the needed example binaries
first):

```sh
make examples            # builds mka_link and mka_macsec
sudo make interop            # Tier 1 (control plane)
sudo make interop-dataplane  # Tier 2 (data plane)
sudo make interop-eap        # Tier 3 (EAP-derived CAK)
sudo make interop-mkad MKAD=/path/to/mkad   # Tier 4 (MKAdaemon)
```

or directly:

```sh
sudo MKA_LINK=examples/mka_link            test/interop/run-interop.sh
sudo MKA_MACSEC=examples/mka_macsec        test/interop/run-interop-dataplane.sh
sudo MKA_MACSEC=examples/mka_macsec MKAD=/path/to/mkad \
    test/interop/run-interop-mkad.sh
```

Environment overrides: `WPA_SUPPLICANT` (path/name of the binary), `MKAD`
(MKAdaemon binary), `TIMEOUT` (seconds to wait for convergence), `MKA_LINK` /
`MKA_MACSEC` (binary paths).

## Notes / tuning

- These are **not** part of the unit CI: they need privilege, the kernel MACsec
  module, and an external wpa_supplicant build. Run them on a privileged host or
  a `NET_ADMIN` container / self-hosted runner.
- Interface naming for wpa's auto-created MACsec device varies by version; the
  Tier 2 script discovers it with `ip -o link show type macsec`. If your
  wpa_supplicant names it unusually, adjust the discovery `awk`/`sed`.
- Timing of protocol convergence over real sockets is environment-sensitive;
  raise `TIMEOUT` on a slow or loaded host.
- Tier 2 keys both kernel devices from the SAK MKA agreed; if `ping` fails after
  the control plane converged, that is a genuine data-plane interop finding
  (SCI/AN/cipher mismatch) worth investigating, not a harness artefact.
