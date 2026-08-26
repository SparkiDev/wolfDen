# wolfMKA — OPEN Alliance TC17 Automotive MKA conformance map

This document maps wolfMKA against the **OPEN Alliance** *Automotive MKA
Specification* v1.0 (26 February 2025), produced by Technical Committee 17
(MACsec Automotive Profile). That specification profiles IEEE Std 802.1X-2020
MKA for in-vehicle Ethernet: it removes features an automotive network does not
need and tightens the startup budget from seconds to tens of milliseconds.

It is the OPEN-Alliance-facing companion to [`REQUIREMENTS.md`](REQUIREMENTS.md)
(the IEEE 802.1X requirements matrix) and [`AUTOSAR.md`](AUTOSAR.md) (the
AUTOSAR `Mka` API map), and follows the same "supports, not certified" scope
discipline as [`COMPLIANCE.md`](COMPLIANCE.md).

> wolfMKA is **not certified** to the Automotive MKA Specification and has not
> been tested at an OPEN Alliance plugfest. This document records, requirement
> by requirement, what the library implements, what the integrator must supply,
> and what is deliberately out of scope. Wording is deliberate: wolfMKA
> **supports** the Automotive MKA profile; do not upgrade that to "conforms" or
> "certified" in downstream material.
>
> The specification itself is copyright OPEN Alliance and its text is not
> reproduced here. Requirement identifiers (`AutoMKA-*`) are cited so a reader
> holding the specification can follow along; obtain it from
> <https://opensig.org/tech-committee/tc17-macsec-automotive-profile/>.

## Building the profile

```sh
make test-automotive          # build + run the suite under the profile
gcc ... -DWOLFMKA_AUTOMOTIVE_PROFILE
```

`WOLFMKA_AUTOMOTIVE_PROFILE` sets the two things that must be decided at compile
time:

| Effect | Requirement |
|--------|-------------|
| MKPDUs are emitted with MKA version **3** (`WOLFMKA_MKA_VERSION`) | §4, "Automotive MKA only uses Version 3 MKPDUs or above" (stated in the chapter text, not a numbered requirement) |
| Secure Announcements and cipher-suite negotiation are compiled out (implies `WOLFMKA_NO_ANNOUNCEMENTS`; combining it with `WOLFMKA_CIPHER_NEGOTIATION` is a build error) | AutoMKA-11001, AutoMKA-02001 |

Everything else the profile fixes is **runtime configuration**.
`wm_Participant_AutomotiveDefaults()` fills a `MkaParticipantConfig` with the
recommended values and leaves the caller's own fields (CAK/CKN, SCI, priority,
role, hooks) untouched:

```c
MkaParticipantConfig cfg = {0};
/* ... your CAK/CKN, SCI, priority, SecY and transmit hooks ... */
wm_Participant_AutomotiveDefaults(&cfg);   /* profile timing + fast response */
wm_Participant_Init(&p, &cfg);
```

It sets `immediate_response = true` and, in a build with the retry ramp,
`retry_base_ms = 10` / `retry_cyclic_ms = MKA_HELLO_TIME_MS`. Both settings are
available in **every** build — the profile macro is not required to use them.

## Startup behaviour

The profile's headline requirement is startup, so it is worth stating exactly
what wolfMKA does and what it measures.

Two mechanisms drive it, and they compose:

1. **The ramp** (AutoMKA-03004) — while no peer is live, the transmit interval
   starts at `retry_base_ms` and doubles toward `retry_cyclic_ms` (10, 20,
   40 ms … 2 s) instead of sitting at the Hello Time. This is the pre-existing
   MKA retry back-off, configured to the profile's proposed ramp.
2. **The immediate response** (AutoMKA-03003, AutoMKA-01015) — with
   `immediate_response` set, a change to the Potential or Live Peer List, an
   installed SAK, or the transmit gate releasing marks the participant's state
   as new information, and the next `wm_Participant_Run()` transmits rather
   than waiting out the interval. This is the `newInfo` concept of IEEE Std
   802.1X-2010 9.4. As Key Server it is what releases the Distributed SAK the
   moment a peer goes live; as a member it is what returns the MACsec SAK Use
   that lets the peer's transmit gate open.

`test_automotive_fast_startup` (in `test/test_kay.c`, run by `make test`) drives
two participants at a 1 ms tick and asserts MACsec is transmitting at both ends
well inside one Hello Time; it currently settles at **t = 3 ms** of protocol
time.

> **Read that figure honestly.** It is an in-process simulation: two
> participants, a zero-latency frame queue, and a SecY shim that installs keys
> instantly. It measures the *protocol* — how many MKPDU round trips the
> implementation needs and whether it waits on a timer between them — and not
> PHY link-up, driver latency, or a slow external PHY's key-install time. The
> profile's 30 ms budget (AutoMKA-01014) is a system budget covering all of
> those; wolfMKA's contribution to it is the protocol part, and a real
> measurement must be made on the target with its own SecY.

## Peer-reset recovery

The profile's other timing requirement is what happens when the peer at the far
end reboots (AutoMKA-03006). It returns with the same SCI but a fresh Member
Identifier, and a naive implementation carries the dead MI until the Life Time
expires it — the profile notes this costs up to six seconds of downtime, because
the CA is waiting on a member that no longer exists.

wolfMKA admits the new MI as an ordinary Potential peer, so both incarnations
are held at once, and retires the old entry as soon as the new one becomes live.
Liveness is the deliberate trigger: proving it requires echoing this
participant's own MI and Message Number back to it, which a replayed or forged
MKPDU cannot do, so the stale entry can never be evicted by an attacker who
merely claims an SCI. This costs one extra peer slot per device during the
handover, which is why the profile asks for peer lists of size two to track one
peer (AutoMKA-03016).

`test_peer_reset_new_mi` covers both halves: that the two incarnations coexist
while the new MI is unproven, and that the stale one is gone once it is live —
asserted well inside the Life Time, so it cannot pass by expiry.

A device that resets *twice* inside the Life Time is the awkward case, and it
used to reintroduce exactly the downtime the requirement exists to remove. Its
first incarnation still holds a slot, its second was admitted but never got far
enough to prove liveness, and a third then hits the per-SCI cap — so the device
is refused until the first entry ages out, up to a full Life Time after the
reset it had already recovered from. Nothing else frees either entry: the
retirement above runs only when an entry for that SCI *becomes* live, which is
precisely what cannot happen. Admission therefore reclaims the oldest entry for
that SCI that never proved liveness. An entry that once went live is never
taken — admission happens before the newcomer has proved anything, so a member
asserting another member's SCI must not be able to displace it — and where
there is nothing safe to reclaim the admission is still refused. The cap itself
is unchanged: a device holds at most `MKA_MAX_PEERS_PER_SCI` entries, it may now
churn its own share. `test_double_reset_is_not_locked_out` and
`test_no_eviction_displaces_a_proven_peer` pin the two directions.

## Requirement map

Status values: **Library** — implemented in wolfMKA. **Config** — a
configuration value the integrator sets (helper noted where one exists).
**Integrator** — outside the library's scope by design (transport, SecY, or
platform). **N/A** — the requirement is an explicit permission not to support a
feature, which wolfMKA satisfies by having it off (or compiled out).

### Basic concept (§4)

| Req | Subject | Status | Notes |
|-----|---------|--------|-------|
| AutoMKA-01001 | MACsec capabilities: integrity-only and confidentiality with offset 0 | Library | `MKA_CAP_*` and `confidentiality_offset`; both advertised and honoured |
| AutoMKA-01002 | Confidentiality offset 30 / 50 optional | Library | supported (`MKA_CONF_OFFSET_30/50`) |
| AutoMKA-01003 | SecTAG with and without SCI | Integrator | a SecY property; `MkaSecyOps` passes the SCI, the SecY decides the tag |
| AutoMKA-01004 | Negotiate XPN and non-XPN cipher suites | Library | GCM-AES-128/256 and both XPN suites |
| AutoMKA-01005 | 128-bit and 256-bit CAKs | Library | `MkaCakPair.cak_len` 16 or 32 |
| AutoMKA-01006 | May operate without in-service upgrade | N/A | not implemented |
| AutoMKA-01007 | May operate without MKA suspension | N/A | opt-in `WOLFMKA_SUSPENSION`, off in the profile build |
| AutoMKA-01008 | May operate without Distributed CAK | N/A | opt-in `WOLFMKA_DISTRIBUTED_CAK`, off in the profile build |
| AutoMKA-01009 | May operate without KMD | N/A | opt-in `WOLFMKA_KMD`, off in the profile build |
| AutoMKA-01010 | May operate without NIDs | N/A | not implemented |
| AutoMKA-01011 | No dynamic MACsec downgrade on announced capability | N/A | capability-driven downgrade lives in `WOLFMKA_CIPHER_NEGOTIATION`, which the profile build excludes; peers behave as configured |
| AutoMKA-01012 | Replay protection on | Integrator | a SecY setting; wolfMKA additionally enforces MKPDU replay protection on the control plane |
| AutoMKA-01013 | Replay window 0 | Integrator | SecY setting |
| AutoMKA-01014 | 30 ms worst-case startup | Config + Integrator | see **Startup behaviour** above — a system budget, not a library-only figure |
| AutoMKA-01015 | Startup optimisation: answer at once while MACsec is not up | Library + Config | `immediate_response`; `wm_Participant_AutomotiveDefaults()` |
| AutoMKA-01016 | Still interoperates with a standard implementation | Library | the profile changes timing and feature set, not the wire format; wolfMKA's interop tests run against wpa_supplicant unchanged |
| AutoMKA-01017 | ICK and KEK length equals the CAK length | Library | `wm_Crypto_DeriveKeys` sets `kek_len = ick_len = cak_len` |

### 802.1X Clause 6 and 9 changes (§5, §6)

| Req | Subject | Status | Notes |
|-----|---------|--------|-------|
| AutoMKA-02001 | Network announcements not transmitted, ignored on receipt | Library | `WOLFMKA_NO_ANNOUNCEMENTS`, implied by the profile; unknown parameter sets are skipped on decode |
| AutoMKA-03001 | At most two participants per CA | Config | set `MKA_MAX_PEERS` (default 32) to bound the peer table; a two-party session is verified to converge at `MKA_MAX_PEERS=2` |
| AutoMKA-03002 | Consider caching/storing KEK and ICK | Library | KEK/ICK are derived once in `wm_Participant_Init` and held in the participant, not re-derived per MKPDU |
| AutoMKA-03003 | Transmit immediately on a peer-list change | Library + Config | `immediate_response` (see **Startup behaviour**) |
| AutoMKA-03004 | Faster-than-Hello ramp after link up / participate | Config | `retry_base_ms` / `retry_cyclic_ms`; the helper installs 10 ms → Hello Time |
| AutoMKA-03005 | "Acceptably recent" MN = one of the last three emitted | Library | `mka_mn_recent` accepts an echoed MN within the last `MKA_MN_RECENT_WINDOW` emitted (default 3, the profile's value). This is separate from the per-MI replay guard on the *sender's* own MN, which stays strictly increasing. `test_mn_recency_window` |
| AutoMKA-03006 | Peer-reset handling: same SCI, new MI | Library | A reset peer is admitted as an additional Potential peer, both incarnations coexist, and the stale MI is retired the moment the new one proves liveness — never on first sight of it, so a forged or replayed MI cannot evict a working peer. A device that resets again before the second incarnation proves liveness reclaims the oldest of its own never-live entries rather than being locked out for the rest of the Life Time. `mka_retire_stale_mi`, `mka_evict_stale_sci_entry`; `test_peer_reset_new_mi`, `test_double_reset_is_not_locked_out`, `test_no_eviction_displaces_a_proven_peer` |
| AutoMKA-03007 | Speed up on priority 0 (always KS) / 255 (never KS) | Library | under the profile the values are absolute: `MKA_PRIORITY_NEVER_KS` (255) removes a candidate from the election entirely — self or peer — so two participants both set to it discover each other but neither serves; `MKA_PRIORITY_ALWAYS_KS` (0) needs no special case, being the lowest value the 9.5 comparison already prefers. `MkaRole` remains available for a pinned role in any build. `test_ks_priority_extremes` |
| AutoMKA-03008 | Key Server always secures if configured; no implicit Null cipher | Library | the configured cipher suite is used; there is no implicit downgrade path in the profile build |
| AutoMKA-03009 | Confidentiality offset 0 supported; 30/50 optional | Library | as AutoMKA-01001/01002 |
| AutoMKA-03010 | Should distribute the SAK before installing it | Library | `MkaParticipantConfig.distribute_before_install` has the Key Server adopt the new key, send the MKPDU carrying it, then program the SecY (`mka_program_sak`), so both ends install together. Off by default; `wm_Participant_AutomotiveDefaults()` turns it on. Two properties make it safe: programming waits for the send to succeed, so a key is never installed that no peer was told about; and while it is outstanding the MACsec SAK Use withholds the receive claim, so no peer starts sending protected frames the data plane cannot yet decrypt. That claim also waits on any asynchronous SecY install still in flight (`secy_pending`), not just on the deferred distribution - the receive bit is what releases the *peer's* transmit gate, so it has to be at least as conservative as the local one. Only the Key Server defers — see **Interactions**. `test_distribute_before_install`, `test_deferred_install_send_failure`, `test_profile_rekey_is_single` |
| AutoMKA-03011 | Rekey when a peer's SAK Use goes missing/invalid/empty | Library | `mka_note_sak_use` tracks whether each peer still reports the key in force; when one that was using it stops — no SAK Use, an empty one, or a Key Number we never issued — the Key Server rekeys. A peer mid-handover still naming the Old key is not a loss. The flag clears on rekey, bounding it to one per loss rather than one per MKPDU. `test_rekey_on_lost_sak_use` The profile keeps the immediate reaction: `MKA_SAK_LOSS_THRESHOLD` is 1 under `WOLFMKA_AUTOMOTIVE_PROFILE`, where recovery speed is the point and the peers are known, against a default of 3 elsewhere where the peer may legitimately omit the set now and then. |
| AutoMKA-03012 | May operate without Distributed CAK | N/A | as AutoMKA-01008 |
| AutoMKA-03013 | Deterministic SCI, stable across power cycles | Integrator | `cfg.sci` is supplied by the integrator; derive it from MAC + port |
| AutoMKA-03014 | May operate without in-service upgrade / suspension | N/A | as AutoMKA-01006/01007 |
| AutoMKA-03015 | Always send the XPN parameter set when XPN is in use | Library | `mka_build_xpn` sets the set present whenever the SAK cipher suite is XPN |
| AutoMKA-03016 | Peer lists of size two | Config | `MKA_MAX_PEERS` |

### EAPOL PDU transmission and validation (§7)

| Req | Subject | Status | Notes |
|-----|---------|--------|-------|
| AutoMKA-04001 | EAPOL frames addressed to multicast | Integrator | wolfMKA emits a bare EAPOL PDU; the transport adds the destination address. `MKA_PAE_GROUP_ADDR` (01-80-C2-00-00-03) is provided, and `examples/mka_link.c` uses it |
| AutoMKA-04002 | May operate without Distributed CAK | N/A | as AutoMKA-01008 |
| AutoMKA-04003 | KMD support optional | N/A | opt-in `WOLFMKA_KMD` |
| AutoMKA-04004 | An MKPDU listing us in its Live Peer List with an unacceptable MI/MN is invalid, and must not restart the Life timer | Library | `mka_stale_live_echo` discards such an MKPDU before the peer table is touched, so no slot is allocated and no Life timer refreshed. `test_mn_recency_window` |

### PAE operation (§8)

| Req | Subject | Status | Notes |
|-----|---------|--------|-------|
| AutoMKA-05001 | CP state machine performs multiple transitions to a final state in one tick, and interoperates with peers doing the same | Library | wolfMKA does not implement the CP state machine as a literal state machine; one `wm_Participant_Run()` / `wm_Participant_Receive()` advances installation, the transmit gate and Old-key retirement as far as the current state allows (`mka_advance_state`), which is the behaviour the requirement asks for. Nothing in the receive path assumes a peer takes one transition per tick. |
| AutoMKA-05002 | `unauthAllowed` = never | Integrator | the controlled port is the integrator's; wolfMKA never authorises traffic itself |
| AutoMKA-05003 | `unsecureAllowed` = never | Integrator | as AutoMKA-05002; the `macsec_up` event is the signal to open the controlled port |
| AutoMKA-05004 | May operate without NIDs, session statistics, virtual ports, EAPOL frame statistics/diagnostics | N/A | none of these are implemented |
| AutoMKA-05005 | CAK cache: KMD and NID optional | N/A | wolfMKA has no CAK cache — the integrator supplies the CAK/CKN per participant |
| AutoMKA-05006 | CAK cache: distributing a KMD optional | N/A | as AutoMKA-05005; KMD emission is the opt-in `WOLFMKA_KMD` |

### PAE MIB (§9)

| Req | Subject | Status | Notes |
|-----|---------|--------|-------|
| AutoMKA-06001 | Operates without SNMP and MIBs | Library | wolfMKA has no SNMP or MIB dependency of any kind; state is read through the accessor API below |

### Management and diagnostics (§10)

The profile asks for these APIs "or equivalent". wolfMKA supplies the
information, but as accessors on a participant rather than in this shape: an
integrator building to the profile writes a thin adapter over them, and the
per-port rows are the integrator's because wolfMKA holds no cross-port registry
and no state across power cycles.

| Req | Subject | Status | Notes |
|-----|---------|--------|-------|
| AutoMKA-07001 | Notation for this chapter | N/A | informational |
| AutoMKA-07002 | Activate/deactivate MKA per port | Integrator | a port is an `MkaKay`; the integrator creates, runs or stops one. wolfMKA has no port table and no persistence across power cycles |
| AutoMKA-07003 | Get MKA activation for a port | Integrator | as AutoMKA-07002 |
| AutoMKA-07004 | Get MKA activations for all ports | Integrator | as AutoMKA-07002 — wolfMKA holds no cross-port registry |
| AutoMKA-07005 | Activate/deactivate a CKN on a port | Library | `wm_Kay_AddParticipant` / `wm_Kay_RemoveParticipant`; the "active at next power cycle" semantics are the integrator's |
| AutoMKA-07006 | Get CKN activation | Library | `wm_Kay_Find` / `wm_Kay_ParticipantCount` |
| AutoMKA-07007 | Event: CKN activations | Integrator | wolfMKA raises no event on add/remove — those calls are the integrator's own actions, so it already knows |
| AutoMKA-07008 | Get PAE status: status enum, peer SCI, CKN in use, cipher suite | Library | `wm_Participant_GetPaeStatus()` returns `MkaPaeStatus` — the profile's status enum plus peer SCI, CKN in use and the cipher suite in force. `MKA_PAE_WAITING_FOR_LINK_UP` is never returned: wolfMKA has no view of link state, so an integrator gating MKA on the link reports that itself. `MKA_PAE_RUNNING` means protection is transmitting and stays set across a make-before-break rekey, where the demoted Old key carries traffic while the new one is gated. `test_pae_status` |
| AutoMKA-07009 | Get MACsec statistics (802.1AE SecY, TxSC and RxSC counters) | Library | `MkaSecyOps.get_secy_stats` / `get_tx_sc_stats` / `get_rx_sc_stats` (all optional) feed `wm_Participant_GetSecyStats()`, `GetTxScStats()` and `GetRxScStats()`, returning `MkaSecyStats` / `MkaTxScStats` / `MkaRxScStats`. The counters stay the SecY's — wolfMKA routes, never counts. Peers are indexed as by `wm_Participant_GetPeer`. `test_macsec_statistics` |

### Configuration (§11)

| Req | Subject | Status | Notes |
|-----|---------|--------|-------|
| AutoMKA-08001 | A configuration supporting the requirements of this specification | Config | `MkaParticipantConfig` plus the build-time macros; `wm_Participant_AutomotiveDefaults()` sets the profile's timing |
| AutoMKA-08002 | Rekey after a configured time, 0 s to 24 h | Library | `sak_rekey_time_ms` (0 disables); 24 h fits a `uint32_t` millisecond value |
| AutoMKA-08003 | Global timing configuration incl. the hello ramp | Config | `MKA_HELLO_TIME_MS`, `MKA_BOUNDED_HELLO_TIME_MS`, `MKA_LIFE_TIME_MS` at build time; the ramp via `retry_base_ms`/`retry_cyclic_ms`. wolfMKA's ramp is a doubling function, not the profile's arbitrary array of steps |
| AutoMKA-08004 | Per-port configuration (PSK, role, delay protection, ...) | Config | `MkaParticipantConfig` per participant, `MkaKay` per port. The profile's `Participant activation {DISABLED, ONOPERUP, ALWAYS}` and `Logon Use_EAP {NEVER, IMMEDIATE, ON_MKA_FAIL}` have no wolfMKA equivalent — the integrator decides when to create a participant |

### Automotive features (§12–§15)

| Req | Subject | Status | Notes |
|-----|---------|--------|-------|
| AutoMKA-09001 | Multiple CAK/CKN in parallel; stop the rest once one establishes MACsec | Library | `MkaKay` runs several participants and routes by CKN; `wm_Kay_SetQuiesceOthers()` holds the losers silent for as long as one CA has MACsec up. Opt-in, since a deployment running several CAs deliberately needs them all live. `test_kay_quiesce_others` |
| AutoMKA-09002 | All participants resume on link up / session drop | Library | with `wm_Kay_SetQuiesceOthers()` enabled, every participant is released the moment no CA has MACsec up; re-initialising them on link up also restarts the search. `test_kay_quiesce_others` |
| AutoMKA-09003 | Maximum number of CAKs/CKNs left to the implementer | Library | `MKA_MAX_PARTICIPANTS` (default 4) |
| AutoMKA-10001 | Change the MI on every link down | Integrator | `wm_Participant_Init` generates a fresh random MI, so re-initialising on link down satisfies this |
| AutoMKA-11001 | May operate without cipher-suite negotiation and Secure Announcements | Library | compiled out by the profile |
| AutoMKA-12001 | Allow delaying link up while MACsec is disabled | Integrator | a platform/PHY concern |
| AutoMKA-12002 | Should support running MKA with MACsec disabled | Library | `macsec_desired = false` now disables the MACsec interaction outright: the participant declines a distributed SAK (`mka_dist_sak_skip`), so no Secure Channel is created, no SA installed, no packet number read — every SecY call hangs off an installed Latest key. MKA itself keeps running, so peers still discover each other. wolfMKA expresses this as "no key installed" rather than by selecting a Null Cipher Suite, which it has no value for. `test_kay_macsec_undesired` |

## Known gaps

None. Every requirement of the specification resolves to an implementation, a
configuration item the integrator sets, or behaviour that is outside a
protocol library's scope (the transport, the SecY, or the platform) — see the
status column in the tables above.

Two differences of expression are worth stating rather than leaving implicit,
since a reviewer comparing against the specification's wording will meet them:

- **AutoMKA-12002** describes the MACsec-disabled configuration as "explicitly
  select Null Cipher Suite". wolfMKA has no null cipher-suite value; it reaches
  the same end state by installing no key at all, which is what the
  requirement's substantive clause asks for.
- **AutoMKA-08003** asks for the Hello time ramp as an array of millisecond
  values. wolfMKA's ramp is a doubling function between `retry_base_ms` and
  `retry_cyclic_ms`, which produces the specification's own proposed sequence
  (10, 20, 40 ms … 2 s) but cannot express an arbitrary one.

Neither affects interoperability: both concern how a behaviour is configured,
not what goes on the wire.

## Interactions worth knowing

Two of the profile's requirements pull against each other, and the resolution is
worth stating because it is not obvious from either one alone.

AutoMKA-03011 has the Key Server rekey when a member stops reporting the SAK in
use. AutoMKA-03010 has a participant hold its data plane back until the key is
on the wire — and a participant whose data plane lacks the key must not claim to
be receiving on it, or the peer will send protected frames it cannot decrypt.

Applied to a member, those two combine badly: the member withholds its receive
claim while it programs, and the Key Server reads the silence as a lost key and
rekeys, which starts the member installing again. wolfMKA therefore defers only
on the **Key Server**, which is also the case AutoMKA-03010 describes — a member
has nothing to distribute early, so waiting would only delay its own data plane.
`test_profile_rekey_is_single` holds this down: a rekey with the full automotive
configuration on both ends advances the Key Number exactly once.

The same shape appears again with a peer that is not running this profile.
Live interop against wpa_supplicant showed it emitting an MKPDU with no MACsec
SAK Use parameter set from time to time; read as a lost key, that rekeys, which
leaves the peer chasing a key it has not finished adopting, which produces
another silent MKPDU. `MKA_SAK_LOSS_THRESHOLD` therefore counts *consecutive*
misses before declaring a loss, and it is **1** under this profile — where
recovery speed is the point and every peer is known to report the key in every
MKPDU — against 3 elsewhere. `MkaParticipantConfig::sak_loss_threshold`
overrides it per participant.

A third consequence of AutoMKA-03010 is worth stating: while a deferred key is
still undelivered, `wm_Participant_Rekey()` returns `MKA_ERR_REKEY_BUSY` rather
than adopting another. A second key cannot help before the first has reached the
peers, and stacking them lets the Latest and Old keys' Association Numbers
collide - the un-programmed key is discarded on replacement while the Old key
stays, so the two stop tracking each other. The automatic
packet-number-exhaustion rekey is unaffected; it acts on a key that is already
in force.

## Related specifications

The Automotive MKA Specification has a companion, the OPEN Alliance
*Automotive MACsec Specification* v1.0, which profiles the 802.1AE data plane.
That is the SecY's scope, not MKA's — wolfMKA drives the SecY through
`MkaSecyOps` and makes no claim about the data-plane profile.

Reference: OPEN Alliance, *Automotive MKA Specification for Automotive Ethernet
and MACsec*, v1.0, 26 February 2025 (OPEN Alliance TC17).
