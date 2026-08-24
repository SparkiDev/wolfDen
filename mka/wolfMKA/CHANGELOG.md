# Changelog

All notable changes to wolfMKA are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). The version is
exposed in code as `WOLFMKA_VERSION_MAJOR` / `_MINOR` / `_PATCH` /
`_STRING` / `_HEX` (`include/wolfmka/mka_types.h`).

## [Unreleased]

### Added

- **OPEN Alliance TC17 Automotive MKA profile** (`WOLFMKA_AUTOMOTIVE_PROFILE`,
  opt-in) — emits version 3 MKPDUs and removes Secure Announcements and
  cipher-suite negotiation, with `wm_Participant_AutomotiveDefaults()` supplying
  the profile's startup timing. `make test-automotive` builds and runs the suite
  under it, and it is one of the enforced `make coverage-configs`
  configurations. [`OPEN-ALLIANCE.md`](OPEN-ALLIANCE.md) maps the profile
  requirement by requirement, including the gaps that remain.
- **Fast response to new information** — `MkaParticipantConfig.immediate_response`
  (off by default, all builds). A change to the Potential or Live Peer List, a
  newly installed SAK, or the transmit gate releasing is transmitted on the next
  `wm_Participant_Run()` rather than at the next Hello Time — the `newInfo`
  behaviour of IEEE Std 802.1X-2010 9.4. In the in-process two-party test this
  brings MACsec up 3 ms into the exchange.
- **Rekey when a peer loses the SAK** — a peer whose MACsec SAK Use goes
  missing, turns up empty, or names a Key Number never issued has lost the key;
  the Key Server now distributes a fresh one instead of leaving the peer
  undecryptable (OPEN Alliance AutoMKA-03011). A peer still naming the Old key
  mid-handover is not treated as a loss, and the trigger clears on rekey, so one
  loss causes one rekey rather than one per MKPDU. Applies in every build, on
  the same footing as the existing rekey when a live peer departs.
- **Distribute before install** — `MkaParticipantConfig.distribute_before_install`
  (off by default) puts a newly generated SAK on the wire before programming the
  local SecY, so a peer behind a slow data plane starts installing at the same
  moment rather than after (AutoMKA-03010). Programming waits only until the
  send succeeds, so a key is never installed that no peer has been told about.
  `wm_Participant_AutomotiveDefaults()` enables it. Only the Key Server defers:
  a member has nothing to distribute early, and one that held its data plane
  back would stop reporting itself as receiving, which the Key Server reads as a
  lost key. While programming is outstanding the MACsec SAK Use withholds the
  receive claim, so no peer sends protected frames the data plane cannot yet
  decrypt.
- **Key Server priority extremes** (automotive profile) — priority 255 now means
  *never* Key Server and 0 means *always*, rather than merely the least and most
  preferred values (OPEN Alliance AutoMKA-03007). Two participants both set to
  255 discover each other but neither serves. Honoured only under
  `WOLFMKA_AUTOMOTIVE_PROFILE`; elsewhere 255 remains an ordinary low preference
  and `key_server_capable` is how a participant declines the role.
- **Message Number recency window** — liveness now requires a peer to echo a
  Message Number this participant actually emitted recently, not just its
  Member Identifier (IEEE Std 802.1X-2010 9.4.3; OPEN Alliance AutoMKA-03005).
  The depth is `MKA_MN_RECENT_WINDOW`, default 3. An MKPDU that reports us live
  on a stale number is discarded without refreshing the peer's Life timer
  (AutoMKA-04004), so a peer looping stale information cannot hold an
  association open.
- **MACsec statistics** — `MkaSecyOps.get_secy_stats` / `get_tx_sc_stats` /
  `get_rx_sc_stats` (all optional) and the `wm_Participant_GetSecyStats()`,
  `GetTxScStats()` and `GetRxScStats()` accessors return the 802.1AE SecY,
  TxSC and RxSC counter groups (AutoMKA-07009). The counters remain the SecY's;
  wolfMKA routes to them and keeps none of its own.
- **PAE status** — `wm_Participant_GetPaeStatus()` returns `MkaPaeStatus`: the
  state, the peer's SCI, the CKN in use and the cipher suite in force
  (AutoMKA-07008).
- **Connectivity Association quiescing** — `wm_Kay_SetQuiesceOthers()` (opt-in)
  holds the other participants on a port silent while one has MACsec up, and
  releases them when it drops (AutoMKA-09001 / AutoMKA-09002).
- **Peer-reset recovery** — a peer that returns with the same SCI but a fresh
  Member Identifier is admitted alongside its previous entry, and the stale one
  is retired as soon as the new MI proves liveness rather than being left to
  expire at the Life Time (OPEN Alliance AutoMKA-03006). Retiring on liveness,
  not on first sight, means a forged or replayed MI cannot evict a working peer.
- **Build-selectable announced MKA version** — `WOLFMKA_MKA_VERSION` (default 1,
  as before; the automotive profile selects 3). Receive is unchanged: a peer's
  announced version has never been used to reject a frame.

### Fixed

- **`make features` was broken** — a stray backslash in the configuration list
  (`\"-DWOLFMKA_AUTOSAR"`) made the shell abort with a syntax error, so the
  whole feature-matrix gate silently stopped compiling anything, including the
  AUTOSAR configuration.
- **`make cxx` was broken** — `test/test_icv_l2.c` needs `WOLFMKA_ICV_L2_ADDR`,
  but the C++ sweep compiles every test source in the default configuration.
  The file now self-guards and reports SKIP without the flag.
- **The L2-address ICV was outside the test and coverage gates.** The suite's
  `reseal` helper and four other places sealed frames with the non-L2
  `wm_Crypto_IcvCompute`, so the whole suite failed when built with
  `WOLFMKA_ICV_L2_ADDR`. They now share `test_seal_icv()`, which signs whatever
  the library verifies, and the L2 configuration is a first-class build: `make
  test-icv-l2-suite` runs the full suite over it, `make coverage-configs`
  enforces 100% MC/DC on it, and `make misra` checks it.
- **`mka_aes_cmac_l2` could not be fault-injected per stage.** Routing only the
  result through `MKA_FI` left the three "did the previous step fail" guards of
  the streaming CMAC unreachable in test builds; each call now goes through the
  hook, as the reviewer suggested.

### Changed

- **A participant configured `macsec_desired = false` no longer programs the
  data plane.** It previously declined only the Key Server role, but still
  installed a SAK distributed to it — creating the Secure Channels and
  programming the SAs it was configured not to have. It now declines the key as
  well, so no SecY call is made at all while MKA itself keeps running (OPEN
  Alliance AutoMKA-12002). A deployment that relied on the old behaviour was
  asking for MACsec; set `macsec_desired = true`.
- `MKA_MKA_VERSION_ID` (a private constant in `mka_kay.c`) is replaced by the
  public, overridable `WOLFMKA_MKA_VERSION`.

## [1.0.0] - 2026-06-23

First release. MACsec Key Agreement (IEEE Std 802.1X-2010, Clause 9) over
wolfSSL.

### Added

- **MKA protocol** — participant discovery, Live/Potential peer lists, Key
  Server election, SAK generation/distribution and installation, make-before-
  break rekey (`wm_Participant_Rekey`), and the AUTOSAR `Mka_*` binding
  (Document ID 1066).
- **Crypto** (over wolfSSL) — AES-CMAC, the IEEE 802.1X KDF (KEK/ICK/SAK), AES
  Key Wrap, and EAP-MSK derivation of the CAK/CKN (`WOLFMKA_NO_EAP` to omit).
- **Cipher suites** — GCM-AES-128/256 and the XPN variants (Extended Packet
  Numbering with SSCI and 64-bit packet numbers; `WOLFMKA_NO_XPN` to omit).
- **Optional features** — Distributed CAK, Key Management Domain, MKA
  Suspension, cipher-suite negotiation, Announcements, delay protection,
  automatic/timed rekey, and MKA retry back-off, each behind a build flag.
- **Footprint controls** — caller-allocated participants, `WOLFMKA_SMALL_STACK`
  and `WOLFMKA_NO_MALLOC` for a zero-dynamic-allocation, bounded-stack build; a
  redefinable allocator hook.
- **Portability** — C89-clean (with a `<stdbool.h>`/`<stdint.h>` shim and the
  `MKA_U64` helper), endianness configurable (`WOLFMKA_LITTLE_ENDIAN` /
  `WOLFMKA_BIG_ENDIAN`, auto-detected), and every source also compiles as C++.
- **Examples** — `mka_demo`, `mka_eap`, `mka_xpn`, `mka_rekey`, `mka_autosar`,
  `mka_group_cak`, plus the Linux integration shims `mka_link`,
  `secy_macsec_linux` and the combined `mka_macsec`.

### Verification

- 978 unit checks, fault-injection and negotiation suites, and the AUTOSAR
  binding test; 100% line + decision + MC/DC structural coverage across the
  delivered configurations.
- MISRA C:2012 conformance (cppcheck addon, documented deviations), valgrind,
  AddressSanitizer + UndefinedBehaviorSanitizer (`make sanitize`), GCC
  `-fanalyzer` (`make analyze`), and coverage-guided libFuzzer harnesses for the
  decoder and the stateful receive path (`make fuzz`).
- Interoperability pinned byte-for-byte to hostapd/wpa_supplicant crypto (RFC
  4493/3394 plus hostapd EAP-path vectors), with a live wire harness against
  wpa_supplicant over a veth pair (`test/interop/`, `make interop` /
  `make interop-dataplane`).
- Big-endian serialization executed on ppc64 under qemu (`make test-endian`).

[1.0.0]: https://github.com/wolfSSL/wolfMKA/releases/tag/v1.0.0
