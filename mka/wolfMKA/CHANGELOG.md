# Changelog

All notable changes to wolfMKA are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). The version is
exposed in code as `WOLFMKA_VERSION_MAJOR` / `_MINOR` / `_PATCH` /
`_STRING` / `_HEX` (`include/wolfmka/mka_types.h`).

## [Unreleased]

### Added

- **`MkaEventOps.key_server_lost`** — the other edge of `key_server_elected`.
  Losing the elected Key Server (the last live peer expiring, or a participant
  that cannot serve losing the peer it was following) previously fired nothing
  at all, because the election-changed test is guarded on being elected. An
  integrator gating a controlled port or a status indicator on the election saw
  it made and never saw it lost. Reported once, on the transition, with the SCI
  that was in force — `ks_sci` keeps its stale value across the gap. Optional
  like every other hook, so an integrator that does not set it is unaffected.
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

### Changed

- **The RNG workspace is now mandatory**, as the CMAC workspace already was.
  `MkaParticipantConfig.rng` is validated at `wm_Participant_Init`, and
  `wm_Crypto_Random` / `wm_Crypto_GenerateSak` reject a `NULL` with
  `MKA_ERR_BAD_ARG`. The per-call fall-back is gone: it declared a `WC_RNG` in
  wolfMKA's own stack frame, which under `WOLFSSL_NO_MALLOC` carries its DRBG
  state inline — hundreds of octets of stack in exactly the
  `WOLFMKA_SMALL_STACK` / `WOLFMKA_NO_MALLOC` build the pool exists to serve —
  while an ordinary wolfSSL build heap-allocated the DRBG on every participant
  init and every SAK generation. Neither cost was visible to
  `make test-nomalloc`, which greps wolfMKA's own objects and cannot see an
  allocation made inside libwolfssl. **Migration:** call
  `wm_Crypto_RandomInit()` once and set `cfg.rng`, as you already do for
  `cfg.cmac`; raise `WOLFMKA_RANDOM_POOL_SIZE` if more than one holder is live
  at a time.
- **`wm_Crypto_DeriveCakFromMsk` requires `msk_len == cak_len`.** The MSK is the
  KDF key in full — `CAK = KDF(MSK, "IEEE8021 EAP CAK", mac1 | mac2, CAKlength)`
  — and the CMAC key length is what selects AES-128 or AES-256. The function
  previously accepted any `msk_len >= cak_len` and keyed with the leftmost
  `cak_len` octets, so a 32-octet MSK and a 128-bit CAK never fed the upper half
  of the MSK into the derivation and produced a CAK that neither the formula nor
  hostapd's `ieee802_1x_cak_aes_cmac` (which passes `8 * msk_bytes`) would
  reproduce. No interoperating deployment was affected — hostapd's callers
  always pass equal lengths, since `wpa_supplicant` clamps the MSK to the CAK
  length first — so the divergence was reachable only through this API accepting
  a longer MSK. Requiring the lengths to match removes that region without
  changing any value the function has ever produced. `wm_Crypto_DeriveCknFromMsk`
  is unchanged; it already keyed with the whole MSK, as hostapd does.
  **Migration:** pass exactly as much MSK as the CAK you want.

- **The ICV verifiers' branchless select no longer relies on an
  implementation-defined conversion.** The mask was applied to `MKA_ERR_ICV`
  itself, so the result was `0xFFFFFFFB` converted back to `int32_t` on the way
  out — implementation-defined by C99 6.3.1.3p3, correct on every
  two's-complement target and mandated by C23, but an unrecorded reliance in the
  one piece of the library written to be branchless. The mask now selects the
  error *magnitude* and the return negates it, keeping every intermediate in
  range at the same cost. A compile-time assertion ties the magnitude to the
  enumerator.
- **`Mka_PaeRtType.lastSecyResult` is documented as diagnostic-only** — written
  by the four SecY notifications, read by nothing, with no accessor in `Mka.h`.
  It is not state any decision depends on; the KaY is deliberately told nothing
  about a failed SecY operation (FMEA FM-06 assigns that to the integrator).
- **`mka_pdu.c` internals consolidated.** The four open-coded 64-bit big-endian
  loops now call a shared `w_be64` / `rd_be64` pair in `mka_bytes.h` (with
  cursor wrappers and their own big-endian test vectors); the SAK Use and
  Distributed SAK body lengths have one function each, called by both the
  encoder and its mirror size helper, so the invariant that licenses
  `wm_Pdu_Encode`'s unchecked writes is structural rather than hand-copied; and
  the repeated wire constants 40 / 24 / 8 / 2 are named
  (`MKA_SAK_USE_BODY_LEN`, `MKA_WRAPPED_SAK_128_LEN`, `MKA_CIPHER_SUITE_LEN`,
  `MKA_ANN_TLV_HDR_LEN`, `MKA_LPN_LEN`). The file's cursor helpers take the
  project's `mka_*` static prefix (`mka_w_be32`, `mka_r_be32`, ...), and the
  `Writer` / `Reader` tags become `MkaWriter` / `MkaReader`.
- **`src/autosar/Mka.c` file statics take the `mka_*` prefix** (`mka_add_ckn`,
  `mka_pae_ok_det`, ...), so the module's internals are distinguishable by name
  from its exported `Mka_*` SWS API.
- **The packet-number rekey thresholds are named** —
  `MKA_PN_EXHAUSTION_THRESHOLD` and `MKA_XPN_EXHAUSTION_THRESHOLD` - and
  `mka_pn_exhausted` selects between them instead of writing the whole
  `get_next_pn` expression out twice.
- **`mka_status_peer_sci` stops at the first match in both of its loops.** It
  previously took the last live peer but the first merely-valid one, so the
  reported SCI could change when an unrelated peer's slot was reused. A live
  peer still outranks one merely heard from; only the tie-break within each
  group changed, and it is now the same rule twice.
- **`mka_expire_peers` validates a peer-table slot before reading it**, matching
  every other walk of that table and skipping the deadline arithmetic for empty
  slots.
- **The crypto pool's reentrancy contract is documented.** `wm_Crypto_CmacInit`
  / `RandomInit` scan-and-claim without a lock, and the `Free` functions check
  neither pool membership nor whether the slot is in use; acquire and release
  from one thread.

### Fixed

- **Duplicate MACsec Cipher Suites TLVs are rejected.** An announcement carries
  at most one, and the walk assigned rather than merged - so a second TLV
  replaced the first, letting an authenticated member state a cipher-suite
  constraint and then bury it under a permissive copy. Same shape as the
  duplicate parameter set above, one nesting level down.
- **A device that reset twice inside the Life Time locked itself out.** Its
  first incarnation still held a peer-table entry and its second had been
  admitted but never proved liveness, so the third hit the per-SCI cap and was
  refused with `MKA_ERR_FULL` — for up to a full `MKA_LIFE_TIME_MS` after a
  reset it had already recovered from. Nothing else freed either entry:
  `mka_retire_stale_mi` runs only when an entry for that SCI *becomes* live,
  which is exactly what could not happen. Admission now reclaims the oldest
  entry for that SCI that never proved liveness. An entry that once went live
  is never taken — admission happens before the newcomer has proved anything,
  so a member asserting another member's SCI must not be able to displace it —
  and when there is nothing safe to reclaim the refusal stands. The cap itself
  is unchanged: a member cycling Member Identifiers still holds at most
  `MKA_MAX_PEERS_PER_SCI` entries, it may now churn its own share.
- **A repeated Member Identifier in a peer list let the last copy win.**
  `mka_list_echo` kept scanning after a match, so a Live Peer List naming this
  participant twice - once with a current Message Number and once with a stale
  one - was discarded as a replay, taking a perfectly good liveness proof with
  it. It now stops at the first match, as `mka_set_latest_ks_mi` already did.
- **The KDF's 255-block bound is enforced in `mka_kdf_run`**, not only in the
  public `wm_Crypto_Kdf` wrapper. The block counter is a single octet and the
  output-length field a `uint16_t`, so an internal caller asking for more than
  4080 octets would have got a silently wrong derivation; every internal caller
  now passes through the same check.
- **`wc_InitRng_ex` replaces `wc_InitRng`** at both RNG initialisation sites, so
  the DRBG state is allocated from `WOLFMKA_HEAP_HINT` like every other wolfSSL
  allocation in the library. An integrator routing wolfSSL into a static pool
  was previously getting the DRBG from the default heap instead.
- **The wrapped group CAK no longer passes through a stack scratch buffer**
  (`WOLFMKA_DISTRIBUTED_CAK`). `mka_build_dist_cak` wraps straight into the
  parameter set, which is sized for it - removing an unwiped second copy of the
  wrapped key rather than adding a wipe for it.
- **`wm_Crypto_IcvVerify` / `wm_Crypto_IcvVerifyL2` wipe `computed` on their
  error return** as well as on the compare path, so the buffer has one lifetime
  rule instead of two.
- **AUTOSAR: 64-bit SecY counters saturate into the 32-bit statistics** rather
  than wrapping. `Mka_Stats_SecYType` is fixed at `uint32` by SWS 8.2.10, so the
  value must narrow; a pegged `0xFFFFFFFF` reads as "at least this many", where
  a wrapped one reads as a wrong number and appears to run backwards.
- **A member kept believing a peer was using a key it had dropped.** A
  participant that still holds a key always sends the MACsec SAK Use parameter
  set, so its absence says the peer has stopped. The Key Server acts on that
  (`mka_note_sak_use`), but a plain member does not run that check and left
  `sak_rx` / `sak_tx` / `latest_kn` standing indefinitely - state that feeds the
  transmit gate and the Old-key retirement rule. A peer's SAK Use claim is now
  cleared when its MKPDU carries no such set.
- **A SAK Use set with no body no longer keeps its key-in-use flags.** The
  encoder omits the 40-octet body exactly when no key is in use; the decoder
  copied the flags out regardless, so `03 20 00 00` decoded to a peer
  transmitting under a key whose Key Server MI, Key Number and Lowest Acceptable
  PN were never on the wire. Decode is now the inverse of encode.
- **Duplicate parameter sets are rejected.** IEEE Std 802.1X-2010 11.11 allows
  at most one set of each type per MKPDU, and every decoder assigns rather than
  merges - so a second set of a type silently replaced the first. An
  authenticated member could send two Live Peer Lists, the first proving this
  participant's liveness and the second naming an unrelated peer, and the proof
  would never be seen; the same trick buried a Distributed SAK or a SAK Use. A
  repeated type is now `MKA_ERR_PARSE`. Parameter-set types this decoder does
  not know are still skipped, repeated or not, so forward compatibility is
  unchanged.
- **A manual rekey did not restart the automatic rekey interval.**
  `wm_Participant_Rekey()` takes no time argument, so `last_rekey_ms` kept
  measuring from the previous key: the automatic rekey fired again as soon as
  the manual handover retired, and a rekey issued before the first
  `wm_Participant_Run()` measured from zero and fired on that very first run.
  The interval is now restarted from the next run.
- **A failing MKPDU *build* was retried on every tick.** The transmit cadence
  was stamped only on success, so an AES-Key-Wrap or CMAC fault - or a peer list
  too large for the frame - left `do_tx` true on every subsequent tick: a full
  parameter-set fill plus an AES-CMAC per tick of the integrator's loop, and
  `wm_Participant_Run()` returning the error each time. The comment claiming
  one attempt per interval now holds for build failures as well as send
  failures.
- **`macsec_capability` was not range-checked.** It is a two-bit wire field, so
  a configured 4 was advertised as `MKA_CAP_NOT_IMPLEMENTED` while the local
  capability comparison went on reading 4 - telling every peer this participant
  implements no MACsec while concluding the CA can do everything. It is now
  rejected at init with `MKA_ERR_BAD_ARG`, like the other out-of-range
  configuration values (FMEA FM-24).
- **AUTOSAR: the binding still treated the RNG workspace as optional.** Its
  comment said "a NULL rng still works, it just seeds per call" — true before
  the workspace became mandatory, and false after: `Mka_Init` would come up
  reporting success while every subsequent `Mka_StartPae` failed, for a reason
  the integrator would have had to infer. An unobtainable RNG is now refused
  with `MKA_E_INIT_FAILED`, exactly as a missing CMAC workspace already was, and
  the CMAC case is checked first so a refusal does not leave an RNG pool object
  claimed by a module that never came up.
- **AUTOSAR: `Mka_LinkStateChange` accepted any value.** An unrecognised
  `EthTrcv_LinkStateType` was stored verbatim and handed back out as
  `Mka_PaeStatusType::ConnectionStatus`, so a typo'd constant round-tripped
  through the module unflagged. It is now refused with `E_NOT_OK` and
  `MKA_E_PARAM_INVALID`, matching `Mka_SetPaePermissiveMode`.
- **AUTOSAR: a PAE with no runnable CA counted as started.** `Mka_StartPae`
  marked the PAE started even when every CKN failed to instantiate, so it became
  "active" for permissive mode: under `MKA_PERMISSIVE_MODE_TIMEOUT` it
  accumulated unsecured time it could never end and latched the controlled port
  open in plaintext - opening the port on a configuration fault rather than on a
  peer that could not be reached. It now fails closed. The enable flags are
  untouched, so `Mka_StartPae` can be called again to retry.
- **AUTOSAR: `Mka_GetCknStatus` reported CKNs that were not running.** The
  enable flag is the integrator's request and is deliberately left set when an
  instantiation fails, so a later call can retry; reporting it back claimed a
  CKN was enabled when the KaY held no participant for it. On a started PAE the
  status is now read from the KaY, on the same footing as `Mka_GetPaeStatus`.
- **The ICV Indicator was accepted anywhere, at any length.** Type 255 ends the
  parameter-set walk, so one placed early - with a CAK holder to reseal the
  frame - hid every set after it from the decoder. It must now sit immediately
  before the ICV and declare exactly `MKA_DEFAULT_ICV_LEN` octets.
- **One device could fill the peer table by cycling Member Identifiers.**
  Peer-reset recovery deliberately admits a returning device's new MI alongside
  its previous entry, with no cap; a member that kept changing MI could crowd
  every other member out of the table. Entries per SCI are now bounded by
  `MKA_MAX_PEERS_PER_SCI` (2 - the stale incarnation and the live one).
- **The Lowest Acceptable PN was a hard-coded 1 for the Old key**, and for the
  Latest key too in a `WOLFMKA_NO_DELAY_PROTECT` build - the query sat inside
  that guard. The LPN a participant transmits is what its *peer* uses to advance
  its replay window, so a constant 1 silently disabled delay protection at the
  far end: an interop decision, not a local one. Both keys now get their own
  `get_next_pn` query in every build, falling back to 1 only when the SecY
  cannot answer.
- **A failed SAK unwrap left the wrong-key plaintext in the caller's buffer.**
  AES Key Unwrap writes every block before its integrity check fails;
  `wm_Crypto_UnwrapSak` now wipes the output on that path (the library's own
  callers already wiped their own scratch).
- **A shorter SAK inherited the tail of the key it replaced.** `p->latest.sak`
  is a fixed 32 octets and only `sak_len` were written, so a 256-bit key
  succeeded by a 128-bit one left its upper half in place - and that half
  outlived the Old copy, which is force-zeroed on retirement. The whole buffer
  is now cleared before the copy.
- **A cipher-suite announcement lasted exactly one MKPDU.** Announcements are
  optional in any given MKPDU, but the peer's advertised set was cleared on
  every one that omitted it, which reads as "accepts anything" - so the
  negotiated suite depended on which frame happened to arrive last before a
  rekey, and a peer that announced 128-only could be handed a 256-bit SAK. What
  a peer has announced now stands until it announces something else.
- **Quiescing released the losing CAs for the whole of a rekey.** A
  make-before-break rekey demotes the in-force key to Old and leaves
  `latest.tx` false until the peers report receiving on the new one, so testing
  `latest.tx` alone found no winner - and the CAs that
  `wm_Kay_SetQuiesceOthers()` exists to keep silent resumed transmitting across
  the handover. The Old key now counts as MACsec being up.
- **A pinned `MKA_ROLE_PEER` adopted a Key Server advertising priority 255.**
  Under the automotive profile 255 is an absolute "never Key Server"
  (AutoMKA-03007), which the dynamic election honours for self and every peer;
  the fixed-peer path did not, so a device that had declared itself ineligible
  to issue a SAK was accepted as the one issuing it. It is now refused, leaving
  the participant without a Key Server - the fail-closed outcome.
- **Lengths crossing into wolfSSL were narrowed to 32 bits unchecked.** On a
  64-bit host `wm_Crypto_IcvCompute(..., 0x100000000, ...)` computed an AES-CMAC
  over zero octets and returned `MKA_OK`, handing the caller a valid-looking ICV
  that authenticated nothing. The public ICV and random entry points now reject
  a length that does not fit a `word32`; the check compiles out where `size_t`
  already fits. Unreachable from inside the library, which bounds everything by
  `MKA_MKPDU_MAX_LEN`.
- **`wm_Pdu_Encode` trusted the length fields of a caller-filled `MkaPdu`.**
  Encode sizes the whole frame once and then writes without per-field bounds
  checks, so a length larger than the fixed array behind it - `basic.ckn_len` of
  100 against a 32-octet `ckn`, say - was reported in the size, passed the
  capacity check, and then over-read the caller's struct by the difference. Every
  length is now validated up front (`MKA_ERR_BAD_ARG`, and
  `wm_Pdu_EncodedSize` returns 0), covering the CKN, the wrapped SAK, both peer
  lists, the announcement count, the Distributed CAK body and the KMD.
  Unreachable from inside the library, which fills all of them from state bounded
  at participant init.
- **`wm_Pdu_Encode` / `wm_Pdu_Decode` did not reject a NULL `cmac` locally.** It
  was caught downstream, but encode reached that point only after laying the
  whole frame into the caller's buffer. Both now check it first, and the headers
  list it.
- **`wm_Crypto_IcvVerify` did not wipe its computed ICV** while the L2 variant
  did.
- **The KDF's length check ran after callers had placed context in the buffer.**
  `wm_Crypto_DeriveCknFromMsk` writes the joined MACs at an offset derived from
  the label and Session-Id lengths before `mka_kdf_run` validates the total. It
  is in bounds today, but only because of a relationship between three constants
  declared apart from each other - raising `MKA_KDF_CTX_MAX` without
  `MKA_KDF_LABEL_MAX` would make it a stack overflow with an EAP-supplied
  length. A compile-time check now fails the build instead, and the early
  argument-error exit wipes the buffer like every other one.
- **Liveness accepted two Message Numbers that were never emitted.** While only
  one MKPDU had been sent, the recency window still ran three values back, so 0
  and - by wraparound - 0xFFFFFFFF counted as recent. The window is now clamped
  to the number actually emitted.
- **The Distributed-SAK Key Server MI could be taken from a stale peer.** With
  peer-reset handling two entries may share an SCI; the scan took the last match
  rather than the live one.
- **`mka_admit_peer` reported a peer as newly added when the table was full**
  (latent: the caller returns on the error first).
- **`wm_Kay_Free` left the quiesce policy set**, so a freed KaY reused without
  re-initialising carried it.
- **The lost-SAK signal is now tracked only by the Key Server** — a member has
  no use for it and cannot compare a peer's report against a key it did not
  issue. Defensive: the spurious latch this was reported to cause could not be
  reproduced.
- **`MKA_MN_RECENT_WINDOW` of 0 is now a build error** rather than silently
  preventing any peer from becoming live.
- **`Mka_SetEnable` stored the caller's boolean unnormalised**, so
  `Mka_GetEnable` could hand back a value that was neither TRUE nor FALSE.
- **The fuzz harness sealed frames with the non-L2 ICV**, so under
  `WOLFMKA_ICV_L2_ADDR` every forged frame failed verification and the stateful
  fuzzer never reached the state machine. A `fuzz-receive-l2` target now covers
  that decode path, and the harness takes a seeded RNG instead of seeding one
  per draw.
- **`mka_build_l2_prefix` now takes the PDU length** and asserts it, rather than
  relying on the call sites incidentally guaranteeing the six octets it reads.
- **The AUTOSAR binding never acquired an RNG**, so every Member Identifier and
  SAK draw seeded a throwaway generator - the exact cost the library's RNG pool
  exists to avoid. It now acquires one alongside the CMAC workspace.
- **`mka_add_ckn` left the plaintext CAK on the stack.** The staging
  `MkaParticipantConfig` is a local; it is now wiped on every path.
- **`Mka_GetMacSecStatistics` always returned zeros.** Nothing ever filled the
  buffer. It now reads the SecY through `MkaSecyOps.get_secy_stats` where the
  data plane offers it, leaving the asynchronous confirmation flow unchanged.
- **`Mka_Init` dereferenced `ConfigPtr->Paes` and `->Ckns` unchecked**, so a
  non-zero `PaeCount` with a NULL array crashed rather than being refused.
- **`MKA_PERMISSIVE_MODE_TIMEOUT` with a zero `PermissiveTimeoutMs` opened
  plaintext on the very first tick.** An unset timeout now fails closed.
- **The AUTOSAR binding used libc `memset`/`memcpy`/`memcmp` directly**, the
  only source in the tree to do so, bypassing the redefinable `WOLFMKA_MEM*`
  primitives an integrator may override.
- **`Mka.h` documented `ConfidentialityOffset` as "(0/30/50)"** while the core
  requires the `MkaConfidentialityOffset` encoding 0/1/2 and rejects anything
  above 2 - so following the documentation made `Mka_StartPae` fail.
- **A parameter set could consume the trailing ICV octets.** The walk bounded
  each set against the whole body rather than the pre-ICV region, so a set
  declaring a long enough body was handed the 16 ICV octets as payload — as KMD
  content, a Distributed-CAK body or peer-list entries. The mandatory Basic set
  was bounded the same loose way. Not a memory-safety or forgery issue, but
  parse laxness a CA member could exploit to inject unforgeable-looking octets.
- **Declared body lengths of 12..15 authenticated almost nothing.** The ICV is
  the last 16 octets of the *body*, but the guard measured the whole frame, so
  those lengths passed with an authenticated region of 0..3 octets and a
  "received ICV" overlapping the EAPOL header. `wm_Pdu_PeekBasic` had no such
  guard at all.
- **A Key Server's cipher-suite choice was adopted unchecked.** The value is
  carried straight to the SecY, so an unsupported suite — or one contradicting
  the key length actually sent — would have programmed the data plane with
  something the CA never negotiated. It is now validated against the same rule
  the local configuration is.
- **A pinned `MKA_ROLE_KEY_SERVER` ignored `macsec_desired`.** The dynamic
  election refuses a participant that does not want MACsec, but the fixed role
  bypassed the election entirely and generated, installed and programmed a SAK
  anyway — defeating the MACsec-disabled mode.
- **An unprogrammed SAK was demoted to Old.** With `distribute_before_install`,
  a rekey landing while the previous key was still waiting on the wire demoted a
  key the SecY had never seen, leaving an Old entry whose SAs did not exist and
  would later be deleted. It is now replaced outright.
- **The one-shot suspension announcement was consumed before it was sent**, so a
  rejected frame lost it permanently. It is now spent only on delivery, like
  `newInfo`.
- **`MKA_MAX_PEERS` and `MKA_MKPDU_MAX_LEN` could not both be satisfied.** At
  their defaults a full membership needed ~1.3 KiB against a 516-octet buffer,
  so past roughly ten peers `wm_Pdu_Encode` failed and the participant stopped
  transmitting entirely. `MKA_MKPDU_MAX_LEN` now derives from `MKA_MAX_PEERS`,
  and an inconsistent override is a build error rather than a runtime death.
- **`wm_Crypto_ForceZero` dereferenced NULL** despite being documented to ignore
  it — reachable from the failure paths that wipe key material.
- **The L2 streaming CMAC leaked its key schedule on an intermediate failure.**
  Only `wc_CmacFinal` releases a wolfSSL CMAC context, so a failing
  `wc_CmacUpdate` left the ICK-derived AES key schedule and subkeys
  un-zeroized in wolfMKA's own static CMAC pool slot. `mka_aes_cmac_l2` now
  frees the context on that path, as wolfSSL's own one-shot wrapper does.
- **A participant whose initialisation failed kept the caller's plaintext CAK.**
  `wm_Participant_Init` copies the configuration - CAK included - before
  deriving keys and generating the Member Identifier, and returned a failure
  without wiping, contradicting its own documented contract. Worse through the
  manager: `wm_Kay_AddParticipant` does not count a participant that failed, so
  `wm_Kay_Free` never walked that slot and the CAK, KEK and ICK survived
  teardown of the entire KaY. Reachable without fault injection by passing a
  NULL CMAC workspace.
- **Forward secrecy was lost when the *last* live peer departed.** The rekey was
  gated on the live-peer count being non-zero, but by then the departing peer
  had already been removed, so the trigger was dropped and a member joining
  later was handed the departed member's SAK - the common case on a
  point-to-point link.
- **Delay protection bounded the wrong Secure Association during a rekey.** The
  replay window was always applied to the Latest key's Association Number,
  ignoring the Key Number the peer actually reported. Mid make-before-break a
  peer still names the Old key, so the new key's window was advanced to the old
  key's packet number and every frame the peer sent after installing was
  discarded - permanently, when the rekey was driven by packet-number
  exhaustion. The bound now follows the reported key, and an unknown Key Number
  bounds nothing.
- **MACsec SAK Use was acted on before the sender had proven liveness.** A CA
  member holding the CAK but never echoing our Member Identifier stays merely
  Potential, yet could still steer the SecY: naming another member's SCI to
  poison that member's replay window, or oscillating the Key Number to force a
  rekey on every tick. SAK Use is now processed only for a live peer.
- **A peer that stopped proving liveness left silently.** Only the
  not-live -> live transition was handled, so a peer dropping out of the Live
  Peer List raised nothing: by the time it expired it was no longer live, the
  forward-secrecy rekey never ran, and a member joining later was handed the key
  that peer still held. The downgrade now counts as a departure. Its receive SAs
  deliberately stay installed until it expires, since the loss may be
  one-directional and transient.
- **`peer_lost` reported the instantaneous liveness flag**, so a member that had
  been live but was demoted first was reported with `was_live = false` -
  contradicting the documented contract. The event now reports whether the peer
  had ever been live.
- **`Mka_Init` did not tear down the previous configuration.** It reset state
  with a plain `memset` and never freed the running participants, so the SecY
  kept every SAK it had been programmed with while the control plane forgot
  them - unrecoverable, as there is no `Mka_DeInit`. It also cleared only the
  PAEs the *new* configuration uses, leaving any surplus PAE holding its CAK,
  derived keys and a dangling config pointer. It now frees the old KaYs first
  and clears every slot.
- **`permissiveOpen` was never retracted.** A latch set in
  `MKA_PERMISSIVE_MODE_TIMEOUT` survived a switch back to
  `MKA_PERMISSIVE_MODE_NEVER`, so `Mka_GetPaeStatus` kept reporting that
  plaintext was permitted on a port that should have been blocked. Switching to
  any non-timeout mode now clears it immediately.
- **A rejected transmit discarded the update it carried.** `newInfo` was cleared
  whenever the frame was *built*, not when the callback accepted it, so an
  update lost to a failed send waited a full Hello Time for the next attempt -
  worst in the automotive configuration, where it left the local SecY without
  the SAK for that window. The transmit cadence still advances, so a failing
  transmit path is rate-limited as before.

- **`make features` was broken** — a stray backslash before the opening quote
  of the `-DWOLFMKA_AUTOSAR` entry made the shell abort with a syntax error, so
  the whole feature-matrix gate silently stopped compiling anything, including
  the AUTOSAR configuration itself.
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
- **The AUTOSAR binding ran a second PAE state machine, and the two had
  drifted.** `Mka_GetPaeStatus` rebuilt the state ladder from
  `wm_Participant_HasSak` / `wm_Participant_LivePeerCount` plus its own
  ICV-failure latch, rather than translating the `MkaPaeState` the KaY already
  computes. It now translates, so there is one ladder. Two reported states
  change: `MKA_STATUS_MACSEC_RUNNING` requires protection to be *transmitting*
  rather than merely a SAK to have been agreed - reporting it while the transmit
  gate is still closed would tell an integrator to open the controlled port
  while frames still leave unprotected - and `MKA_STATUS_IN_PROGRESS` now
  follows any tracked peer rather than a live one. A link transition no longer
  clears `MKA_STATUS_AUTH_FAIL_UNKNOWN_PEER`; the first MKPDU that authenticates
  does.
- **`MKA_PAE_RUNNING` dropped to `MKA_PAE_IN_PROGRESS` for the duration of every
  rekey.** `wm_Participant_GetPaeStatus` tested `latest.tx` alone, but a
  make-before-break rekey demotes the in-force key - which keeps its transmit SA
  - and leaves the new one gated until the peers report receiving on it.
  Protection is unbroken throughout, so the Old key now counts as running.
- **`MKA_PAE_AUTH_FAIL_UNKNOWN_PEER` was reported for the rest of a
  participant's life** after a single ICV failure, whenever the peer table
  happened to be empty - `counters.icv_failures` never decreases. It now needs
  `counters.mkpdu_in == 0` as well, so it means what it says: frames are
  arriving and none has *ever* authenticated. One corrupted frame on an
  association that has worked is not an authentication failure.
- **`Mka_Init` accepted a zero `MainFunctionPeriodMs`.** That field is what
  advances the KaY's clock, so a zero - the value a memset-ed `Mka_ConfigType`
  holds - left MKA transmitting one MKPDU and then sitting there with every
  hello, retry and rekey timer permanently unfired. The configuration is now
  refused, leaving the module uninitialised.
- **`Mka_SetPaePermissiveMode` stored a value outside the enumeration** and then
  behaved as `MKA_PERMISSIVE_MODE_NEVER`. With no Det to report the misuse, that
  hid the mistake; it is now `E_NOT_OK`. [`AUTOSAR.md`](AUTOSAR.md) records the
  §7 development-error-reporting gap these two sit inside.
- **The L2 ICV entry points were absent from the manual.** They shared one prose
  block with no `@param`/`@return` tags, and `make docs` did not catch it because
  Doxygen dropped the whole `#ifdef`. `WOLFMKA_ICV_L2_ADDR` is now in the
  Doxyfile `PREDEFINED` list, so the pair is documented and gated like the rest
  of the API. `REQUIREMENTS.md` gained its traceability row.
- **Two doc comments overstated what the code guarantees.**
  `mka_retire_stale_mi` claimed a forged MKPDU could never evict a working peer;
  anything reaching it has already passed the ICV, so the real boundary is the
  CAK, and inside a group CA a member can assert another member's
  (self-asserted) SCI. `mka_install_peer_rx` now states that the cipher suite,
  confidentiality offset and SSCI are per-Secure-Channel, so a suite-changing
  rekey cannot validate the Old key's in-flight frames. The comment above
  `wm_Kay_Run` had drifted onto `wm_Kay_SetQuiesceOthers`; both have their own
  again.
- **Test gaps closed.** Quiescing across a rekey, adding a CA while a winner
  exists and removing the holding CA; the multi-CA `wm_Kay_Free` teardown; the
  AUTOSAR oversized-CAK/CKN and `PaeCount`-clamp configuration guards and the
  `Mka_Init` re-initialisation contract; KEK/ICK and L2-ICV known-answer
  vectors.

### Added

- **Det development-error reporting for the AUTOSAR binding** (SWS section 7),
  the last open item from the security review. `MKA_DEV_ERROR_DETECT` (default
  `STD_OFF`) turns it on; error IDs (`MKA_E_UNINIT`, `MKA_E_PARAM_POINTER`,
  `MKA_E_INVALID_PAE_IDX`, `MKA_E_INIT_FAILED`, `MKA_E_PARAM_INVALID`, and the
  vendor-specific `MKA_E_KAY_RUN_FAILED`) and a service ID per API mean a report
  says both what was called and what was wrong with it — the module previously
  detected every one of these and returned the same undifferentiated `E_NOT_OK`.

  Detection is unchanged by the switch: every condition is still checked and
  still rejected with `E_NOT_OK` either way, so turning the reporting off cannot
  change behaviour. With it off it compiles away entirely and the binding links
  with no Det present, which is why that is the default. `MKA_DET_REPORT_ERROR`
  can be defined to route reports somewhere other than `Det_ReportError`.

  Two reports are edge-triggered rather than per-call, both documented in
  [`AUTOSAR.md`](AUTOSAR.md), because a BSW scheduler calls `Mka_MainFunction`
  cyclically and forever: `MKA_E_UNINIT` from the main function is reported once
  per uninitialised period (a successful `Mka_Init` re-arms it), and
  `MKA_E_KAY_RUN_FAILED` once on the transition into failure. Both conditions
  can persist indefinitely - a refused configuration leaves the module down for
  good - so per-call reporting would be one message per tick with nothing added
  after the first.

  This also closes the residual gap that came with it: `Mka_MainFunction` used
  to discard `wm_Kay_Run`'s status, so a per-CA failure — a crypto error during
  SAK generation, say — vanished and the PAE simply sat at `WAITING_PEER`.

### Verification

- **`make test-det`** runs the AUTOSAR suite with the reporting on, asserting
  the exact `(service ID, error ID)` pair for every rejection, that a successful
  call reports nothing, and that each edge-triggered report is made once and not
  repeated. `make coverage-autosar` now runs twice, holding both switch
  settings to 100% line + decision + MC/DC; `make cxx` compiles the binding as
  C++ in both. All three are in CI.
- **The AUTOSAR binding now has a structural-coverage gate.**
  `src/autosar/Mka.c` sits outside `make coverage-configs` — it needs
  `-DWOLFMKA_AUTOSAR` and its own suite — so its coverage was measured by hand
  and had quietly regressed to 97.18% line / 95.83% decision / 95.11% MC/DC. The
  uncovered outcomes were the failure paths of guards added in this same release:
  a `PaeCount` with a NULL `Paes`, a zero `PermissiveTimeoutMs`, and the entire
  SecY statistics pass-through, which no test had ever supplied a
  `get_secy_stats` hook for. New target **`make coverage-autosar`** holds it to
  the same enforced 100% line + decision + MC/DC bar and runs in CI; the file is
  now at 100% of 285 lines, 190 branch outcomes and 182 condition outcomes. One
  decision in `mka_active_status` was removed rather than covered, being
  unreachable (`wm_Participant_GetPaeStatus` fails only on a NULL argument).
- **A capability-reducing join now rekeys** (`WOLFMKA_CIPHER_NEGOTIATION`). The
  confidentiality offset and the integrity-only decision were frozen at
  SAK-install time from the then-current membership, and a join is deliberately
  not a rekey trigger - so a member less capable than the CA had negotiated for
  was programmed with an offset the Key Server was not using, each end
  configuring its data plane from a different answer. Both values travel inside
  the Distributed SAK parameter set, so they belong to the key: no message can
  change them for a key already issued, and a fresh SAK is the only way to move
  the whole CA at once. Only a *reduction* triggers it, so an ordinary join
  stays rekey-free.

  Worth noting for anyone comparing against hostapd: this goes beyond what
  wpa_supplicant does. Its `ieee802_1x_kay_decide_macsec_use()` computes the
  minimum capability across live peers, but never sets `new_sak` for it, and
  `kay->macsec_confidentiality` is fixed once in `ieee802_1x_kay_init()` from
  local policy and never revisited. wolfMKA's negotiation is an extension, and
  this closes a gap in that extension rather than a deviation from the
  reference.
- **MACsec SAK Use claimed Latest-Rx before the receive SAs were installed.**
  The transmit gate refuses to send while `secy_pending != 0`, but the
  advertised receive claim consulted only `sak_program_pending` - which
  `mka_program_sak` clears *before* issuing create_rx_sc / install_rx_sa /
  enable_receive, any of which may return `MKA_SECY_PENDING`. The Latest-Rx bit
  is what releases the *peer's* transmit gate, so the asymmetry ran the unsafe
  way: this end would not send on an SA the hardware lacked, but told the peer
  that it could. The claim now waits for the data plane too.
- **XPN SSCI ranks went stale when a member departed.** An SSCI is an SCI's rank
  within the *live* membership, and the join direction was reprogrammed
  explicitly while the departure direction was not. On a Key Server that was
  masked - a departure forces a rekey, which reapplies the suite to every
  channel - but a member never rekeys, so it went on transmitting XPN frames
  with a rank nobody else computed. Reapplied on both departure paths: the
  not-live transition, and expiry (a peer that simply goes quiet leaves by the
  latter, since the former needs an MKPDU from the peer to run at all).
- **`wm_Participant_Rekey` now refuses to stack on an undelivered key**, with
  the new `MKA_ERR_REKEY_BUSY`. The pending-replace path discards an
  un-programmed Latest key while leaving the Old key in place, so the two stop
  tracking each other and the 2-bit Association Number can wrap onto an AN whose
  Secure Associations are still installed - reachable from documented API use by
  an integrator polling the transmit packet number and rekeying on each poll.
  Only the undelivered case is refused: a make-before-break handover that is
  merely still running is a normal state to rekey out of, and the
  packet-number-exhaustion rekey depends on being able to.
- **`key_server_capable = false` is now visible on the wire.** It excluded the
  participant from its own election but left it advertising its configured Key
  Server Priority, so an attractive value made peers elect a participant that
  would never serve - while it elected them, because it knew it could not. Both
  ends believed the other was Key Server and no SAK was ever agreed, silently.
  Such a participant now advertises `MKA_PRIORITY_NEVER_KS`, which is the only
  way the Basic Parameter Set can express "I cannot": `basic.key_server` means
  "I *am* the elected Key Server", so it is false for everyone at startup and
  cannot serve as a capability signal.
- **`Mka_SetEnable(idx, FALSE)` now tears the PAE down.** It previously set a
  flag: `Mka_MainFunction` stopped ticking the KaY and `Mka_RxIndication`
  stopped routing to it, while every SAK stayed programmed in the data plane.
  The controlled port went on protecting traffic with a key whose control plane
  had stopped, and once the far end expired this member and rekeyed, it was
  encrypting with a key nobody else held. Disabling now frees the participants -
  deleting their SecY SAs and wiping their key material - and clears `started`,
  matching what `Mka_SetCknStatus(..., FALSE, ...)` already did for one CKN.
  `Mka_LinkStateChange` deliberately still does *not* tear down: a link bounce
  does not change which CAK the far end holds.
- **Configurations beyond the build's static limits are refused, not truncated.**
  A `PaeCount` above `MKA_MAX_PAES` was clamped and a `CknCount` above
  `MKA_MAX_PARTICIPANTS` silently skipped, so an ECU came up looking healthy
  while controlled ports its configuration declared protected were simply
  absent - and `Mka_StartPae` still returned `E_OK`. Both now report
  `MKA_E_PARAM_INVALID`; the PAE count is refused outright, and `Mka_StartPae`
  returns `E_NOT_OK` while still instantiating the CKNs within the bound.
- **`src/autosar/Mka.c` is now inside the MISRA gate.** `make misra` scanned
  `$(SRC)` only, so the AUTOSAR binding was outside the check the project says
  covers `src/` - it is not part of `$(SRC)` and needs its own flags. It is now
  scanned in two further configurations (`WOLFMKA_AUTOSAR`, Det off and on).
  Nine violations that scan surfaced are fixed rather than deviated: AUTOSAR's
  `boolean` is a `uint8`, so `if (someBoolean)` is an integer controlling
  expression (14.4) and `(boolean)(a != b)` a wrong-essential-type cast (10.5),
  and the file now compares against `FALSE` and uses `? TRUE : FALSE` - which is
  idiomatic AUTOSAR style regardless. One deviation is recorded: the send
  bridge's `void*` context cast (11.5), which a generic callback cannot express
  otherwise.
- **The Det suite asserted 9 of 18 API service IDs** while
  [`AUTOSAR.md`](AUTOSAR.md) claimed it covered each rejection. All eighteen are
  now asserted - the thirteen APIs taking a PAE index are driven with an
  out-of-range one and checked against their own ID, and the five without an
  index are covered by their own conditions.
- **`make docs` is now a real documentation gate.** `EXTRACT_ALL` was `YES`,
  which renders an undocumented member with an empty description and stops
  `WARN_IF_UNDOCUMENTED` ever firing - so the target could not tell a documented
  API from an undocumented one, and 204 public types, fields and enumerators had
  no description in the manual. Struct-field and enumerator comments across the
  public headers are now Doxygen (`/** */`), the ones that had no comment have
  been written, and `EXTRACT_ALL` is `NO` so a member that loses its
  documentation fails the build. `EXTRACT_STATIC` is `NO` for the converse
  reason: file-static helpers in `src/*.c` are implementation notes, not
  published API.
- **Every `.c` file in `src/` is now under an enforced coverage gate.**
  `mka_status.c` was at 100% but ungated, the same structural gap that let the
  AUTOSAR binding regress unnoticed; it joins `COV_FILES`, so
  `make coverage-configs` holds it to 100% in all eleven configurations. Nothing
  under `src/` is measured by hand any more.
- `make test` is at **1408 checks** (from 1106), and every fix above is pinned by
  a test verified to fail when the fix is reverted.
- `make coverage-configs` enforces 100% line + decision + MC/DC on
  `mka_crypto.c`, `mka_kay.c` and `mka_pdu.c` across **eleven** delivered
  configurations, including the two added here (`WOLFMKA_AUTOMOTIVE_PROFILE` and
  `WOLFMKA_ICV_L2_ADDR`). See [`MCDC-AND-COVERAGE.md`](MCDC-AND-COVERAGE.md).
- New known-answer vectors for the KEK/ICK derivation and the L2-address ICV,
  computed against an independent AES-CMAC oracle rather than wolfMKA itself, so
  an interop-breaking change to either cannot pass.
- New gate targets: `make test-automotive`, `test-icv-l2-suite` and
  `fuzz-receive-l2`; all are wired into CI.

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

- **Known-answer vectors for the key hierarchy and the L2 ICV.** The KEK/ICK
  derivation and the L2-inclusive ICV were previously only self-consistent -
  derive-then-check tests that an interop-breaking change would pass. Both are
  now pinned to values produced by an independent implementation of the
  802.1X 6.2.1 KDF driving OpenSSL's AES-CMAC, itself checked against the
  RFC 4493 vectors. The vectors cover the short-CKN zero-pad and the
  full-length-CKN truncation of the KDF context, and a two-block derivation so
  the counter is exercised.

- 1106 unit checks, fault-injection and negotiation suites, and the AUTOSAR
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
