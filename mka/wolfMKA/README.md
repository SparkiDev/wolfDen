# wolfMKA

An implementation of the **MACsec Key Agreement (MKA)** protocol from
**IEEE Std 802.1X-2010, Clause 9**, using **wolfSSL** for all cryptography.

MKA is the control plane for MACsec (IEEE 802.1AE). It does not encrypt user
data itself; instead it discovers peers on a LAN, proves mutual liveness,
elects a *Key Server*, and securely distributes the *Secure Association Keys
(SAKs)* that the MACsec data plane (the SecY) then uses to protect traffic.

```
   ┌──────────────┐   EAPOL-MKA (EtherType 0x888E)   ┌──────────────┐
   │  KaY  (MKA)  │◀────────── MKPDUs ──────────────▶│  KaY  (MKA)  │
   │  this code   │                                   │   peer       │
   └──────┬───────┘                                   └──────┬───────┘
          │ install SAK                                      │
          ▼                                                  ▼
   ┌──────────────┐                                   ┌──────────────┐
   │  SecY (data) │◀═══════ protected frames ════════▶│  SecY (data) │
   └──────────────┘                                   └──────────────┘
```

## What is implemented

| Area | Standard reference | Status |
|------|--------------------|--------|
| AES-CMAC KDF | 802.1X-2010 §6.2.1 (SP 800-108 counter mode) | ✅ |
| CAK/CKN derivation from EAP MSK | §9.3.2 | ✅ |
| KEK & ICK derivation from CAK | §9.3.3 | ✅ |
| SAK generation (random, Key Server) | §9.8 | ✅ |
| SAK wrap/unwrap (AES Key Wrap, RFC 3394) | §9.8.2 | ✅ |
| MKPDU encode/decode (all core parameter sets) | §11.11 | ✅ |
| ICV computation/verification (AES-CMAC) | §9.4.1 / §11.11 | ✅ |
| Peer discovery & liveness (Live/Potential lists) | §9.4.3 | ✅ |
| Key Server election | §9.5 | ✅ |
| SAK distribution & installation into a SecY | §9.8 / Clause 10 | ✅ |
| Make-before-break SAK rekey (Old + Latest handover) | §9.8 | ✅ |
| Multiple CAs per port, MKPDUs routed by CKN | §9.6 / §12.5 | ✅ |
| Periodic MKPDU transmission (Hello/Life timers) | §9.16 | ✅ |
| MKPDU replay protection (Message Number) | §9.4.2 | ✅ |
| Transmit gating on peer Rx-readiness | §9.x | ✅ |
| Delay protection (LPN exchange) | §9.4.1 | ✅ (optional) |
| Extended Packet Numbering + SSCI | 802.1Xbx / AE | ✅ (optional) |
| Distributed CAK (group-CAK distribution) | §9.x / §11.11 (type 5) | ✅ (opt-in) |
| Key Management Domain advertisement | §11.11 (type 6) | ✅ (opt-in) |
| MKA participant suspension | 802.1Xbx-2014 | ✅ (opt-in, XPN) |
| Fast startup: peer-list change answered at once | §9.4 (`newInfo`) | ✅ (opt-in) |
| Peer-reset recovery (same SCI, new MI) | OA AutoMKA-03006 | ✅ |
| L2-address ICV (wpa_supplicant-compatible ICV input) | §11.11.3 | ✅ (opt-in) |
| Liveness requires an acceptably recent echoed MN | §9.4.3 / OA AutoMKA-03005, -04004 | ✅ |
| SecY MACsec statistics + PAE status accessors | OA AutoMKA-07008, -07009 | ✅ |
| Losing CAs quiesce once one establishes MACsec | OA AutoMKA-09001, -09002 | ✅ (opt-in) |
| Key Server priority 255 = never, 0 = always | OA AutoMKA-03007 | ✅ (profile) |
| MACsec-disabled mode: MKA runs, data plane untouched | OA AutoMKA-12002 | ✅ |
| Rekey when a peer stops reporting the SAK | OA AutoMKA-03011 | ✅ |
| Distribute a new SAK before installing it locally | OA AutoMKA-03010 | ✅ (opt-in) |
| OPEN Alliance TC17 Automotive MKA profile | OA Automotive MKA v1.0 | ✅ (opt-in — see [`OPEN-ALLIANCE.md`](OPEN-ALLIANCE.md)) |

All cryptography is performed by wolfSSL: `wc_AesCmacGenerate_ex` (KDF/ICV),
`wc_AesKeyWrap`/`wc_AesKeyUnWrap` (SAK distribution), and `wc_RNG_*`
(MI/SAK generation).

The RNG is drawn from a small pool to avoid re-seeding on every call (seeding
is the costly step). `wm_Crypto_RandomInit()` acquires and seeds one RNG
object and returns a reference; pass it to the random-consuming functions (or
via `MkaParticipantConfig.rng`) and release it with `wm_Crypto_RandomFree()`.
The workspace is **required** in every build, exactly as the CMAC one is: a
`NULL` is rejected with `MKA_ERR_BAD_ARG`, never silently replaced by a per-call
RNG. wolfSSL's `WC_RNG` would otherwise have to live in wolfMKA's own frame, and
under `WOLFSSL_NO_MALLOC` it carries its DRBG state inline — hundreds of octets
of stack in precisely the small-stack/no-malloc build the pool exists to serve,
while an ordinary build heap-allocates the DRBG on every call. The pool size is
`WOLFMKA_RANDOM_POOL_SIZE` (default 1, override at build time) — size it for the
number of concurrent RNG holders.

The AES-CMAC context follows the same pattern, and for the same reason wolfMKA —
not wolfSSL — owns where it lives: the wolfSSL `Cmac` object is ~1 KB, and the
one-shot `wc_AesCmacGenerate` places it on wolfSSL's own stack frame (or heap, if
wolfSSL is built `WOLFSSL_SMALL_STACK`), outside wolfMKA's memory policy. wolfMKA
instead calls `wc_AesCmacGenerate_ex` with a **caller-supplied** workspace from a
pool: `wm_Crypto_CmacInit()` hands back a `MkaCmacCtx*` that you pass to the
CMAC-consuming functions (or via `MkaParticipantConfig.cmac`) and release with
`wm_Crypto_CmacFree()`. The workspace is **required** in every build —
wolfMKA never falls back to a stack or heap context, so the ~1 KB object is never
placed on the stack or allocated on your behalf; a `NULL` workspace is rejected
with `MKA_ERR_BAD_ARG`. The pool size is `WOLFMKA_CMAC_POOL_SIZE` (default 1,
override at build time) — one per participant covers the common single-threaded
case, since a participant's CMAC operations do not nest.

### Security hardening (implemented)

- **MKPDU replay protection** — a received MKPDU is rejected unless its Message
  Number strictly increases for that Member Identifier (802.1X 9.4.2).
- **Transmit gating** — a newly installed transmit SA is held disabled until
  every live peer reports receiving on the SAK (MACsec SAK Use), so traffic is
  never sent that peers cannot yet decrypt.
- **Delay protection** *(optional)* — the lowest-acceptable-PN exchange advances
  each receive replay window to bound frame delay; uses the Bounded Hello Time.
  The LPN a participant *transmits* is what its peer uses, so both the Latest and
  the Old key report their real packet number from the SecY in every build,
  including one compiled `WOLFMKA_NO_DELAY_PROTECT` — that switch removes this
  end's own delay handling, not the far end's.
- **Extended Packet Numbering** *(optional)* — GCM-AES-XPN-128/256 cipher suites
  with deterministic Short SCI (SSCI) assignment (802.1Xbx). The Salt is derived
  by the SecY from the SAK per 802.1AE-2018, not distributed by MKA.
- **Keys are identified by KI, not Key Number** — IEEE Std 802.1X-2010 names a
  SAK by its Key Identifier, KI = (Key Server MI ‖ Key Number). Key Numbers are
  unique only per Key-Server incarnation: one that restarts comes back with a
  fresh MI, no stored key, and begins again at KN 1 — with different key bytes.
  Recognising a key by Key Number alone would make a member decline that install
  as a duplicate and keep the dead key while the Key Server transmitted on the
  new one, both ends reporting MACsec up over a silent black-hole. The issuing
  Key Server's MI is stored with the key and compared alongside the Key Number.
- **Peer-table fair share** — a device is identified on the wire by its SCI, but
  its Member Identifier changes on every restart, and peer-reset recovery
  deliberately admits a returning device's new MI alongside the old one. Entries
  per SCI are capped at `MKA_MAX_PEERS_PER_SCI` (2) so a member cycling MIs is
  bounded to its own share of the table rather than crowding out the CA.
- **Bounded parameter-set parsing** — every set is bounded against where the ICV
  starts rather than the end of the body, so none can consume the ICV octets; the
  ICV Indicator must sit immediately before the ICV and declare its length, so a
  forged one cannot hide the sets behind it; and a body too short to hold an ICV
  is rejected before anything is authenticated.
- **Secure key zeroization** — transient secrets (generated/unwrapped SAKs and
  the KDF scratch that holds derived key material) are wiped with
  `wm_Crypto_ForceZero()` — wolfSSL's `wc_ForceZero`, which the optimiser may not
  elide — the moment they are no longer needed; `wm_Participant_Free()` /
  `wm_Kay_Free()` tear down the SecY SAs and wipe a participant's CAK,
  KEK/ICK and SAKs at end of life. A failed `wm_Crypto_UnwrapSak()` wipes the
  caller's output too, so plaintext from a key that never authenticated is not
  handed back.

See [`REQUIREMENTS.md`](REQUIREMENTS.md) for the full requirements-to-test
traceability matrix.

### Optional features (build-time)

Each optional feature can be compiled out (wolfSSL's `NO_*` idiom):

| Define | Removes |
|--------|---------|
| `WOLFMKA_NO_EAP` | EAP-MSK CAK/CKN derivation (PSK-only build) |
| `WOLFMKA_NO_XPN` | XPN cipher suites + SSCI assignment |
| `WOLFMKA_NO_DELAY_PROTECT` | delay-protection LPN handling |
| `WOLFMKA_NO_RETRY` | MKA retry exponential back-off |
| `WOLFMKA_NO_ANNOUNCEMENTS` | Announcement (cipher-suite) emit/decode |
| `WOLFMKA_NO_AUTO_REKEY` | automatic SAK rekey (time span + PN exhaustion) |

`make features` compiles each optional-feature configuration (every `NO_*` on
its own, each opt-in feature, AUTOSAR, and the fully-stripped build). The
maximally-stripped embedded build is `WOLFMKA_NO_EAP NO_XPN NO_DELAY_PROTECT
NO_RETRY NO_ANNOUNCEMENTS NO_AUTO_REKEY SMALL_STACK NO_MALLOC`.

Some features are **opt-in** (off by default, so the default build is unchanged):

| Define | Adds |
|--------|------|
| `WOLFMKA_DISTRIBUTED_CAK` | Distributed CAK parameter set (type 5): the `wm_Participant_DistributeCak` Key-Server API, plus a `cak_received` event by which a member reports the unwrapped group CAK to the integrator. `make test-distcak` builds and tests with it enabled. |
| `WOLFMKA_KMD` | Key Management Domain parameter set (type 6): a configured `kmd` the Key Server advertises, and a `wm_Participant_GetKmd` accessor by which a member reads the received domain name. Informational only (authenticated by the MKPDU ICV; no extra crypto). `make test-kmd` builds and tests with it enabled. |
| `WOLFMKA_ICV_L2_ADDR` | Computes and verifies the MKPDU ICV over an L2 prefix — destination (PAE group address), source (the SCI from the Basic Parameter Set) and EAPOL EtherType — followed by the MKPDU, which is the ICV input wpa_supplicant uses (IEEE Std 802.1X-2010 §11.11.3). Off by default; enable it to interoperate with peers that bind the Ethernet framing into the ICV. It changes what is signed, so **both ends must agree**. `make test-icv-l2` runs the standalone check and `make test-icv-l2-suite` runs the whole suite over this ICV path. |
| `WOLFMKA_AUTOMOTIVE_PROFILE` | The OPEN Alliance TC17 **Automotive MKA** profile: version 3 MKPDUs and no Secure Announcements / cipher-suite negotiation, plus `wm_Participant_AutomotiveDefaults()` for the profile's startup timing (10 ms → Hello Time ramp and immediate response to a peer-list change). `make test-automotive` builds and tests with it enabled; [`OPEN-ALLIANCE.md`](OPEN-ALLIANCE.md) is the requirement-by-requirement map, including the known gaps. |
| `WOLFMKA_SUSPENSION` | MKA participant suspension (802.1Xbx-2014): `wm_Participant_Suspend(p, seconds)` / `wm_Participant_Resume(p)`. A suspended participant advertises a suspension time (in the XPN set's MKA Suspension Time field) and goes quiet; peers hold its state past the Life Time so the SAK survives the gap. **Requires XPN** (must not be combined with `WOLFMKA_NO_XPN`). `make test-suspension` builds and tests with it enabled. |
| `WOLFMKA_CIPHER_NEGOTIATION` | Key Server cipher-suite **and** MACsec-capability negotiation. (1) Each participant adds a `cipher_prefs` / `cipher_pref_count` preference list to its config and announces it; the elected Key Server picks the most-preferred suite **every live peer accepts** (a peer accepts a suite it announced, or any suite when it sends no Announcement), and that choice drives the SAK length. With no preference list a participant keeps the configured `cipher_suite` / `sak_len`. (2) The Key Server also reduces the confidentiality offset to the lowest MACsec Capability across the CA — a member that can only do `INTEGRITY_CONF` forces offset 0, and one that can only do `INTEGRITY_ONLY` (or no MACsec) drops the CA to integrity-only, signalled to the SecY as `MKA_CONF_OFFSET_NONE`. Both values travel inside the Distributed SAK parameter set, so they belong to the key rather than to the CA: a member joining a keyed CA with a *lower* capability than it was negotiated for therefore forces a rekey, which is the only way to move every member to the new offset at once. An ordinary join — one that reduces nothing — still does not rekey. **Requires the Announcement set** (must not be combined with `WOLFMKA_NO_ANNOUNCEMENTS`). `make test-negotiation` builds and tests with it enabled. |

The Key Server wraps a group CAK with the CA's KEK and emits it; each member
unwraps it (a wrong KEK fails the AES Key Unwrap integrity check and is ignored)
and hands the plaintext CAK to the integrator through `cak_received`. wolfMKA
does **not** itself start the group CA — the integrator decides, typically by
calling `wm_Kay_AddParticipant` for the new CKN, keeping the
one-participant-per-CA model intact.

With `WOLFMKA_NO_AUTO_REKEY` the Key Server still generates the first SAK and
rekeys for forward secrecy when a live peer departs; only the timed and
PN-exhaustion automatic rekey are removed, and `wm_Participant_Rekey()`
remains for integrator-driven rekey. Builds using an XPN cipher suite should
keep auto-rekey (or drive `wm_Participant_Rekey` from `get_next_pn`) to
avoid packet-number exhaustion.

**`WOLFMKA_AUTOSAR` profile.** The AUTOSAR `Mka` binding keys MACsec from a
pre-shared CAK and does not use EAP-MSK derivation, so `-DWOLFMKA_AUTOSAR`
implies `WOLFMKA_NO_EAP`. The retry back-off, Announcements, XPN and delay
protection all stay in — each is configurable through `Mka_PaeConfigType`
(`RetryBaseMs`/`RetryCyclicMs`, `AnnounceCipherSuites`, `CipherSuite`,
`DelayProtect`). `make autosar` builds and tests with this profile.

Development-error reporting (SWS §7) is available behind `MKA_DEV_ERROR_DETECT`,
which defaults to `STD_OFF` so the binding links without a generated `Det`. Set
it to `STD_ON` and every condition the module already rejects is also reported
to Det with the API service ID and a specific error — `MKA_E_UNINIT`,
`MKA_E_PARAM_POINTER`, `MKA_E_INVALID_PAE_IDX` and the rest — instead of an
undifferentiated `E_NOT_OK`. Detection itself is identical either way, so the
switch cannot change behaviour. `make test-det` runs the suite with it on;
[`AUTOSAR.md`](AUTOSAR.md) documents the error and service IDs.

**`WOLFMKA_AUTOMOTIVE_PROFILE`.** The OPEN Alliance TC17 *Automotive MKA
Specification* v1.0 profiles 802.1X-2020 MKA for in-vehicle Ethernet: version 3
MKPDUs, no Secure Announcements or cipher-suite negotiation, and a startup
budget of tens of milliseconds instead of seconds. The macro selects the
compile-time half; `wm_Participant_AutomotiveDefaults()` fills a config with the
runtime half — the 10 ms → Hello Time ramp and `immediate_response`, which
answers a peer-list change, a newly installed SAK or the transmit gate opening
on the next `wm_Participant_Run()` instead of waiting out the interval
(the `newInfo` behaviour of 802.1X 9.4). In the in-process two-party test
MACsec is transmitting at both ends **3 ms** into the exchange.
`make test-automotive` builds and tests with the profile;
[`OPEN-ALLIANCE.md`](OPEN-ALLIANCE.md) maps all 65 of the specification's
requirements to an implementation, a configuration item, or the integrator —
with no gaps outstanding. wolfMKA is not certified to the profile and has
not been through an OPEN Alliance plugfest.

`immediate_response` is a plain configuration field, available in every build —
the profile macro is not needed to use it.

### Out of scope

- All standard MKPDU parameter sets are handled: the Announcement (type 7) and
  XPN (type 8) sets always; the **Distributed CAK** (type 5) and **KMD**
  (type 6) sets, and **MKA suspension** (802.1Xbx, carried in the XPN set), under
  their opt-in `WOLFMKA_DISTRIBUTED_CAK` / `WOLFMKA_KMD` / `WOLFMKA_SUSPENSION`
  features (see above). Unknown/unsupported parameter sets are skipped on decode.
- **One participant per CA.** A participant is bound to a single CKN/CAK; the
  `MkaKay` manager runs several participants on one port and routes inbound
  MKPDUs to the right one by CKN. Group CAs work because all members share the
  CAK (hence the same KEK). MKA-driven group-CAK *distribution* is available as
  the opt-in `WOLFMKA_DISTRIBUTED_CAK` feature, which delivers the unwrapped CAK
  to the integrator rather than auto-creating the CA.
- **Data plane & wire transport are abstract** (see below), per the chosen scope.

## Architecture

| File | Responsibility |
|------|----------------|
| `include/wolfmka/mka_types.h` | On-wire constants, enums, value structs |
| `include/wolfmka/mka_bytes.h` | Shared big-endian octet read/write helpers (internal) |
| `mka_crypto.[ch]` | KDF, CAK/CKN/KEK/ICK derivation, SAK gen, key wrap, ICV — all via wolfSSL |
| `mka_pdu.[ch]` | MKPDU (EAPOL-MKA) encode / decode + ICV |
| `mka_secy.h` | Abstract SecY callback interface (install SA, enable, delete) |
| `mka_kay.[ch]` | The KaY: participant state machine, peers, election, SAK agreement |

The **SecY** (data plane) and the **frame transport** are abstract callbacks,
so the same engine drives a Linux kernel `macsec` device, a hardware offload,
or an in-process test shim without change.

## Building

wolfSSL must be built with CMAC and AES key wrap enabled:

```sh
cmake -S wolfssl -B build \
      -DWOLFSSL_CMAC=yes -DWOLFSSL_AESKEYWRAP=yes \
      -DCMAKE_INSTALL_PREFIX=/path/to/wolfssl-install
cmake --build build --target install -j
```

Then build wolfMKA, pointing it at that install prefix:

```sh
make WOLFSSL_DIR=/path/to/wolfssl-install        # builds libwolfmka.a + demo
make WOLFSSL_DIR=/path/to/wolfssl-install test    # run the test suite
make WOLFSSL_DIR=/path/to/wolfssl-install examples
./examples/mka_demo
```

`make docs` generates the Doxygen HTML API reference into `doc/html/`
(treating Doxygen warnings as errors). Public-API documentation lives in the
headers; the C files carry implementation notes. Every push and pull request is
exercised by GitHub Actions ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)):
unit + fault tests, valgrind, ASan+UBSan, a libFuzzer smoke pass, GCC
`-fanalyzer`, big-endian serialization on ppc64 via qemu (`make test-endian`),
the no-malloc and all-feature builds, MISRA, 100% MC/DC coverage, and the docs
build.

The release version is exposed as `WOLFMKA_VERSION_MAJOR` / `_MINOR` / `_PATCH`
/ `_STRING` / `_HEX` (`include/wolfmka/mka_types.h`); changes are tracked in
[`CHANGELOG.md`](CHANGELOG.md). Memory and code-size budgets per build
configuration are in [`FOOTPRINT.md`](FOOTPRINT.md) (`make footprint`).

`WOLFSSL_DIR` defaults to `../wolfssl/install-mka` (the in-tree dev layout).

**C and C++.** The library is C99, but every source also compiles as C++ and
the public headers carry `extern "C"` guards, so wolfMKA can be dropped into a
C++ project or built by a C++-only toolchain. `make cxx` verifies this (each
source is compiled with `g++`).

## Examples

- **`examples/mka_demo`** — two participants reach a SAK entirely in process
  (no sockets); shows discovery → election → SAK distribution and prints the
  agreed key. Also wires the optional `MkaEventOps` hooks, narrating each
  milestone (peer added/live, Key Server elected, SAK installed, MACsec up) as
  it fires. Portable.
- **`examples/mka_eap`** — derives the CAK and CKN from an 802.1X **EAP MSK**
  (`wm_Crypto_DeriveCakFromMsk` / `DeriveCknFromMsk`, IEEE 802.1X-2010 §9.3.2)
  rather than using a pre-shared CAK, confirms both ends derive the same keys,
  then runs MKA to a SAK. Portable.
- **`examples/mka_xpn`** — selects an **XPN** suite (`GCM-AES-XPN-128`) and
  drives the XPN-specific SecY hooks: `set_cipher_suite` (negotiated suite +
  per-channel SSCI) and the 64-bit `get_next_pn` / `set_lowest_pn` (the wide
  packet number the 32-bit suites cannot reach). Portable.
- **`examples/mka_rekey`** — performs a make-before-break SAK rollover via
  `wm_Participant_Rekey()`, showing the Key Number advance 1 → 2 on both ends
  while the Old key stays installed for in-flight traffic. Portable.
- **`examples/mka_link`** — runs a real participant over a Linux `AF_PACKET`
  raw socket (EAPOL, EtherType 0x888E to 01:80:C2:00:00:03). This is the
  concrete form of the abstract `send`/`receive` interface — the glue a
  deployment normally writes. Linux-only, needs root.
- **`examples/secy_macsec_linux.c`** — a reference SecY (data-plane) driver
  that programs the Linux kernel `macsec` device via generic netlink; the
  concrete counterpart to the abstract `MkaSecyOps` hooks.
- **`examples/mka_macsec`** — the two Linux shims combined into the binary a
  deployment actually ships: EAPOL control over an `AF_PACKET` socket **and**
  the agreed SAK programmed into the kernel `macsec` device. Used by the
  data-plane interop harness. Linux-only, needs root.
- **`examples/mka_group_cak`** — the Distributed-CAK demo (a Key Server hands a
  group CAK to a peer). Built and run by `make example-distcak` (needs
  `WOLFMKA_DISTRIBUTED_CAK`).
- **`examples/mka_autosar`** — drives two PAEs to a MACsec session through the
  **AUTOSAR `Mka_*` API** (`Mka_Init` / `Mka_MainFunction` / `Mka_RxIndication`)
  instead of the native `wm_Participant_*` interface. Built and run by
  `make example-autosar` (needs `WOLFMKA_AUTOSAR` and `src/autosar/Mka.c`).

Run two wolfMKA endpoints across a `veth` pair sharing one CAK/CKN:

```sh
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth0 up && sudo ip link set veth1 up
CAK=cacacacacacacacacacacacacacacaca; CKN=0011223344
sudo ./examples/mka_link veth0 10 $CAK $CKN   # priority 10 -> Key Server
sudo ./examples/mka_link veth1 20 $CAK $CKN   # priority 20  (other terminal)
```

Both print `state: live=1 key_server=… sak=1` and the installed SAK once they
agree.

## Tests

`make test` runs 1408 checks across three layers:

- **crypto** — anchored to published vectors: **RFC 4493** (AES-CMAC) and
  **RFC 3394** (AES Key Wrap), plus KDF determinism, SAK wrap/unwrap roundtrip
  and ICV tamper detection. The derivations that have no published vector — the
  KEK/ICK from a CAK, and the L2-address ICV — carry known-answer tests computed
  against an independent AES-CMAC oracle rather than against wolfMKA itself, so a
  change to either fails the suite instead of silently breaking interoperability.
- **pdu** — MKPDU encode/decode roundtrips (basic-only and full, incl. an
  explicit-cipher-suite 256-bit Distributed SAK), ICV tamper / wrong-key
  rejection, and the pre-ICV "peek" path used to select a CAK on receive. Beside
  the bounds cases there is a set of *semantic* ones — frames that parse cleanly
  but must not mean what they appear to: a duplicated parameter set, a repeated
  cipher-suites TLV, a SAK Use whose key-in-use flags have no body behind them,
  and the forward-compatible shapes (an over-long parameter set, a present but
  empty peer list) that a future peer may legitimately send.
- **kay** — a two-participant in-process simulation that runs discovery →
  liveness → Key Server election → SAK distribution and asserts both ends
  install the *same* SAK through their SecY; also covers replay rejection, Tx
  gating, XPN/SSCI, delay protection, a make-before-break **rekey** (Old/Latest
  handover and retirement, including the 2-bit Association Number wrapping
  0-1-2-3-0), peer-reset recovery and its per-device entry cap, the observability
  hooks at each transition, and the **multi-CA manager** routing MKPDUs by CKN.

**Fault injection.** The `MKA_ERR_CRYPTO` branches only fire when a wolfSSL
primitive fails, which valid inputs never trigger. `make test-fault` rebuilds
the suite with `-DWOLFMKA_FAULT_INJECT` and a programmable hook (`MKA_FI`, see
[`include/wolfmka/internal/mka_fault.h`](include/wolfmka/internal/mka_fault.h)) that forces each
primitive to fail, exercising those fail-closed paths. In a normal build
`MKA_FI` is a no-op macro: zero overhead, no behavioural change, and no
injection symbols in the library.

**Coverage.** With the fault-injection build, **line, decision (branch) and
MC/DC coverage are all 100%** of every `.c` file in `src/` — `mka_crypto.c`,
`mka_kay.c`, `mka_pdu.c` and `mka_status.c` under `make coverage`, and
`src/autosar/Mka.c` under `make coverage-autosar` —
both outcomes of every branch are taken, and every operand of each compound
`&&`/`||` condition is shown to independently affect the result. Run `make
coverage` to reproduce the figures (gcov `--conditions`, built at `-O0` with
`-DWOLFMKA_FAULT_INJECT`); the target **fails** below 100% on any of the three
metrics. `make coverage-configs` re-runs the same enforced check across all eleven
delivered configurations (cert base, cipher negotiation, the automotive profile,
the L2-address ICV, small-stack/no-malloc, and the six `NO_*` feature-off
builds). MC/DC is the masking variant accepted by
DO-178C, measured with GCC's `-fcondition-coverage`. Every public function is
exercised with invalid parameters at each pointer position, and — where it takes
a caller-supplied length — with one past the bound it is checked against. Two defensive guards
that valid operation cannot reach are covered deliberately: the Key Number
wrap-around reset (would need 2³² rekeys) by a white-box test that drives the KN
to its maximum before a rekey, and the EAPOL-body-exceeds-64 KiB buffer check
(MKA frames are bounded far below that) via the `MKA_FI_BODY_LEN` injection hook.

**Runtime safety.** Beyond the valgrind run in the gate, the suite runs clean
under **AddressSanitizer + UndefinedBehaviorSanitizer** (`make sanitize`:
`-fsanitize=address,undefined -fno-sanitize-recover=undefined`) across the
delivered configurations — no memory errors and no undefined behaviour. 100%
structural coverage proves every branch is *executed*; the sanitizers prove that
execution is also free of UB. A second static-analysis pass independent of the
MISRA/cppcheck one runs via `make analyze` (GCC `-fanalyzer`, findings are
errors).

**Fuzzing.** Two coverage-guided libFuzzer harnesses (`make fuzz`, clang
`-fsanitize=fuzzer,address,undefined`) exercise the input-handling surface:
`fuzz-pdu` drives the stateless MKPDU decoder (both raw bytes and
authentically-framed bodies, so the full parameter-set parser is reached), and
`fuzz-receive` drives the stateful participant receive path — sequences of
ICV-valid forged frames interleaved with clock ticks, through peer tracking,
liveness, Key Server election and SAK distribution. CI runs a bounded smoke
pass; raise `FUZZ_SECONDS` (and supply a corpus directory) for a campaign.

**Mutation testing.** Coverage proves code is executed; it does not prove the
tests would *notice* a fault. Assertion strength is validated by injecting
operator-flip mutations (`==`↔`!=`, `<=`↔`<`, `&&`↔`||`) into the core sources
and confirming the suite fails for each. It kills ~90% of the reachable sites;
every survivor was triaged to a disabled-assert no-op, a semantic equivalent, or
a boundary on a build-private constant, and any that exposed a genuine gap was
closed with an added assertion.

## MISRA C:2012

The library source is written to conform to **MISRA C:2012**. The fully
compliant configuration is the no-allocation build (`-DWOLFMKA_NO_MALLOC
-DWOLFMKA_SMALL_STACK`); the deviation record and compliance statement are in
[`MISRA.md`](MISRA.md). Conformance is checked with Cppcheck's MISRA addon:

```sh
make misra          # (override CPPCHECK= if not on PATH)
```

No *Mandatory* rule is deviated; the only deviations are Advisory rules (15.5
single-exit, 8.7 public-API linkage, 2.x unused public-API symbols) plus the
dynamic-allocation rules (21.3/11.5) which apply **only** to the optional heap
build, not the compliant `WOLFMKA_NO_MALLOC` one. Boolean flags use `bool`,
sizes are unsigned, and all narrowing conversions are explicit casts.

## IEC 61508 / IEC 62443

wolfMKA is **not certified** to either standard (source alone cannot be — both
certify a *system* through a *lifecycle*), but it is written and documented to
**support** such an effort. The boundary — what the library provides vs. what an
integrator must supply — is stated in [`COMPLIANCE.md`](COMPLIANCE.md), backed
by a component [`FMEA.md`](FMEA.md), a vulnerability-handling process
([`SECURITY.md`](SECURITY.md)), the requirements/traceability matrix
([`REQUIREMENTS.md`](REQUIREMENTS.md)), and the MISRA conformance record
([`MISRA.md`](MISRA.md)). The two industry-profile maps are
[`AUTOSAR.md`](AUTOSAR.md) (AUTOSAR Classic `Mka`) and
[`OPEN-ALLIANCE.md`](OPEN-ALLIANCE.md) (OPEN Alliance TC17 Automotive MKA).

## Small-stack / no-malloc / embedded builds

Large local variables (>= 64 octets — the working `MkaPdu`, the KDF scratch, the
outgoing frame) can be placed in three ways:

| Configuration | Where large locals live | Allocations |
|---------------|--------------------------|-------------|
| *(default)* | on the stack (plain arrays/structs) | none |
| `WOLFMKA_SMALL_STACK` | on the heap (`WOLFMKA_MALLOC`) | per call |
| `WOLFMKA_SMALL_STACK` + `WOLFMKA_NO_MALLOC` | fields of an object | **none** |

This follows wolfSSL's convention via `MKA_DECLARE_VAR` / `MKA_ALLOC_VAR` /
`MKA_FREE_VAR` (see `include/wolfmka/mka_mem.h`): the variable is a stack array
normally and a pointer under small-stack, with identical access syntax. Under
`WOLFMKA_NO_MALLOC` the pointer is bound to a caller-provided object field
instead of being allocated — for the KaY that field is part of `MkaParticipant`
(`ws_pdu`, `ws_frame`).

Variables under 128 octets stay on the stack; only larger ones (the working
`MkaPdu`, the outgoing frame) are placed off-stack. The key-derivation scratch
is right-sized to MKA's maxima (label <= 16, context <= 96 with EAP) so it stays
under 128 octets and lives on the stack in **every** build. The one large crypto
object is wolfSSL's ~1 KB `Cmac` context; it is handled by the CMAC workspace
(`wm_Crypto_CmacInit` / `MkaParticipantConfig.cmac`) rather than the
`MKA_DECLARE_VAR` mechanism, so it lives in wolfMKA-owned pool storage instead of
a wolfSSL stack frame or allocation. The workspace is **required** for any CMAC
operation in every build — wolfMKA never substitutes a stack or heap context —
so this object is the caller's to place, never a hidden stack or heap cost.

```sh
make SMALL_STACK=1 test                # off-stack via heap
make SMALL_STACK=1 NO_MALLOC=1 test     # off-stack via object fields, zero malloc
make test-nomalloc                      # the above + asserts no alloc symbols are linked
```

Peak stack frame for the heaviest functions (gcc `-fstack-usage`):

| Function | normal | small-stack (heap or no-malloc) |
|----------|-------:|--------------------------------:|
| `wm_Participant_Receive`   | 1408 B | ~112 B |
| `wm_Participant_BuildMkpdu` | 1408 B | ~96 B |
| `wm_Participant_Run`       | 624 B  | ~144 B |
| `wm_Crypto_Kdf`                   | 288 B  | ~160 B |

When malloc *is* allowed it goes through redefinable macros so a platform can
supply its own allocator (e.g. a static pool) without touching wolfMKA:

```c
/* via -D, or a wolfmka_user_settings.h compiled with -DWOLFMKA_USER_SETTINGS */
#define WOLFMKA_MALLOC(sz, heap, type)  my_pool_alloc((sz), (type))
#define WOLFMKA_FREE(ptr, heap, type)   my_pool_free((ptr))
```

The `(heap, type)` arguments mirror wolfSSL's `XMALLOC`/`XFREE` so a typed pool
allocator can route by `MKA_DYN_*` tag. `make test-alloc` builds the library
small-stack with a counting allocator and asserts every allocation is freed;
`make test-nomalloc` builds it with no malloc at all and asserts the objects
reference no allocation symbols.

## Interoperability with hostapd / wpa_supplicant

wolfMKA implements the IEEE Std 802.1X-2010 wire format and the published
cryptographic constructions, so it interoperates with conformant MKA peers such
as hostapd/wpa_supplicant. The interoperable parts are pinned as regression
vectors in the test suite:

| Property | Pinned to | Test |
|----------|-----------|------|
| AES-CMAC primitive | RFC 4493 vectors | `test_rfc4493_cmac` |
| AES Key Wrap | RFC 3394 vectors | `test_rfc3394_keywrap` |
| KEK / ICK derivation, CAK/CKN-from-MSK (EAP path), ICV | the exact bytes produced by hostapd's `ieee802_1x_*_aes_cmac` | `test_eap_derivation`, `test_icv` |
| MKPDU layout (all §11.11 parameter sets) | the 802.1X-2010 wire format | `test_roundtrip_*` |

> The EAP-path expected values were obtained by running hostapd's real
> `src/pae/ieee802_1x_key.c` and are baked into the suite, so the key hierarchy
> and ICV are checked to be byte-identical to hostapd's output on every `make
> test`. (That cross-check originally caught two EAP-path bugs: the
> two MAC addresses must be concatenated lowest-first, and the CKN KDF context
> has no key-id separator octet.)

Those vectors pin the *cryptographic constructions*. A **live wire** harness
([`test/interop/`](test/interop/)) additionally runs wolfMKA back-to-back with
wpa_supplicant's MKA over a veth pair in two network namespaces, proving two
independent stacks complete the protocol on the wire:

- `sudo make interop` (Tier 1) — `mka_link` ↔ wpa_supplicant reach discovery →
  Key Server election → SAK agreement (control plane).
- `sudo make interop-dataplane` (Tier 2) — the combined `mka_macsec` example
  (raw-socket EAPOL **plus** the kernel MACsec netlink data plane) ↔
  wpa_supplicant: both program the kernel SA, `ping` flows MACsec-protected
  (verified on the wire), and a Key Server rekey rolls the key without dropping
  traffic.

These need root, the kernel `macsec` module and a MACsec-capable wpa_supplicant,
so they are a manual/privileged gate rather than part of unit CI; each script
`SKIP`s cleanly when a prerequisite is absent. See the
[`test/interop/`](test/interop/) directory.

## Using the library

```c
MkaParticipantConfig cfg = {0};
cfg.cak = my_psk_cak_pair;          /* CAK + CKN (PSK), or derive from EAP MSK */
memcpy(cfg.sci, my_sci, 8);
cfg.priority = 16;
cfg.macsec_desired = 1;
cfg.macsec_capability = MKA_CAP_INTEGRITY_CONF_OFFSET;
cfg.key_server_capable = 1; /* 0 means *cannot*: advertises priority 255 */
cfg.sak_len = 16;                   /* GCM-AES-128 */
cfg.secy = my_secy_ops;            /* install_tx_sa / install_rx_sa / ... */
cfg.send = my_send_fn;             /* write the frame to EtherType 0x888E   */

/* Both crypto workspaces are caller-owned and required: wolfSSL's ~1 KB Cmac
 * context and its WC_RNG never live on wolfMKA's stack or heap, so a missing
 * one is rejected rather than substituted. Acquire once, not per participant.
 */
cfg.cmac = wm_Crypto_CmacInit();    /* NULL if the pool is exhausted */
cfg.rng  = wm_Crypto_RandomInit();  /* NULL if exhausted or seeding failed */

MkaParticipant p;
if (wm_Participant_Init(&p, &cfg) != MKA_OK) { /* bad configuration */ }

/* event loop */
for (;;) {
    uint32_t now = monotonic_ms();
    wm_Participant_Run(&p, now, NULL);                 /* tx + timers       */
    if (got_frame) wm_Participant_Receive(&p, buf, len, now);
}
```

Deriving the CAK/CKN from an EAP MSK instead of a PSK:

```c
/* cfg.cmac is the caller-owned CMAC workspace (wm_Crypto_CmacInit()).
 * The MSK is the KDF key in full, and its length is what selects AES-128 or
 * AES-256 CMAC - so supply exactly as much MSK as the CAK you want. Pass more
 * and the call is refused rather than quietly deriving from a prefix, which
 * would produce a CAK no other implementation reproduces. hostapd arranges the
 * same thing from the other end: wpa_supplicant clamps the MSK to the CAK
 * length before deriving. */
wm_Crypto_DeriveCakFromMsk(cfg.cmac, msk, 16, mac_lo, mac_hi,
                        cfg.cak.cak, 16);
wm_Crypto_DeriveCknFromMsk(cfg.cmac, msk, msk_len, eap_session_id, sid_len,
                        mac_lo, mac_hi, cfg.cak.ckn, ckn_len);
cfg.cak.cak_len = 16; cfg.cak.ckn_len = ckn_len;
```

**Faster establishment.** By default a participant transmits on its periodic
cadence, so each step of discovery, election and the SAK Use handshake waits a
Hello Time. Setting `cfg.immediate_response = 1` makes it transmit as soon as it
has something new to report — a peer entering the Potential list or becoming
live, a SAK installed, or the transmit gate releasing (the `newInfo` behaviour
of 802.1X §9.4). Combined with the retry ramp it takes establishment from
several Hello Times to a few milliseconds of protocol time:

```c
/* the OPEN Alliance TC17 automotive timing, on any build */
wm_Participant_AutomotiveDefaults(&cfg);  /* immediate_response + 10 ms ramp */
wm_Participant_Init(&p, &cfg);
```

**Key loss and recovery.** A peer whose MACsec SAK Use stops reporting the key
has lost it — its data plane restarted, typically — and nothing in the protocol
brings it back on its own. A member that still holds a key always
sends the parameter set, so an MKPDU arriving without one is a statement, and
every participant - not only the Key Server - drops what it was recording about
that peer's use of the key rather than letting a stale claim stand. The Key Server notices and distributes a fresh SAK
(one rekey per loss, not one per MKPDU). Setting `cfg.distribute_before_install`
additionally has the Key Server put a new SAK on the wire *before* programming
its own SecY, so a peer behind a slow data plane starts installing at the same
moment; while that programming is outstanding the participant withholds its
receive claim, so no peer sends protected frames it could not yet decrypt.

**Rekeying.** When the SecY reports the transmit packet number nearing
exhaustion (or on a policy timer), the Key Server calls
`wm_Participant_Rekey(&p)`. This generates a fresh SAK and begins a
make-before-break handover: the current key is kept installed as the *Old* key
for in-flight traffic while the new *Latest* key is distributed, and is retired
automatically once every peer has moved over.

**Multiple CAs on one port.** Use the `MkaKay` manager to run several
Connectivity Associations (distinct CKNs) on a single port; it demultiplexes
each inbound MKPDU to the participant that owns its CKN.

```c
MkaKay kay;
wm_Kay_Init(&kay);
wm_Kay_AddParticipant(&kay, &cfg_ca1, NULL);   /* one CAK/CKN */
wm_Kay_AddParticipant(&kay, &cfg_ca2, NULL);   /* another     */

for (;;) {
    uint32_t now = monotonic_ms();
    wm_Kay_Run(&kay, now);                       /* step every CA      */
    if (got_frame) wm_Kay_Receive(&kay, buf, len, now);  /* route by CKN */
}
```

## License

wolfMKA is licensed under the **GNU General Public License v3.0 or later**
(`SPDX-License-Identifier: GPL-3.0-or-later`); the full text is in
[`COPYING`](COPYING). For users who cannot use wolfMKA under GPLv3, a
**commercial license** is available — see [`LICENSING`](LICENSING) or contact
licensing@wolfssl.com.

wolfMKA depends on **wolfSSL** for all cryptography, which is offered under the
same dual GPLv3 / commercial model.
