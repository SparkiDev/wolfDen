# wolfMKA — AUTOSAR Classic Platform MKA conformance map

This document maps wolfMKA against the **AUTOSAR Classic Platform**
*Specification of MACsec Key Agreement* (Document ID 1066), which profiles the
IEEE Std 802.1X-2020 MKA protocol for automotive use. It is the AUTOSAR-facing
companion to [`REQUIREMENTS.md`](REQUIREMENTS.md) (the 802.1X requirements
matrix) and follows the same "supports, not certified" scope discipline as
[`COMPLIANCE.md`](COMPLIANCE.md). Its sibling for the other automotive profile
is [`OPEN-ALLIANCE.md`](OPEN-ALLIANCE.md) (OPEN Alliance TC17 Automotive MKA).
The two are separate profiles of the same core and select different feature
sets: `WOLFMKA_AUTOSAR` compiles out EAP and keeps Announcements,
`WOLFMKA_AUTOMOTIVE_PROFILE` compiles out Announcements and announces MKPDU
version 3. They do compile together, but the combination drops
`Mka_PaeConfigType.AnnounceCipherSuites` (that field is itself
`WOLFMKA_NO_ANNOUNCEMENTS`-guarded), so build them together only if the ECU
genuinely wants both profiles' restrictions.

> wolfMKA is a portable MKA control-plane library, not a generated AUTOSAR BSW
> module, and is not certified to any AUTOSAR conformance class. It ships an
> `Mka`-API **binding** (`include/wolfmka/autosar/Mka.h`, `src/autosar/Mka.c`)
> that realises the module's API surface over the core KaY, but the binding is
> hand-written C with plain-struct configuration, not RTE/ECU-configuration
> output. Wording is deliberate: wolfMKA **supports** the AUTOSAR MKA profile and
> provides its API; do not upgrade that to "conforms" in downstream material.

## The Mka API binding

`Mka.h` realises the SWS API (§8) over the core library; see `make autosar` for
an end-to-end run (two PAEs reaching a MACsec session purely through the API).
The mapping:

| AUTOSAR | wolfMKA |
|---------|---------|
| PAE (controlled port) | one `MkaKay` |
| CKN/CAK | one `MkaParticipant` |
| `Mka_Init` | `wm_Kay_Init` per PAE, store config |
| `Mka_SetCknStatus` / `Mka_StartPae` | `wm_Kay_AddParticipant` |
| `Mka_MainFunction` | `wm_Kay_Run` for every enabled, started, linked PAE |
| `Mka_RxIndication` | `wm_Kay_Receive` (routed by `RxPduId`) |
| `Mka_GetPaeStatus` | `wm_Participant_GetPaeStatus`, translated (see below) |
| `Mka_LinkStateChange` / `Mka_SetEnable` | gate `Mka_MainFunction` |

Functions implemented — §8.3: `Mka_Init`, `Mka_GetVersionInfo`,
`Mka_Set/GetCknStatus`, `Mka_Set/GetEnable`, `Mka_GetPaeStatus`,
`Mka_SetPaePermissiveMode`, `Mka_StartPae`, `Mka_GetMacSecStatistics`,
`Mka_LinkStateChange`; §8.4: `Mka_GetMacSecStatisticsNotification`,
`Mka_RxIndication`, `Mka_TxConfirmation`, `Mka_MacSecUpdateSecYNotification`,
`Mka_MacSecAddTxSaNotification`, `Mka_MacSecAddRxSaNotification`; §8.5:
`Mka_MainFunction`.

The SecY/MacSec interface is asynchronous in AUTOSAR (request + `*Notification`
callback). `Mka_GetMacSecStatistics` is therefore deferred: it accepts the
request (returning `E_NOT_OK` if one is already pending) and the SecY confirms
via `Mka_GetMacSecStatisticsNotification`. The wolfMKA SecY (`MkaSecyOps`) is
synchronous, so the SA/SecY-update notifications are acknowledgements here — an
async MacSec module may still call them; the synchronous install path does not
block on them.

The integrator supplies, via the config structs, the lower-layer transmit
(`Mka_TransmitFnType`, the EthIf abstraction) and the MACsec SecY (`MkaSecyOps`).
`Mka_Std.h` is a small shim providing AUTOSAR base types (`Std_ReturnType`,
`PduInfoType`, ...) for standalone builds; in a real stack the platform headers
provide these (define `MKA_NO_STD_SHIM`). `MacSec` statistics counters live in
the SecY, so `Mka_GetMacSecStatistics` reads them back through
`wm_Participant_GetSecyStats`, saturating each 64-bit counter into the 32-bit
AUTOSAR field; a PAE whose data plane exposes no counters reports zeros. The binding uses AUTOSAR naming conventions
and so is built separately from the MISRA-checked core (`make autosar`, not part
of `make misra`). That applies to the module's *API surface*: the file's own
file-static helpers take the project's `mka_*` prefix like every other static
in `src/`, so a reader can tell `mka_add_ckn` (internal) from `Mka_StartPae`
(exported SWS API) by name alone.

Reference: AUTOSAR CP R24-11, `AUTOSAR_CP_SWS_MACsecKeyAgreement.pdf`.
Requirement IDs below are the `CP_SWS_Mka_*` items of that document.

## The AUTOSAR profile is a restricted subset

The AUTOSAR MKA SWS (§4.1, "Limitations") deliberately removes much of IEEE
802.1X. wolfMKA already covers the retained behaviour and additionally
implements features AUTOSAR drops, so on the profile's own scope there is no
functional gap from these exclusions:

| AUTOSAR exclusion (§4.1) | wolfMKA |
|--------------------------|---------|
| EAP authentication — PSK CAK only | PSK supported; EAP is an optional extra (`WOLFMKA_NO_EAP`) |
| Point-to-Multipoint | Point-to-point supported (one SC per port), matching the profile |
| In-service upgrades (EAPoL-MKA) | not implemented (matches profile) |
| Temporary MKA suspension | available as opt-in `WOLFMKA_SUSPENSION` (XPN only); compiled out of the AUTOSAR build, matching the profile |
| Dynamic Key Server election | supported *and* a fixed configured role is available (see Mka_00011) |
| Distributed CAK (type 5), KMD (type 6) | available as opt-in `WOLFMKA_DISTRIBUTED_CAK` / `WOLFMKA_KMD` (these parameter sets are `#ifdef`-compiled out of the default and AUTOSAR builds, matching the profile); the core Distributed SAK (type 4) is always present |

## Requirements traceability

| Req | Requirement (abridged) | Implementation | Verification |
|-----|------------------------|----------------|--------------|
| CP_SWS_Mka_00005/16/33 | Pre-shared CAK; key selection by CKN | `wm_Participant_Init`, `wm_Crypto_DeriveKeys`, `wm_Kay_Find` | `test_kdf_and_keys`, `test_kay_manager` |
| CP_SWS_Mka_00007 | SAK generation by KDF + RNG | `mka_ks_generate_sak`, `wm_Crypto_GenerateSak` | `test_two_party_agreement` |
| CP_SWS_Mka_00008 | MKPDU parameter sets: Basic, Live (1), Potential (2), SAK Use (3), Distributed SAK (4), **Announcement (7)**, **XPN (8)** | `encode_*`/`decode_*` in `mka_pdu.c` | `test_roundtrip_*`, `test_pdu` (XPN + announcement round-trips) |
| CP_SWS_Mka_00009 | EAPoL-MKA-Announcement, MACsec Cipher Suites TLV (type 112) | `mka_announce_encode`/`mka_decode_announce`, opt-in via `Mka_PaeConfigType.AnnounceCipherSuites` | `test_pdu` (announcement round-trip), `test_autosar` |
| CP_SWS_Mka_00011 | Configured fixed role (`MKA_KEY_SERVER`/`MKA_PEER`) | `MkaRole`, `mka_run_election` (fixed-role bypass) | `test_fixed_role_and_auto_rekey` |
| CP_SWS_Mka_00012 | MKA retry with exponential back-off (base → cyclic) | `wm_Participant_Run`, configured via `Mka_PaeConfigType.RetryBaseMs`/`RetryCyclicMs` | `test_retry_backoff`, `test_autosar` |
| CP_SWS_Mka_00013 | Key Server auto-rekey after a configured time span | `wm_Participant_Run` (`sak_rekey_time_ms`) | `test_fixed_role_and_auto_rekey` |
| CP_SWS_Mka_00014 | Auto-rekey at PN exhaustion (`0xC0000000` / `0xC000000000000000` XPN) | `mka_pn_exhausted`, `wm_Participant_Run` | Review (driven by the SecY `get_next_pn` hook) |
| 8.2.9 / 8.3.8 Permissive mode | Plaintext fallback after a timeout when MACsec cannot be established | `Mka_SetPaePermissiveMode`, `Mka_PaeConfigType.PermissiveTimeoutMs`, `Mka_PaeStatusType.PermissivePlaintext` | `test_autosar` (permissive timeout) |
| (cipher suites) | GCM-AES-128/256, GCM-AES-XPN-128/256 configurable | `mka_cipher_suite_valid`, `MKA_CIPHER_*` | `test_kay_cipher_variants`, `make features` |

## XPN parameter set (type 8)

Implemented to IEEE Std 802.1X-2020 §11.11.6 (Figure 11-16): header octet 2 is
the MKA suspension time in seconds (transmitted as 0 by this AUTOSAR binding,
which is built without the optional `WOLFMKA_SUSPENSION` feature), and a fixed
8-octet body carries the 32 most-significant bits of the Latest and Old
Lowest-Acceptable-PNs, the low 32 bits of which travel in MACsec SAK Use. The KaY emits it whenever an XPN cipher suite is in
use and reconstructs the 64-bit value on receipt. The full 64-bit transmit PN is
sourced through the optional SecY hook `get_next_pn`.

## Announcement parameter set (type 7)

Implemented to IEEE Std 802.1X-2020 §11.12 verified against the normative text:

- **Parameter set** — type 7 (Figure 11-15), body is a sequence of TLVs.
- **TLV header** — IEEE Std 802.1AB style (Figure 11-19): 7-bit type, 9-bit
  information-string length.
- **MACsec Cipher Suites TLV** — type 112 (§11.12.3, Figure 11-22): the
  information string is a multiple of 10 octets, each entry a 2-octet
  implementation capability (the MACsec Capability of Table 11-6 in the two
  least-significant bits; the 14 more-significant bits transmitted as 0 and
  ignored on receipt) followed by the 8-octet IEEE Std 802.1AE Cipher Suite
  reference number.

Announcements are optional in IEEE Std 802.1X (and removed entirely by the
OpenAlliance automotive profile), so KaY emission is off by default and enabled
via `MkaParticipantConfig.announce_cipher_suites` (exposed to the AUTOSAR
binding as `Mka_PaeConfigType.AnnounceCipherSuites`); decode is always active.
Both the feature and its AUTOSAR config field can be compiled out with
`WOLFMKA_NO_ANNOUNCEMENTS` (likewise `WOLFMKA_NO_RETRY` for the back-off); the
`WOLFMKA_AUTOSAR` profile keeps both in and compiles out only EAP.

## Permissive mode (8.2.9)

`Mka_SetPaePermissiveMode` selects a PAE's behaviour when MKA cannot establish a
Secure Channel:

- **`MKA_PERMISSIVE_MODE_NEVER`** (the reset default) — the controlled port stays
  blocked; the binding never reports a plaintext fallback.
- **`MKA_PERMISSIVE_MODE_TIMEOUT`** — while the PAE is active (enabled, started,
  link up) but has not agreed a SAK, the unsecured time accumulates each
  `Mka_MainFunction` cycle. Once it reaches
  `Mka_PaeConfigType.PermissiveTimeoutMs`, `Mka_GetPaeStatus` reports
  `PermissivePlaintext = TRUE`, signalling that the integrator may open the
  controlled port for unprotected traffic. Establishing MACsec, or the PAE going
  inactive, clears it.

Permissive mode answers "MKA could not establish a Secure Channel with the
peer". It deliberately does *not* answer "this ECU's own configuration is
broken": a PAE whose every CKN failed to instantiate has no CA to run, so
`Mka_StartPae` leaves it unstarted and it never becomes active for the timeout.
Opening the controlled port on a configuration fault would be the wrong failure
direction, and it is the same reasoning that makes a `PermissiveTimeoutMs` of
zero fail closed rather than run plaintext from the first tick. The enable flags
are untouched, so `Mka_StartPae` can simply be called again once the
configuration is fixed.

As with the SecY data plane and the transport, the binding only *decides and
reports* the permissive state; physically opening the controlled port in
plaintext is the integrator's action behind that abstracted seam.

## What an AUTOSAR integration must still supply

The `Mka` API binding (above) provides the module surface; an integration still
wires it into the platform:

- The `EthIf`/`Eth` transport behind `Mka_TransmitFnType`, and the calls into
  `Mka_RxIndication` / `Mka_MainFunction` from the BSW scheduler.
- The SecY data plane (via the `MkaSecyOps` hooks) — hardware or `macsec` driver.
- Configuration generation (PAEs, roles, CAK/CKN, timers) — the binding consumes
  plain `Mka_ConfigType` structs; an ECU-configuration generator producing them
  is out of scope.
- `Det`, if development-error reporting is wanted: set `MKA_DEV_ERROR_DETECT` to
  `STD_ON` and put your `Det.h` on the include path. Optional — the default is
  `STD_OFF` and the binding links without one.

## Status reporting is the KaY's ladder, translated

`Mka_GetPaeStatus` does not compute the PAE state itself. It reads
`wm_Participant_GetPaeStatus` for each of the PAE's CAs, translates the
`MkaPaeState` into `Mka_MkaStatusType`, and reports the most advanced state any
CA reached — so there is one state machine, not two. Link state and the enable
flag are the binding's own, and are applied first: a disabled PAE reports
`MKA_STATUS_UNDEFINED` and one without link `MKA_STATUS_WAITING_PEER_LINK`,
neither of which the KaY has a view of.

`Mka_GetCknStatus` follows the same rule. `Mka_SetCknStatus`'s enable flag is
the integrator's *request*, and both it and `Mka_StartPae` leave it set when the
instantiation fails so that a later call can retry — so on a started PAE the
status is read from the KaY (`wm_Kay_Find`) rather than off the flag, and a CKN
whose participant never came up reads back `FALSE`. Before the PAE is started
there is nothing in the KaY to read, and the flag is reported as configured.

Two consequences worth stating, because both are narrower than a reading of the
enumeration names might suggest:

- **`MKA_STATUS_MACSEC_RUNNING` means protection is transmitting**, not that a
  SAK has been agreed. A key whose transmit SA is still being installed — the
  asynchronous SecY case, where `install_tx_sa` returns `MKA_SECY_PENDING` and
  completion arrives via `Mka_MacSecAddTxSaNotification` — reports
  `MKA_STATUS_IN_PROGRESS`. An integrator that opened the controlled port on
  MACSEC_RUNNING would otherwise send unprotected frames. It *does* stay set
  across a make-before-break rekey, where the demoted Old key carries traffic
  while the new one is gated.
- **`MKA_STATUS_AUTH_FAIL_UNKNOWN_PEER` means no MKPDU has ever
  authenticated** on that CA, which is the CAK/CKN-mismatch case. It is not
  cleared by `Mka_LinkStateChange` — a link transition does not change which CAK
  the far end holds — and it is not reported for an isolated ICV failure on an
  association that has been working.

## MISRA and structural coverage of the binding

`src/autosar/Mka.c` is checked by `make misra` in two configurations of its own
(`WOLFMKA_AUTOSAR`, with `MKA_DEV_ERROR_DETECT` off and on). It is not part of
`$(SRC)`, so it needs a separate invocation - without one it sat outside the
gate that the project says covers `src/`.

AUTOSAR's `boolean` is a `uint8` typedef rather than C99's `bool`, so MISRA's
essential type model reads `if (someBoolean)` as an integer controlling
expression (14.4) and `(boolean)(a != b)` as a cast to the wrong essential type
(10.5). The file avoids both without changing behaviour: controlling
expressions compare explicitly against `FALSE`, and boolean assignments use
`? TRUE : FALSE` instead of a cast - which is idiomatic AUTOSAR style anyway.
One deviation remains, recorded in [`MISRA.md`](MISRA.md): `mka_send_bridge`
recovers its PAE from the opaque `void*` context `MkaSendFn` carries (11.5),
which a generic callback hook cannot express any other way.

## Structural coverage of the binding

`src/autosar/Mka.c` is not part of `make coverage-configs`: it needs
`-DWOLFMKA_AUTOSAR` (which implies `WOLFMKA_NO_EAP` and changes struct layout)
and its own suite. It has its own gate instead — **`make coverage-autosar`**,
held to the same bar as the core sources: **100% line, 100% decision and 100%
MC/DC**, enforced (the target fails below), measured with GCC's
`-fcondition-coverage`. It runs twice, once in each `MKA_DEV_ERROR_DETECT`
setting, since the reporting adds branches of its own; both are in CI alongside
`coverage-configs`.

Reaching it needed the failure paths a happy-path suite never touches: an
undersized `WOLFMKA_CMAC_POOL_SIZE` or `WOLFMKA_RANDOM_POOL_SIZE` at init (both
must run before any successful `Mka_Init`, since each workspace is acquired once
and never released; the CMAC case is checked and refused before the RNG is even
requested, so a refusal never leaves a pool object claimed by a module that
never came up),
a `PaeCount` with a NULL `Paes`, a PAE declaring CKNs with no array, a zero
`PermissiveTimeoutMs` under `MKA_PERMISSIVE_MODE_TIMEOUT`, and
`Mka_GetMacSecStatistics` both with and without a `get_secy_stats` hook behind
it. One branch was removed rather than covered: `mka_active_status` used to test
`wm_Participant_GetPaeStatus`'s return, which fails only on a NULL argument and
so could never be false there — the status is now seeded to `MKA_PAE_UNDEFINED`
and the call's result used directly.

## Development-error reporting (§7)

The module reports development errors to Det, guarded by the usual
configuration switch:

```c
#define MKA_DEV_ERROR_DETECT STD_ON     /* default: STD_OFF */
```

**Detection does not depend on the switch.** Every condition below is checked,
and rejected with `E_NOT_OK`, in both settings — the switch only controls
whether the rejection is also *reported*. Turning it off cannot change what the
module does, only what a developer is told about it. With it off the reporting
compiles away to nothing and the binding links with no Det present, which is why
`STD_OFF` is the default: wolfMKA ships a hand-written binding that must build
outside a generated BSW stack.

### Errors

| Error | ID | Raised when |
|---|---|---|
| `MKA_E_UNINIT` | 0x01 | an API is called before `Mka_Init`, or after it refused a configuration |
| `MKA_E_PARAM_POINTER` | 0x02 | a required pointer argument is NULL — including a `PaeCount` with a NULL `Paes` |
| `MKA_E_INVALID_PAE_IDX` | 0x03 | `MkaPaeIdx` is outside `0 .. PaeCount-1` |
| `MKA_E_INIT_FAILED` | 0x04 | `Mka_Init` refused the configuration (zero `MainFunctionPeriodMs`, or no CMAC workspace free) |
| `MKA_E_PARAM_INVALID` | 0x05 | a parameter is outside its permitted range or enumeration |
| `MKA_E_KAY_RUN_FAILED` | 0x80 | **vendor-specific**: a Connectivity Association failed inside `Mka_MainFunction` |

Every API has a service ID (`MKA_SID_*`), so a report says both *what was
called* and *what was wrong with it* — "uninitialised", "bad PAE index" and
"NULL pointer" are three different mistakes with three different fixes, and the
previous code returned the same `E_NOT_OK` for all of them.

The numeric values follow the conventional AUTOSAR numbering, and every one is
`#ifndef`-guarded so an integration can align them with the exact SWS revision
or Det configuration it builds against. `MKA_VENDOR_ID`, `MKA_MODULE_ID` and
`MKA_INSTANCE_ID` are overridable for the same reason — Det uses them to
attribute the report.

### Two deliberate departures

- **`Mka_MainFunction` reports `MKA_E_UNINIT` once per uninitialised period,
  not once per call.** A BSW scheduler calls main functions cyclically and
  unconditionally, and the module can stay uninitialised indefinitely — before
  the ECU has run `Mka_Init`, or after `Mka_Init` refused a configuration, which
  leaves it down for good. Reporting on every call would be one message per
  tick, forever, at whatever rate the task is configured for; the first one
  already says everything the rest would. It is still worth that one, because an
  integration that schedules the main function but never calls `Mka_Init`, and
  calls no other API, has nothing else to tell it so. A successful `Mka_Init`
  re-arms the report, so a later refusal gets its own. Every other entry point
  reports on every call, because those are called by application code that chose
  the moment — there one report answers one mistake.
- **`MKA_E_KAY_RUN_FAILED` is edge-triggered.** `Mka_MainFunction` used to
  discard `wm_Kay_Run`'s status, so a per-CA failure — a crypto error during SAK
  generation, say — vanished and the PAE simply sat at `WAITING_PEER`. It is now
  reported, but only on the transition into failure: such a condition usually
  persists, and one message per tick would bury the rest of the log. The
  remaining PAEs are still stepped, so one CA's failure cannot stall the others.

### Routing reports elsewhere

With the switch on, `MKA_DET_REPORT_ERROR(sid, err)` defaults to
`Det_ReportError(MKA_MODULE_ID, MKA_INSTANCE_ID, sid, err)` and pulls in
`Det.h`. Define the macro yourself first — a project Det wrapper, a trace
buffer, a test double — and `Det.h` is not included at all.

### Verification

`make test-det` runs the whole AUTOSAR suite with `MKA_DEV_ERROR_DETECT=STD_ON`
against `test/Det.h`, a stand-in for the generated module, and asserts the exact
`(service ID, error ID)` pair for each rejection. **All eighteen** service IDs
are covered, not a sample: the thirteen APIs that take a PAE index are driven
with an out-of-range one and checked for `MKA_E_INVALID_PAE_IDX` against their
own ID, and the remaining five — `Mka_Init`, `Mka_GetVersionInfo`,
`Mka_MainFunction`, `Mka_RxIndication`, `Mka_TxConfirmation` — have no index and
are covered by their own conditions. The suite also asserts that a successful
call reports nothing, and that the two edge-triggered reports (the main function
running without a module, and a persistently failing CA) are made once and then
not repeated. Because
the stand-in has the AUTOSAR signature, what is exercised is the binding's real
default wiring rather than an override that bypasses it. `make coverage-autosar`
enforces 100% line, decision and MC/DC in **both** switch settings.

