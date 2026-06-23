# wolfMKA — AUTOSAR Classic Platform MKA conformance map

This document maps wolfMKA against the **AUTOSAR Classic Platform**
*Specification of MACsec Key Agreement* (Document ID 1066), which profiles the
IEEE Std 802.1X-2020 MKA protocol for automotive use. It is the AUTOSAR-facing
companion to [`REQUIREMENTS.md`](REQUIREMENTS.md) (the 802.1X requirements
matrix) and follows the same "supports, not certified" scope discipline as
[`COMPLIANCE.md`](COMPLIANCE.md).

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
| `Mka_GetPaeStatus` | derived from `wm_Participant_HasSak` / live-peer count |
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
the SecY, so `Mka_GetMacSecStatistics` returns the integrator-tracked values
(zero in the standalone binding). The binding uses AUTOSAR naming conventions
and so is built separately from the MISRA-checked core (`make autosar`, not part
of `make misra`).

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
