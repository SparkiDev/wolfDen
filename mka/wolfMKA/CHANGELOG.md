# Changelog

All notable changes to wolfMKA are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). The version is
exposed in code as `WOLFMKA_VERSION_MAJOR` / `_MINOR` / `_PATCH` /
`_STRING` / `_HEX` (`include/wolfmka/mka_types.h`).

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

- 728 unit checks, fault-injection and negotiation suites, and the AUTOSAR
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
