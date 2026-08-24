# wolfMKA — Competitive Comparison

> **How to read this:** every competitor claim below is sourced to a public page
> (links at the end) and dated. Claims marked **[verified]** come from the
> vendor's own public material or source repository; **[inferred]** is our
> reading, not their statement; **[unknown]** means they publish nothing and we
> must not assert either way. wolfMKA figures are from this tree
> (`FOOTPRINT.md`, `README.md`, `make coverage-configs`) and are reproducible.
> Do not put an [inferred] or [unknown] claim on a slide as fact.

---

## 1. The bottom line

**wolfMKA is the only MKA in this comparison that is an embeddable,
zero-allocation C library with audit-grade verification evidence and a
FIPS-capable crypto core.** Everything else is either a Linux daemon, a
commercial automotive stack that publishes no assurance evidence, a test tool,
or a router feature you cannot buy as software.

The five products are not five versions of the same thing. They fall into four
categories, and wolfMKA only truly *competes* with two of them:

| Category | Products | Is it a competitor? |
|---|---|---|
| **Embeddable MKA library** | **wolfMKA**, MACH SYSTEMS MKA Stack, Vector MICROSAR MACsec | **Yes — head to head** |
| **Linux daemon / reference implementation** | wpa_supplicant, Technica MKAdaemon | **Partly** — competes on Linux, loses on MCU |
| **Test & validation tooling** | Vector CANoe + Security Manager + VN5650, MACH SYSTEMS MKA Tester | **No** — this is what we get tested *against* |
| **Vendor-integrated network feature** | Nokia ANYsec (FP5 silicon, SR OS) | **No** — it is a market signal and an opportunity |

**The single sentence for a slide:**
> *Everyone else ships MKA as a Linux process, an automotive-only product, or a
> feature of their own hardware. wolfMKA ships it as a portable library with
> 100% MC/DC, MISRA C:2012 conformance and no malloc — on the same wolfCrypt
> core the customer already validated.*

---

## 2. Master comparison

| | **wolfMKA** | **wpa_supplicant** | **Technica MKAdaemon** | **MACH SYSTEMS MKA Stack** | **Vector (MICROSAR + CANoe)** | **Nokia ANYsec** |
|---|---|---|---|---|---|---|
| **What it is** | Embeddable C library | Linux supplicant daemon | Linux daemon (open source) | Commercial C stack + tester | AUTOSAR BSW module + test tool | Router feature in FP5 silicon |
| **Deploy target** | Bare metal, RTOS, AUTOSAR, Linux | Linux userland | Linux (Ubuntu 20.04/22.04 tested) | Linux, Windows, STM32 | AUTOSAR ECU / CANoe host | Nokia 7750 SR only |
| **Base standard** | 802.1X-2010 + 802.1Xbx-2014 (announces v3 in the automotive profile) | 802.1X (MKA) | 802.1X-2020 | 802.1X + OPEN Alliance TC17 | 802.1AE-2018 + 802.1X-2020 | 802.1AE + 802.1X, extended to IP/UDP |
| **Automotive profile (OA TC17)** | ✔ implemented + 65/65 requirement map; not plugfest-tested | ✗ | ✔ (Technica edits the spec) | ✔ claimed | ✔ plugfest-proven | n/a |
| **PSK CAK** | ✔ | ✔ | ✔ | ✔ [inferred] | ✔ | ✔ |
| **EAP-MSK-derived CAK** | ✔ | ✔ | ✗ "not supported yet" | [unknown] | [unknown] | ✔ (802.1X) |
| **XPN (GCM-AES-XPN-128/256)** | ✔ | ✗ upstream; SONiC forked to add it | ✔ | [unknown] | [unknown] | n/a |
| **Distributed CAK / KMD** | ✔ opt-in | partial decode only | [unknown] | [unknown] | [unknown] | [unknown] |
| **Cipher-suite negotiation** | ✔ opt-in | minimal | [unknown] | OA removes it | [unknown] | [unknown] |
| **Zero dynamic allocation** | ✔ enforced by build | ✗ heavy `os_zalloc` | [unknown] | [unknown] | [unknown] | n/a |
| **Bounded stack** | ✔ 176 B worst frame (embedded profile) | ✗ | [unknown] | [unknown] | [unknown] | n/a |
| **Code size** | ~18.8 KB default / ~16.3 KB minimal | not published | not published | not published | not published | n/a |
| **MISRA C:2012** | ✔ conformance statement + deviation record | ✗ | ✗ | "MISRA-conscious coding practices" | [unknown] | n/a |
| **Structural coverage** | ✔ 100% line + branch + **MC/DC**, enforced, 9 configs | ✗ | ~90% target, GoogleTest + gcov | [unknown] | [unknown] | n/a |
| **Fuzzing / sanitizers / static analysis** | ✔ libFuzzer, ASan+UBSan, valgrind, `-fanalyzer` | [unknown] | [unknown] | [unknown] | [unknown] | n/a |
| **Big-endian proven** | ✔ ppc64 under qemu in CI | [inferred] yes | [unknown] | [unknown] | [unknown] | n/a |
| **AUTOSAR `Mka_*` API** | ✔ | ✗ | ✗ | ✗ [inferred] | ✔ (it *is* AUTOSAR) | ✗ |
| **Crypto core** | wolfCrypt, **FIPS 140-3 capable** | OpenSSL / wolfSSL / mbedTLS | [unknown] | [unknown] | Vector crypto / HSM | Nokia RNG (FIPS 140-2, NIAP) |
| **Licence** | GPLv3 **or** commercial | BSD (permissive) | GPLv2 **or** commercial | Commercial | Commercial | Sold with hardware |
| **Public interop evidence** | hostapd vectors + live wpa_supplicant, control **and** data plane | is the de-facto reference | [unknown] | Tester product implies it | OA Plugfest 2025, 8 companies | n/a |

---

## 3. Head-to-head, one competitor at a time

### 3.1 wpa_supplicant / hostapd — *the incumbent we must displace, not beat*

**What it is.** The reference MKA on Linux, BSD-licensed, part of a full
802.1X/WPA supplicant. Its KaY (`src/pae/ieee802_1x_kay.c`) allocates
everything on the heap with `os_zalloc`, keeps peers on linked lists with no
fixed bound, and runs as a userland daemon over a kernel `macsec` device.

**Where it beats us.** Ubiquity and a permissive BSD licence. It is already in
every distro, and for a Linux box with a MACsec NIC it is free, familiar and
"good enough". *Do not argue the licence — BSD beats GPLv3-or-commercial for a
customer who just wants to ship.*

**Where we win.**
- **It cannot leave Linux.** Daemon architecture, heap-dependent, full userland
  dependency chain. On an MCU, an RTOS, or a line-card control CPU it is not a
  candidate. wolfMKA is 17 KB with no malloc and a 176-byte worst-case stack.
- **XPN.** Upstream wpa_supplicant's MKA has historically lacked the XPN cipher
  suites — SONiC maintains its own fork to add GCM-AES-XPN-128/256. At 100G a
  32-bit packet number exhausts in seconds. wolfMKA ships XPN and SSCI in the
  base product. **[verify against the current upstream tree before publishing]**
- **No assurance evidence.** No MISRA statement, no MC/DC, no requirements
  traceability. A safety or grid auditor cannot use it as-is.
- **We interoperate with it.** This is the killer move: we are byte-pinned to
  hostapd's own key-hierarchy vectors and run live against wpa_supplicant on
  both control and data plane. The customer does not have to choose sides.

**The message:** *"Keep wpa_supplicant on your Linux hosts. Put wolfMKA on
everything that can't run it — and we've already proven the two talk."*

---

### 3.2 Technica Engineering MKAdaemon — *the automotive open-source reference*

**What it is.** An open-source (GPLv2, commercial licence available) MKA daemon
implementing 802.1X-**2020** with PSK, all four cipher suites including both XPN
variants, tested on Ubuntu 20.04/22.04. Unit-tested with GoogleTest/GoogleMock
targeting ~90% coverage, generating PCAPs and JUnit XML for CI.

**Where it beats us.** Credibility position, not technology. Technica's
Dr. Lars Völker co-chairs the OPEN Alliance TC17 MKA subgroup and **edited the
Automotive MKA Specification v1.0**. In an automotive room, MKAdaemon is treated
as the reference implementation of the profile. It is also free.

**Where we win.**
- **No EAP.** Their README states EAP is not supported yet; PSK only. wolfMKA
  ships EAP-MSK CAK/CKN derivation, byte-checked against hostapd.
- **Linux-only, daemon-shaped.** Same structural limit as wpa_supplicant — it is
  not an embeddable library and Technica does not claim MCU support.
- **Coverage ambition vs. coverage guarantee.** "At least 90%" line coverage
  against our *enforced* 100% line + decision + **MC/DC** across nine build
  configurations, with the build failing below it. That is the difference
  between a target and a gate — and MC/DC is the DO-178C DAL-A metric.
- **No MISRA conformance statement**, no deviation record, no FMEA, no
  requirements traceability matrix.
- **No AUTOSAR `Mka_*` API.**

**The message:** *"Great reference daemon, and we respect the spec work. But
it's PSK-only, Linux-only, and 90%-coverage-targeted. If your MKA has to run in
an ECU and survive a functional-safety review, that's a different product."*

**⚠ Watch-out:** never disparage the OA spec or Technica's role in it. If the
prospect is an OA member, Technica has the room. Compete on deployability and
evidence, not on standing.

---

### 3.3 MACH SYSTEMS MKA Stack + MKA Tester — *our closest structural match*

**What it is.** A commercial C MKA runtime with a hardware abstraction layer to
any MACsec PHY or system driver, for Linux, Windows and **STM32**, implementing
IEEE 802.1X and the **OPEN Alliance TC17 MACsec Automotive Profile**. Sold
alongside an MKA Tester (GUI, Python wrapper, USB/CAN control, observer
diagnostics) for bring-up and peer validation.

**Where it beats us.**
- **They claim OA TC17 profile compliance as a product property.** We now ship a
  profile build and a published conformance map that names its own gaps — more
  transparent, but "claims compliance" still reads stronger on a procurement
  checklist than "documents where it conforms".
- **The Tester.** A GUI bring-up and diagnostics product is a real sales asset in
  an automotive lab. We ship examples and an interop script.
- Same embedded posture we have (HAL + MCU target), so the "it's a library, not a
  daemon" argument does not differentiate us here.

**Where we win.**
- **They publish no numbers.** No code size, no stack bound, no allocation
  policy, no coverage figure. We publish all four and they are reproducible from
  the source tree by the customer.
- **"MISRA C:2012-conscious coding practices" is not a conformance statement.**
  Ours is: a compliance statement, a deviation record, a checker pinned to an
  exact cppcheck version, run in CI across four configurations. That contrast is
  the single strongest line to use against them, and it is their own wording.
- **No MC/DC, no fuzzing, no sanitizer, no FMEA, no traceability matrix**
  published.
- **FIPS.** wolfCrypt gives a FIPS 140-3 path; they name no validated crypto core.
- **Licence flexibility.** Commercial-only vs. our GPLv3-or-commercial dual model.

**The message:** *"Ask them for their stack's code size, worst-case stack depth,
allocation policy, and MC/DC number. We publish ours and you can rebuild them
yourself in an afternoon."*

**⚠ Now available:** `make test-automotive` builds the profile, and
`OPEN-ALLIANCE.md` maps all 65 of the specification's requirements with none
outstanding — including a section on where two of them pull against each other
and how that is resolved. Ask them for the equivalent document; they publish
none.

---

### 3.4 Vector — MICROSAR MACsec + CANoe/Security Manager — *the incumbent tool vendor*

**What it is.** Two different threats in one logo:
1. **MICROSAR Classic** includes a module to realise MACsec in software — a
   direct AUTOSAR BSW competitor, and MICROSAR is certified to ISO/SAE 21434.
2. **CANoe.Ethernet + Security Manager + VN5650** is the *test tool* the customer
   uses to validate whoever's MKA they chose. Security Manager implements MACsec
   802.1AE-2018 and MKA 802.1X-2020. Vector took the VN5650 and CANoe.Ethernet to
   the **OPEN Alliance TC17 MACsec Plugfest (Feb 2025, WEKA Automotive Ethernet
   Congress, 8 companies)** and reported compatibility with every other
   participant, for both encrypted data exchange and MKA key negotiation.

**Where it beats us.** Incumbency, ISO/SAE 21434 certification on MICROSAR, a
full AUTOSAR toolchain and generator flow, and a plugfest interop result we
cannot yet match. If the customer is already a MICROSAR shop, the MACsec module
arrives with the rest of the BSW and the integration cost is near zero.

**Where we win.**
- **Scope.** Vector's answer is automotive-shaped and priced. wolfMKA runs the
  same code on an RTOS switch, a grid gateway, a SmartNIC control CPU and an
  AUTOSAR ECU. Anyone outside automotive cannot buy MICROSAR at all.
- **You get the source and the evidence.** MISRA record, FMEA, requirements
  traceability, MC/DC report, fuzzing — as files in the repository, not as a
  certificate summary.
- **Crypto consolidation.** One wolfCrypt core, FIPS 140-3 capable, shared with
  the customer's TLS/SSH/secure-boot stack.
- **Cost and licence model.** Dual GPLv3/commercial vs. a MICROSAR seat.

**The message:** *"Vector's MKA comes with Vector's toolchain and Vector's price.
If you're MICROSAR end-to-end, fine. If you need the same MKA in a non-AUTOSAR
product too — or you're not automotive at all — that's us."*

**⚠ Positioning note:** CANoe is the *referee*, not only the opponent. "Validated
against CANoe.Ethernet" would be a stronger interop claim for us than any
feature bullet. Treat Vector tooling as a target to be tested against.

---

### 3.5 Nokia ANYsec — *not a competitor; a market proof and an opening*

**What it is.** A proprietary Nokia feature of FP5 silicon (SR OS 23.10R1+),
using the 802.1AE encryption engine with **802.1X MKA as its control plane**, and
extending it beyond Ethernet: ANYsec encapsulates **MKA over IP/UDP** so the same
machinery encrypts MPLS, segment-routing and IP payloads. Nokia has taken this to
the IETF (`draft-hb-intarea-eap-mka`, presented at IETF 118/121) and to IEEE 802.1
as "MACsec Enhanced" (2025). You cannot license it; it ships inside Nokia routers.

**Why it matters to us — three usable arguments:**
1. **Market validation from a tier-1 carrier vendor.** Nokia chose MKA as the
   key-agreement control plane for a quantum-safe, line-rate encryption product.
   That is the strongest available third-party answer to "is MKA strategic?"
2. **It proves MKA is leaving Layer 2.** If MKA-over-UDP standardises, every
   vendor building L3 link encryption needs an MKA implementation that is not
   welded to an Ethernet socket.
3. **We are already shaped for it.** wolfMKA's encoder emits a bare
   **EAPOL PDU** — no Ethernet header — and hands it to a caller-supplied
   `send` callback; receive takes a buffer and a length. Carrying that PDU in a
   UDP datagram instead of an 802.1X frame is a transport shim in the
   integrator's code, **not a change to the library**. wpa_supplicant, by
   contrast, is bound to its Linux driver layer.

**The message:** *"Nokia just built a quantum-safe, multi-layer encryption
product with MKA as the control plane and MKA-over-UDP as the transport. Our
protocol engine is transport-agnostic by construction — the PDU comes out of a
callback, so you choose the wire."*

---

## 4. The five claims that only wolfMKA can make

Use these; they are all reproducible from the source tree by a sceptical
engineer in one sitting.

1. **100% line, decision *and* MC/DC coverage — enforced, across nine build
   configurations.** `make coverage-configs` fails the build below 100%. MC/DC is
   the DO-178C DAL-A metric. Nobody else in this comparison publishes MC/DC at all.
2. **Zero dynamic allocation, provable.** `make test-nomalloc` fails if a single
   `malloc`/`free`/`calloc`/`realloc` symbol is linked into the library.
   Worst-case stack frame 176 bytes; ~14.5–19 KB of code depending on features.
3. **MISRA C:2012 with a published deviation record**, checked in CI against a
   pinned cppcheck across four configurations, with no Mandatory-rule deviations.
4. **A FIPS 140-3-capable crypto core shared with the rest of the customer's
   stack** — wolfCrypt does the CMAC, AES Key Wrap and AES-GCM.
5. **Two APIs, one engine** — the portable `wm_*` interface and an AUTOSAR
   Classic `Mka_*` binding, plus a complete evidence set (`REQUIREMENTS.md`,
   `FMEA.md`, `COMPLIANCE.md`, `MISRA.md`, `MCDC-AND-COVERAGE.md`, `SECURITY.md`).

**Automotive:** the OPEN Alliance TC17 Automotive MKA profile is implemented and
mapped requirement by requirement in `OPEN-ALLIANCE.md` — all 65, none
outstanding — with a build (`make test-automotive`) held to the same enforced
100% MC/DC as every other configuration. No competitor publishes a comparable
document.

Supporting: 978 test checks; libFuzzer harnesses on both the stateless decoder
and the stateful receive path; ASan+UBSan and valgrind clean; GCC `-fanalyzer`
clean; big-endian verified on ppc64 under qemu; compiles as C++; interop pinned
to RFC 4493, RFC 3394 and hostapd's own key-hierarchy output.

---

## 5. Where we are genuinely behind — do not claim these

Being straight about this protects the rest of the material. Each has a rough
engineering cost so the gap can be closed before it is quoted at us.

### Closed since the first draft of this brief

| Was | Now |
|---|---|
| No OPEN Alliance TC17 profile mode | **`WOLFMKA_AUTOMOTIVE_PROFILE`** build (`make test-automotive`), plus `OPEN-ALLIANCE.md` — a published, requirement-by-requirement conformance map with the remaining gaps named. It is one of the ten configurations held at 100% MC/DC. |
| No "transmit immediately on peer-list change" | **`immediate_response`** config field (all builds). A peer-list change, a newly installed SAK, or the transmit gate releasing is sent on the next `wm_Participant_Run()` — the `newInfo` behaviour of 802.1X 9.4. In the two-party test **MACsec is up 3 ms into the exchange**. |
| Emitting MKA version 1 with no way to change it | **`WOLFMKA_MKA_VERSION`** (default 1, profile selects 3). Receive was already version-agnostic. |
| The OA profile map covered only 48 of its 65 requirements, and cited one requirement ID that does not exist | **All 65 mapped**, no invented IDs. Every requirement resolves to an implementation, a configuration item, the integrator, or a named gap. |
| Liveness accepted any echoed MI regardless of Message Number | **AutoMKA-03005 + 04004 implemented.** A peer must echo an MN we actually emitted recently (`MKA_MN_RECENT_WINDOW`, default 3); one reporting us live on a stale number is discarded without refreshing its Life timer. |
| No way to reach the SecY's MACsec counters | **AutoMKA-07009 implemented.** Three optional `MkaSecyOps` hooks and three accessors return the 802.1AE SecY / TxSC / RxSC counter groups. |
| No single management status call | **AutoMKA-07008 implemented.** `wm_Participant_GetPaeStatus()` returns the profile's status enum plus peer SCI, CKN in use and cipher suite. |
| A peer that lost the SAK stayed undecryptable until something else forced a rekey | **AutoMKA-03011 implemented** (all builds). The Key Server rekeys when a peer that was using the key stops reporting it; a peer mid-handover still naming the Old key is not a false trigger, and the flag clears on rekey so one loss causes one rekey. |
| The SAK was always installed locally before being distributed | **AutoMKA-03010 implemented** (opt-in). `distribute_before_install` has the Key Server put the key on the wire first so both ends install together. Two safety properties: programming waits for the send to succeed, and while it is outstanding the participant withholds its receive claim — so no peer sends protected frames the data plane cannot yet decrypt. |
| Losing CAKs kept transmitting after one CA won | **AutoMKA-09001/09002 implemented.** `wm_Kay_SetQuiesceOthers()` holds the losers silent while one CA has MACsec up, releasing them when it drops. |
| Key Server priority 255 was only "least preferred", so two participants both set to "never Key Server" still elected one | **AutoMKA-03007 implemented** (profile builds). 255 removes a candidate from the election outright; 0 needs no special case, being the value the 802.1X comparison already prefers. |
| `macsec_desired = false` still programmed the SecY | **AutoMKA-12002 implemented.** Such a participant now declines a distributed SAK, so no Secure Channel is created, no SA installed and no packet number read — while MKA itself keeps running. |
| Peer reset cost up to a Life Time of downtime | **AutoMKA-03006 implemented** (all builds). A peer returning with the same SCI and a fresh MI is admitted alongside its old entry, which is retired the moment the new MI proves liveness — not left to expire. Retiring on liveness, not first sight, is what stops a forged MI evicting a working peer. |

The startup figure is an in-process protocol measurement — zero-latency
transport and an instant SecY — so quote it as *protocol* time, not system
startup. The profile's 30 ms budget is a system budget that also covers PHY
link-up and key install.

### Still open

| Gap | Impact | Rough fix |
|---|---|---|
| **No third-party plugfest or independent interop certificate.** Vector has one; we have self-run wpa_supplicant testing. | "Who else have you tested against?" | Attend an OA TC17 plugfest, or publish a CANoe-validated result. |
| **No safety/security certification.** We *support* IEC 61508 / 62443 evidence; MICROSAR is *certified* to ISO/SAE 21434. | Never blur this line — `COMPLIANCE.md` is deliberately worded "supports, not certified". | Out of scope for a library alone. |
| **No named public reference customer.** | Every competitor here is a shipping product with users. | Sales, not engineering. |

---

## 6. Qualifying questions that sort the field

Ask these in order; each one eliminates competitors:

1. **"Where does the key agreement run — a Linux host, an RTOS, or bare metal?"**
   → not Linux eliminates wpa_supplicant and MKAdaemon outright.
2. **"Does anyone have to review this code — MISRA, functional safety, a security
   audit?"** → eliminates wpa_supplicant and MKAdaemon; exposes "MISRA-conscious".
3. **"Are you already using wolfSSL, and do you need FIPS?"** → the cross-sell,
   and no competitor here answers it.
4. **"Is this automotive-only, or does the same protocol need to ship in other
   products too?"** → eliminates Vector MICROSAR and the OA-only stacks.
5. **"What link speed?"** → 10G+ makes XPN mandatory, which upstream
   wpa_supplicant does not carry.

---

## 7. Claim discipline

- **Do not reproduce the OPEN Alliance specification.** Its copyright notice
  explicitly forbids including any portion in marketing material without written
  consent. Reference it by name, version and public URL only.
- **Re-verify before publishing.** wpa_supplicant's XPN status and MKAdaemon's
  EAP status are both "not yet" claims that a competitor can fix. Re-check the
  upstream trees the week the material ships, and date the comparison.
- **Never say "certified".** We support certification evidence; we hold no
  certificate. MICROSAR does hold ISO/SAE 21434 — do not imply parity.
- **Keep the wpa_supplicant relationship friendly.** Interoperability with it is
  one of our strongest proof points; positioning it as broken undermines our own
  claim.
- **Company and product facts here are dated August 2026** and sourced below.

---

## Sources

- Technica Engineering MKAdaemon — <https://github.com/Technica-Engineering/MKAdaemon>
- OPEN Alliance TC17 (MACsec Automotive Profile) — <https://opensig.org/tech-committee/tc17-macsec-automotive-profile/>
- OPEN Alliance *Automotive MKA Specification* v1.0, 26 Feb 2025 — <https://opensig.org/wp-content/uploads/2025/03/OA_MACsec_Automotive-MKA-v1.pdf>
- OPEN Alliance *Automotive MACsec Specification* v1.0 — <https://opensig.org/wp-content/uploads/2025/05/Automotive-MACsec-Specification-v1.0.pdf>
- MACH SYSTEMS MKA Stack and MKA Tester — <https://www.machsystems.cz/en/news/2026/mka-stack-and-tester-for-automotive-ethernet>
- Vector, MACsec Plugfest 2025 result — <https://www.vector.com/int/en/news/news/successful-macsec-plugfest-2025-interoperability-tests-with-focus-on-mka/>
- Vector CANoe Option Ethernet — <https://www.vector.com/int/en/products/products-a-z/software/canoe/option-ethernet/>
- Vector MICROSAR Classic — <https://www.vector.com/int/en/products/products-a-z/embedded-software/microsar-classic/>
- wpa_supplicant (BSD licence, MKA/KaY) — <https://w1.fi/wpa_supplicant/>
- SONiC wpa_supplicant XPN fork — <https://github.com/sonic-net/sonic-wpa-supplicant/pull/17>
- Nokia ANYsec overview — <https://documentation.nokia.com/sar/25-10-1/books/mpls/anysec_overview.html>
- Nokia "MKA over IP/UDP", IETF 118 — <https://datatracker.ietf.org/meeting/118/materials/slides-118-emu-macsec-key-agreement-over-ip-00>
- IETF draft "MKA over IP" — <https://datatracker.ietf.org/doc/html/draft-hb-intarea-eap-mka-00>
- Nokia/IEEE 802.1 "MACsec Enhanced", July 2025 — <https://www.ieee802.org/1/files/public/docs2025/new-bidgoli-macsec-enhanced-0725-v05.pdf>

wolfMKA figures: `wolfMKA/FOOTPRINT.md`, `wolfMKA/README.md`,
`wolfMKA/MCDC-AND-COVERAGE.md`, `wolfMKA/MISRA.md` — all reproducible with
`make footprint`, `make coverage-configs`, `make misra`, `make test`.
