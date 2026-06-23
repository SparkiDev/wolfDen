# wolfMKA — Sales Briefing

> **Caveat for the rep:** This briefing names example companies to illustrate
> the industry plays. It is **not** sourced from the wolfSSL CRM. Each example
> is flagged as either a *publicly-known wolfSSL adopter* or a *net-new
> prospect*, and inferences are marked as such. **Verify account status before
> putting any logo on a slide.**

## What it is, in one sentence
**wolfMKA is wolfSSL's implementation of MACsec Key Agreement (MKA,
IEEE 802.1X-2010 Clause 9)** — the control-plane protocol that lets two devices
mutually authenticate and continuously negotiate the keys that drive **MACsec
(802.1AE)** Layer-2 encryption. It's the piece that turns a MACsec-capable NIC
or switch ASIC into a *managed, key-rotating, standards-interoperable* secure
link.

## Where it sits
- **MACsec (802.1AE)** = the wire encryption (usually in hardware/SecY).
- **MKA (802.1X-2010)** = the brains: peer discovery, Key Server election, SAK
  distribution, rekey. **This is wolfMKA.**
- wolfMKA rides on **wolfSSL/wolfCrypt** for the crypto primitives (CMAC, AES
  Key Wrap, AES-GCM), so a customer already using wolfCrypt — especially
  **wolfCrypt FIPS 140-3** — gets MKA on the same validated engine. That's the
  key cross-sell hook.

## Why it wins (lead with these)
- **Tiny, deterministic footprint** — caller-allocated state, **no malloc**
  option, small-stack build. Measured: ~17 KB code, ~1.5 KB worst-case stack
  default; an embedded profile drops stack to ~176 B. Fits MCUs and line-card
  control processors where Linux `wpa_supplicant` won't.
- **Pairs with wolfCrypt FIPS 140-3** — one validated crypto core across TLS,
  MACsec, and the rest of the stack. Compelling for regulated buyers.
- **Safety/assurance pedigree that maps to the customer's own audits:** 100%
  MC/DC coverage, MISRA C:2012-clean, valgrind/ASan/UBSan, static analysis,
  **coverage-guided fuzzing**, and **proven big-endian operation** (ppc64) 
  This is the language automotive and grid customers already speak.
- **AUTOSAR-native API** — ships a `Mka_*` Classic AUTOSAR interface
  (Init/MainFunction/RxIndication) alongside the portable `wm_*` API. Drops into
  an AUTOSAR BSW stack without a shim.
- **Proven interoperability** — byte-pinned against hostapd test vectors **and**
  runs live against `wpa_supplicant` (control plane *and* kernel-MACsec data
  plane). De-risks "will it talk to the other vendor's box?"
- **Full modern feature set:** Key Server election, make-before-break rekey,
  **XPN** (Extended Packet Numbering — GCM-AES-XPN-128/256 for 10/100G+ links
  that exhaust 32-bit PNs in seconds), EAP-derived and pre-shared CAK,
  Distributed CAK, delay protection, cipher negotiation.
- **Commercial licensing + wolfSSL support** — the usual escape from GPL for
  product teams, plus the support SLA and FIPS lineage embedded buyers pay for.

## The qualifying question for any prospect
*"You have MACsec in the silicon — what's managing the keys today?"*
If the answer is "nothing / we rekey manually / we're hand-rolling it / we
ported wpa_supplicant and it's too heavy" → that's wolfMKA.

---

## Industry plays & example targets

### 1. Automotive (AUTOSAR)
**The play:** In-vehicle Ethernet backbones (zonal architectures, ADAS,
telematics) are standardizing on MACsec to protect L2 traffic between ECUs.
AUTOSAR Classic defines the `Mka` module — and wolfMKA implements that interface
directly. Lead with the **AUTOSAR API + MISRA + FIPS-capable wolfCrypt**
combination; that trio is exactly the procurement checklist.

- **Existing-adopter angle — NXP Semiconductors.** wolfSSL has a long-standing,
  publicly-documented relationship with NXP (wolfSSL/wolfCrypt is supported and
  benchmarked on NXP automotive/MCU silicon). NXP's automotive Ethernet
  switches/processors are a natural home for a MACsec key-agreement layer.
  *Treat as a warm, relationship-exists lead; confirm the specific automotive BU
  and whether MACsec/MKA is in scope.*
- **Net-new prospect — a Tier-1 ECU/gateway vendor (e.g., Continental, Bosch, or
  Aptiv).** They build the AUTOSAR-based zonal controllers and gateways whereo
  the `Mka` module lands. Pitch: "AUTOSAR-conformant MKA on the same
  FIPS-validated crypto you can carry across the whole
  secure-onboard-communication stack." *Net-new; verify against CRM.*

### 2. Network Equipment
**The play:** Switch/router/NIC vendors whose ASICs do MACsec but who need a
small, portable, interoperable key-agreement stack for the control CPU — without
dragging in a full Linux supplicant. Lead with **footprint, interop (proven vs.
wpa_supplicant), and commercial license**.

- **Existing-adopter angle — a wolfSSL networking customer already shipping
  wolfSSL in their firmware.** wolfSSL is widely embedded in networking gear;
  the cross-sell is "you already trust wolfCrypt for TLS/SSH on this box — add
  MACsec key management on the same core." *Pull the actual account from CRM;
  the pattern is real even if the specific logo isn't named here.*
- **Net-new prospect — Arista, Juniper, or a merchant-silicon NIC vendor (e.g.,
  a SmartNIC/DPU maker).** Campus/data-center switches and DC interconnects
  increasingly mandate MACsec; the key-management layer is the gap.
  *Net-new; verify.*

### 3. Power Grid (NERC CIP-012)
**The play:** **NERC CIP-012-1** requires protecting the confidentiality and
integrity of **Real-time Assessment / Real-time Monitoring data between Control
Centers**. MACsec is a clean, link-layer way to meet that for the
substation/control-center communications, and MKA is what keeps those keys live
and rotated. Lead with **assurance evidence (MC/DC, MISRA, fuzzing, FIPS-capable
crypto)** — utilities and their vendors live and die by auditable compliance.

- **Existing-adopter angle — Schweitzer Engineering Laboratories (SEL).** SEL
  builds substation gear and ruggedized networking for utilities and is a
  recognizable name in grid security; wolfSSL has strong penetration in
  industrial/utility embedded. *Likely-fit, possibly existing — confirm account
  status; if not yet a customer, it's a high-value warm prospect.*
- **Net-new prospect — Hitachi Energy, GE Vernova (Grid), or Siemens Grid.**
  These vendors supply the control-center and substation communication equipment
  directly in CIP-012 scope. Pitch: "FIPS-capable, audit-evidenced MACsec key
  agreement to help your utility customers satisfy CIP-012 data-in-motion
  protection." *Net-new; verify.*

---

## One-slide recap
| | |
|---|---|
| **Product** | wolfMKA — IEEE 802.1X-2010 MKA for MACsec key management |
| **Runs on** | wolfCrypt (incl. FIPS 140-3); bare-metal, RTOS, AUTOSAR, Linux |
| **Footprint** | ~17 KB code, sub-200 B stack possible, no-malloc option |
| **Assurance** | 100% MC/DC, MISRA C:2012, fuzzed, big-endian-proven, interop-tested |
| **Interop** | Validated vs. hostapd vectors and live wpa_supplicant |
| **Features** | Key Server election, SAK rekey, XPN, EAP/PSK/Distributed CAK, delay protection |
| **License** | GPLv3 or commercial + wolfSSL support |
